// PocketBase live tests. Same principles as the Supabase and Firebase adapters:
//  - A creates a record of its own (marker text, owner = A); B and an anonymous visitor attack it.
//  - Every finding is a request that succeeded. We never print other users' data, only counts.
//  - A PASS needs proof. PocketBase answers in three ways when a rule says no:
//      null rule (superusers only)        → 403 "Only superusers can perform this action."
//      list rule that doesn't match       → 200 with an empty items array
//      view/update/delete rule no match   → 404
//      create rule that doesn't match     → 400 "Failed to create record." with NO field errors
//    A 403 is a PASS. A 404 / empty list only counts when A's control read through the same
//    endpoint shows the record still exists and is unchanged. A refused create only counts
//    when A's identical payload was accepted (so validation cannot be the reason).

import { randomUUID } from 'node:crypto';
import { COMMON_OWNER_FIELDS, pointsToUsers, privilegedByName } from './rules.js';
import * as fix from './fixes.js';

const rand = () => Math.random().toString(36).slice(2, 8);
// same-length variant of a marker (so a length limit can't cause the refusal)
const tamper = (m) => `${m.slice(0, -1)}${m.endsWith('x') ? 'y' : 'x'}`;
const ok = (r) => Boolean(r && r.ok);
const superusersOnly = (r) => Boolean(r) && r.status === 403;
// "Missing collection context." is a 404 too — but it means the collection does not exist
const missingCollection = (r) => Boolean(r) && r.status === 404 && /missing (or invalid )?collection/i.test(msg(r.data));
const hidden = (r) => Boolean(r) && r.status === 404 && !missingCollection(r);
const fieldErrors = (r) => (r?.data?.data && typeof r.data.data === 'object' ? Object.keys(r.data.data) : []);
const createRefused = (r) => superusersOnly(r) || (Boolean(r) && r.status === 400 && /failed to create/i.test(msg(r.data)) && !fieldErrors(r).length);
const owns = (rec, field, user) => Boolean(rec && field && (rec[field] === user.id || (Array.isArray(rec[field]) && rec[field].includes(user.id))));
const MARKER_CANDIDATES = ['title', 'text', 'name', 'content', 'body', 'description', 'note', 'message', 'label', 'subject'];

export function msg(d) {
  if (!d) return '';
  if (typeof d === 'string') return d.trim().slice(0, 160);
  const errs = d.data && typeof d.data === 'object' ? Object.keys(d.data) : [];
  return `${d.message || JSON.stringify(d).slice(0, 120)}${errs.length ? ` (fields: ${errs.join(', ')})` : ''}`.slice(0, 200);
}

// ---------------------------------------------------------------- users

export async function setupUsers(client, authName, { userA, userB, emailDomain = 'example.com', log }) {
  const run = rand();
  const users = [];
  const unreachable = []; // signed up, but never signed in: no token to delete them with
  try {
    return await signInBoth();
  } catch (e) {
    // never leave half-created users behind: the ones with a token delete themselves
    const left = [...unreachable];
    for (const u of users.filter((x) => x.created)) if (!ok(await client.remove(authName, u.id, { token: u.token }))) left.push(u.email);
    if (left.length) e.message += `\n  Test users already created (delete them in the PocketBase dashboard → ${authName}): ${left.join(', ')}`;
    throw e;
  }

  async function signInBoth() {
    const fail = (m) => new Error(m);
    for (const [label, cred] of [
      ['A', userA],
      ['B', userB],
    ]) {
      let email;
      let password;
      let created = false;
      if (cred) {
        const i = cred.indexOf(':');
        if (i < 1) throw fail(`--user-${label.toLowerCase()} must look like email:password`);
        email = cred.slice(0, i);
        password = cred.slice(i + 1);
      } else {
        email = `accessprobe-${run}-${label.toLowerCase()}@${emailDomain}`;
        password = `Rp-${randomUUID()}`;
        const r = await client.signUp(authName, email, password);
        if (superusersOnly(r)) {
          throw fail(
            `Sign-up is closed: the "${authName}" collection's create rule is superusers-only, so accessprobe cannot create test users.\n` +
              `  Create two test users yourself (Dashboard → Collections → ${authName} → New record)\n` +
              '  and pass them with --user-a email:password --user-b email:password',
          );
        }
        if (!ok(r)) throw fail(`Sign-up of test user ${label} failed (${r.status}): ${msg(r.data)}`);
        created = true;
        log(`  created test user ${label}: ${email}`);
      }
      const a = await client.authWithPassword(authName, email, password);
      if (!ok(a) || !a.data?.token || !a.data?.record?.id) {
        if (created) {
          unreachable.push(email);
          throw fail(
            `Test user ${label} was signed up but could not sign in (${a.status} ${msg(a.data)}) — email verification, OTP/MFA or a custom auth rule may be required.\n` +
              '  Create two test users that can sign in with a password and pass them with --user-a email:password --user-b email:password',
          );
        }
        throw fail(`Sign-in of user ${label} failed (${a.status}): ${msg(a.data)}`);
      }
      users.push({ label, email, id: a.data.record.id, token: a.data.token, record: a.data.record, created });
  }
  return users;
  }
}

// test users delete themselves (default users rule: deleteRule "id = @request.auth.id")
export async function deleteUsers(client, authName, users, notes) {
  const left = [];
  for (const u of users.filter((x) => x.created && !x.gone)) {
    const r = await client.remove(authName, u.id, { token: u.token });
    if (!ok(r)) left.push(`${u.email} (${r.status} ${msg(r.data)})`);
  }
  if (left.length) notes.push(`Could not delete test users — delete them in the PocketBase dashboard → ${authName}: ${left.join('; ')}`);
}

// ---------------------------------------------------------------- payloads

const SAMPLE = { number: 1, bool: true, email: () => `accessprobe-${rand()}@example.com`, url: 'https://example.com', date: () => new Date().toISOString().replace('T', ' '), json: {} };

// A record for collection t, owned by `user`. From the migrations' fields when known.
function schemaPayload(t, user, marker, auth) {
  const data = {};
  let markerField = null;
  const missing = [];
  for (const f of t.fields) {
    if (f.system || f.type === 'autodate' || f.type === 'password') continue;
    if (f.name === t.ownerField) {
      data[f.name] = user.id;
      continue;
    }
    if ((f.type === 'text' || f.type === 'editor') && !f.pattern && !markerField && (f.max == null || f.max === 0 || f.max >= marker.length)) {
      data[f.name] = marker;
      markerField = f.name;
      continue;
    }
    if (!f.required) continue;
    if (f.type === 'relation' && pointsToUsers(f, auth)) data[f.name] = user.id;
    else if (f.type === 'select' && Array.isArray(f.values) && f.values.length) data[f.name] = f.values[0];
    else if (f.type === 'text' && !f.pattern) data[f.name] = marker;
    else if (f.type in SAMPLE) data[f.name] = typeof SAMPLE[f.type] === 'function' ? SAMPLE[f.type]() : SAMPLE[f.type];
    else missing.push(`${f.name} (${f.type})`);
  }
  return { data, markerField, missing };
}

// No schema: send the common owner + text field names at once. PocketBase ignores unknown
// fields, and the response shows which ones exist. Wrongly typed ones are dropped and retried.
async function createGuessing(client, t, A, marker) {
  const data = { ...(t.ownerField ? { [t.ownerField]: A.id } : Object.fromEntries(COMMON_OWNER_FIELDS.map((f) => [f, A.id]))) };
  for (const f of MARKER_CANDIDATES) data[f] ??= marker;
  let r;
  for (let i = 0; i < 4; i++) {
    r = await client.create(t.name, data, { token: A.token });
    if (ok(r) || r.status !== 400) break;
    const bad = fieldErrors(r).filter((f) => f in data && !(t.ownerField && f === t.ownerField));
    if (!bad.length) break;
    for (const f of bad) delete data[f];
  }
  return { r, data };
}

// ---------------------------------------------------------------- collections

// targets: [{ name, coll (from migrations or null), ownerField, fields, type }]
export async function probeCollections(client, targets, [A, B], h) {
  const { log, refs, auth } = h;
  const findings = [];
  const passed = [];
  const skipped = [];
  const left = [];
  let fullyTested = 0;
  let readOnly = 0;
  const leftovers = []; // { coll, id, by: [users who may delete it] }

  try {
    for (const t of targets) {
      log(`  collection ${t.name}`);
      const tf = (f) => findings.push({ resource: t.name, ...f });
      const publicList = t.coll?.listRule === '';
      const publicView = t.coll?.viewRule === '';
      let publicNoted = false;
      const notePublic = (r) => {
        if (publicNoted) return;
        publicNoted = true;
        tf({
          id: 'public-by-rule',
          severity: 'info',
          title: `"${t.name}" is public by design (${[publicList && 'listRule', publicView && 'viewRule'].filter(Boolean).join(' and ')} = "")`,
          detail: 'Everyone, signed in or not, can read every record here. Make sure nothing personal is ever stored in it.',
          evidence: r.evidence,
          fix: null,
        });
      };

      if (t.type !== 'base') {
        await freshUserList(client, t, [A, B], { tf, passed, skipped, notePublic, publicList });
        skipped.push(`${t.name}: write tests skipped — ${t.type === 'view' ? 'a view collection is read-only' : 'other auth collections need their own sign-up'}`);
        continue;
      }

      // 1) A creates a record
      const marker = `accessprobe-${rand()}`;
      let mine = null;
      let res;
      let sent;
      if (t.fields) {
        const p = schemaPayload(t, A, marker, auth);
        if (p.missing.length) {
          skipped.push(`${t.name}: write tests skipped — accessprobe cannot fill the required field(s) ${p.missing.join(', ')}`);
          await freshUserList(client, t, [A, B], { tf, passed, skipped, notePublic, publicList });
          continue;
        }
        sent = p.data;
        res = await client.create(t.name, sent, { token: A.token });
      } else {
        ({ r: res, data: sent } = await createGuessing(client, t, A, marker));
      }
      if (missingCollection(res)) {
        skipped.push(`${t.name}: no such collection on this server (the name came from ${t.coll ? 'pb_migrations' : 'the app code'})`);
        continue;
      }
      if (ok(res)) {
        const rec = res.data || {};
        const ownerField = (t.ownerField && owns(rec, t.ownerField, A) && t.ownerField) || COMMON_OWNER_FIELDS.find((f) => owns(rec, f, A)) || null;
        const markerField = Object.keys(rec).find((k) => rec[k] === marker) || null;
        // keep only the fields that exist, so B's forged copy is exactly what A sent successfully
        const payload = Object.fromEntries(Object.entries(sent).filter(([k]) => k in rec));
        mine = { id: rec.id, ownerField, markerField, marker, payload };
        leftovers.push({ coll: t.name, id: rec.id, by: [A, B] });
      } else {
        if (superusersOnly(res)) {
          readOnly++;
          passed.push(`${t.name}: users cannot create records (create rule is superusers-only)`);
        } else if (createRefused(res)) {
          skipped.push(`${t.name}: write tests skipped — the create rule refused user A's record (${res.status} ${msg(res.data)})`);
        } else {
          skipped.push(`${t.name}: write tests skipped — user A could not create a test record (${res.status} ${msg(res.data)})`);
        }
        await freshUserList(client, t, [A, B], { tf, passed, skipped, notePublic, publicList });
        continue;
      }

      // 2) control: A reads its own record back through the same endpoint every attack uses
      const aView = async () => {
        const r = await client.view(t.name, mine.id, { token: A.token });
        return ok(r) ? r.data : null;
      };
      const expected = { marker: mine.marker };
      const unchanged = async () => {
        const rec = await aView();
        return Boolean(rec) && (!mine.markerField || rec[mine.markerField] === expected.marker) && (!mine.ownerField || owns(rec, mine.ownerField, A));
      };
      const aList = async (filter) => {
        const r = await client.list(t.name, { token: A.token, filter, perPage: 1 });
        return Boolean(r.items?.some((x) => x.id === mine.id));
      };
      if (!(await aView())) {
        skipped.push(`${t.name}: user A cannot read its own new record (view rule), so B's results would prove nothing`);
        continue;
      }
      fullyTested++;
      const owned = Boolean(mine.ownerField);
      const ownerDesc = owned ? `field ${mine.ownerField}` : null;
      const rulesFor = (...which) => (owned ? fix.ownerFix(t.name, mine.ownerField, which) : fix.noOwnerFix(t.name));

      // privileged fields of A's own record that other rules trust (@collection.<this>.role = "admin")
      await probeEscalation(client, t, mine.id, A, refs.get(t.name) || [], { tf, passed, skipped, owner: mine.ownerField });

      // 3) B views A's record
      const bView = await client.view(t.name, mine.id, { token: B.token });
      if (ok(bView) && publicView) notePublic(bView);
      else if (ok(bView)) {
        tf({
          id: owned ? 'cross-user-read' : 'shared-no-owner',
          severity: owned ? 'critical' : 'warning',
          title: owned ? `User B can read user A's records in "${t.name}"` : `Records in "${t.name}" are readable by every signed-in user`,
          detail: owned
            ? `Proven: A created a record (owner: ${ownerDesc}), B fetched it by id. Typical cause: viewRule @request.auth.id != "".`
            : 'A record created by A is visible to B, and accessprobe found no owner field — fine only if this data is meant to be shared.',
          evidence: `as user B: ${bView.evidence}`,
          fix: { code: rulesFor('viewRule') },
        });
      } else if (superusersOnly(bView) || (hidden(bView) && (await unchanged()))) passed.push(`${t.name}: B cannot read A's records`);
      else skipped.push(`${t.name}: read test inconclusive (${bView.status} ${msg(bView.data)})`);

      // 4) B lists the collection (the list rule is separate from the view rule)
      const byId = `id = "${mine.id}"`;
      const bList = await client.list(t.name, { token: B.token, filter: byId, perPage: 1 });
      if (bList.items?.some((x) => x.id === mine.id) && publicList) notePublic(bList);
      else if (bList.items?.some((x) => x.id === mine.id)) {
        const cnt = owned ? await client.list(t.name, { token: B.token, filter: `${mine.ownerField} != "${B.id}"`, perPage: 1 }) : await client.list(t.name, { token: B.token, perPage: 1 });
        tf({
          id: owned ? 'cross-user-list' : 'shared-no-owner-list',
          severity: owned ? 'critical' : 'warning',
          title: `User B can list ${cnt.total ?? '?'} record(s) of other users in "${t.name}"`,
          detail: owned
            ? `Proven: B's list request returned A's record. The list rule does not restrict records to their owner (${mine.ownerField}), so any signed-in user can page through everything.`
            : 'B\'s list request returned A\'s record, and accessprobe found no owner field.',
          evidence: `as user B: ${bList.evidence} → returned A's record`,
          fix: { code: rulesFor('listRule') },
        });
      } else if (superusersOnly(bList) || (bList.items && (await aList(byId)))) passed.push(`${t.name}: B cannot list A's records`);
      else skipped.push(`${t.name}: list test inconclusive (${bList.status} ${msg(bList.data)})`);

      // 5) anonymous view + list
      const anView = await client.view(t.name, mine.id);
      if (ok(anView) && publicView) notePublic(anView);
      else if (ok(anView)) {
        tf({
          id: 'anon-read',
          severity: owned ? 'critical' : 'warning',
          title: `Anyone (not logged in) can read records in "${t.name}"`,
          detail: owned ? "Proven: an unauthenticated request fetched A's record. The view rule is empty (public) or doesn't require sign-in." : 'Fine for public content, not for anything personal.',
          evidence: `anonymous: ${anView.evidence}`,
          fix: { code: rulesFor('viewRule') },
        });
      } else if (superusersOnly(anView) || (hidden(anView) && (await unchanged()))) passed.push(`${t.name}: anonymous visitors cannot read A's records`);
      else skipped.push(`${t.name}: anonymous read test inconclusive (${anView.status} ${msg(anView.data)})`);

      const anList = await client.list(t.name, { filter: byId, perPage: 1 });
      if (anList.items?.some((x) => x.id === mine.id) && publicList) notePublic(anList);
      else if (anList.items?.some((x) => x.id === mine.id)) {
        const cnt = await client.list(t.name, { perPage: 1 });
        tf({
          id: 'anon-list',
          severity: owned ? 'critical' : 'warning',
          title: `Anyone (not logged in) can list ${cnt.total ?? '?'} record(s) in "${t.name}"`,
          detail: owned ? "Proven: an unauthenticated list request returned A's record." : 'Fine for public content, not for anything personal.',
          evidence: `anonymous: ${anList.evidence} → returned A's record`,
          fix: { code: rulesFor('listRule') },
        });
      } else if (superusersOnly(anList) || (anList.items && (await aList(byId)))) passed.push(`${t.name}: anonymous visitors cannot list A's records`);
      else skipped.push(`${t.name}: anonymous list test inconclusive (${anList.status} ${msg(anList.data)})`);

      // 6) B modifies A's record (marker text, same length)
      const patch = mine.markerField ? { [mine.markerField]: tamper(mine.marker) } : owned ? { [mine.ownerField]: A.id } : null;
      if (!patch) skipped.push(`${t.name}: modify test skipped (no field to change)`);
      else {
        const bUpd = await client.update(t.name, mine.id, patch, { token: B.token });
        if (ok(bUpd)) {
          if (mine.markerField) expected.marker = patch[mine.markerField];
          tf({
            id: 'cross-user-update',
            severity: 'critical',
            title: `User B can MODIFY user A's records in "${t.name}"`,
            detail: 'Proven: B changed a record that A created.',
            evidence: `as user B: ${bUpd.evidence}`,
            fix: { code: rulesFor('updateRule') },
          });
        } else if (superusersOnly(bUpd) || (hidden(bUpd) && (await unchanged()))) passed.push(`${t.name}: B cannot modify A's records`);
        else skipped.push(`${t.name}: modify test inconclusive (${bUpd.status} ${msg(bUpd.data)})`);
      }

      // 7) B reassigns A's record to itself: an update rule that only checks the NEW owner
      //    (@request.body.user = @request.auth.id) lets anyone take records over
      let takenOver = false;
      if (owned) {
        const bTake = await client.update(t.name, mine.id, { [mine.ownerField]: B.id }, { token: B.token });
        if (ok(bTake)) {
          takenOver = true;
          leftovers.find((l) => l.id === mine.id).by = [B, A];
          tf({
            id: 'cross-user-takeover',
            severity: 'critical',
            title: `User B can take over user A's records in "${t.name}"`,
            detail: `Proven: B set ${mine.ownerField} of A's record to itself. The update rule checks only the new value (@request.body.${mine.ownerField}), not the current owner (${mine.ownerField} = @request.auth.id).`,
            evidence: `as user B: ${bTake.evidence}`,
            fix: { code: rulesFor('updateRule') },
          });
        } else if (superusersOnly(bTake) || (hidden(bTake) && (await unchanged()))) passed.push(`${t.name}: B cannot reassign A's records to itself`);
        else skipped.push(`${t.name}: takeover test inconclusive (${bTake.status} ${msg(bTake.data)})`);
      }

      // 8) B creates a record in A's name — the exact payload A's request had, new marker
      const forged = { ...mine.payload, ...(mine.markerField && { [mine.markerField]: `${mine.marker}-fake` }) };
      const bNew = await client.create(t.name, forged, { token: B.token });
      if (ok(bNew)) {
        leftovers.push({ coll: t.name, id: bNew.data.id, by: [A, B] });
        if (owned)
          tf({
            id: 'impersonated-create',
            severity: 'critical',
            title: `User B can create records in "${t.name}" in user A's name`,
            detail: `The create rule does not check ${mine.ownerField} against the signed-in user (@request.body.${mine.ownerField} = @request.auth.id), so anyone can forge data for another user.`,
            evidence: `as user B: ${bNew.evidence}`,
            fix: { code: rulesFor('createRule') },
          });
      } else if (createRefused(bNew)) passed.push(`${t.name}: B cannot create records as A`);
      else skipped.push(`${t.name}: forged-create test inconclusive (${bNew.status} ${msg(bNew.data)})`);

      // 9) anonymous visitor creates (and deletes) a record
      const anNew = await client.create(t.name, { ...forged, ...(mine.markerField && { [mine.markerField]: `${mine.marker}-anon` }) });
      if (ok(anNew)) {
        const anDel = await client.remove(t.name, anNew.data.id);
        if (!ok(anDel)) leftovers.push({ coll: t.name, id: anNew.data.id, by: [A, B] });
        tf({
          id: ok(anDel) ? 'anon-write' : 'anon-create',
          severity: owned || ok(anDel) ? 'critical' : 'warning',
          title: ok(anDel) ? `Anyone (not logged in) can create AND delete records in "${t.name}"` : `Anyone (not logged in) can create records in "${t.name}"${owned ? " in user A's name" : ''}`,
          detail: ok(anDel) ? 'No sign-in needed to write here: the create and delete rules are effectively public.' : owned ? `The create rule is public or does not require sign-in, and does not check ${mine.ownerField}.` : 'Fine for a contact form or guestbook; otherwise require sign-in.',
          evidence: `anonymous: ${anNew.evidence}${ok(anDel) ? `, then ${anDel.evidence}` : ''}`,
          fix: { code: rulesFor('createRule', ...(ok(anDel) ? ['deleteRule'] : [])) },
        });
      } else if (createRefused(anNew)) passed.push(`${t.name}: anonymous visitors cannot create records`);
      else skipped.push(`${t.name}: anonymous create test inconclusive (${anNew.status} ${msg(anNew.data)})`);

      // 10) B deletes A's record (last: it destroys the test record)
      if (takenOver) {
        skipped.push(`${t.name}: delete test skipped — B already took the record over`);
        continue;
      }
      const bDel = await client.remove(t.name, mine.id, { token: B.token });
      if (ok(bDel)) {
        leftovers.splice(leftovers.findIndex((l) => l.id === mine.id), 1);
        tf({
          id: 'cross-user-delete',
          severity: 'critical',
          title: `User B can DELETE user A's records in "${t.name}"`,
          detail: 'Proven: B deleted a record that A created.',
          evidence: `as user B: ${bDel.evidence}`,
          fix: { code: rulesFor('deleteRule') },
        });
      } else if (superusersOnly(bDel) || (hidden(bDel) && (await aView()))) passed.push(`${t.name}: B cannot delete A's records`);
      else skipped.push(`${t.name}: delete test inconclusive (${bDel.status} ${msg(bDel.data)})`);
    }
  } finally {
    // cleanup runs even if a probe threw; the caller deletes the users only afterwards
    for (const l of leftovers) {
      let done = false;
      for (const u of l.by) {
        if (ok(await client.remove(l.coll, l.id, { token: u.token }))) {
          done = true;
          break;
        }
      }
      if (!done) left.push(`${l.coll}/${l.id}`);
    }
  }
  return { findings, passed, skipped, left, fullyTested, readOnly };
}

// A could not write here: can a brand-new user B (or a visitor) list anything?
async function freshUserList(client, t, [, B], { tf, passed, skipped, notePublic, publicList }) {
  const r = await client.list(t.name, { token: B.token, perPage: 30 });
  if (missingCollection(r)) {
    skipped.push(`${t.name}: no such collection on this server`);
    return;
  }
  if (superusersOnly(r)) passed.push(`${t.name}: users cannot list records (list rule is superusers-only)`);
  else if (!r.items) skipped.push(`${t.name}: list test inconclusive (${r.status} ${msg(r.data)})`);
  else {
    const foreign = r.items.filter((x) => !(x.id === B.id || COMMON_OWNER_FIELDS.some((f) => owns(x, f, B)) || owns(x, t.ownerField, B)));
    if (!foreign.length) skipped.push(`${t.name}: a new user may list this collection but saw no records — not proven either way (no test record)`);
    else if (publicList) notePublic(r);
    else
      tf({
        id: 'fresh-user-sees-records',
        severity: 'warning',
        title: `A brand-new user can list ${r.total ?? `${foreign.length}+`} record(s) in "${t.name}"`,
        detail: 'Test user B was created seconds ago and owns nothing here. Either this data is meant to be shared, or the list rule is too broad. (Not proven with test data: user A could not create a record here.)',
        evidence: `as user B: ${r.evidence}`,
        fix: { code: t.ownerField ? fix.ownerFix(t.name, t.ownerField, ['listRule', 'viewRule']) : fix.noOwnerFix(t.name) },
      });
  }
  const an = await client.list(t.name, { perPage: 1 });
  if (superusersOnly(an)) passed.push(`${t.name}: anonymous visitors cannot list records (list rule is superusers-only)`);
  else if (an.items?.length && !publicList)
    tf({
      id: 'anon-list-existing',
      severity: 'warning',
      title: `Anyone (not logged in) can list ${an.total ?? '?'} record(s) in "${t.name}"`,
      detail: 'Fine for public content, not for anything personal.',
      evidence: `anonymous: ${an.evidence}`,
      fix: { code: t.ownerField ? fix.ownerFix(t.name, t.ownerField, ['listRule', 'viewRule']) : fix.noOwnerFix(t.name) },
    });
}

// ---------------------------------------------------------------- the users collection itself

// B against A's own user record (owner = the record id). Run after every other collection
// was cleaned up: B deleting A's account would otherwise break that cleanup.
export async function probeUsers(client, t, [A, B], h) {
  const { log, refs } = h;
  const findings = [];
  const passed = [];
  const skipped = [];
  const tf = (f) => findings.push({ resource: t.name, ...f });
  log(`  collection ${t.name} (test users' own records)`);

  const aView = async () => {
    const r = await client.view(t.name, A.id, { token: A.token });
    return ok(r) ? r.data : null;
  };
  const before = await aView();
  if (!before) {
    skipped.push(`${t.name}: user A cannot read its own user record, so B's results would prove nothing`);
    return { findings, passed, skipped, fullyTested: 0 };
  }
  // a text field of A's own record to tamper with (default users collection: name)
  const markerField = ['name', 'username', 'displayName'].find((f) => typeof before[f] === 'string') || null;
  const expected = markerField ? before[markerField] : null;
  const unchanged = async () => {
    const rec = await aView();
    return Boolean(rec) && (!markerField || rec[markerField] === expected);
  };
  const rulesFor = (...which) => fix.ownerFix(t.name, 'id', which);

  // privilege escalation on A's own record: rule-referenced fields, then privilege-like names
  const known = refs.get(t.name) || [];
  const extra = privilegedByName(t.fields, before, known);
  await probeEscalation(client, t, A.id, A, [...known, ...extra], { tf, passed, skipped, owner: 'id' });

  const bView = await client.view(t.name, A.id, { token: B.token });
  if (ok(bView)) {
    tf({
      id: 'cross-user-read',
      severity: t.coll?.viewRule === '' ? 'warning' : 'critical',
      title: `User B can read user A's account record in "${t.name}"`,
      detail: `Proven: B fetched A's user record by id. Profile fields (and the email, if emailVisibility is on) are exposed to every signed-in user.`,
      evidence: `as user B: ${bView.evidence}`,
      fix: { code: rulesFor('viewRule') },
    });
  } else if (superusersOnly(bView) || (hidden(bView) && (await unchanged()))) passed.push(`${t.name}: B cannot read A's user record`);
  else skipped.push(`${t.name}: read test inconclusive (${bView.status} ${msg(bView.data)})`);

  const byId = `id = "${A.id}"`;
  const bList = await client.list(t.name, { token: B.token, filter: byId, perPage: 1 });
  if (bList.items?.some((x) => x.id === A.id)) {
    const cnt = await client.list(t.name, { token: B.token, filter: `id != "${B.id}"`, perPage: 1 });
    tf({
      id: 'cross-user-list',
      severity: 'critical',
      title: `User B can list ${cnt.total ?? '?'} other user account(s) in "${t.name}"`,
      detail: 'Proven: B\'s list request returned A\'s user record. Any signed-in user can page through your user list.',
      evidence: `as user B: ${bList.evidence} → returned A's record`,
      fix: { code: rulesFor('listRule') },
    });
  } else if (superusersOnly(bList) || bList.items) {
    const aSees = await client.list(t.name, { token: A.token, filter: byId, perPage: 1 });
    if (superusersOnly(bList) || aSees.items?.some((x) => x.id === A.id)) passed.push(`${t.name}: B cannot list other users`);
    else skipped.push(`${t.name}: list test inconclusive (A cannot list its own user record either)`);
  } else skipped.push(`${t.name}: list test inconclusive (${bList.status} ${msg(bList.data)})`);

  const anView = await client.view(t.name, A.id);
  if (ok(anView)) {
    tf({
      id: 'anon-read',
      severity: 'critical',
      title: `Anyone (not logged in) can read user accounts in "${t.name}"`,
      detail: "Proven: an unauthenticated request fetched A's user record.",
      evidence: `anonymous: ${anView.evidence}`,
      fix: { code: rulesFor('viewRule') },
    });
  } else if (superusersOnly(anView) || (hidden(anView) && (await unchanged()))) passed.push(`${t.name}: anonymous visitors cannot read user records`);
  else skipped.push(`${t.name}: anonymous read test inconclusive (${anView.status} ${msg(anView.data)})`);

  const anList = await client.list(t.name, { perPage: 1 });
  if (anList.items?.length) {
    tf({
      id: 'anon-list',
      severity: 'critical',
      title: `Anyone (not logged in) can list ${anList.total ?? '?'} user account(s) in "${t.name}"`,
      detail: 'Proven: an unauthenticated list request returned user records.',
      evidence: `anonymous: ${anList.evidence}`,
      fix: { code: rulesFor('listRule') },
    });
  } else if (superusersOnly(anList) || anList.items) passed.push(`${t.name}: anonymous visitors cannot list users`);
  else skipped.push(`${t.name}: anonymous list test inconclusive (${anList.status} ${msg(anList.data)})`);

  if (!markerField) skipped.push(`${t.name}: modify test skipped (no text field such as name on the user record)`);
  else {
    const bUpd = await client.update(t.name, A.id, { [markerField]: `accessprobe-${rand()}` }, { token: B.token });
    if (ok(bUpd)) {
      await client.update(t.name, A.id, { [markerField]: expected }, { token: A.token });
      tf({
        id: 'cross-user-update',
        severity: 'critical',
        title: `User B can MODIFY user A's account in "${t.name}"`,
        detail: `Proven: B changed ${markerField} on A's user record (accessprobe put the old value back).`,
        evidence: `as user B: ${bUpd.evidence}`,
        fix: { code: rulesFor('updateRule') },
      });
    } else if (superusersOnly(bUpd) || (hidden(bUpd) && (await unchanged()))) passed.push(`${t.name}: B cannot modify A's user record`);
    else skipped.push(`${t.name}: modify test inconclusive (${bUpd.status} ${msg(bUpd.data)})`);
  }

  // last: B deletes A's account
  const bDel = await client.remove(t.name, A.id, { token: B.token });
  if (ok(bDel)) {
    A.gone = true;
    tf({
      id: 'cross-user-delete',
      severity: 'critical',
      title: `User B can DELETE user A's account in "${t.name}"`,
      detail: "Proven: B deleted test user A's account.",
      evidence: `as user B: ${bDel.evidence}`,
      fix: { code: rulesFor('deleteRule') },
    });
  } else if (superusersOnly(bDel) || (hidden(bDel) && (await aView()))) passed.push(`${t.name}: B cannot delete A's account`);
  else skipped.push(`${t.name}: delete test inconclusive (${bDel.status} ${msg(bDel.data)})`);

  return { findings, passed, skipped, fullyTested: 1 };
}

// ---------------------------------------------------------------- privilege escalation

// A sets a privilege field on its OWN record (role = "admin", plan = "pro", isAdmin = true…).
// A finding needs the change to show up in A's own re-read; the old value is put back.
async function probeEscalation(client, t, recId, A, fields, { tf, passed, skipped, owner }) {
  if (!fields.length) return;
  const read = async () => {
    const r = await client.view(t.name, recId, { token: A.token });
    return ok(r) ? r.data : null;
  };
  const start = await read();
  if (!start) return;
  const same = (a, b) => (Array.isArray(a) ? a.map(String).includes(String(b)) : String(a) === String(b));
  const changed = [];
  let evidence = null;
  for (const f of fields) {
    if (!(f.field in start)) {
      if (f.rules.length) skipped.push(`${t.name}: rules use ${f.field} (${f.rules.join(', ')}), but the field is not visible on the user's own record — change test skipped`);
      continue;
    }
    const before = start[f.field];
    if (same(before, f.value)) continue;
    const r = await client.update(t.name, recId, { [f.field]: f.value }, { token: A.token });
    if (ok(r)) {
      const now = await read();
      if (now && same(now[f.field], f.value)) {
        changed.push(f);
        evidence ??= `as user A on its own record: ${r.evidence} with {"${f.field}": ${JSON.stringify(f.value)}}`;
        const back = await client.update(t.name, recId, { [f.field]: before }, { token: A.token });
        f.restored = ok(back);
      } else skipped.push(`${t.name}: ${f.field} change test inconclusive (accepted, but the value did not change — a hook may reset it)`);
    } else if (superusersOnly(r)) passed.push(`${t.name}: users cannot change their own ${f.field}`);
    else if (hidden(r)) {
      const now = await read();
      if (now && same(now[f.field], before)) passed.push(`${t.name}: users cannot change their own ${f.field}`);
      else skipped.push(`${t.name}: ${f.field} change test inconclusive (404, and the record could not be re-read)`);
    } else skipped.push(`${t.name}: ${f.field} change test inconclusive (${r.status} ${msg(r.data)})`);
  }
  if (!changed.length) return;
  const referenced = changed.filter((f) => f.rules.length);
  const names = changed.map((f) => f.field);
  const where = [...new Set(referenced.flatMap((f) => f.rules))];
  tf({
    id: 'self-escalation',
    severity: referenced.length ? 'critical' : 'warning',
    title: `Users can give themselves extra rights: they may set ${names.join(', ')} on their own "${t.name}" record`,
    detail:
      `Proven: user A set ${changed.map((f) => `${f.field} = ${JSON.stringify(f.value)}`).join(', ')} on its own record. ` +
      (referenced.length
        ? `Your API rules grant extra access based on it (${where.join(', ')}), so any user can unlock that for themselves.`
        : 'No API rule accessprobe could read uses it, but if your app or hooks trust this field, any user can upgrade themselves.') +
      (changed.every((f) => f.restored) ? ' The old value was put back right away.' : ' accessprobe could not put the old value back; the test user is deleted during cleanup.'),
    evidence,
    fix: { code: fix.privilegeFix(t.name, owner, names, t.coll || {}) },
  });
}
