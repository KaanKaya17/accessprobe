// Appwrite live tests. Same principles as the other adapters:
//  - A creates a document of its own (marker text), WITHOUT explicit permissions, so the
//    collection's defaults apply — exactly what most apps do. A client SDK then grants the
//    creating user read / update / delete on it. B and an anonymous visitor attack it.
//  - Every finding is a request that succeeded. We never print other users' data, only counts.
//  - A PASS needs proof. Appwrite answers in two ways when a permission says no:
//      no collection/bucket-level permission (or the action itself is refused)  → 401 user_unauthorized
//      document security on, document not readable by the caller              → 404 document_not_found / empty list
//    A 401/403 refusal is a PASS. A 404 / empty list only counts when A's control read through the
//    same endpoint shows the document still exists and is unchanged.

import { randomUUID } from 'node:crypto';
import { API } from './client.js';
import { rolesFor } from './config.js';
import * as fix from './fixes.js';

const rand = () => Math.random().toString(36).slice(2, 8);
// same-length variant of a marker (so a size limit or a unique index can't cause the refusal)
const tamper = (m) => `${m.slice(0, -1)}${m.endsWith('x') ? 'y' : 'x'}`;
// other same-length variants, distinct from the marker and from tamper(marker)
const variant = (m, a, b) => `${m.slice(0, -2)}${m.endsWith(a) ? b : a}`;
const ok = (r) => Boolean(r && r.ok);
const errType = (r) => (r?.data && typeof r.data === 'object' ? String(r.data.type || '') : '');
// an explicit refusal of the action — not a broken session, an unknown origin or a rate limit
const refused = (r) => Boolean(r) && (r.status === 401 || r.status === 403) && /unauthorized/.test(errType(r));
const missingContainer = (r) => Boolean(r) && r.status === 404 && /^(collection|table|database|storage_bucket)_not_found$|^general_route_not_found$/.test(errType(r));
const hidden = (r) => Boolean(r) && r.status === 404 && /^(document|row|storage_file)_not_found$/.test(errType(r));
const DEFAULT_ACTIONS = ['read', 'update', 'delete'];
const MARKER_CANDIDATES = ['title', 'text', 'name', 'content', 'body', 'description', 'note', 'message', 'label', 'subject'];
const STRING_TYPES = new Set(['string', 'varchar', 'text', 'mediumtext', 'longtext']);
const own = (u) => DEFAULT_ACTIONS.map((a) => `${a}("user:${u.id}")`);

export function msg(d) {
  if (!d) return '';
  if (typeof d === 'string') return d.trim().slice(0, 160);
  return `${d.message || JSON.stringify(d).slice(0, 120)}${d.type ? ` [${d.type}]` : ''}`.slice(0, 200);
}

// ---------------------------------------------------------------- users

export async function setupUsers(client, { userA, userB, emailDomain = 'example.com', log }) {
  const run = rand();
  const users = [];
  try {
    return await signInBoth();
  } catch (e) {
    // never leave half-created users behind unmentioned: the ones with a session block themselves
    const left = [];
    for (const u of users.filter((x) => x.created)) {
      if (u.auth) await client.blockSelf(u.auth);
      left.push(u.email);
    }
    if (left.length) e.message += `\n  Test users already created (delete them in the Appwrite Console → Auth → Users): ${left.join(', ')}`;
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
        const r = await client.signUp(email, password);
        if (r.status === 404 && /project/.test(errType(r))) throw fail(`Appwrite project "${client.projectId}" not found on ${client.url} (${msg(r.data)}). Check --project-id.`);
        if (r.status === 429) throw fail(`Appwrite rate limit hit while signing up test user ${label} (${msg(r.data)}). Wait a while, or pass existing users with --user-a / --user-b.`);
        if (!ok(r)) {
          throw fail(
            `Sign-up of test user ${label} failed (${r.status}): ${msg(r.data)}\n` +
              '  Email/password sign-up may be disabled or limited (Console → Auth → Settings). Create two test users yourself\n' +
              '  (Console → Auth → Users → Create user) and pass them with --user-a email:password --user-b email:password',
          );
        }
        users.push({ label, email, id: r.data.$id, auth: null, created: true });
        created = true;
        log(`  created test user ${label}: ${email}`);
      }
      const s = await client.signIn(email, password);
      if (!ok(s.r) || !s.auth) {
        throw fail(
          `Sign-in of ${created ? 'test ' : ''}user ${label} failed (${s.r.status} ${s.auth || !ok(s.r) ? msg(s.r.data) : 'no session cookie in the answer'}).` +
            (created ? '\n  Create two test users that can sign in with email + password and pass them with --user-a email:password --user-b email:password' : ''),
        );
      }
      const me = await client.account(s.auth);
      if (!ok(me) || !me.data?.$id) throw fail(`User ${label} signed in, but GET /v1/account failed (${me.status} ${msg(me.data)}) — MFA may be required.`);
      const u = users.find((x) => x.label === label) || { label, email, created };
      Object.assign(u, { id: me.data.$id, auth: s.auth });
      if (!users.includes(u)) users.push(u);
    }
    return users;
  }
}

// Appwrite clients cannot delete their own account. Test users block themselves instead (that
// also ends their sessions) and the report lists them for deletion in the console.
export async function deleteUsers(client, users, notes) {
  const blocked = [];
  const left = [];
  for (const u of users) {
    if (!u.auth) continue;
    if (!u.created) {
      await client.signOut(u.auth);
      continue;
    }
    const r = await client.blockSelf(u.auth);
    if (ok(r)) blocked.push(u.email);
    else left.push(`${u.email} (${r.status} ${msg(r.data)})`);
  }
  if (blocked.length) notes.push(`Appwrite clients cannot delete their own account: the test users blocked themselves (PATCH /v1/account/status). Delete them in the Appwrite Console → Auth → Users: ${blocked.join(', ')}`);
  if (left.length) notes.push(`Could not block test users — delete them in the Appwrite Console → Auth → Users: ${left.join('; ')}`);
}

// ---------------------------------------------------------------- payloads

function sample(a, marker) {
  const t = a.type;
  if (STRING_TYPES.has(t)) {
    if (a.format === 'email') return `accessprobe-${rand()}@example.com`;
    if (a.format === 'url') return 'https://example.com';
    if (a.format === 'ip') return '127.0.0.1';
    if (a.format === 'enum') return a.elements?.[0];
    return a.size ? marker.slice(0, a.size) : marker;
  }
  if (t === 'email') return `accessprobe-${rand()}@example.com`;
  if (t === 'url') return 'https://example.com';
  if (t === 'ip') return '127.0.0.1';
  if (t === 'enum') return a.elements?.[0];
  if (t === 'integer' || t === 'double' || t === 'float') {
    let n = 1;
    if (a.min != null && n < a.min) n = a.min;
    if (a.max != null && n > a.max) n = a.max;
    return n;
  }
  if (t === 'boolean') return true;
  if (t === 'datetime') return new Date().toISOString();
  return undefined; // relationship, point, line, polygon …
}

// A document from the attributes in appwrite.json
export function schemaPayload(attrs, marker) {
  const data = {};
  let markerField = null;
  const missing = [];
  for (const a of attrs) {
    if (!a.key || a.status === 'deleting' || a.status === 'failed') continue;
    if (STRING_TYPES.has(a.type) && !a.format && !markerField && (a.size == null || a.size >= marker.length)) {
      data[a.key] = a.array ? [marker] : marker;
      markerField = a.array ? null : a.key;
      continue;
    }
    if (!a.required) continue;
    const v = sample(a, marker);
    if (v === undefined) missing.push(`${a.key} (${a.type})`);
    else data[a.key] = a.array ? [v] : v;
  }
  return { data, markerField, missing };
}

// No schema: a document with one string attribute, guessed — names from the app's
// createDocument calls first, then common names. Appwrite's answer names the problem: an unknown
// attribute is dropped (next guess), a missing required one is added as a string. Anything else
// (a required number, enum, relationship …) ends the guessing: the caller notes it as not tested.
async function createGuessing(client, t, A, marker) {
  const candidates = [...new Set([...(t.codeAttributes || []), ...MARKER_CANDIDATES])];
  const data = {};
  let key = candidates.shift();
  data[key] = marker;
  let r;
  for (let i = 0; i < 24; i++) {
    r = await client.create(t, data, { auth: A.auth });
    if (ok(r) || r.status !== 400) break;
    const m = msg(r.data);
    const missing = /missing required (?:attribute|column)[:\s]*"([^"]+)"/i.exec(m)?.[1];
    const unknown = /unknown (?:attribute|column)[:\s]*"([^"]+)"/i.exec(m)?.[1];
    const badType = /(?:attribute|column) "([^"]+)" has invalid (?:type|format)/i.exec(m)?.[1];
    if (missing && !(missing in data)) data[missing] = marker;
    else if ((unknown && unknown in data) || (badType && badType === key)) {
      delete data[unknown || badType];
      if ((unknown || badType) === key) {
        key = candidates.shift();
        if (key && !(key in data)) data[key] = marker;
      }
      if (!Object.keys(data).length && !key) {
        // a collection whose attributes are all optional and none is a string
        r = await client.create(t, {}, { auth: A.auth });
        break;
      }
    } else break;
  }
  return { r, data };
}

// ---------------------------------------------------------------- collections / tables

// targets: [{ name, db, id, mode, config (from appwrite.json or null), codeAttributes }]
export async function probeCollections(client, targets, [A, B], h) {
  const { log, configFile } = h;
  const findings = [];
  const passed = [];
  const skipped = [];
  const left = [];
  let fullyTested = 0;
  let readOnly = 0;
  const leftovers = []; // { t, id, by: [auth | null] }

  try {
    for (const t of targets) {
      const api = API[t.mode];
      log(`  ${api.container} ${t.name}`);
      const tf = (f) => findings.push({ resource: t.name, ...f });
      const fixFor = (...which) => fix.permissionFix(t, which, { configFile: t.config ? configFile : null });
      const docs = `${api.noun}s`;

      if (t.config && !t.config.enabled) {
        skipped.push(`${t.name}: the ${api.container} is disabled in ${configFile}, not tested`);
        continue;
      }

      // 1) A creates a document, without explicit permissions
      const marker = `accessprobe-${rand()}`;
      let res;
      let sent;
      let markerField = null;
      if (t.config?.attributes?.length) {
        const p = schemaPayload(t.config.attributes, marker);
        if (p.missing.length) {
          skipped.push(`${t.name}: write tests skipped — accessprobe cannot fill the required attribute(s) ${p.missing.join(', ')}`);
          await freshUserList(client, t, [A, B], { tf, passed, skipped, fixFor, docs });
          continue;
        }
        sent = p.data;
        markerField = p.markerField;
        res = await client.create(t, sent, { auth: A.auth });
      } else {
        ({ r: res, data: sent } = await createGuessing(client, t, A, marker));
        markerField = Object.keys(sent).find((k) => sent[k] === marker) || null;
      }
      // Appwrite older than 1.8 has no TablesDB route, newer ones keep the documents route:
      // a target from code may use either name
      if (res.status === 404 && errType(res) === 'general_route_not_found' && !t.config) {
        t.mode = t.mode === 'rows' ? 'documents' : 'rows';
        res = await client.create(t, sent, { auth: A.auth });
      }
      if (missingContainer(res)) {
        skipped.push(`${t.name}: no such database or ${api.container} on this server (${msg(res.data)}; the id came from ${t.config ? configFile : 'the app code / --table'})`);
        continue;
      }
      if (!ok(res)) {
        if (refused(res)) {
          readOnly++;
          passed.push(`${t.name}: users cannot create ${docs} (no create permission for users)`);
        } else if (res.status === 400 && /structure|attribute|column/i.test(msg(res.data))) {
          skipped.push(`${t.name}: write tests skipped — Appwrite refused user A's ${api.noun} (schema): ${msg(res.data)}.${t.config ? '' : ' Add appwrite.json (appwrite pull collections) so accessprobe knows the attributes'}`);
        } else {
          skipped.push(`${t.name}: write tests skipped — user A could not create a test ${api.noun} (${res.status} ${msg(res.data)})`);
        }
        await freshUserList(client, t, [A, B], { tf, passed, skipped, fixFor, docs });
        continue;
      }
      const doc = res.data || {};
      const mine = { id: doc.$id, marker, markerField: markerField && doc[markerField] === marker ? markerField : null, perms: Array.isArray(doc.$permissions) ? doc.$permissions : null };
      leftovers.push({ t: { ...t }, id: mine.id, by: [A.auth, B.auth] });
      const assigned = mine.perms ? (mine.perms.length ? mine.perms.map((p) => p.split(A.id).join('<user A id>')).join(', ') : 'no permissions at all') : 'unknown permissions';
      const usual = mine.perms && own(A).every((p) => mine.perms.includes(p)) && mine.perms.length === 3;
      if (!usual) skipped.push(`${t.name}: A's ${api.noun}, created without explicit permissions, got ${assigned} (a client SDK normally grants the creator read, update and delete)`);
      const why = (action) => cause(t, action, { configFile, assigned, api });

      // 2) control: A reads its own document back through the same endpoint every attack uses
      const aView = async () => {
        const r = await client.view(t, mine.id, { auth: A.auth });
        return ok(r) ? r.data : null;
      };
      const expected = { marker };
      const unchanged = async () => {
        const d = await aView();
        return Boolean(d) && (!mine.markerField || d[mine.markerField] === expected.marker);
      };
      const aList = async () => {
        const r = await client.list(t, { auth: A.auth, equalId: mine.id });
        return Boolean(r.items?.some((x) => x.$id === mine.id));
      };
      if (!(await aView())) {
        skipped.push(`${t.name}: user A cannot read its own new ${api.noun}, so B's results would prove nothing`);
        continue;
      }
      fullyTested++;

      // 3) B reads A's document by id
      const bView = await client.view(t, mine.id, { auth: B.auth });
      if (ok(bView)) {
        tf({
          id: 'cross-user-read',
          severity: 'critical',
          title: `User B can read user A's ${docs} in "${t.name}"`,
          detail: `Proven: A created a ${api.noun} (it got ${assigned}), B fetched it by id. ${why('read')}`,
          evidence: `as user B: ${bView.evidence}`,
          fix: { code: fixFor('read') },
        });
      } else if (refused(bView) || (hidden(bView) && (await unchanged()))) passed.push(`${t.name}: B cannot read A's ${docs}`);
      else skipped.push(`${t.name}: read test inconclusive (${bView.status} ${msg(bView.data)})`);

      // 4) B lists the collection, looking for A's document
      const bList = await client.list(t, { auth: B.auth, equalId: mine.id });
      if (bList.items?.some((x) => x.$id === mine.id)) {
        const cnt = await client.list(t, { auth: B.auth, limit: 1 });
        tf({
          id: 'cross-user-list',
          severity: 'critical',
          title: `User B can list ${cnt.total ?? '?'} ${api.noun}(s) of other users in "${t.name}"`,
          detail: `Proven: B's list request returned A's ${api.noun}, so any signed-in user can page through everything. ${why('read')}`,
          evidence: `as user B: ${bList.evidence} → returned A's ${api.noun}`,
          fix: { code: fixFor('read') },
        });
      } else if (refused(bList) || (bList.items && (await aList()))) passed.push(`${t.name}: B cannot list A's ${docs}`);
      else skipped.push(`${t.name}: list test inconclusive (${bList.status} ${msg(bList.data)})`);

      // 5) anonymous read + list
      const anView = await client.view(t, mine.id);
      if (ok(anView)) {
        tf({
          id: 'anon-read',
          severity: 'critical',
          title: `Anyone (not logged in) can read ${docs} in "${t.name}"`,
          detail: `Proven: a request with only the project id fetched A's ${api.noun}. ${why('read')} Fine only for public content (a catalog, blog posts) that never holds anything personal.`,
          evidence: `anonymous: ${anView.evidence}`,
          fix: { code: fixFor('read') },
        });
      } else if (refused(anView) || (hidden(anView) && (await unchanged()))) passed.push(`${t.name}: anonymous visitors cannot read A's ${docs}`);
      else skipped.push(`${t.name}: anonymous read test inconclusive (${anView.status} ${msg(anView.data)})`);

      const anList = await client.list(t, { equalId: mine.id });
      if (anList.items?.some((x) => x.$id === mine.id)) {
        const cnt = await client.list(t, { limit: 1 });
        tf({
          id: 'anon-list',
          severity: 'critical',
          title: `Anyone (not logged in) can list ${cnt.total ?? '?'} ${api.noun}(s) in "${t.name}"`,
          detail: `Proven: an unauthenticated list request returned A's ${api.noun}. ${why('read')}`,
          evidence: `anonymous: ${anList.evidence} → returned A's ${api.noun}`,
          fix: { code: fixFor('read') },
        });
      } else if (refused(anList) || (anList.items && (await aList()))) passed.push(`${t.name}: anonymous visitors cannot list A's ${docs}`);
      else skipped.push(`${t.name}: anonymous list test inconclusive (${anList.status} ${msg(anList.data)})`);

      // 6) B modifies A's document (marker text, same length)
      if (!mine.markerField) skipped.push(`${t.name}: modify test skipped (no string attribute to change)`);
      else {
        const patch = { [mine.markerField]: tamper(marker) };
        const bUpd = await client.update(t, mine.id, { data: patch }, { auth: B.auth });
        if (ok(bUpd)) {
          expected.marker = patch[mine.markerField];
          tf({
            id: 'cross-user-update',
            severity: 'critical',
            title: `User B can MODIFY user A's ${docs} in "${t.name}"`,
            detail: `Proven: B changed a ${api.noun} that A created. ${why('update')}`,
            evidence: `as user B: ${bUpd.evidence}`,
            fix: { code: fixFor('update') },
          });
        } else if (refused(bUpd) || (hidden(bUpd) && (await unchanged()))) passed.push(`${t.name}: B cannot modify A's ${docs}`);
        else skipped.push(`${t.name}: modify test inconclusive (${bUpd.status} ${msg(bUpd.data)})`);
      }

      // 7) anonymous visitor creates a document (A's accepted payload, new marker). It carries
      //    delete("any") so the visitor can remove it again right away.
      const anData = { ...sent, ...(mine.markerField && { [mine.markerField]: variant(marker, 'zz', 'ww') }) };
      const anNew = await client.create(t, anData, { permissions: ['delete("any")'] });
      if (ok(anNew)) {
        const anDel = await client.remove(t, anNew.data.$id);
        if (!ok(anDel)) leftovers.push({ t: { ...t }, id: anNew.data.$id, by: [A.auth, B.auth] });
        tf({
          id: 'anon-create',
          severity: 'warning',
          title: `Anyone (not logged in) can create ${docs} in "${t.name}"`,
          detail: `Proven: a request with only the project id created a ${api.noun}. ${why('create')} Fine for a contact form or guestbook; otherwise use create("users").`,
          evidence: `anonymous: ${anNew.evidence}`,
          fix: { code: fixFor('create') },
        });
      } else if (refused(anNew)) passed.push(`${t.name}: anonymous visitors cannot create ${docs}`);
      else skipped.push(`${t.name}: anonymous create test inconclusive (${anNew.status} ${msg(anNew.data)})`);

      // 8) B deletes A's document
      const bDel = await client.remove(t, mine.id, { auth: B.auth });
      if (ok(bDel)) {
        leftovers.splice(leftovers.findIndex((l) => l.id === mine.id), 1);
        tf({
          id: 'cross-user-delete',
          severity: 'critical',
          title: `User B can DELETE user A's ${docs} in "${t.name}"`,
          detail: `Proven: B deleted a ${api.noun} that A created. ${why('delete')}`,
          evidence: `as user B: ${bDel.evidence}`,
          fix: { code: fixFor('delete') },
        });
      } else if (refused(bDel) || (hidden(bDel) && (await aView()))) passed.push(`${t.name}: B cannot delete A's ${docs}`);
      else skipped.push(`${t.name}: delete test inconclusive (${bDel.status} ${msg(bDel.data)})`);
      // 9) B rewrites the permissions of a second, fresh document of A to itself: whoever may
      //    update a document may also change who it belongs to
      const second = await client.create(t, { ...sent, ...(mine.markerField && { [mine.markerField]: variant(marker, 'qq', 'jj') }) }, { auth: A.auth });
      if (!ok(second)) {
        skipped.push(`${t.name}: permission takeover test skipped — A could not create a second test ${api.noun} (${second.status} ${msg(second.data)})`);
        continue;
      }
      const sid = second.data.$id;
      leftovers.push({ t: { ...t }, id: sid, by: [A.auth, B.auth] });
      const bTake = await client.update(t, sid, { permissions: own(B) }, { auth: B.auth });
      const aStill = async () => {
        const r = await client.view(t, sid, { auth: A.auth });
        return ok(r) && JSON.stringify(r.data.$permissions || []) === JSON.stringify(second.data.$permissions || []);
      };
      if (ok(bTake)) {
        leftovers.find((l) => l.id === sid).by = [B.auth, A.auth];
        tf({
          id: 'cross-user-takeover',
          severity: 'critical',
          title: `User B can take over user A's ${docs} in "${t.name}"`,
          detail: `Proven: B replaced the $permissions of A's ${api.noun} with read/update/delete for itself — ${t.config && !t.config.security ? `${t.mode === 'rows' ? 'row' : 'document'} security is off, so this only bites once it is turned on, but then A is locked out of its own data` : 'that locks A out of its own data'}. ${why('update')}`,
          evidence: `as user B: ${bTake.evidence} with {"permissions": [read/update/delete("user:<user B id>")]}`,
          fix: { code: fixFor('update') },
        });
      } else if (refused(bTake) || (hidden(bTake) && (await aStill()))) passed.push(`${t.name}: B cannot change the permissions of A's ${docs}`);
      else skipped.push(`${t.name}: permission takeover test inconclusive (${bTake.status} ${msg(bTake.data)})`);
    }
  } finally {
    // cleanup runs even if a probe threw; the caller removes the users only afterwards
    for (const l of leftovers) {
      let done = false;
      for (const auth of l.by) {
        if (ok(await client.remove(l.t, l.id, { auth }))) {
          done = true;
          break;
        }
      }
      if (!done) left.push(`${l.t.db}/${l.t.id}/${l.id}`);
    }
  }
  return { findings, passed, skipped, left, fullyTested, readOnly };
}

// Why B / a visitor got through, from appwrite.json when we have it
function cause(t, action, { configFile, assigned, api }) {
  const c = t.config;
  const sec = t.mode === 'rows' ? 'row security' : 'document security';
  if (!c) {
    return `A's own ${api.noun} only named user A, so the ${api.container} permissions grant this to everyone: typically ${action}("users") or ${action}("any") at ${api.container} level (those apply to every ${api.noun}, whatever its own permissions say).`;
  }
  const broad = rolesFor(c.permissions, action).filter((r) => r === 'any' || r === 'users' || r === 'guests' || /^users\//.test(r));
  if (broad.length) {
    return `${configFile} grants ${broad.map((r) => `${action}("${r}")`).join(', ')} at ${api.container} level${c.security ? '' : ` with ${sec} off`} — that applies to every ${api.noun}, whatever its own permissions say (${assigned}).`;
  }
  return `${configFile} does not explain it (the ${api.container} on the server may differ: run appwrite pull and compare).`;
}

// A could not write here: can a brand-new user B (or a visitor) list anything?
async function freshUserList(client, t, [, B], { tf, passed, skipped, fixFor, docs }) {
  const r = await client.list(t, { auth: B.auth, limit: 25 });
  if (missingContainer(r)) {
    skipped.push(`${t.name}: no such database or ${API[t.mode].container} on this server`);
    return;
  }
  if (refused(r)) passed.push(`${t.name}: users cannot list ${docs} (no read permission for users)`);
  else if (!r.items) skipped.push(`${t.name}: list test inconclusive (${r.status} ${msg(r.data)})`);
  else {
    const foreign = r.items.filter((x) => !(Array.isArray(x.$permissions) && x.$permissions.some((p) => p.includes(`user:${B.id}`))));
    if (!foreign.length) skipped.push(`${t.name}: a new user may list this ${API[t.mode].container} but saw no ${docs} — not proven either way (no test ${API[t.mode].noun})`);
    else
      tf({
        id: 'fresh-user-sees-records',
        severity: 'warning',
        title: `A brand-new user can list ${r.total ?? `${foreign.length}+`} ${API[t.mode].noun}(s) in "${t.name}"`,
        detail: `Test user B was created seconds ago and owns nothing here. Either this data is meant to be shared, or read("users") / read("any") is set too broadly. (Not proven with test data: user A could not create a ${API[t.mode].noun} here.)`,
        evidence: `as user B: ${r.evidence}`,
        fix: { code: fixFor('read') },
      });
  }
  const an = await client.list(t, { limit: 1 });
  if (refused(an)) passed.push(`${t.name}: anonymous visitors cannot list ${docs}`);
  else if (an.items?.length)
    tf({
      id: 'anon-list-existing',
      severity: 'warning',
      title: `Anyone (not logged in) can list ${an.total ?? '?'} ${API[t.mode].noun}(s) in "${t.name}"`,
      detail: 'Fine for public content, not for anything personal.',
      evidence: `anonymous: ${an.evidence}`,
      fix: { code: fixFor('read') },
    });
}

// ---------------------------------------------------------------- storage buckets

// buckets: [{ id, config (from appwrite.json or null) }]
export async function probeBuckets(client, buckets, [A, B], { log, configFile }) {
  const findings = [];
  const passed = [];
  const skipped = [];
  const left = [];
  let fullyTested = 0;
  let readOnly = 0;
  const leftovers = []; // { bucket, id, by }

  try {
    for (const b of buckets) {
      log(`  bucket ${b.id}`);
      const name = `bucket ${b.id}`;
      const tf = (f) => findings.push({ resource: name, ...f });
      const fixFor = (...which) => fix.bucketFix(b, which, { configFile: b.config ? configFile : null });
      const why = (action) => {
        const broad = b.config ? rolesFor(b.config.permissions, action).filter((r) => r === 'any' || r === 'users' || r === 'guests') : [];
        return broad.length
          ? `${configFile} grants ${broad.map((r) => `${action}("${r}")`).join(', ')} at bucket level — that applies to every file.`
          : `A's file only named user A, so the bucket permissions grant this to everyone (typically ${action}("users") or ${action}("any") at bucket level, or file security off).`;
      };
      if (b.config && !b.config.enabled) {
        skipped.push(`${name}: the bucket is disabled in ${configFile}, not tested`);
        continue;
      }

      const marker = `accessprobe-${rand()}`;
      const fileName = `${marker}.txt`;
      const up = await client.upload(b.id, fileName, marker, { auth: A.auth });
      if (missingContainer(up)) {
        skipped.push(`${name}: no such bucket on this server`);
        continue;
      }
      if (!ok(up)) {
        if (refused(up)) {
          readOnly++;
          passed.push(`${name}: users cannot upload files (no create permission for users)`);
        } else skipped.push(`${name}: storage tests skipped — user A could not upload a test file (${up.status} ${msg(up.data)}; allowed extensions or size limits?)`);
        continue;
      }
      const fid = up.data.$id;
      leftovers.push({ bucket: b.id, id: fid, by: [A.auth, B.auth] });
      const aMeta = async () => {
        const r = await client.fileMeta(b.id, fid, { auth: A.auth });
        return ok(r) ? r.data : null;
      };
      const expected = { name: fileName };
      const unchanged = async () => {
        const m = await aMeta();
        return Boolean(m) && m.name === expected.name;
      };
      if (!(await aMeta())) {
        skipped.push(`${name}: user A cannot read its own new file, so B's results would prove nothing`);
        continue;
      }
      fullyTested++;

      const bGet = await client.download(b.id, fid, { auth: B.auth });
      if (ok(bGet) && String(bGet.data) === marker) {
        tf({
          id: 'storage-cross-user-read',
          severity: 'critical',
          title: `User B can download user A's files in bucket "${b.id}"`,
          detail: `Proven: A uploaded a file, B downloaded it by id. ${why('read')}`,
          evidence: `as user B: ${bGet.evidence}`,
          fix: { code: fixFor('read') },
        });
      } else if (refused(bGet) || (hidden(bGet) && (await unchanged()))) passed.push(`${name}: B cannot download A's files`);
      else skipped.push(`${name}: download test inconclusive (${bGet.status} ${msg(bGet.data)})`);

      const bList = await client.listFiles(b.id, { auth: B.auth, equalId: fid });
      if (bList.items?.some((x) => x.$id === fid)) {
        tf({
          id: 'storage-cross-user-list',
          severity: 'critical',
          title: `User B can list other users' files in bucket "${b.id}"`,
          detail: `Proven: B's list request returned A's file (names, sizes, ids). ${why('read')}`,
          evidence: `as user B: ${bList.evidence} → returned A's file`,
          fix: { code: fixFor('read') },
        });
      } else if (refused(bList) || (bList.items && (await client.listFiles(b.id, { auth: A.auth, equalId: fid })).items?.some((x) => x.$id === fid))) passed.push(`${name}: B cannot list A's files`);
      else skipped.push(`${name}: list test inconclusive (${bList.status} ${msg(bList.data)})`);

      const anGet = await client.download(b.id, fid);
      if (ok(anGet) && String(anGet.data) === marker) {
        tf({
          id: 'storage-anon-read',
          severity: 'critical',
          title: `Anyone (not logged in) can download files in bucket "${b.id}"`,
          detail: `Proven: a request with only the project id downloaded A's file. ${why('read')} Fine only for public assets.`,
          evidence: `anonymous: ${anGet.evidence}`,
          fix: { code: fixFor('read') },
        });
      } else if (refused(anGet) || (hidden(anGet) && (await unchanged()))) passed.push(`${name}: anonymous visitors cannot download A's files`);
      else skipped.push(`${name}: anonymous download test inconclusive (${anGet.status} ${msg(anGet.data)})`);

      const bRen = await client.updateFile(b.id, fid, { name: `${tamper(marker)}.txt` }, { auth: B.auth });
      if (ok(bRen)) {
        expected.name = `${tamper(marker)}.txt`;
        tf({
          id: 'storage-cross-user-update',
          severity: 'critical',
          title: `User B can change user A's files in bucket "${b.id}"`,
          detail: `Proven: B renamed a file A uploaded. ${why('update')}`,
          evidence: `as user B: ${bRen.evidence}`,
          fix: { code: fixFor('update') },
        });
      } else if (refused(bRen) || (hidden(bRen) && (await unchanged()))) passed.push(`${name}: B cannot change A's files`);
      else skipped.push(`${name}: update test inconclusive (${bRen.status} ${msg(bRen.data)})`);

      let takenOver = false;
      const bTake = await client.updateFile(b.id, fid, { permissions: own(B) }, { auth: B.auth });
      if (ok(bTake)) {
        takenOver = true;
        leftovers.find((l) => l.id === fid).by = [B.auth, A.auth];
        tf({
          id: 'storage-cross-user-takeover',
          severity: 'critical',
          title: `User B can take over user A's files in bucket "${b.id}"`,
          detail: `Proven: B replaced the permissions of A's file with its own. ${why('update')}`,
          evidence: `as user B: ${bTake.evidence} with {"permissions": [read/update/delete("user:<user B id>")]}`,
          fix: { code: fixFor('update') },
        });
      } else if (refused(bTake) || (hidden(bTake) && (await unchanged()))) passed.push(`${name}: B cannot change the permissions of A's files`);
      else skipped.push(`${name}: permission takeover test inconclusive (${bTake.status} ${msg(bTake.data)})`);

      const anUp = await client.upload(b.id, `${marker}-anon.txt`, marker, { permissions: ['delete("any")'] });
      if (ok(anUp)) {
        const anDel = await client.removeFile(b.id, anUp.data.$id);
        if (!ok(anDel)) leftovers.push({ bucket: b.id, id: anUp.data.$id, by: [A.auth, B.auth] });
        tf({
          id: 'storage-anon-upload',
          severity: 'warning',
          title: `Anyone (not logged in) can upload files to bucket "${b.id}"`,
          detail: `Proven: a request with only the project id uploaded a file. ${why('create')} Anyone can fill your storage (and your bill).`,
          evidence: `anonymous: ${anUp.evidence}`,
          fix: { code: fixFor('create') },
        });
      } else if (refused(anUp)) passed.push(`${name}: anonymous visitors cannot upload files`);
      else skipped.push(`${name}: anonymous upload test inconclusive (${anUp.status} ${msg(anUp.data)})`);

      if (takenOver) {
        skipped.push(`${name}: delete test skipped — B already took the file over`);
        continue;
      }
      const bDel = await client.removeFile(b.id, fid, { auth: B.auth });
      if (ok(bDel)) {
        leftovers.splice(leftovers.findIndex((l) => l.id === fid), 1);
        tf({
          id: 'storage-cross-user-delete',
          severity: 'critical',
          title: `User B can DELETE user A's files in bucket "${b.id}"`,
          detail: `Proven: B deleted a file A uploaded. ${why('delete')}`,
          evidence: `as user B: ${bDel.evidence}`,
          fix: { code: fixFor('delete') },
        });
      } else if (refused(bDel) || (hidden(bDel) && (await aMeta()))) passed.push(`${name}: B cannot delete A's files`);
      else skipped.push(`${name}: delete test inconclusive (${bDel.status} ${msg(bDel.data)})`);
    }
  } finally {
    for (const l of leftovers) {
      let done = false;
      for (const auth of l.by) {
        if (ok(await client.removeFile(l.bucket, l.id, { auth }))) {
          done = true;
          break;
        }
      }
      if (!done) left.push(`bucket ${l.bucket}/${l.id}`);
    }
  }
  return { findings, passed, skipped, left, fullyTested, readOnly };
}
