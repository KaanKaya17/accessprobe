// Firebase live tests. Same principles as the Supabase adapter:
//  - A creates a document/file of its own; B and an anonymous visitor attack it.
//  - Every critical finding is a request that succeeded.
//  - A PASS is only recorded when the request was refused (403/401) — never on a
//    404, a validation error or anything we can't explain.
//  - We never print other people's data, only counts.

import { randomUUID } from 'node:crypto';
import { decodeFields } from './client.js';
import { parseRules, allowsFor, ownerField, ownerPathVar, staticFlags, collectionOf } from './rules.js';
import * as fix from './fixes.js';

const rand = () => Math.random().toString(36).slice(2, 8);
// same-length variant of a marker (so a length check in the rules can't cause the refusal)
const tamper = (m) => `${m.slice(0, -1)}${m.endsWith('x') ? 'y' : 'x'}`;
const ok = (r) => r && r.ok;
// Only an explicit refusal counts as "denied" (see test/firebase/API-NOTES.md, trap 8):
// Firestore 403 PERMISSION_DENIED, Storage 403 "No X permission", RTDB 401 "Permission denied".
// A 400 (bad token), 404 or anything else is inconclusive, never a PASS.
const denied = (r) =>
  Boolean(r) &&
  ((r.status === 403 && /PERMISSION_DENIED|No \w+ permission|Permission denied/i.test(JSON.stringify(r.data ?? ''))) ||
    (r.status === 401 && /Permission denied/i.test(JSON.stringify(r.data ?? ''))));
const COMMON_OWNER_FIELDS = ['userId', 'uid', 'ownerId', 'owner', 'createdBy', 'user', 'authorId', 'user_id'];

export function msg(d) {
  if (!d) return '';
  if (typeof d === 'string') return d.trim().slice(0, 160);
  const e = Array.isArray(d) ? d[0]?.error : d.error;
  if (e) return (typeof e === 'string' ? e : e.status || e.message || JSON.stringify(e)).trim().slice(0, 160);
  return JSON.stringify(d).slice(0, 160);
}

// ---------------------------------------------------------------- users

export async function setupUsers(client, { userA, userB, emailDomain = 'example.com', log }) {
  const run = rand();
  const users = [];
  const made = [];
  try {
    for (const [label, cred] of [
      ['A', userA],
      ['B', userB],
    ]) {
      let r;
      let created = false;
      let email = null;
      if (cred) {
        const i = cred.indexOf(':');
        if (i < 1) throw new Error(`--user-${label.toLowerCase()} must look like email:password`);
        email = cred.slice(0, i);
        r = await client.signIn(email, cred.slice(i + 1));
        if (!ok(r)) throw new Error(`Sign-in of user ${label} failed (${r.status}): ${msg(r.data)}`);
      } else {
        email = `rlsprobe-${run}-${label.toLowerCase()}@${emailDomain}`;
        r = await client.signUp(email, `Rp-${randomUUID()}`);
        if (!ok(r) && /OPERATION_NOT_ALLOWED|ADMIN_ONLY_OPERATION/.test(msg(r.data))) {
          // email sign-up disabled: anonymous accounts still pass "request.auth != null"
          r = await client.signUp(null, null);
          email = `(anonymous ${label})`;
        }
        if (!ok(r)) throw new Error(`Sign-up of test user ${label} failed (${r.status}): ${msg(r.data)}`);
        created = true;
        made.push(r.data.idToken);
        log(`  created test user ${label}: ${email}`);
      }
      users.push({ label, email, id: r.data.localId, token: r.data.idToken, created });
    }
  } catch (e) {
    for (const t of made) await client.deleteAccount(t); // never leave half-created users behind
    throw e;
  }
  return users;
}

export async function deleteUsers(client, users, notes) {
  for (const u of users.filter((x) => x.created)) {
    const r = await client.deleteAccount(u.token);
    if (!ok(r)) notes.push(`Could not delete test user ${u.email} (${r.status} ${msg(r.data)}) — remove it in Firebase console → Authentication.`);
  }
}

// ---------------------------------------------------------------- Firestore

// Build the list of collections to test from rules + code.
export function firestoreTargets(src) {
  const targets = [];
  const seen = new Set();
  const matches = src.firestoreRules ? parseRules(src.firestoreRules) : [];
  for (const m of matches) {
    const c = collectionOf(m);
    if (!c || seen.has(c.collectionPath)) continue;
    seen.add(c.collectionPath);
    targets.push({ ...c, ownerField: ownerField(m), ownerPathVar: ownerPathVar(m), match: m, fromRules: true });
  }
  for (const name of src.collections || []) {
    if (seen.has(name)) continue;
    seen.add(name);
    targets.push({ collectionPath: name, docVar: 'id', ownerField: null, ownerPathVar: null, match: null, fromRules: false });
  }
  return { targets, matches };
}

// "users/{uid}/private" for user A -> "users/<A.uid>/private"
function fillPath(t, user) {
  return t.collectionPath.replace(/\{(\w+)\}/g, (_, v) => (v === t.ownerPathVar ? user.id : `rlsprobe-${v}`));
}

export async function probeFirestore(client, src, [A, B], { log }) {
  const findings = [];
  const passed = [];
  const skipped = [];
  const leftovers = [];
  const left = [];
  let fullyTested = 0;
  const { targets, matches } = firestoreTargets(src);
  // A 403 from a project whose Firestore API is off (or App Check-enforced) looks like a rule
  // refusal. PASSes that rest only on such a refusal wait until some Firestore request succeeded.
  const pendingPass = [];
  let firestoreAnswers = false;
  try {

  for (const m of matches) {
    for (const f of staticFlags(m)) {
      findings.push({
        id: `rules-${f.kind}`,
        resource: m.path,
        severity: 'warning',
        title:
          f.kind === 'test-mode-expiry'
            ? `"${m.path}" uses a test-mode time limit instead of real rules`
            : `"${m.path}" opens every document (${f.ops.join(', ')}: if true)`,
        detail:
          f.kind === 'test-mode-expiry'
            ? 'When the date passes the app stops working — and the usual "fix" is to push the date forward, leaving everything open. (Static finding from firestore.rules.)'
            : 'A recursive wildcard with "if true" applies to every collection, including ones added later. (Static finding from firestore.rules; live tests below show the effect.)',
        evidence: `firestore.rules: match ${m.path} { allow ${f.ops.join(', ')}: if ${f.cond}; }`,
        fix: { code: fix.ownerOnlyRules(m.path, null, null) },
      });
    }
  }

  for (const t of targets) {
    log(`  collection ${t.collectionPath}`);
    const tf = (f) => findings.push({ resource: t.collectionPath, ...f });
    const aColl = fillPath(t, A);
    const owned = Boolean(t.ownerField || t.ownerPathVar);

    // A creates a document. Try the known owner field first, then common names.
    const marker = `rlsprobe-${rand()}`;
    // match /profiles/{uid}: the document id itself is the owner's uid
    const docId = t.ownerPathVar && t.ownerPathVar === t.docVar ? A.id : `rlsprobe-${rand()}`;
    let mine = null;
    let lastErr = null;
    for (const cand of payloadCandidates(t, A, marker)) {
      const r = await client.createDoc(aColl, docId, cand.data, { token: A.token });
      if (ok(r)) {
        firestoreAnswers = true;
        mine = { path: `${aColl}/${docId}`, payload: cand.data, ownerField: cand.ownerField, markerField: cand.markerField };
        break;
      }
      lastErr = r;
    }

    if (!mine) {
      await freshUserList(client, t, aColl, B, { tf, passed: pendingPass, skipped, owned });
      if (denied(lastErr)) skipped.push(`${t.collectionPath}: write tests skipped — user A may not create documents here (${lastErr.status} ${msg(lastErr.data)})`);
      else skipped.push(`${t.collectionPath}: write tests skipped — user A could not create a test document (${lastErr?.status} ${msg(lastErr?.data)})`);
      continue;
    }
    leftovers.push({ path: mine.path, by: [A, B], mine: true });
    const aGet = await client.getDoc(mine.path, { token: A.token });
    if (!ok(aGet)) {
      skipped.push(`${t.collectionPath}: user A cannot read its own new document (${aGet.status} ${msg(aGet.data)}), so B's results would prove nothing`);
      continue;
    }
    fullyTested++;
    const ownedNow = owned || Boolean(mine.ownerField);
    const ownerDesc = t.ownerPathVar ? `path {${t.ownerPathVar}}` : mine.ownerField ? `field ${mine.ownerField}` : null;
    const rules = () => fix.ownerOnlyRules(t.match?.path || `/${t.collectionPath}/{${t.docVar}}`, mine.ownerField, t.ownerPathVar);
    // "allow read: if true" is a deliberate choice (public content), not a leak
    const publicByRule = Boolean(t.match && allowsFor(t.match, 'get').includes('true'));
    let publicNoted = false;
    const notePublic = (r) => {
      if (publicNoted) return;
      publicNoted = true;
      tf({
        id: 'public-by-rule',
        severity: 'info',
        title: `"${t.collectionPath}" is public by design (allow read: if true)`,
        detail: 'Everyone, signed in or not, can read every document here. Make sure nothing personal is ever stored in it.',
        evidence: r.evidence,
        fix: null,
      });
    };

    // B reads A's document
    const bGet = await client.getDoc(mine.path, { token: B.token });
    if (ok(bGet) && publicByRule) notePublic(bGet);
    else if (ok(bGet)) {
      tf({
        id: ownedNow ? 'cross-user-read' : 'shared-no-owner',
        severity: ownedNow ? 'critical' : 'warning',
        title: ownedNow ? `User B can read user A's documents in "${t.collectionPath}"` : `Documents in "${t.collectionPath}" are readable by every signed-in user`,
        detail: ownedNow
          ? `Proven: A created a document (owner: ${ownerDesc}), B fetched it. Typical cause: "allow read: if request.auth != null".`
          : 'A document created by A is visible to B, and rlsprobe found no owner field — fine only if this data is meant to be shared.',
        evidence: `as user B: ${bGet.evidence}`,
        fix: { code: rules() },
      });
    } else if (denied(bGet)) passed.push(`${t.collectionPath}: B cannot read A's documents`);
    else skipped.push(`${t.collectionPath}: read test inconclusive (${bGet.status} ${msg(bGet.data)})`);

    // B lists the collection (what "allow list" really permits)
    const bList = await client.listDocs(aColl, { token: B.token });
    const foreign = bList.docs.filter((d) => !belongsTo(d, B, mine.ownerField));
    if (ok(bList) && foreign.length && publicByRule) notePublic(bList);
    else if (ok(bList) && foreign.length) {
      const cnt = await client.countDocs(aColl, { token: B.token });
      tf({
        id: 'cross-user-list',
        severity: ownedNow ? 'critical' : 'warning',
        title: `User B can list ${cnt.count ?? `${foreign.length}+`} document(s) in "${t.collectionPath}"`,
        detail: 'An unfiltered query from B returns other users\' documents. "allow read" also grants list; use "allow get" or require a where-filter on the owner field.',
        evidence: `as user B: ${bList.evidence} → ${foreign.length} foreign document(s) in the first page`,
        fix: { code: rules() },
      });
    } else if (denied(bList)) passed.push(`${t.collectionPath}: B cannot list other users' documents`);
    else skipped.push(`${t.collectionPath}: list test inconclusive (${bList.status} ${msg(bList.data)})`);

    // anonymous read + list
    const anGet = await client.getDoc(mine.path);
    if (ok(anGet) && publicByRule) notePublic(anGet);
    else if (ok(anGet)) {
      tf({
        id: 'anon-read',
        severity: ownedNow ? 'critical' : 'warning',
        title: `Anyone (not logged in) can read documents in "${t.collectionPath}"`,
        detail: ownedNow ? 'Proven: an unauthenticated request fetched A\'s document.' : 'Fine for public content, not for anything personal.',
        evidence: `anonymous: ${anGet.evidence}`,
        fix: { code: rules() },
      });
    } else if (denied(anGet)) passed.push(`${t.collectionPath}: anonymous visitors cannot read`);

    // B modifies A's document
    const patch = mine.markerField ? { [mine.markerField]: tamper(marker) } : mine.ownerField ? { [mine.ownerField]: A.id } : null;
    const bUpd = patch ? await client.updateDoc(mine.path, patch, { token: B.token }) : null;
    if (!patch) skipped.push(`${t.collectionPath}: modify test skipped (no field to change)`);
    else if (ok(bUpd)) {
      tf({
        id: 'cross-user-update',
        severity: 'critical',
        title: `User B can MODIFY user A's documents in "${t.collectionPath}"`,
        detail: 'Proven: B changed a document that A created.',
        evidence: `as user B: ${bUpd.evidence}`,
        fix: { code: rules() },
      });
    } else if (denied(bUpd)) passed.push(`${t.collectionPath}: B cannot modify A's documents`);
    else skipped.push(`${t.collectionPath}: modify test inconclusive (${bUpd.status} ${msg(bUpd.data)})`);

    // B reassigns A's document to itself: rules that only check request.resource.data.owner
    // (the NEW value) on update let anyone take other users' documents over
    let takenOver = false;
    if (mine.ownerField) {
      const bTake = await client.updateDoc(mine.path, { [mine.ownerField]: B.id }, { token: B.token });
      if (ok(bTake)) {
        takenOver = true;
        tf({
          id: 'cross-user-takeover',
          severity: 'critical',
          title: `User B can take over user A's documents in "${t.collectionPath}"`,
          detail: `Proven: B set ${mine.ownerField} of A's document to itself. The update rule checks only the new value (request.resource.data), not the current owner (resource.data).`,
          evidence: `as user B: ${bTake.evidence}`,
          fix: { code: rules() },
        });
      } else if (denied(bTake)) passed.push(`${t.collectionPath}: B cannot reassign A's documents to itself`);
      else skipped.push(`${t.collectionPath}: takeover test inconclusive (${bTake.status} ${msg(bTake.data)})`);
    }

    // B forges a document in A's name — identical payload to A's accepted one
    const forgeId = `rlsprobe-${rand()}`;
    const forged = { ...mine.payload, ...(mine.markerField ? { [mine.markerField]: `${marker}-fake` } : {}) };
    const bNew = await client.createDoc(aColl, forgeId, forged, { token: B.token });
    if (ok(bNew)) {
      leftovers.push({ path: `${aColl}/${forgeId}`, by: [A, B] });
      if (ownedNow)
        tf({
          id: 'impersonated-create',
          severity: 'critical',
          title: `User B can create documents in "${t.collectionPath}" in user A's name`,
          detail: `The create rule does not check ${ownerDesc} against request.auth.uid, so anyone can forge data for another user.`,
          evidence: `as user B: ${bNew.evidence}`,
          fix: { code: rules() },
        });
    } else if (denied(bNew)) passed.push(`${t.collectionPath}: B cannot create documents as A`);
    else skipped.push(`${t.collectionPath}: forged-create test inconclusive (${bNew.status} ${msg(bNew.data)})`);

    // anonymous visitor creates (and deletes) a document
    const anId = `rlsprobe-${rand()}`;
    const anNew = await client.createDoc(aColl, anId, { ...forged, ...(mine.markerField ? { [mine.markerField]: `${marker}-anon` } : {}) });
    if (ok(anNew)) {
      const anDel = await client.deleteDoc(`${aColl}/${anId}`);
      if (!ok(anDel)) leftovers.push({ path: `${aColl}/${anId}`, by: [A, B] });
      tf({
        id: ok(anDel) ? 'anon-write' : 'anon-create',
        severity: ownedNow || ok(anDel) ? 'critical' : 'warning',
        title: ok(anDel)
          ? `Anyone (not logged in) can create AND delete documents in "${t.collectionPath}"`
          : `Anyone (not logged in) can create documents in "${t.collectionPath}"`,
        detail: ok(anDel)
          ? 'No sign-in needed to write here: the rules are effectively open.'
          : 'Fine for a contact form or guestbook; otherwise require sign-in.',
        evidence: `anonymous: ${anNew.evidence}${ok(anDel) ? `, then ${anDel.evidence}` : ''}`,
        fix: { code: rules() },
      });
    } else if (denied(anNew)) passed.push(`${t.collectionPath}: anonymous visitors cannot create documents`);

    // B deletes A's document (last: it destroys the test doc)
    if (takenOver) {
      skipped.push(`${t.collectionPath}: delete test skipped — B already took the document over`);
      continue;
    }
    const bDel = await client.deleteDoc(mine.path, { token: B.token });
    let gone = false;
    if (ok(bDel)) {
      gone = true;
      tf({
        id: 'cross-user-delete',
        severity: 'critical',
        title: `User B can DELETE user A's documents in "${t.collectionPath}"`,
        detail: 'Proven: B deleted a document that A created.',
        evidence: `as user B: ${bDel.evidence}`,
        fix: { code: rules() },
      });
    } else if (denied(bDel)) passed.push(`${t.collectionPath}: B cannot delete A's documents`);
    else skipped.push(`${t.collectionPath}: delete test inconclusive (${bDel.status} ${msg(bDel.data)})`);

    if (gone) leftovers.splice(leftovers.findIndex((l) => l.path === mine.path), 1);
  }
  } finally {
    // cleanup runs even if a probe threw; the caller deletes the users only afterwards
    for (const l of leftovers) {
      let done = false;
      for (const u of l.by) {
        if (ok(await client.deleteDoc(l.path, { token: u.token }))) {
          done = true;
          break;
        }
      }
      if (!done) left.push(l.path);
    }
  }
  if (firestoreAnswers) passed.push(...pendingPass);
  else for (const p of pendingPass) skipped.push(`${p} — not proven: no Firestore request succeeded in this run (API disabled or App Check?)`);
  return { findings, passed, skipped, left, fullyTested, count: targets.length };
}

// Read the shape a create rule demands: keys().hasOnly([...]) and "data.x is string"
export function ruleSchema(match) {
  if (!match) return null;
  const conds = allowsFor(match, 'create').join(' && ');
  const only = conds.match(/request\.resource\.data\.keys\(\)\.hasOnly\(\[([^\]]*)\]\)/);
  const types = {};
  for (const m of conds.matchAll(/request\.resource\.data\.(\w+)\s+is\s+(string|int|float|number|bool|timestamp|list|map)/g)) types[m[1]] = m[2];
  const allKeys = conds.match(/request\.resource\.data\.keys\(\)\.hasAll\(\[([^\]]*)\]\)/);
  const list = (x) => (x ? x[1].split(',').map((k) => k.trim().replace(/^['"]|['"]$/g, '')).filter(Boolean) : null);
  return { only: list(only), required: list(allKeys) || [], types };
}

const SAMPLE = { string: null, int: 1, float: 1.5, number: 1, bool: false, timestamp: new Date(), list: [], map: {} };

// Ordered payloads for A's first document: rule-shaped first, then simple guesses.
export function payloadCandidates(t, A, marker) {
  const out = [];
  const owners = t.ownerField ? [t.ownerField] : t.ownerPathVar ? [null] : [null, ...COMMON_OWNER_FIELDS];
  const schema = ruleSchema(t.match);
  if (schema && (schema.only || Object.keys(schema.types).length || schema.required.length)) {
    const of = owners[0];
    const data = of ? { [of]: A.id } : {};
    let markerField = null;
    const keys = new Set([...(schema.only || []), ...Object.keys(schema.types), ...schema.required]);
    for (const k of keys) {
      if (k === of) continue;
      const type = schema.types[k] || 'string';
      if (type === 'string') {
        data[k] = marker;
        markerField ??= k;
      } else data[k] = SAMPLE[type];
    }
    if (!schema.only && !markerField) {
      data.rlsprobe = marker;
      markerField = 'rlsprobe';
    }
    out.push({ data, ownerField: of, markerField });
  }
  for (const of of owners) {
    out.push({ data: of ? { [of]: A.id, rlsprobe: marker } : { rlsprobe: marker }, ownerField: of, markerField: 'rlsprobe' });
    if (of) out.push({ data: { [of]: A.id }, ownerField: of, markerField: null });
  }
  return out;
}

function belongsTo(doc, user, ownerFieldName) {
  if (doc.name?.includes(`/${user.id}/`)) return true;
  const f = decodeFields(doc.fields);
  if (ownerFieldName && f[ownerFieldName] === user.id) return true;
  return COMMON_OWNER_FIELDS.some((k) => f[k] === user.id);
}

// A could not write here: can a brand-new user B see anything? (Firewreck-style count)
async function freshUserList(client, t, coll, B, { tf, passed, skipped, owned }) {
  const r = await client.listDocs(coll, { token: B.token });
  if (denied(r)) {
    passed.push(`${t.collectionPath}: a new user cannot list documents`);
    return;
  }
  if (!ok(r)) {
    skipped.push(`${t.collectionPath}: list test inconclusive (${r.status} ${msg(r.data)})`);
    return;
  }
  const foreign = r.docs.filter((d) => !belongsTo(d, B, t.ownerField));
  if (!foreign.length) {
    skipped.push(`${t.collectionPath}: a new user may list this collection but it looked empty — not proven either way`);
    return;
  }
  const cnt = await client.countDocs(coll, { token: B.token });
  tf({
    id: 'fresh-user-sees-docs',
    severity: 'warning',
    title: `A brand-new user can list ${cnt.count ?? `${foreign.length}+`} document(s) in "${t.collectionPath}"`,
    detail: owned
      ? 'Test user B was created seconds ago and owns nothing here, yet reads other users\' documents.'
      : 'Test user B was created seconds ago and owns nothing here. Either this data is meant to be shared, or the read rule is too broad.',
    evidence: `as user B: ${r.evidence}`,
    fix: { code: fix.ownerOnlyRules(t.match?.path || `/${t.collectionPath}/{${t.docVar}}`, t.ownerField, t.ownerPathVar) },
  });
}

export { allowsFor };
