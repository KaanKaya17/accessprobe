// Verification script: documents (by actually calling them) how the Firebase
// emulator REST endpoints behave when security rules ALLOW vs DENY a request.
// No SDK, only fetch, using the same auth headers a browser client sends.
//
//   node test/firebase/verify-api.js            # starts + stops emulators itself
//   node test/firebase/verify-api.js --attach   # use already-running emulators
//   node test/firebase/verify-api.js --json out.json   # also dump raw results
//
// Findings are summarised in test/firebase/API-NOTES.md.

import { writeFileSync } from 'node:fs';
import { startEmulators, hosts as H } from './emulator.js';

const argv = process.argv.slice(2);
const attach = argv.includes('--attach');
const jsonOut = argv.includes('--json') ? argv[argv.indexOf('--json') + 1] : null;

const AUTH = `${H.auth}/identitytoolkit.googleapis.com/v1`;
const FS = `${H.firestore}/v1/projects/${H.projectId}/databases/(default)/documents`;
const NS = H.rtdbNamespace;
const BUCKET = H.storageBucket;
const ST = `${H.storage}/v0/b/${BUCKET}/o`;

const results = [];
const run = Date.now().toString(36); // unique ids per run

async function call(label, method, url, { token, style = 'bearer', body, headers = {}, raw } = {}) {
  const h = { ...headers };
  let u = url;
  if (token) {
    if (style === 'bearer') h.Authorization = `Bearer ${token}`;
    else if (style === 'firebase') h.Authorization = `Firebase ${token}`;
    else if (style === 'query') u += (u.includes('?') ? '&' : '?') + `auth=${encodeURIComponent(token)}`;
  }
  let payload;
  if (raw !== undefined) payload = raw;
  else if (body !== undefined) { payload = JSON.stringify(body); h['Content-Type'] ??= 'application/json'; }
  const res = await fetch(u, { method, headers: h, body: payload });
  const text = await res.text();
  let parsed = text;
  try { parsed = JSON.parse(text); } catch { /* not json */ }
  const r = { label, method, url: u.replace(/auth=[^&]+/, 'auth=<idToken>'), auth: token ? style : 'none', status: res.status, body: parsed };
  results.push(r);
  const shown = typeof parsed === 'string' ? parsed : JSON.stringify(parsed);
  console.log(`${String(res.status).padEnd(4)} ${label}\n     ${method} ${r.url}\n     -> ${shown.slice(0, 300)}`);
  return r;
}

const fsStr = (o) => ({ fields: Object.fromEntries(Object.entries(o).map(([k, v]) =>
  [k, typeof v === 'number' ? { integerValue: String(v) } : typeof v === 'boolean' ? { booleanValue: v } : { stringValue: v }])) });

async function main() {
  let emu;
  if (!attach) {
    emu = await startEmulators();
    console.log(`emulators ready in ${emu.startupMs} ms`);
  }
  try {
    // ------------------------------------------------------------- AUTH
    console.log('\n=== AUTH ===');
    const emailA = `a-${run}@example.test`, emailB = `b-${run}@example.test`, pw = 'test-password-123';
    const sa = await call('signUp A (email/password)', 'POST', `${AUTH}/accounts:signUp?key=any`, { body: { email: emailA, password: pw, returnSecureToken: true } });
    const sb = await call('signUp B (email/password)', 'POST', `${AUTH}/accounts:signUp?key=any`, { body: { email: emailB, password: pw, returnSecureToken: true } });
    await call('signUp duplicate email', 'POST', `${AUTH}/accounts:signUp?key=any`, { body: { email: emailA, password: pw, returnSecureToken: true } });
    await call('signUp weak password', 'POST', `${AUTH}/accounts:signUp?key=any`, { body: { email: `w-${run}@example.test`, password: '123', returnSecureToken: true } });
    const anon = await call('signUp anonymous (no email)', 'POST', `${AUTH}/accounts:signUp?key=any`, { body: { returnSecureToken: true } });
    const si = await call('signInWithPassword A', 'POST', `${AUTH}/accounts:signInWithPassword?key=any`, { body: { email: emailA, password: pw, returnSecureToken: true } });
    await call('signInWithPassword wrong password', 'POST', `${AUTH}/accounts:signInWithPassword?key=any`, { body: { email: emailA, password: 'nope-nope', returnSecureToken: true } });
    await call('signUp without ?key', 'POST', `${AUTH}/accounts:signUp`, { body: { returnSecureToken: true } });
    const A = sa.body.idToken, B = sb.body.idToken, ANON = anon.body.idToken;
    const uidA = sa.body.localId, uidB = sb.body.localId, uidAnon = anon.body.localId;
    const [hdr] = A.split('.');
    console.log('     idToken header:', Buffer.from(hdr, 'base64url').toString());
    console.log('     idToken claims:', Buffer.from(A.split('.')[1], 'base64url').toString());
    console.log('     signIn token === signUp token?', si.body.idToken === A);

    // ------------------------------------------------------------- FIRESTORE
    console.log('\n=== FIRESTORE ===');
    const noteA = `n-${run}`;
    await call('notes: A creates own note (?documentId)', 'POST', `${FS}/notes?documentId=${noteA}`, { token: A, body: fsStr({ ownerId: uidA, title: 'secret' }) });
    await call('notes: A creates same id again', 'POST', `${FS}/notes?documentId=${noteA}`, { token: A, body: fsStr({ ownerId: uidA, title: 'dup' }) });
    await call('notes: B forges note with ownerId=A', 'POST', `${FS}/notes?documentId=forge-${run}`, { token: B, body: fsStr({ ownerId: uidA, title: 'forged' }) });
    await call('notes: anon (no token) creates', 'POST', `${FS}/notes?documentId=anon-${run}`, { body: fsStr({ ownerId: uidA, title: 'x' }) });
    await call('notes: A get own', 'GET', `${FS}/notes/${noteA}`, { token: A });
    await call('notes: B get A note (denied)', 'GET', `${FS}/notes/${noteA}`, { token: B });
    await call('notes: no-auth get A note (denied)', 'GET', `${FS}/notes/${noteA}`);
    await call('notes: A get MISSING doc (rule uses resource.data)', 'GET', `${FS}/notes/missing-${run}`, { token: A });
    await call('logs: get MISSING doc (open rule)', 'GET', `${FS}/logs/missing-${run}`);
    await call('notes: B patch A note (denied)', 'PATCH', `${FS}/notes/${noteA}?updateMask.fieldPaths=title`, { token: B, body: fsStr({ title: 'pwned' }) });
    await call('notes: A patch own note', 'PATCH', `${FS}/notes/${noteA}?updateMask.fieldPaths=title`, { token: A, body: fsStr({ title: 'edited' }) });
    await call('logs: PATCH a MISSING doc (upsert?)', 'PATCH', `${FS}/logs/upsert-${run}?updateMask.fieldPaths=msg`, { body: fsStr({ msg: 'created by patch' }) });
    await call('logs: PATCH missing doc with currentDocument.exists=true', 'PATCH', `${FS}/logs/upsert2-${run}?updateMask.fieldPaths=msg&currentDocument.exists=true`, { body: fsStr({ msg: 'x' }) });
    await call('notes: B delete A note (denied)', 'DELETE', `${FS}/notes/${noteA}`, { token: B });
    await call('notes: A get own after B delete attempt', 'GET', `${FS}/notes/${noteA}`, { token: A });
    await call('logs: DELETE MISSING doc (open rule)', 'DELETE', `${FS}/logs/missing-${run}`);
    await call('logs: DELETE MISSING doc with currentDocument.exists=true', 'DELETE', `${FS}/logs/missing-${run}?currentDocument.exists=true`);
    await call('notes: A DELETE MISSING doc (rule uses resource.data)', 'DELETE', `${FS}/notes/missing-${run}`, { token: A });

    // orders: leak + forgery
    const ordA = `o-${run}`;
    await call('orders: A creates own order', 'POST', `${FS}/orders?documentId=${ordA}`, { token: A, body: fsStr({ userId: uidA, total: 42 }) });
    await call('orders: B forges order userId=A (allowed = forgery)', 'POST', `${FS}/orders?documentId=forged-${run}`, { token: B, body: fsStr({ userId: uidA, total: 1 }) });
    await call('orders: B get A order (allowed = leak)', 'GET', `${FS}/orders/${ordA}`, { token: B });
    await call('orders: B patch A order (denied)', 'PATCH', `${FS}/orders/${ordA}?updateMask.fieldPaths=total`, { token: B, body: fsStr({ total: 0 }) });
    await call('orders: B delete A order (denied)', 'DELETE', `${FS}/orders/${ordA}`, { token: B });
    await call('orders: no-auth get (denied)', 'GET', `${FS}/orders/${ordA}`);

    // profiles
    await call('profiles: A writes own (POST documentId=uid)', 'POST', `${FS}/profiles?documentId=${uidA}`, { token: A, body: fsStr({ name: 'Alice', email: emailA }) });
    await call('profiles: B reads A profile (allowed = leak)', 'GET', `${FS}/profiles/${uidA}`, { token: B });
    await call('profiles: anonymous-auth user reads A profile', 'GET', `${FS}/profiles/${uidA}`, { token: ANON });
    await call('profiles: B overwrites A profile (denied)', 'PATCH', `${FS}/profiles/${uidA}`, { token: B, body: fsStr({ name: 'pwned' }) });

    // public_posts, logs
    await call('public_posts: A creates', 'POST', `${FS}/public_posts?documentId=p-${run}`, { token: A, body: fsStr({ ownerId: uidA, body: 'hello' }) });
    await call('public_posts: no-auth get (intended public)', 'GET', `${FS}/public_posts/p-${run}`);
    await call('public_posts: B patch (denied)', 'PATCH', `${FS}/public_posts/p-${run}?updateMask.fieldPaths=body`, { token: B, body: fsStr({ body: 'x' }) });
    await call('logs: no-auth create (wide open)', 'POST', `${FS}/logs?documentId=l-${run}`, { body: fsStr({ msg: 'hi' }) });
    await call('logs: no-auth delete existing (wide open)', 'DELETE', `${FS}/logs/l-${run}`);

    // users/{uid}/private
    await call('users/A/private: A creates', 'POST', `${FS}/users/${uidA}/private?documentId=d-${run}`, { token: A, body: fsStr({ ssn: 'fake' }) });
    await call('users/A/private: B get (denied)', 'GET', `${FS}/users/${uidA}/private/d-${run}`, { token: B });
    await call('users/A/private: B creates in A subcollection (denied)', 'POST', `${FS}/users/${uidA}/private?documentId=f-${run}`, { token: B, body: fsStr({ x: 'y' }) });

    // strict: validator vs permission rejection
    await call('strict: A valid create', 'POST', `${FS}/strict?documentId=s-${run}`, { token: A, body: fsStr({ ownerId: uidA, title: 'ok' }) });
    await call('strict: A create with EXTRA field (validator rejects)', 'POST', `${FS}/strict?documentId=s2-${run}`, { token: A, body: fsStr({ ownerId: uidA, title: 'ok', admin: true }) });
    await call('strict: A create with title=int (validator rejects)', 'POST', `${FS}/strict?documentId=s3-${run}`, { token: A, body: fsStr({ ownerId: uidA, title: 5 }) });
    await call('strict: B forge ownerId=A (permission rejects)', 'POST', `${FS}/strict?documentId=s4-${run}`, { token: B, body: fsStr({ ownerId: uidA, title: 'ok' }) });
    await call('strict: B patch A doc (permission rejects)', 'PATCH', `${FS}/strict/s-${run}?updateMask.fieldPaths=title`, { token: B, body: fsStr({ title: 'x' }) });
    await call('strict: A patch own adding extra field (validator rejects)', 'PATCH', `${FS}/strict/s-${run}?updateMask.fieldPaths=evil`, { token: A, body: fsStr({ evil: 'x' }) });

    // queries
    const q = (coll, where) => ({ structuredQuery: { from: [{ collectionId: coll }], ...(where ? { where } : {}) } });
    const eq = (field, value) => ({ fieldFilter: { field: { fieldPath: field }, op: 'EQUAL', value: { stringValue: value } } });
    await call('runQuery orders as B (unfiltered, rule auth!=null)', 'POST', `${FS}:runQuery`, { token: B, body: q('orders') });
    await call('runQuery orders as no-auth (denied)', 'POST', `${FS}:runQuery`, { body: q('orders') });
    await call('runQuery notes as B unfiltered (denied: rule not provable)', 'POST', `${FS}:runQuery`, { token: B, body: q('notes') });
    await call('runQuery notes as B where ownerId==A (denied)', 'POST', `${FS}:runQuery`, { token: B, body: q('notes', eq('ownerId', uidA)) });
    await call('runQuery notes as B where ownerId==B (allowed, empty)', 'POST', `${FS}:runQuery`, { token: B, body: q('notes', eq('ownerId', uidB)) });
    await call('runQuery notes as A where ownerId==A (allowed)', 'POST', `${FS}:runQuery`, { token: A, body: q('notes', eq('ownerId', uidA)) });
    await call('runQuery nonexistent collection as no-auth (no rule)', 'POST', `${FS}:runQuery`, { body: q(`nope_${run}`) });
    await call('runQuery collectionGroup private as B (denied: no ** rule)', 'POST', `${FS}:runQuery`, { token: B, body: { structuredQuery: { from: [{ collectionId: 'private', allDescendants: true }] } } });
    await call('runQuery logs (empty-ish, open rule)', 'POST', `${FS}:runQuery`, { body: q(`logs`, eq('msg', 'no-such-value')) });
    await call('list orders via GET collection as B', 'GET', `${FS}/orders?pageSize=5`, { token: B });
    await call('list notes via GET collection as B (denied)', 'GET', `${FS}/notes?pageSize=5`, { token: B });
    const agg = (coll, where) => ({ structuredAggregationQuery: { structuredQuery: q(coll, where).structuredQuery, aggregations: [{ alias: 'n', count: {} }] } });
    await call('runAggregationQuery count orders as B', 'POST', `${FS}:runAggregationQuery`, { token: B, body: agg('orders') });
    await call('runAggregationQuery count notes as B (denied)', 'POST', `${FS}:runAggregationQuery`, { token: B, body: agg('notes') });
    await call('runAggregationQuery count orders no-auth (denied)', 'POST', `${FS}:runAggregationQuery`, { body: agg('orders') });

    // emulator-only bypasses / token handling
    await call('notes: get A note with "Bearer owner" (emulator admin bypass)', 'GET', `${FS}/notes/${noteA}`, { token: 'owner' });
    await call('notes: get with garbage bearer token', 'GET', `${FS}/notes/${noteA}`, { token: 'garbage' });
    const forged = [Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url'),
      Buffer.from(JSON.stringify({ sub: uidA, user_id: uidA, aud: H.projectId, iss: `https://securetoken.google.com/${H.projectId}`, iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 3600, firebase: { sign_in_provider: 'password' } })).toString('base64url'), ''].join('.');
    await call('notes: get A note with HAND-FORGED unsigned token (emulator accepts?)', 'GET', `${FS}/notes/${noteA}`, { token: forged });

    // ------------------------------------------------------------- RTDB
    console.log('\n=== REALTIME DATABASE ===');
    const R = (p, qs = '') => `${H.database}/${p}.json?ns=${NS}${qs}`;
    await call('rtdb: A PUT users/A (?auth=)', 'PUT', R(`users/${uidA}`), { token: A, style: 'query', body: { name: 'Alice', secret: 's3' } });
    await call('rtdb: A PUT users/A (Bearer header)', 'PUT', R(`users/${uidA}/viaBearer`), { token: A, body: 'yes' });
    await call('rtdb: B GET users/A (allowed = leak)', 'GET', R(`users/${uidA}`), { token: B, style: 'query' });
    await call('rtdb: no-auth GET users/A (denied)', 'GET', R(`users/${uidA}`));
    await call('rtdb: B PUT users/A (denied)', 'PUT', R(`users/${uidA}/name`), { token: B, style: 'query', body: 'pwned' });
    await call('rtdb: B PATCH users/A (denied)', 'PATCH', R(`users/${uidA}`), { token: B, style: 'query', body: { name: 'pwned' } });
    await call('rtdb: B DELETE users/A (denied)', 'DELETE', R(`users/${uidA}`), { token: B, style: 'query' });
    await call('rtdb: B POST push into users/A (denied)', 'POST', R(`users/${uidA}`), { token: B, style: 'query', body: { x: 1 } });
    await call('rtdb: B GET users (parent, no .read at users)', 'GET', R('users'), { token: B, style: 'query' });
    await call('rtdb: B GET users shallow=true', 'GET', R('users', '&shallow=true'), { token: B, style: 'query' });
    await call('rtdb: no-auth GET root (denied)', 'GET', R(''));
    await call('rtdb: no-auth GET root shallow (denied)', 'GET', R('', '&shallow=true'));
    await call('rtdb: no-auth PUT open/x', 'PUT', R(`open/x-${run}`), { body: { hello: 'world' } });
    await call('rtdb: no-auth GET open shallow', 'GET', R('open', '&shallow=true'));
    await call('rtdb: no-auth GET missing path under open', 'GET', R(`open/missing-${run}`));
    await call('rtdb: no-auth DELETE missing path under open', 'DELETE', R(`open/missing-${run}`));
    await call('rtdb: no-auth DELETE open/x', 'DELETE', R(`open/x-${run}`));
    await call('rtdb: A GET users/missing uid (auth!=null)', 'GET', R(`users/missing-${run}`), { token: A, style: 'query' });
    await call('rtdb: B DELETE users/B missing (allowed, nothing there)', 'DELETE', R(`users/${uidB}`), { token: B, style: 'query' });
    await call('rtdb: garbage ?auth=', 'GET', R(`users/${uidA}`), { token: 'garbage', style: 'query' });
    await call('rtdb: no ns param, no-auth PUT users/x (other namespace, NO rules!)', 'PUT', `${H.database}/users/x-${run}.json`, { body: 1 });
    await call('rtdb: wrong ns, no-auth PUT users/x (NO rules!)', 'PUT', `${H.database}/users/x-${run}.json?ns=wrong-ns`, { body: 1 });
    await call('rtdb: root with "Bearer owner" header (admin bypass)', 'GET', R('', '&shallow=true'), { token: 'owner', style: 'bearer' });
    await call('rtdb: root with ?auth=owner (NOT a bypass)', 'GET', R('', '&shallow=true'), { token: 'owner', style: 'query' });

    // ------------------------------------------------------------- STORAGE
    console.log('\n=== STORAGE ===');
    const up = (p) => `${ST}?name=${encodeURIComponent(p)}`;
    const obj = (p, qs = '') => `${ST}/${encodeURIComponent(p)}${qs}`;
    const png = Buffer.from('fake-png-bytes');
    const avA = `avatars/${uidA}/pic.png`;
    await call('storage: A upload own avatar (Firebase header)', 'POST', up(avA), { token: A, style: 'firebase', raw: png, headers: { 'Content-Type': 'image/png' } });
    await call('storage: A upload own private (Bearer header)', 'POST', up(`private/${uidA}/doc.txt`), { token: A, style: 'bearer', raw: 'secret text', headers: { 'Content-Type': 'text/plain' } });
    await call('storage: B GET A avatar metadata (allowed = leak)', 'GET', obj(avA), { token: B, style: 'firebase' });
    await call('storage: B download A avatar alt=media (allowed = leak)', 'GET', obj(avA, '?alt=media'), { token: B, style: 'firebase' });
    await call('storage: no-auth download A avatar (denied)', 'GET', obj(avA, '?alt=media'));
    await call('storage: B download A private (denied)', 'GET', obj(`private/${uidA}/doc.txt`, '?alt=media'), { token: B, style: 'firebase' });
    await call('storage: B overwrite A avatar (denied)', 'POST', up(avA), { token: B, style: 'firebase', raw: 'evil', headers: { 'Content-Type': 'image/png' } });
    await call('storage: B upload into avatars/A/new (forge, denied)', 'POST', up(`avatars/${uidA}/new.png`), { token: B, style: 'firebase', raw: 'evil', headers: { 'Content-Type': 'image/png' } });
    await call('storage: B DELETE A avatar (denied)', 'DELETE', obj(avA), { token: B, style: 'firebase' });
    await call('storage: B list avatars/A/ WITHOUT delimiter (denied: rule {file} is one segment)', 'GET', `${ST}?prefix=${encodeURIComponent(`avatars/${uidA}/`)}`, { token: B, style: 'firebase' });
    await call('storage: B list avatars/A/ delimiter=/ (allowed = leak, what listAll() sends)', 'GET', `${ST}?prefix=${encodeURIComponent(`avatars/${uidA}/`)}&delimiter=%2F`, { token: B, style: 'firebase' });
    await call('storage: prefix without trailing slash (400)', 'GET', `${ST}?prefix=${encodeURIComponent(`avatars/${uidA}`)}&delimiter=%2F`, { token: B, style: 'firebase' });
    await call('storage: B list avatars/ delimiter=/', 'GET', `${ST}?prefix=avatars%2F&delimiter=%2F`, { token: B, style: 'firebase' });
    await call('storage: B list private/A/ delimiter=/ (denied)', 'GET', `${ST}?prefix=${encodeURIComponent(`private/${uidA}/`)}&delimiter=%2F`, { token: B, style: 'firebase' });
    await call('storage: A list private/A/ delimiter=/ (owner, allowed)', 'GET', `${ST}?prefix=${encodeURIComponent(`private/${uidA}/`)}&delimiter=%2F`, { token: A, style: 'firebase' });
    await call('storage: B download A avatar with Bearer header', 'GET', obj(avA, '?alt=media'), { token: B, style: 'bearer' });
    await call('storage: A private with "Bearer owner" (emulator admin bypass)', 'GET', obj(`private/${uidA}/doc.txt`, '?alt=media'), { token: 'owner', style: 'bearer' });
    await call('storage: no-auth list root', 'GET', `${ST}?prefix=`);
    await call('storage: A download MISSING own private file', 'GET', obj(`private/${uidA}/missing.txt`, '?alt=media'), { token: A, style: 'firebase' });
    await call('storage: A DELETE MISSING own private file', 'DELETE', obj(`private/${uidA}/missing.txt`), { token: A, style: 'firebase' });
    await call('storage: B DELETE MISSING file in A private (denied or 404?)', 'DELETE', obj(`private/${uidA}/missing.txt`), { token: B, style: 'firebase' });
    await call('storage: A DELETE own avatar', 'DELETE', obj(avA), { token: A, style: 'firebase' });
    await call('storage: other bucket name *.firebasestorage.app', 'GET', `${H.storage}/v0/b/${H.projectId}.firebasestorage.app/o?prefix=`, { token: A, style: 'firebase' });
    await call('storage: A upload own avatar into random bucket (auto-created)', 'POST', `${H.storage}/v0/b/some-other-bucket/o?name=${encodeURIComponent(avA)}`, { token: A, style: 'firebase', raw: 'x', headers: { 'Content-Type': 'image/png' } });
    await call('storage: A download from *.firebasestorage.app bucket (separate, empty)', 'GET', `${H.storage}/v0/b/${H.projectId}.firebasestorage.app/o/${encodeURIComponent(`private/${uidA}/doc.txt`)}?alt=media`, { token: A, style: 'firebase' });
    await call('storage: garbage token download avatar', 'GET', obj(`private/${uidA}/doc.txt`, '?alt=media'), { token: 'garbage', style: 'firebase' });

    // ------------------------------------------------------------- AUTH delete
    console.log('\n=== AUTH delete ===');
    await call('accounts:delete B with own idToken (no admin)', 'POST', `${AUTH}/accounts:delete?key=any`, { body: { idToken: B } });
    await call('signIn B after delete', 'POST', `${AUTH}/accounts:signInWithPassword?key=any`, { body: { email: emailB, password: pw, returnSecureToken: true } });
    await call('Firestore: deleted B old token still reads orders?', 'GET', `${FS}/orders/${ordA}`, { token: B });
    await call('accounts:delete B again (already deleted)', 'POST', `${AUTH}/accounts:delete?key=any`, { body: { idToken: B } });
    await call('accounts:delete anon with own idToken', 'POST', `${AUTH}/accounts:delete?key=any`, { body: { idToken: ANON } });
    await call('accounts:delete A with garbage token', 'POST', `${AUTH}/accounts:delete?key=any`, { body: { idToken: 'garbage' } });
    void uidAnon;
  } finally {
    if (jsonOut) writeFileSync(jsonOut, JSON.stringify(results, null, 2));
    if (emu) await emu.stop();
  }
}

main().catch((e) => { console.error(e); process.exit(1); });
