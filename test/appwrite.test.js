// Appwrite adapter end-to-end against the faithful mock server (test/mock-appwrite.js), whose
// collections, buckets and permissions come from the fixture app's appwrite.json.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, FIXTURE_DIR, PROJECT_ID } from './mock-appwrite.js';
import { scan } from '../src/core/scan.js';
import { grade, markdownReport } from '../src/core/report.js';
import { recordRequests, assertReadOnly } from './read-only-helper.js';

let server;
let url;
let result;
let codeOnly;

before(async () => {
  server = createServer();
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  url = `http://127.0.0.1:${server.address().port}/v1`;
  result = await scan({ url, projectId: PROJECT_ID, source: FIXTURE_DIR, quiet: true });
  // no appwrite.json: ids from --table only, attributes guessed from the answers
  codeOnly = await scan({ platform: 'appwrite', url, projectId: PROJECT_ID, tables: ['main/shared_docs', 'main/guestbook', 'main/tasks'], quiet: true });
});
after(() => server.close());

const on = (res, r = result) => r.findings.filter((f) => f.resource === res);
const ids = (res, r = result) => on(res, r).map((f) => f.id).sort();
const passedFor = (res, r = result) => r.passed.filter((p) => p.startsWith(`${res}: `));

test('--url + --project-id: only Appwrite is tested (not Firebase, not Supabase)', () => {
  assert.deepEqual(result.platforms.map((p) => p.id), ['appwrite']);
  assert.equal(result.platforms[0].stats.resources, 9);
});

test('notes: document security on + create("users") only → zero findings, every attack passes', () => {
  assert.deepEqual(on('notes'), []);
  for (const p of [
    "notes: B cannot read A's documents",
    "notes: B cannot list A's documents",
    "notes: anonymous visitors cannot read A's documents",
    "notes: anonymous visitors cannot list A's documents",
    "notes: B cannot modify A's documents",
    'notes: anonymous visitors cannot create documents',
    "notes: B cannot delete A's documents",
    "notes: B cannot change the permissions of A's documents",
  ])
    assert.ok(passedFor('notes').includes(p), `missing PASS "${p}"\n${passedFor('notes').join('\n')}`);
  assert.ok(!result.notes.some((n) => n.startsWith('notes:')), result.notes.join('\n'));
});

test('profiles: collection-level read("any") on private data is a proven read and list leak', () => {
  assert.deepEqual(ids('profiles'), ['anon-list', 'anon-read', 'cross-user-list', 'cross-user-read']);
  const f = on('profiles').find((x) => x.id === 'anon-read');
  assert.equal(f.severity, 'critical');
  assert.match(f.detail, /appwrite\.json grants read\("any"\) at collection level/);
  assert.match(f.detail, /read\("user:<user A id>"\)/, 'what Appwrite assigned to A\'s document is recorded');
  assert.match(f.fix.code, /Document security:\s+ON/);
  assert.match(f.fix.code, /"\$permissions": \["create\(\\"users\\"\)"\]/);
  assert.match(f.fix.code, /Permission\.read\(Role\.user\(user\.\$id\)\)/);
  assert.match(f.fix.code, /databases\.createDocument\('main', 'profiles', ID\.unique\(\), data, perms\)/);
  assert.ok(passedFor('profiles').includes("profiles: B cannot modify A's documents"));
});

test('tasks: collection-level update("users") → B modifies A\'s document and rewrites its permissions', () => {
  assert.deepEqual(ids('tasks'), ['cross-user-takeover', 'cross-user-update']);
  for (const f of on('tasks')) assert.equal(f.severity, 'critical');
  assert.match(on('tasks')[0].detail, /update\("users"\) at collection level/);
  assert.ok(passedFor('tasks').includes("tasks: B cannot read A's documents"), 'a 404 + control read proves the read side');
  assert.ok(passedFor('tasks').includes("tasks: B cannot delete A's documents"));
});

test('guestbook: create("any") → anonymous insert is reported (warning: not a leak of A\'s data)', () => {
  const f = on('guestbook');
  assert.deepEqual(f.map((x) => [x.id, x.severity]), [['anon-create', 'warning']]);
  assert.match(f[0].fix.code, /create\("any"\) lets visitors/);
  assert.equal(server.state.containers.get('documents:main/guestbook').docs.size, 0, 'the anonymous document was removed again');
});

test('shared_docs: document security off + users permissions → B reads, lists, changes and deletes', () => {
  assert.deepEqual(ids('shared_docs'), ['cross-user-delete', 'cross-user-list', 'cross-user-read', 'cross-user-takeover', 'cross-user-update']);
  assert.match(on('shared_docs')[0].fix.code, /now: create\("users"\), read\("users"\), update\("users"\), delete\("users"\); document security off/);
  assert.ok(passedFor('shared_docs').includes("shared_docs: anonymous visitors cannot read A's documents"));
});

test('admin_reports: no create permission for users is a PASS, an empty list proves nothing', () => {
  assert.ok(result.passed.includes('admin_reports: users cannot create documents (no create permission for users)'));
  assert.deepEqual(on('admin_reports'), []);
  assert.ok(result.notes.some((n) => n.startsWith('admin_reports: a new user may list this collection but saw no documents')));
});

test('todos (TablesDB rows API, row security on) passes through /v1/tablesdb', () => {
  assert.deepEqual(on('todos'), []);
  assert.ok(passedFor('todos').includes("todos: B cannot read A's rows"));
  assert.ok(passedFor('todos').includes("todos: B cannot delete A's rows"));
  assert.ok(server.state.requests.some((r) => r.path.startsWith('/v1/tablesdb/main/tables/todos/rows')));
});

test('buckets: avatars (file security, create("users")) passes; uploads (read("any")) leaks', () => {
  assert.deepEqual(on('bucket avatars'), []);
  assert.ok(passedFor('bucket avatars').includes("bucket avatars: B cannot download A's files"));
  assert.ok(passedFor('bucket avatars').includes("bucket avatars: B cannot delete A's files"));
  assert.deepEqual(ids('bucket uploads'), ['storage-anon-read', 'storage-cross-user-list', 'storage-cross-user-read']);
  assert.match(on('bucket uploads')[0].fix.code, /File security:\s+ON/);
});

test('findings are proven requests; no user ids or marker values in the evidence; report renders', () => {
  const userIds = [...server.state.users.keys()];
  for (const f of result.findings) {
    assert.match(f.evidence, /→ 20\d/, `${f.id}: ${f.evidence}`);
    assert.doesNotMatch(f.evidence, /accessprobe-\w{6}/, 'no marker values in the evidence');
    for (const id of userIds) assert.ok(!f.evidence.includes(id) && !f.detail.includes(id), `user id in ${f.id}`);
  }
  assert.equal(grade(result.findings, result.stats), 'F');
  assert.equal(result.stats.fullyTested + result.stats.readOnly, 9);
  const md = markdownReport(result);
  assert.match(md, /Fix \(Appwrite permissions/);
});

test('only the project header and the session cookie are sent — never an API key', () => {
  assert.ok(server.state.requests.length > 50);
  for (const r of server.state.requests) {
    assert.equal(r.headers['x-appwrite-key'], undefined);
    // real Appwrite refuses an unregistered Origin with 403 general_unknown_origin: never send one
    assert.equal(r.headers.origin, undefined);
    // (other adapters' detection probes, e.g. PocketBase's <url>/api/health, carry no Appwrite headers)
    if (r.path.startsWith('/v1/') && !/health/.test(r.path)) assert.equal(r.headers['x-appwrite-project'], PROJECT_ID, r.path);
  }
  assert.ok(server.state.requests.some((r) => r.headers.cookie && !r.headers['x-appwrite-jwt']), 'users talk through their session cookie');
});

test('cleanup: no test documents or files are left; the two test users are kept and reused', () => {
  for (const [k, c] of server.state.containers) assert.equal(c.docs.size, 0, `${k}: ${c.docs.size} document(s) left`);
  for (const [k, b] of server.state.buckets) assert.equal(b.files.size, 0, `bucket ${k}: ${b.files.size} file(s) left`);
  assert.ok(!result.notes.some((n) => /Could not/.test(n)), result.notes.join('\n'));
  const kept = result.notes.find((n) => n.startsWith('Test users kept for the next run'));
  assert.ok(kept, result.notes.join('\n'));
  assert.ok(codeOnly.notes.some((n) => n.startsWith('Reused the test users')), codeOnly.notes.join('\n'));
  const created = [...server.state.users.values()];
  assert.equal(created.length, 2, 'the second run created no new accounts');
  assert.ok(created.every((u) => u.status !== false && kept.includes(u.email)));
});

test('--fresh-users: new test users block themselves and are listed for deletion', async () => {
  const before = new Set(server.state.users.keys());
  const r = await scan({ url, projectId: PROJECT_ID, source: FIXTURE_DIR, only: ['notes'], freshUsers: true, quiet: true });
  const fresh = [...server.state.users.entries()].filter(([k]) => !before.has(k)).map(([, u]) => u);
  assert.equal(fresh.length, 2);
  assert.ok(fresh.every((u) => u.status === false), 'fresh test users are blocked');
  assert.ok(fresh.every((u) => r.notes.some((n) => n.includes('blocked themselves') && n.includes(u.email))));
});

test('no appwrite.json: --table db/collection is still attacked, attributes guessed from the answers', () => {
  assert.ok(codeOnly.notes.some((n) => /No appwrite\.json found/.test(n)), codeOnly.notes.join('\n'));
  assert.deepEqual(ids('shared_docs', codeOnly), ['cross-user-delete', 'cross-user-list', 'cross-user-read', 'cross-user-takeover', 'cross-user-update']);
  assert.match(on('shared_docs', codeOnly).find((f) => f.id === 'cross-user-update').detail, /typically update\("users"\) or update\("any"\)/);
  // guestbook: "message" is required — learned from the "Missing required attribute" answer
  assert.deepEqual(ids('guestbook', codeOnly), ['anon-create']);
  assert.ok(passedFor('guestbook', codeOnly).includes("guestbook: B cannot read A's documents"));
  // tasks: a required enum cannot be guessed → noted as not tested, never passed
  assert.deepEqual(passedFor('tasks', codeOnly), []);
  assert.ok(codeOnly.notes.some((n) => n.startsWith('tasks: write tests skipped')), codeOnly.notes.join('\n'));
});

test('a missing required attribute without a schema is a note, never a pass', async () => {
  const r = await scan({ platform: 'appwrite', url, projectId: PROJECT_ID, tables: ['main/profiles', 'main/nope'], quiet: true });
  assert.deepEqual(r.findings, []);
  assert.deepEqual(r.passed.filter((p) => p.startsWith('profiles')), []);
  assert.ok(r.notes.some((n) => /^profiles: write tests skipped — Appwrite refused user A's document \(schema\)/.test(n)), r.notes.join('\n'));
  assert.ok(r.notes.some((n) => /^nope: no such database or collection/.test(n)), r.notes.join('\n'));
});

test('--user-a/--user-b: existing users are used, signed out, and never blocked', async () => {
  const before = server.state.users.size;
  const pw = 'Existing-Passw0rd-1';
  for (const email of ['existing-a@example.com', 'existing-b@example.com']) {
    const res = await fetch(`${url}/account`, { method: 'POST', headers: { 'X-Appwrite-Project': PROJECT_ID, 'Content-Type': 'application/json' }, body: JSON.stringify({ userId: 'unique()', email, password: pw }) });
    assert.equal(res.status, 201);
  }
  const r = await scan({ url, projectId: PROJECT_ID, source: FIXTURE_DIR, only: ['notes'], userA: `existing-a@example.com:${pw}`, userB: `existing-b@example.com:${pw}`, quiet: true });
  assert.deepEqual(r.findings, []);
  assert.ok(r.passed.includes("notes: B cannot delete A's documents"));
  assert.equal(server.state.users.size, before + 2, 'no new users');
  const existing = [...server.state.users.values()].filter((u) => u.email.startsWith('existing-'));
  assert.ok(existing.every((u) => u.status === true), 'existing users are not blocked');
  assert.ok(!r.notes.some((n) => n.includes('blocked')));
});

test('closed sign-up: a clear error that asks for --user-a / --user-b', async () => {
  const closed = createServer({ signupOpen: false });
  await new Promise((r) => closed.listen(0, '127.0.0.1', r));
  try {
    await assert.rejects(
      scan({ url: `http://127.0.0.1:${closed.address().port}/v1`, projectId: PROJECT_ID, source: FIXTURE_DIR, quiet: true }),
      /Sign-up of test user A failed \(501\)[\s\S]*--user-a email:password/,
    );
  } finally {
    closed.close();
  }
});

test('--read-only: only reads go out, and nothing is claimed for the skipped writes', async () => {
  const pw = 'Existing-Passw0rd-1';
  for (const email of ['ro-a@example.com', 'ro-b@example.com']) {
    const res = await fetch(`${url}/account`, { method: 'POST', headers: { 'X-Appwrite-Project': PROJECT_ID, 'Content-Type': 'application/json' }, body: JSON.stringify({ userId: 'unique()', email, password: pw }) });
    assert.equal(res.status, 201);
  }
  const before = server.state.users.size;
  const run = await recordRequests(() => scan({ url, projectId: PROJECT_ID, source: FIXTURE_DIR, userA: `ro-a@example.com:${pw}`, userB: `ro-b@example.com:${pw}`, readOnly: true, quiet: true }));
  assertReadOnly(run);
  assert.equal(server.state.users.size, before, 'no users created');
  assert.ok([...server.state.users.values()].every((u) => u.status !== false || !u.email.startsWith('ro-')), 'given users are not blocked');
});
