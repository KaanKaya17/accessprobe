// End-to-end against a real PocketBase binary (pinned release, downloaded once into a cache).
// Skipped cleanly when it cannot be downloaded or started (ACCESSPROBE_SKIP_POCKETBASE=1 to force).
// The superuser created by the harness is used ONLY here, to check what accessprobe left
// behind; accessprobe itself runs exactly like the app's users would, without it.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { available, startPocketBase, APP_DIR, POCKETBASE_VERSION } from './pocketbase/server.js';
import { scan } from '../src/core/scan.js';
import { grade, markdownReport } from '../src/core/report.js';
import * as pocketbase from '../src/providers/pocketbase/index.js';

let pb = null;
let result = null;
let detected = null;
let codeOnly = null;
let skipReason = available() ? null : process.env.ACCESSPROBE_SKIP_POCKETBASE === '1' ? 'ACCESSPROBE_SKIP_POCKETBASE=1' : `no PocketBase ${POCKETBASE_VERSION} build for this OS/arch`;

const FIXTURE = ['notes', 'messages', 'orders', 'claims', 'posts', 'admin_reports', 'premium_videos', 'users'];

before(async () => {
  if (skipReason) return;
  try {
    pb = await startPocketBase({ timeoutMs: 60000 });
  } catch (e) {
    skipReason = `PocketBase could not be downloaded or started: ${e.message.split('\n')[0]}`;
    return;
  }
  detected = await pocketbase.detect({ url: pb.url }, { site: null });
  result = await scan({ url: pb.url, source: APP_DIR, quiet: true });
  // no migrations: only collection names from code (and --table), fields guessed from answers
  codeOnly = await scan({ platform: 'pocketbase', url: pb.url, tables: ['orders', 'claims'], quiet: true });
}, { timeout: 240000 });

after(async () => {
  if (pb) await pb.stop();
});

const t = (name, fn) =>
  test(name, async (ctx) => {
    if (skipReason) return ctx.skip(skipReason);
    await fn();
  });
const has = (id, res, r = result) => r.findings.some((f) => f.id === id && (!res || f.resource === res));
const on = (res, r = result) => r.findings.filter((f) => f.resource === res);
const passedFor = (res, r = result) => r.passed.filter((p) => p.startsWith(`${res}: `));

t('--url alone is detected as PocketBase (health endpoint), and only PocketBase is tested', () => {
  assert.equal(detected, true);
  assert.deepEqual(result.platforms.map((p) => p.id), ['pocketbase']);
});

t('notes: correct owner-only rules → zero findings, every attack listed under passed', () => {
  assert.deepEqual(on('notes'), []);
  for (const p of [
    "notes: B cannot read A's records",
    "notes: B cannot list A's records",
    "notes: anonymous visitors cannot read A's records",
    "notes: anonymous visitors cannot list A's records",
    "notes: B cannot modify A's records",
    "notes: B cannot reassign A's records to itself",
    'notes: B cannot create records as A',
    'notes: anonymous visitors cannot create records',
    "notes: B cannot delete A's records",
  ])
    assert.ok(passedFor('notes').includes(p), `missing PASS "${p}"\n${passedFor('notes').join('\n')}`);
  assert.ok(!result.notes.some((n) => n.startsWith('notes:')), result.notes.join('\n'));
});

t('messages: listRule @request.auth.id != "" is a proven cross-user list; view stays owner-only', () => {
  const f = result.findings.find((x) => x.id === 'cross-user-list' && x.resource === 'messages');
  assert.ok(f && f.severity === 'critical', JSON.stringify(on('messages')));
  assert.match(f.fix.code, /List\/Search rule:\s+user = @request\.auth\.id/);
  assert.ok(passedFor('messages').includes("messages: B cannot read A's records"), 'a 404 + control read proves the view rule');
  assert.ok(!has('cross-user-read', 'messages'));
});

t('orders: createRule without an owner check is a proven forgery', () => {
  const f = result.findings.find((x) => x.id === 'impersonated-create' && x.resource === 'orders');
  assert.ok(f && f.severity === 'critical', JSON.stringify(on('orders')));
  assert.match(f.fix.code, /@request\.auth\.id != "" && @request\.body\.user = @request\.auth\.id/);
  assert.deepEqual(on('orders').map((x) => x.id), ['impersonated-create']);
});

t('claims: updateRule that only checks the NEW owner is a proven takeover', () => {
  const f = result.findings.find((x) => x.id === 'cross-user-takeover' && x.resource === 'claims');
  assert.ok(f && f.severity === 'critical', JSON.stringify(on('claims')));
  assert.match(f.fix.code, /user = @request\.auth\.id && \(@request\.body\.user:isset = false \|\| @request\.body\.user = @request\.auth\.id\)/);
  assert.ok(passedFor('claims').includes("claims: B cannot modify A's records"), 'changing the text without the owner is refused');
});

t('posts: listRule/viewRule "" is reported as public by design, not as a leak', () => {
  assert.deepEqual(on('posts').map((f) => [f.id, f.severity]), [['public-by-rule', 'info']]);
  assert.ok(passedFor('posts').includes("posts: B cannot modify A's records"));
  assert.ok(passedFor('posts').includes('posts: B cannot create records as A'));
});

t('read-only collections: superusers-only create is a PASS, nothing is claimed about empty lists', () => {
  assert.ok(result.passed.includes('admin_reports: users cannot create records (create rule is superusers-only)'));
  assert.deepEqual(on('admin_reports'), []);
  assert.ok(result.notes.some((n) => n.startsWith('admin_reports: a new user may list this collection but saw no records')));
});

t('users: role is user-editable and trusted by a rule → critical; plan is protected → PASS', () => {
  const f = result.findings.find((x) => x.id === 'self-escalation' && x.resource === 'users');
  assert.ok(f && f.severity === 'critical', JSON.stringify(on('users')));
  assert.match(f.title, /set role on their own "users" record/);
  assert.match(f.detail, /role = "admin"/);
  assert.match(f.detail, /admin_reports\.listRule/);
  assert.match(f.detail, /old value was put back/);
  assert.match(f.fix.code, /@request\.body\.role:isset = false/);
  assert.ok(!f.title.includes('plan'));
  assert.ok(passedFor('users').includes('users: users cannot change their own plan'), passedFor('users').join('\n'));
  assert.deepEqual(on('users').map((x) => x.id), ['self-escalation']);
  for (const p of ["users: B cannot read A's user record", 'users: B cannot list other users', "users: B cannot modify A's user record", "users: B cannot delete A's account"])
    assert.ok(passedFor('users').includes(p), `missing PASS "${p}"`);
});

t('findings are proven requests; no user ids or record contents in the evidence', () => {
  for (const f of result.findings) {
    assert.match(f.evidence, /→ 20\d/, `${f.id}: ${f.evidence}`);
    assert.doesNotMatch(f.evidence, /accessprobe-\w{6}(?!-)/, 'no marker values in the evidence');
  }
  assert.equal(grade(result.findings, result.stats), 'F');
  assert.equal(result.stats.resources, FIXTURE.length);
  assert.equal(result.stats.fullyTested + result.stats.readOnly, FIXTURE.length);
  const md = markdownReport(result);
  assert.match(md, /Fix \(PocketBase API rules/);
  assert.match(md, /app\.findCollectionByNameOrId\('orders'\)/);
});

t('cleanup: no test records and no test users are left behind (checked as superuser)', async () => {
  assert.ok(!result.notes.some((n) => /Could not delete/.test(n)), result.notes.join('\n'));
  for (const c of FIXTURE) {
    const r = await pb.admin('GET', `/api/collections/${c}/records?perPage=1`);
    assert.equal(r.status, 200, `${c}: ${JSON.stringify(r.data)}`);
    assert.equal(r.data.totalItems, 0, `${c}: ${r.data.totalItems} record(s) left`);
  }
});

t('no pb_migrations: collections from --table are still attacked, fields guessed from the answers', () => {
  assert.ok(codeOnly.notes.some((n) => /No pb_migrations found/.test(n)), codeOnly.notes.join('\n'));
  assert.ok(has('impersonated-create', 'orders', codeOnly), JSON.stringify(codeOnly.findings.map((f) => [f.resource, f.id])));
  assert.ok(has('cross-user-takeover', 'claims', codeOnly));
  assert.ok(passedFor('orders', codeOnly).includes("orders: B cannot read A's records"));
  assert.ok(!codeOnly.notes.some((n) => /Could not delete/.test(n)), codeOnly.notes.join('\n'));
});

t('--user-a/--user-b: existing test users are used and never deleted', async () => {
  const pw = 'Existing-Passw0rd-1';
  const emails = ['existing-a@example.com', 'existing-b@example.com'];
  const ids = [];
  for (const email of emails) {
    const r = await pb.admin('POST', '/api/collections/users/records', { email, password: pw, passwordConfirm: pw });
    assert.ok(r.ok, JSON.stringify(r.data));
    ids.push(r.data.id);
  }
  try {
    const r = await scan({ url: pb.url, source: APP_DIR, only: ['notes'], userA: `${emails[0]}:${pw}`, userB: `${emails[1]}:${pw}`, quiet: true });
    assert.deepEqual(r.findings, []);
    assert.ok(r.passed.includes("notes: B cannot delete A's records"));
    const left = await pb.admin('GET', '/api/collections/users/records?perPage=1');
    assert.equal(left.data.totalItems, 2, 'the given users still exist');
    assert.equal((await pb.admin('GET', '/api/collections/notes/records?perPage=1')).data.totalItems, 0);
  } finally {
    for (const id of ids) await pb.admin('DELETE', `/api/collections/users/records/${id}`);
  }
});
