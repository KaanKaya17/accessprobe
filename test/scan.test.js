import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, ANON_KEY } from './mock-supabase.js';
import { scan } from '../src/core/scan.js';
import { grade, markdownReport } from '../src/core/report.js';

let server;
let base;
let result;

before(async () => {
  server = createServer();
  await new Promise((r) => server.listen(0, r));
  base = `http://localhost:${server.address().port}`;
  result = await scan({ site: base, quiet: true });
});
after(() => server.close());

const has = (id, where) =>
  result.findings.some((f) => f.id === id && (!where || f.table === where || f.bucket === where));

test('discovers url + anon key from the site and flags the leaked service_role key', () => {
  assert.ok(has('leaked-service-role-key'));
});

test('profiles: authenticated-can-read-all is proven as cross-user read', () => {
  assert.ok(has('cross-user-read', 'profiles'));
});

test('orders: cross-user read + impersonated insert', () => {
  assert.ok(has('cross-user-read', 'orders'));
  assert.ok(has('impersonated-insert', 'orders'));
  assert.ok(!has('cross-user-update', 'orders'));
  assert.ok(!has('cross-user-delete', 'orders'));
});

test('notes: correct owner policies produce no findings', () => {
  assert.equal(result.findings.filter((f) => f.table === 'notes').length, 0);
  assert.ok(result.passed.some((p) => p.startsWith('notes: B cannot read')));
});

test('bigint owner ids via an app users table (FitLog style) are resolved', () => {
  // secure table: full write tests ran and passed
  assert.equal(result.findings.filter((f) => f.table === 'workouts').length, 0);
  assert.ok(result.passed.includes("workouts: B cannot read A's rows"));
  assert.ok(result.passed.includes('workouts: B cannot insert rows as A'));
  // buggy table: proven leak, and the evidence hides A's numeric id
  const leak = result.findings.find((f) => f.table === 'messages' && f.id === 'cross-user-read');
  assert.ok(leak);
  // fix SQL must compare against the app's id, not auth.uid() (bigint vs uuid would not even compile)
  assert.match(leak.fix.sql, /\(select "user_id" from public\."app_users" where "auth_id" = \(select auth\.uid\(\)\)\) = "user_id"/);
  assert.ok(result.passed.includes("app_users: B cannot see other users' rows"));
});

test('products: public catalog is only a warning', () => {
  const f = result.findings.filter((x) => x.table === 'products');
  assert.deepEqual(f.map((x) => x.severity), ['warning']);
});

test('api_logs: RLS disabled → anon create+delete critical, user tests not repeated', () => {
  assert.ok(has('anon-write', 'api_logs'));
  assert.equal(result.findings.filter((f) => f.table === 'api_logs').length, 1);
});

test('guestbook: intended anon insert is a warning and user tests still run', () => {
  const f = result.findings.filter((x) => x.table === 'guestbook');
  assert.ok(f.some((x) => x.id === 'anon-insert' && x.severity === 'warning'));
  assert.ok(!f.some((x) => x.severity === 'critical'));
  assert.ok(result.passed.includes("guestbook: B cannot delete A's rows"));
});

test('counters: no pk + no text column is skipped, never reported as passed', () => {
  assert.ok(!result.passed.some((p) => /^counters: B cannot (read|modify|delete|insert)/.test(p)));
  assert.ok(result.notes.some((n) => n.startsWith('counters:') && n.includes('targeted safely')));
});

test('public bucket is info, not a cross-user leak', () => {
  assert.ok(has('storage-public-bucket', 'public-assets'));
  assert.ok(!has('storage-cross-user-read', 'public-assets'));
});

test('an empty anonymous SELECT is never claimed as "anon cannot read"', () => {
  // guestbook is publicly readable but empty at scan time: must be caught via A's row
  assert.ok(has('anon-read-public', 'guestbook'));
  assert.ok(!result.passed.some((p) => p.startsWith('guestbook: anonymous visitors c')));
  // secure table: proven with A's row
  assert.ok(result.passed.includes("notes: anonymous visitors cannot read A's rows"));
});

test('storage: avatars leaks, documents is safe', () => {
  assert.ok(has('storage-anon-list', 'avatars'));
  assert.ok(has('storage-cross-user-read', 'avatars'));
  assert.ok(!result.findings.some((f) => f.bucket === 'documents'));
});

test('rpc functions are listed for review, never called', () => {
  assert.ok(has('rpc-review'));
});

test('cleanup removes all test rows except where nobody may delete (reported)', () => {
  const left = result.notes.find((n) => n.startsWith('Could not delete'));
  assert.ok(left, 'guestbook rows cannot be deleted by design and must be reported');
  assert.ok(!/(orders|notes|workouts|messages|profiles|api_logs) where/.test(left), left);
});

test('grade F and markdown report contains fix SQL + AI prompt', () => {
  assert.equal(grade(result.findings), 'F');
  const md = markdownReport(result);
  assert.match(md, /create policy "orders_insert_own"/);
  assert.match(md, /Prompt for Lovable/);
  assert.ok(!md.includes(ANON_KEY), 'report must not contain keys');
});

test('rejects a service_role key passed as anon key', async () => {
  const { SERVICE_KEY } = await import('./mock-supabase.js');
  await assert.rejects(scan({ url: base, anonKey: SERVICE_KEY, quiet: true }), /service_role/);
});
