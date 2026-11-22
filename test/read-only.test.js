import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, ANON_KEY } from './mock-supabase.js';
import { scan } from '../src/core/scan.js';
import { readOnlyBlock } from '../src/core/read-only.js';

let server;
let base;
let result;
const requests = [];

async function signUp(email) {
  const r = await fetch(`${base}/auth/v1/signup`, {
    method: 'POST',
    headers: { apikey: ANON_KEY, 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password: 'Pw-123456789' }),
  });
  assert.ok(r.ok, `sign-up ${email}`);
  return `${email}:Pw-123456789`;
}

before(async () => {
  server = createServer();
  await new Promise((r) => server.listen(0, r));
  base = `http://localhost:${server.address().port}`;
  const userA = await signUp('ro-a@example.com');
  const userB = await signUp('ro-b@example.com');
  server.on('request', (req) => requests.push(`${req.method} ${req.url}`));
  result = await scan({ url: base, anonKey: ANON_KEY, userA, userB, readOnly: true, quiet: true });
});
after(() => server.close());

test('read-only: only reads and sign-ins reach the server', () => {
  assert.ok(requests.length > 5);
  const writes = requests.filter((r) => !/^GET /.test(r) && !/^POST \/auth\/v1\/token\?grant_type=password$/.test(r) && !/^POST \/storage\/v1\/object\/list\//.test(r));
  assert.deepEqual(writes, []);
});

test('read-only: skipped writes are never reported as passed', () => {
  const claims = result.passed.filter((p) => /cannot (insert|update|change|delete|create|upload|take)|can't insert/i.test(p));
  assert.deepEqual(claims, []);
});

test('read-only: data that is already readable is still reported', () => {
  assert.ok(result.findings.some((f) => f.table === 'products' && f.id === 'anon-read-public'));
});

test('read-only: the report says coverage is partial', () => {
  assert.match(result.notes[0], /^Read-only run: nothing was written/);
  assert.equal(result.stats.fullyTested, 0);
});

test('readOnlyBlock lets reads and sign-ins through, stops everything else', () => {
  assert.equal(readOnlyBlock('GET', '/rest/v1/notes?select=*'), null);
  assert.equal(readOnlyBlock('POST', '/auth/v1/token?grant_type=password'), null);
  assert.equal(readOnlyBlock('POST', '/v1/projects/p/databases/(default)/documents:runQuery'), null);
  assert.equal(readOnlyBlock('POST', '/v1/accounts:signInWithPassword?key=x'), null);
  assert.equal(readOnlyBlock('POST', '/api/collections/users/auth-with-password'), null);
  assert.equal(readOnlyBlock('POST', '/v1/account/sessions/email'), null);
  for (const [m, u] of [
    ['POST', '/auth/v1/signup'],
    ['POST', '/rest/v1/notes'],
    ['PATCH', '/rest/v1/notes?id=eq.1'],
    ['DELETE', '/rest/v1/notes?id=eq.1'],
    ['POST', '/rest/v1/rpc/delete_my_account'],
    ['POST', '/storage/v1/object/avatars/a.txt'],
    ['POST', '/v1/accounts:signUp?key=x'],
    ['POST', '/v1/projects/p/databases/(default)/documents/notes?documentId=x'],
    ['PUT', '/notes/a.json?auth=t'],
    ['POST', '/api/collections/users/records'],
    ['POST', '/v1/account'],
    ['PATCH', '/v1/account/status'],
  ]) {
    assert.ok(readOnlyBlock(m, u), `${m} ${u} must be blocked`);
  }
});
