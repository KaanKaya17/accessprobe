// The --rules-tests generator on hand-written recipes (no emulator needed). The emulator run in
// firebase.test.js and the firebase-rules-tests CI job run the generated file for real.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, mkdirSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { rulesTests, writeRulesTests } from '../src/providers/firebase/rules-tests.js';

const recipes = [
  {
    service: 'firestore',
    resource: 'profiles',
    collection: 'profiles',
    docId: '{A}',
    ownerField: null,
    markerField: 'accessprobe',
    payload: { accessprobe: '{marker}', createdAt: new Date('2026-01-01T00:00:00Z') },
    checks: [
      { check: 'read', ok: false },
      { check: 'anon-read', ok: true },
      { check: 'anon-auth-read', ok: false },
    ],
    projectId: 'demo-app',
  },
  {
    service: 'firestore',
    resource: 'orders',
    collection: 'orders',
    docId: 'accessprobe-abc123',
    ownerField: 'userId',
    markerField: 'accessprobe',
    payload: { userId: '{A}', accessprobe: '{marker}' },
    checks: [
      { check: 'forge', ok: false },
      { check: 'takeover', ok: true },
      { check: 'escalation', ok: true, field: 'role', value: 'admin' },
    ],
    projectId: 'demo-app',
  },
  { service: 'database', resource: '/', kind: 'root', checks: [{ check: 'anon-auth-read', ok: true }], projectId: 'demo-app' },
  {
    service: 'database',
    resource: 'users/$uid',
    kind: 'user',
    parent: 'users',
    path: 'users/{A}/{marker}',
    value: '{marker}',
    tampered: '{marker}-x',
    checks: [
      { check: 'list', ok: true },
      { check: 'read', ok: false },
      { check: 'anon-auth-read', ok: false },
    ],
    projectId: 'demo-app',
  },
  { service: 'database', resource: 'open', kind: 'shared', node: 'open', checks: [{ check: 'anon-auth-write', ok: false }], projectId: 'demo-app' },
  { service: 'storage', resource: 'avatars/{uid}', path: 'avatars/{A}/accessprobe.txt', checks: [{ check: 'anon-auth-read', ok: false }, { check: 'delete', ok: true }], projectId: 'demo-app' },
];

const tests = (code) => [...code.matchAll(/^test\((".*"), async \(\) => \{(.*)$/gm)].map((m) => ({ desc: JSON.parse(m[1]), failsNow: /FAILS until the fix/.test(m[2]) }));

test('rules tests: one test per verdict, leaks marked to fail, secure behaviour stated', () => {
  const code = rulesTests(recipes, { version: 't', target: 'firebase:demo-app' });
  const t = tests(code);
  assert.equal(t.length, 13);
  const find = (d) => t.find((x) => x.desc === d);
  assert.equal(find("profiles: B cannot read A's documents").failsNow, true);
  assert.equal(find("profiles: anonymous visitors cannot read A's documents").failsNow, false);
  assert.equal(find("profiles: anonymous-auth users cannot read A's documents").failsNow, true);
  assert.equal(find('orders: users cannot set their own role').failsNow, false);
  assert.equal(find('Realtime Database: anonymous-auth users cannot read the root').failsNow, false);
  assert.equal(find('Realtime Database /users: signed-in users cannot list all entries').failsNow, false);
  assert.equal(find('Realtime Database /open: anonymous-auth users cannot write').failsNow, true);
  assert.equal(find('Storage avatars/{uid}: anonymous-auth users cannot download').failsNow, true);
  // the four actors, the seed with rules disabled, and the owner control
  assert.match(code, /sign_in_provider: 'anonymous'/);
  assert.match(code, /withSecurityRulesDisabled/);
  assert.match(code, /control: the owner reads its document/);
  assert.match(code, /new Date\("2026-01-01T00:00:00.000Z"\)/);
  assert.match(code, /"orders\/accessprobe-t[0-9a-z]+-fake"/);
  assert.match(code, /\{ "userId": `\$\{A\}`/);
  assert.ok(!/\{A\}|\{marker\}|abc123/.test(code.replace(/\$\{A\}/g, '')), 'placeholders filled, run ids gone');
  assert.match(code, /const PROJECT_ID = process\.env\.GCLOUD_PROJECT \|\| "demo-app";/);
  assert.match(code, /npm i -D @firebase\/rules-unit-testing/);
  assert.match(code, /firebase emulators:exec --only firestore,database,storage "node --test /);
});

test('rules tests: nothing replayable means no file', () => {
  assert.equal(rulesTests([]), null);
  assert.equal(rulesTests([{ service: 'firestore', checks: [] }]), null);
});

test('rules tests: writeRulesTests writes valid ESM that finds the project relative to itself', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'ap-rt-'));
  try {
    mkdirSync(join(dir, 'app'));
    writeFileSync(join(dir, 'app', 'firestore.rules'), '');
    const file = join(dir, 'app', 'test', 'accessprobe.rules.test.mjs');
    const msg = await writeRulesTests(file, { rulesRecipes: recipes, target: 'x', date: '2026-11-22T00:00:00Z' }, { source: join(dir, 'app') });
    assert.match(msg, /13 tests, 7 of them fail until the leaks are fixed/);
    const code = readFileSync(file, 'utf8');
    assert.match(code, /const ROOT = new URL\("\.\.\/", import\.meta\.url\)/);
    const r = spawnSync(process.execPath, ['--check', file], { encoding: 'utf8' });
    assert.equal(r.status, 0, r.stderr);
    const none = await writeRulesTests(join(dir, 'x.mjs'), { rulesRecipes: [] }, {});
    assert.match(none, /No rules tests written/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
