// End-to-end against the real Firebase rules engine (Emulator Suite).
// Skipped cleanly when Java / the emulator are unavailable (RLSPROBE_SKIP_FIREBASE=1 to force).
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { available, startEmulators, PROJECT_ID } from './firebase/emulator.js';
import { scan } from '../src/core/scan.js';
import { grade, markdownReport } from '../src/core/report.js';

const SOURCE = fileURLToPath(new URL('./firebase/', import.meta.url));
let emu = null;
let result = null;
let skipReason = available() ? null : 'Java/npx not available';

before(async () => {
  if (skipReason) return;
  try {
    emu = await startEmulators({ timeoutMs: 240000 });
  } catch (e) {
    skipReason = `emulator did not start: ${e.message.split('\n')[0]}`;
    return;
  }
  result = await scan({ platform: 'firebase', projectId: PROJECT_ID, apiKey: 'fake-api-key', source: SOURCE, emulator: true, quiet: true });
}, { timeout: 300000 });

after(async () => {
  if (emu) await emu.stop();
});

const t = (name, fn) =>
  test(name, (ctx) => {
    if (skipReason) return ctx.skip(skipReason);
    fn();
  });
const has = (id, res) => result.findings.some((f) => f.id === id && (!res || f.resource === res));
const on = (res) => result.findings.filter((f) => f.resource === res);
const passedFor = (res) => result.passed.filter((p) => p.startsWith(`${res}: `));

t('profiles: "read: if request.auth != null" is proven as a cross-user read + list', () => {
  assert.ok(has('cross-user-read', 'profiles'));
  assert.ok(has('cross-user-list', 'profiles'));
  assert.ok(passedFor('profiles').includes('profiles: B cannot modify A\'s documents'));
  assert.ok(passedFor('profiles').includes('profiles: B cannot create documents as A'));
});

t('orders: leak + forgery found, owner-only update/delete pass', () => {
  assert.ok(has('cross-user-read', 'orders'));
  assert.ok(has('impersonated-create', 'orders'));
  assert.ok(!has('cross-user-update', 'orders'));
  assert.ok(!has('cross-user-delete', 'orders'));
});

t('notes: correct rules → no findings, every attack refused', () => {
  assert.deepEqual(on('notes'), []);
  for (const p of ['read', 'list', 'modify', 'create', 'delete'])
    assert.ok(passedFor('notes').some((x) => x.includes(`cannot ${p}`)), `notes: ${p} not proven`);
});

t('public_posts: "read: if true" is reported as public by design, not as a leak', () => {
  assert.deepEqual(on('public_posts').map((f) => f.id), ['public-by-rule']);
});

t('logs: wide open → anonymous create+delete and cross-user changes are critical', () => {
  assert.ok(has('anon-write', 'logs'));
  assert.ok(has('cross-user-update', 'logs'));
  assert.ok(has('cross-user-delete', 'logs'));
});

t('users/{uid}/private and strict (validator) are fully tested and pass', () => {
  assert.deepEqual(on('users/{uid}/private'), []);
  assert.deepEqual(on('strict'), []);
  assert.ok(passedFor('strict').includes('strict: B cannot create documents as A'), 'validator-shaped payload was used');
  assert.ok(!result.notes.some((n) => n.startsWith('strict:')), result.notes.join('\n'));
});

t('Realtime Database: users/$uid leak and the open node are proven', () => {
  assert.ok(has('rtdb-cross-user-read', 'users/$uid'));
  assert.ok(!has('rtdb-cross-user-write', 'users/$uid'));
  assert.ok(has('rtdb-anon-write', 'open'));
  assert.ok(result.passed.includes('Realtime Database: anonymous visitors cannot read the root'));
});

t('Storage: avatars leak (download + list), private folder passes', () => {
  assert.ok(has('storage-cross-user-read', 'avatars/{uid}'));
  assert.ok(has('storage-cross-user-list', 'avatars/{uid}'), 'list must use delimiter=/ like the SDK');
  assert.deepEqual(on('private/{uid}'), []);
  assert.ok(result.passed.includes('Storage private/{uid}: B cannot download A\'s files'));
});

t('no test data or users are left behind; report renders rules fixes', () => {
  assert.ok(!result.notes.some((n) => /Could not delete/.test(n)), result.notes.join('\n'));
  assert.equal(grade(result.findings, result.stats), 'F');
  const md = markdownReport(result);
  assert.match(md, /Fix \(Security Rules/);
  assert.match(md, /request\.resource\.data\.userId == request\.auth\.uid/);
});
