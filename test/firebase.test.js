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
let codeOnly = null;
const CODE_ONLY = fileURLToPath(new URL('./firebase-app-code/', import.meta.url));
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
  // same emulator, but an app folder with NO rules files: paths come from Java code only
  codeOnly = await scan({ platform: 'firebase', projectId: PROJECT_ID, apiKey: 'fake-api-key', source: CODE_ONLY, emulator: true, quiet: true });
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

t('Realtime Database: a node keyed by backup codes that any user can list is critical', () => {
  const f = result.findings.find((x) => x.id === 'rtdb-list' && x.resource === 'backups');
  assert.ok(f, 'backups listing not found');
  assert.equal(f.severity, 'critical');
  assert.ok(result.passed.includes('Realtime Database /backups/$code: anonymous visitors cannot write'));
});

t('no rules files: RTDB paths are taken from app code and tested for real', () => {
  assert.ok(codeOnly.notes.some((n) => /2 path\(s\) were taken from the app code/.test(n)), codeOnly.notes.join('\n'));
  assert.ok(codeOnly.findings.some((f) => f.id === 'rtdb-cross-user-read' && f.resource === 'users/$uid'));
  assert.ok(codeOnly.findings.some((f) => f.id === 'rtdb-list' && f.resource === 'backups' && f.severity === 'critical'));
  assert.ok(!codeOnly.notes.some((n) => /Could not delete/.test(n)), codeOnly.notes.join('\n'));
});

t('no test data or users are left behind; report renders rules fixes', () => {
  assert.ok(!result.notes.some((n) => /Could not delete/.test(n)), result.notes.join('\n'));
  assert.equal(grade(result.findings, result.stats), 'F');
  const md = markdownReport(result);
  assert.match(md, /Fix \(Security Rules/);
  assert.match(md, /request\.resource\.data\.userId == request\.auth\.uid/);
});
