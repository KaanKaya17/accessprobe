// End-to-end against the real Firebase rules engine (Emulator Suite).
// Skipped cleanly when Java / the emulator are unavailable (ACCESSPROBE_SKIP_FIREBASE=1 to force).
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { available, startEmulators, PROJECT_ID } from './firebase/emulator.js';
import { scan } from '../src/core/scan.js';
import { grade, markdownReport } from '../src/core/report.js';
import { recordRequests, assertReadOnly } from './read-only-helper.js';
import { rulesTests } from '../src/providers/firebase/rules-tests.js';

const SOURCE = fileURLToPath(new URL('./firebase/', import.meta.url));
let emu = null;
let result = null;
let codeOnly = null;
let codeAndRules = null;
let wrongProject = null;
let wrongNs = null;
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
  // existing app data (as in any real app): one backup written by some real user.
  // "Bearer owner" is the emulator's admin bypass — used only by this test setup, never by accessprobe.
  const seed = await fetch(`${emu.hosts.database}/backups/ABC123.json?ns=${emu.hosts.rtdbNamespace}`, {
    method: 'PUT',
    headers: { Authorization: 'Bearer owner', 'Content-Type': 'application/json' },
    body: JSON.stringify({ nickname: 'someone', stats: { total_games: 3 } }),
  });
  if (!seed.ok) throw new Error(`seeding failed: ${seed.status}`);
  const flag = await fetch(`${emu.hosts.database}/settings/maintenance.json?ns=${emu.hosts.rtdbNamespace}`, {
    method: 'PUT',
    headers: { Authorization: 'Bearer owner', 'Content-Type': 'application/json' },
    body: 'true',
  });
  if (!flag.ok) throw new Error(`seeding failed: ${flag.status}`);
  result = await scan({ platform: 'firebase', projectId: PROJECT_ID, apiKey: 'fake-api-key', source: SOURCE, emulator: true, quiet: true });
  // same emulator, but an app folder with NO rules files: paths come from Java code only
  codeOnly = await scan({ platform: 'firebase', projectId: PROJECT_ID, apiKey: 'fake-api-key', source: CODE_ONLY, emulator: true, quiet: true });
  // app code + rules exported from the console (the real-world setup that found the inbox gap)
  const RULES = fileURLToPath(new URL('./firebase/database.rules.json', import.meta.url));
  wrongProject = await scan({ platform: 'firebase', projectId: PROJECT_ID, apiKey: 'k', source: fileURLToPath(new URL('./firebase-wrong-project/', import.meta.url)), databaseRules: RULES, emulator: true, quiet: true });
  wrongNs = await scan({ platform: 'firebase', source: fileURLToPath(new URL('./firebase-wrong-ns/', import.meta.url)), databaseRules: RULES, emulator: true, quiet: true });
  codeAndRules = await scan({
    platform: 'firebase',
    projectId: PROJECT_ID,
    apiKey: 'fake-api-key',
    source: CODE_ONLY,
    databaseRules: fileURLToPath(new URL('./firebase/database.rules.json', import.meta.url)),
    emulator: true,
    quiet: true,
  });
}, { timeout: 300000 });

after(async () => {
  if (emu) await emu.stop();
});

const t = (name, fn) =>
  test(name, async (ctx) => {
    if (skipReason) return ctx.skip(skipReason);
    await fn();
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
  assert.match(f.title, /all 1 entry under/, 'counts the real entry, not accessprobe test data');
  assert.ok(result.passed.includes('Realtime Database /backups/$code: anonymous visitors cannot write'));
});

t('Firestore takeover: update rule that checks only the NEW owner is critical', () => {
  const f = result.findings.find((x) => x.id === 'cross-user-takeover' && x.resource === 'claims');
  assert.ok(f && f.severity === 'critical', JSON.stringify(on('claims').map((x) => x.id)));
  assert.ok(result.passed.includes("notes: B cannot reassign A's documents to itself"), 'correct rules pass the takeover test');
});

test('a writable node holding a plain value is never overwritten', async (ctx) => {
  if (skipReason) return ctx.skip(skipReason);
  const r = await fetch(`${emu.hosts.database}/settings/maintenance.json?ns=${emu.hosts.rtdbNamespace}`, { headers: { Authorization: 'Bearer owner' } });
  assert.equal(await r.json(), true);
  assert.ok(result.notes.some((n) => n.includes('/settings/maintenance: anonymous write not tested')), result.notes.join('\n'));
});

test('shared nodes get no accessprobe test entries (they might be create-only and impossible to clean up)', async (ctx) => {
  if (skipReason) return ctx.skip(skipReason);
  const r = await fetch(`${emu.hosts.database}/backups.json?ns=${emu.hosts.rtdbNamespace}&shallow=true`, {
    headers: { Authorization: 'Bearer owner' },
  });
  assert.deepEqual(Object.keys(await r.json()), ['ABC123']);
});

t('no rules files: RTDB paths are taken from app code and tested for real', () => {
  assert.ok(codeOnly.notes.some((n) => /3 path\(s\) were taken from the app code/.test(n)), codeOnly.notes.join('\n'));
  assert.ok(codeOnly.findings.some((f) => f.id === 'rtdb-cross-user-read' && f.resource === 'users/$uid'));
  assert.ok(codeOnly.findings.some((f) => f.id === 'rtdb-list' && f.resource === 'backups' && f.severity === 'critical'));
  assert.ok(!codeOnly.notes.some((n) => /Could not delete/.test(n)), codeOnly.notes.join('\n'));
});

t('rules .validate shape is used, so a schema-checked user node is fully tested', () => {
  assert.ok(!result.notes.some((n) => n.includes('/scores/$uid: user A could not write')), result.notes.join('\n'));
  assert.ok(result.passed.includes('Realtime Database /scores/$uid: B cannot write to A\'s data'));
  const leak = result.findings.find((f) => f.id === 'rtdb-cross-user-read' && f.resource === 'scores/$uid');
  assert.equal(leak?.severity, 'warning', 'score-like nodes are probably public on purpose');
});

t('rules without key level + code with it: the inbox structure from code is tested', () => {
  const inv = codeAndRules.findings.filter((f) => f.resource === 'invites/$targetUserId');
  assert.ok(inv.some((f) => f.id === 'rtdb-cross-user-read' && f.severity === 'critical'), JSON.stringify(inv.map((f) => f.id)));
  assert.ok(inv.some((f) => f.id === 'rtdb-cross-user-write' && f.severity === 'warning'), 'inbox overwrite is a warning');
  assert.ok(codeAndRules.notes.some((n) => /path\(s\) from the app code were added/.test(n)));
});

t('--project-id wins over a config file from another project (no wrong database)', () => {
  assert.ok(wrongProject.notes.some((n) => /differs from the config found \(some-other-project\)/.test(n)));
  assert.ok(!wrongProject.findings.some((f) => f.id === 'rtdb-anon-root'), 'must not hit a rule-less namespace');
  assert.ok(wrongProject.findings.some((f) => f.id === 'rtdb-cross-user-read' && f.resource === 'users/$uid'), 'tested the real (rules-enforcing) database');
});

t('rules lock the root but the root is readable → wrong database detected, RTDB results discarded', () => {
  assert.ok(wrongNs.notes.some((n) => /probably talking to a different database/.test(n)), wrongNs.notes.join('\n'));
  assert.ok(!wrongNs.findings.some((f) => f.id.startsWith('rtdb-')), 'no RTDB findings from the wrong database');
});

t('no test data or users are left behind; report renders rules fixes', () => {
  assert.ok(!result.notes.some((n) => /Could not delete/.test(n)), result.notes.join('\n'));
  assert.equal(grade(result.findings, result.stats), 'F');
  const md = markdownReport(result);
  assert.match(md, /Fix \(Security Rules/);
  assert.match(md, /request\.resource\.data\.userId == request\.auth\.uid/);
});

t('self-escalation: users may set the field the rules use for admin rights', () => {
  const f = result.findings.find((x) => x.resource === 'members' && x.id === 'self-escalation');
  assert.ok(f && f.severity === 'critical', JSON.stringify(on('members')));
  assert.match(f.detail, /role = "admin"/);
  assert.match(f.fix.code, /affectedKeys\(\)\.hasAny\(\['role'\]\)/);
});

t('self-escalation: a rule that protects the field is a PASS', () => {
  assert.ok(!on('staff').some((f) => f.id === 'self-escalation'), JSON.stringify(on('staff')));
  assert.ok(passedFor('staff').includes('staff: users cannot set their own isStaff'), passedFor('staff').join('\n'));
});

t('anonymous sign-in: "request.auth != null" on private data is proven with an anonymous-auth user', () => {
  const f = result.findings.find((x) => x.id === 'anon-auth-read' && x.resource === 'journal');
  assert.ok(f && f.severity === 'critical', JSON.stringify(on('journal').map((x) => x.id)));
  assert.match(f.detail, /Anonymous sign-in is enabled/);
  assert.match(f.fix.code, /sign_in_provider != 'anonymous'/);
  assert.match(f.fix.code, /disable it in Firebase console/);
  assert.ok(has('rtdb-anon-auth-read', 'users/$uid'));
  assert.ok(has('storage-anon-auth-read', 'avatars/{uid}'));
});

t('anonymous sign-in: rules that exclude anonymous users pass, and nothing is reported twice', () => {
  assert.ok(passedFor('team_wiki').includes('team_wiki: anonymous-auth users cannot read'), passedFor('team_wiki').join('\n'));
  assert.ok(!on('team_wiki').some((x) => x.id.startsWith('anon-auth')));
  assert.ok(result.passed.includes('Storage private/{uid}: anonymous-auth users cannot download'));
  // the unauthenticated visitor already proved these: no anonymous-auth finding on top
  assert.ok(!on('logs').some((x) => x.id.startsWith('anon-auth')));
  assert.ok(!on('public_posts').some((x) => x.id.startsWith('anon-auth')));
  assert.ok(!result.findings.some((x) => x.id.startsWith('rtdb-anon-auth') && x.resource === 'open'));
});

t('rules tests: every clear verdict becomes a test; proven leaks are marked to fail until fixed', () => {
  const code = rulesTests(result.rulesRecipes, { version: 't', target: 'x' });
  const tests = [...code.matchAll(/^test\((".*"), async \(\) => \{(.*)$/gm)].map((m) => ({ desc: JSON.parse(m[1]), failsNow: /FAILS until the fix/.test(m[2]) }));
  const find = (d) => tests.find((x) => x.desc === d);
  assert.equal(find("profiles: B cannot read A's documents")?.failsNow, true);
  assert.equal(find("journal: anonymous-auth users cannot read A's documents")?.failsNow, true);
  assert.equal(find("team_wiki: anonymous-auth users cannot read A's documents")?.failsNow, false);
  assert.equal(find("notes: B cannot read A's documents")?.failsNow, false);
  assert.equal(find('members: users cannot set their own role')?.failsNow, true);
  assert.equal(find("Storage private/{uid}: B cannot download A's files")?.failsNow, false);
  assert.equal(find("Realtime Database /users/$uid: B cannot read A's data")?.failsNow, true);
  assert.ok(!find("public_posts: B cannot read A's documents"), 'public by design: no verdict, no test');
  assert.ok(!/\{A\}|\{marker\}/.test(code.replace(/\$\{A\}/g, '')), 'placeholders are filled');
});

t('--read-only: only reads go out, and nothing is claimed for the skipped writes', async () => {
  const pw = 'Existing-Passw0rd-1';
  const creds = [];
  for (const email of ['ro-a@example.com', 'ro-b@example.com']) {
    const r = await fetch(`${emu.hosts.auth}/identitytoolkit.googleapis.com/v1/accounts:signUp?key=fake-api-key`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password: pw, returnSecureToken: true }),
    });
    assert.ok(r.ok, `sign-up ${email}: ${r.status}`);
    creds.push(`${email}:${pw}`);
  }
  const run = await recordRequests(() =>
    scan({ platform: 'firebase', projectId: PROJECT_ID, apiKey: 'fake-api-key', source: SOURCE, emulator: true, userA: creds[0], userB: creds[1], readOnly: true, quiet: true }),
  );
  assertReadOnly(run);
  // the seeded backup is readable by any signed-in user: found without writing anything
  assert.ok(run.result.findings.length > 0);
});
