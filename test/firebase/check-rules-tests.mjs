// Checks `node --test --test-reporter=tap` output against the rules test file accessprobe generated.
// Usage: node check-rules-tests.mjs accessprobe.rules.test.mjs tap.txt
//   exactly the tests marked "FAILS until the fix" fail (because the request succeeded), all others pass
import { readFileSync } from 'node:fs';

const [testFile, tapFile] = process.argv.slice(2);
const code = readFileSync(testFile, 'utf8');
const tap = readFileSync(tapFile, 'utf8');
const errors = [];
const expect = (ok, what) => {
  if (!ok) errors.push(what);
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${what}`);
};

const tests = [...code.matchAll(/^test\((".*"), async \(\) => \{(.*)$/gm)].map((m) => ({ desc: JSON.parse(m[1]), failsNow: /FAILS until the fix/.test(m[2]) }));
expect(tests.length > 0, `${tests.length} tests in the file`);

// TAP escapes "#" and "\" in test names
const results = new Map();
const blocks = tap.split(/^(?=(?:not ok|ok) \d+ - )/m);
for (const b of blocks) {
  const m = /^(not ok|ok) \d+ - (.*)$/m.exec(b);
  if (m) results.set(m[2].trim().replace(/\\([#\\])/g, '$1'), { passed: m[1] === 'ok', text: b });
}
expect(results.size === tests.length, `all ${tests.length} tests ran (TAP shows ${results.size})`);

for (const t of tests) {
  const r = results.get(t.desc);
  expect(r?.passed === !t.failsNow, `${t.failsNow ? 'fails ' : 'passes'}: ${t.desc}`);
  // a test for a proven leak must fail because the request went through, not because of a bug
  if (t.failsNow && r && !r.passed) expect(/Expected request to fail, but it succeeded/.test(r.text), `fails for the right reason: ${t.desc}`);
}

const failing = new Set(tests.filter((t) => t.failsNow).map((t) => t.desc));
const passing = new Set(tests.filter((t) => !t.failsNow).map((t) => t.desc));
for (const d of [
  "profiles: B cannot read A's documents",
  "profiles: anonymous-auth users cannot read A's documents",
  "journal: anonymous-auth users cannot read A's documents",
  'orders: B cannot create documents as A',
  'members: users cannot set their own role',
  "Realtime Database /users/$uid: B cannot read A's data",
  'Realtime Database /users/$uid: anonymous-auth users cannot read',
  "Storage avatars/{uid}: B cannot download A's files",
  'Storage avatars/{uid}: anonymous-auth users cannot download',
]) expect(failing.has(d), `the proven leak is a failing test: ${d}`);
for (const d of [
  "notes: B cannot read A's documents",
  "team_wiki: anonymous-auth users cannot read A's documents",
  "journal: anonymous visitors cannot read A's documents",
  'staff: users cannot set their own isStaff',
  'Realtime Database: anonymous-auth users cannot read the root',
  "Realtime Database /users/$uid: B cannot write to A's data",
  "Storage private/{uid}: B cannot download A's files",
  'Storage private/{uid}: anonymous-auth users cannot download',
]) expect(passing.has(d), `the passed check is a passing test: ${d}`);

if (errors.length) {
  console.log(`\n${errors.length} problem(s). TAP output:\n${tap.slice(-20000)}`);
  process.exit(1);
}
console.log(`\nRules test results match (${tests.length} tests, ${failing.size} fail until the leaks are fixed).`);
