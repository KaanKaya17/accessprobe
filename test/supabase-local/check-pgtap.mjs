// Checks `supabase test db` output against the pgTAP file accessprobe generated.
// Usage: node check-pgtap.mjs tests.sql tap.txt [--fixed]
//   default: exactly the tests marked "FAILS until the fix" fail, all others pass
//   --fixed: after test/supabase-local/fix.sql was applied, every test passes
import { readFileSync } from 'node:fs';

const [sqlFile, tapFile, mode] = process.argv.slice(2);
const sql = readFileSync(sqlFile, 'utf8');
const tap = readFileSync(tapFile, 'utf8');
const errors = [];
const expect = (ok, what) => {
  if (!ok) errors.push(what);
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${what}`);
};

const unq = (s) => s.replace(/''/g, "'");
const tests = [...sql.matchAll(/^select (?:ok|lives_ok)\(.*, '((?:[^']|'')*)'\);(.*)$/gm)].map((m) => ({ desc: unq(m[1]), failsNow: /FAILS until the fix/.test(m[2]) }));
const planned = Number(/select plan\((\d+)\)/.exec(sql)[1]);
expect(tests.length === planned, `plan(${planned}) matches the ${tests.length} tests in the file`);

const results = new Map();
for (const m of tap.matchAll(/^\s*(not ok|ok) \d+ - (.*)$/gm)) results.set(m[2].trim(), m[1] === 'ok');
expect(results.size === tests.length, `all ${tests.length} tests ran (TAP shows ${results.size})`);

for (const t of tests) {
  const passed = results.get(t.desc);
  const want = mode === '--fixed' ? true : !t.failsNow;
  expect(passed === want, `${want ? 'passes' : 'fails '}: ${t.desc}`);
}

if (mode !== '--fixed') {
  const failing = new Set(tests.filter((t) => t.failsNow).map((t) => t.desc));
  const passing = new Set(tests.filter((t) => !t.failsNow).map((t) => t.desc));
  for (const d of [
    "orders: B cannot read A's rows",
    'orders: B cannot insert rows as A',
    'memberships: users cannot change their own plan',
    'memberships: users cannot change their own is_admin',
    "notes_feed: B cannot read A's private rows through it",
  ]) expect(failing.has(d), `the proven leak is a failing test: ${d}`);
  for (const d of [
    "notes: B cannot read A's rows",
    "notes: anonymous visitors cannot read A's rows",
    "orders: B cannot delete A's rows",
    'subscriptions: users cannot change their own plan',
    "my_notes: B cannot read A's private rows through it",
  ]) expect(passing.has(d), `the passed check is a passing test: ${d}`);
}

if (errors.length) {
  console.log(`\n${errors.length} problem(s). TAP output:\n${tap}`);
  process.exit(1);
}
console.log(`\npgTAP results match (${tests.length} tests${mode === '--fixed' ? ', all green after the fix' : ''}).`);
