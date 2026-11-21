// Asserts accessprobe's result against the real-Postgres fixture (see supabase/migrations).
// Usage: node check.mjs result.json
import { readFileSync } from 'node:fs';

const r = JSON.parse(readFileSync(process.argv[2], 'utf8'));
const errors = [];
const has = (table, id) => r.findings.some((f) => f.table === table && f.id === id);
const none = (table) => !r.findings.some((f) => f.table === table);
const passed = (line) => r.passed.includes(line);
const expect = (ok, what) => {
  if (!ok) errors.push(what);
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${what}`);
};

expect(has('orders', 'cross-user-read'), 'orders: cross-user read is proven');
expect(has('orders', 'impersonated-insert'), 'orders: forged insert is proven');
expect(!has('orders', 'cross-user-update') && !has('orders', 'cross-user-delete'), 'orders: owner-only update/delete hold');

const esc = r.findings.find((f) => f.table === 'memberships' && f.id === 'self-escalation');
expect(Boolean(esc) && /plan/.test(esc.title) && /is_admin/.test(esc.title), 'memberships: users can make themselves admin / upgrade their plan');
expect(r.findings.filter((f) => f.table === 'memberships').length === 1, 'memberships: nothing else is reported');

expect(none('notes'), 'notes: correct policies, no findings');
expect(passed("notes: B cannot read A's rows"), "notes: B's read is refused (passed)");

expect(none('subscriptions'), 'subscriptions: no findings');
expect(passed('subscriptions: users cannot change their own plan'), 'subscriptions: column grant blocks the plan change (passed)');

const feed = r.findings.filter((f) => f.table === 'notes_feed');
expect(feed.some((f) => f.severity === 'critical'), 'notes_feed: view without security_invoker is caught (it skips RLS)');
expect(feed.length > 0 && feed.every((f) => !f.fix || /security_invoker = true/.test(f.fix.sql)), 'notes_feed: every fix is the view fix, never table policies');
expect(none('my_notes'), 'my_notes: security_invoker view, no findings');
expect(passed("my_notes: B cannot read A's private rows through it"), 'my_notes: B sees nothing through it (passed)');

expect(!r.notes.some((n) => n.startsWith('Could not delete')), 'cleanup removed every test row');

if (errors.length) {
  console.log('\nFindings:', JSON.stringify(r.findings.map((f) => [f.table, f.id, f.severity]), null, 1));
  console.log('Notes:', JSON.stringify(r.notes, null, 1));
  process.exit(1);
}
console.log(`\nAll ${r.findings.length} findings and ${r.passed.length} passes match the fixture.`);
