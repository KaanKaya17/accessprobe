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

const fnHas = (fn, id) => r.findings.some((f) => f.resource === fn && f.id === id && (id.startsWith('definer-') || f.severity === 'critical'));
expect(fnHas('all_notes_definer', 'rpc-cross-user-read'), 'all_notes_definer(): SECURITY DEFINER function leaking A\'s notes to B is proven');
expect(fnHas('all_notes_definer', 'rpc-anon-read'), 'all_notes_definer(): ... and to anonymous visitors');
expect(!r.findings.some((f) => f.resource === 'all_notes_definer' && f.id === 'definer-no-auth-check'), 'all_notes_definer(): proven live, so no extra static warning');
expect(!r.findings.some((f) => f.resource === 'notes_invoker'), 'notes_invoker(): invoker rights, no findings');
expect(passed("notes_invoker(): B gets none of A's private rows"), 'notes_invoker(): B gets nothing through it (passed)');
const wipe = r.findings.find((f) => f.resource === 'wipe_canary' && f.id === 'definer-no-auth-check');
expect(Boolean(wipe) && /does not remove the anon/.test(wipe.detail), 'wipe_canary(): static SECURITY DEFINER warning, notes that REVOKE FROM public is not enough');

// organizations (20261122000000_orgs.sql)
const sev = (table, id) => r.findings.find((f) => f.table === table && f.id === id)?.severity;
expect(sev('invoices', 'cross-tenant-read') === 'critical', 'invoices: outsider reads another organization\'s rows (proven)');
expect(passed('projects: users outside the organization cannot read its rows'), 'projects: outsiders refused (passed)');
expect(passed('org_members: users cannot add themselves to another user\'s organization'), 'org_members: self-join refused (passed)');
expect(passed('org_members: users outside an organization cannot list its members'), 'org_members: member list hidden from outsiders (passed)');
expect(sev('org_members', 'tenant-role-escalation') === 'critical', 'org_members: a member makes itself owner (proven)');
expect(sev('org_files', 'removed-member-access') === 'critical', 'org_files: JWT-claim policy keeps a removed member in (proven)');
expect(passed('projects: removed members lose access right away'), 'projects: removed member loses access (passed)');
expect(!r.findings.some((f) => ['projects', 'orgs'].includes(f.table)), 'projects / orgs: no findings');
expect(r.notes.some((n) => n.startsWith('Organizations: tested orgs with members in org_members.org_id')), 'organization model detected');

expect(!r.notes.some((n) => n.startsWith('Could not delete')), 'cleanup removed every test row');

if (errors.length) {
  console.log('\nFindings:', JSON.stringify(r.findings.map((f) => [f.table, f.id, f.severity]), null, 1));
  console.log('Notes:', JSON.stringify(r.notes, null, 1));
  process.exit(1);
}
console.log(`\nAll ${r.findings.length} findings and ${r.passed.length} passes match the fixture.`);
