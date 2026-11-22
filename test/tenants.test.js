import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, ANON_KEY } from './mock-supabase.js';
import { scan } from '../src/core/scan.js';
import { findTenancy } from '../src/providers/supabase/tenants.js';

const col = (name, o = {}) => ({ name, format: o.format || 'text', required: Boolean(o.required), hasDefault: Boolean(o.default), pk: Boolean(o.pk), fk: o.fk ? { table: o.fk, column: 'id' } : null, enum: o.enum || null });
const table = (name, columns, owner = null) => ({ name, columns, pk: columns.find((c) => c.pk) || null, pkCols: columns.filter((c) => c.pk), owner: owner ? columns.find((c) => c.name === owner) : null });

test('findTenancy: tenant table, membership table (by FK or name), role column and scoped tables', () => {
  const schema = {
    tables: [
      table('workspaces', [col('id', { pk: true, default: true, format: 'uuid' }), col('name', { required: true })]),
      table('workspace_members', [col('workspace_id', { required: true, format: 'uuid' }), col('user_id', { required: true, format: 'uuid' }), col('role', { enum: ['owner', 'admin', 'member'] })], 'user_id'),
      table('documents', [col('id', { pk: true, default: true }), col('workspace_id', { required: true, format: 'uuid' }), col('title')]),
      table('notes', [col('id', { pk: true, default: true }), col('user_id', { format: 'uuid' }), col('body')], 'user_id'),
    ],
  };
  const t = findTenancy(schema);
  assert.equal(t.tenant.name, 'workspaces');
  assert.equal(t.members.name, 'workspace_members');
  assert.equal(t.col, 'workspace_id');
  assert.equal(t.userCol, 'user_id');
  assert.equal(t.roleCol, 'role');
  assert.deepEqual(t.scoped.map((x) => x.name), ['documents']);
});

test('findTenancy: no tenant table, or a user table that merely has a team_id, is not an organization model', () => {
  assert.equal(findTenancy({ tables: [table('team_members', [col('team_id', { pk: true }), col('user_id', { pk: true, format: 'uuid' }), col('role')], 'user_id')] }), null);
  assert.equal(findTenancy({ tables: [table('teams', [col('id', { pk: true })]), table('profiles', [col('id', { pk: true, format: 'uuid' }), col('team_id'), col('bio'), col('a'), col('b'), col('c'), col('d'), col('e'), col('f')], 'id')] }), null);
});

let server;
let result;
before(async () => {
  server = createServer();
  await new Promise((r) => server.listen(0, r));
  result = await scan({ url: `http://localhost:${server.address().port}`, anonKey: ANON_KEY, quiet: true, freshUsers: true });
});
after(() => server.close());

const has = (table, id) => result.findings.find((f) => f.table === table && f.id === id);

test('organizations: outsider read of a table open to every signed-in user is proven', () => {
  assert.equal(has('invoices', 'cross-tenant-read')?.severity, 'critical');
  assert.ok(result.passed.includes('projects: users outside the organization cannot read its rows'));
  assert.ok(result.passed.includes('projects: users outside the organization cannot delete its rows'));
});

test('organizations: joining someone else\'s org and raising your own role are proven', () => {
  const join = has('org_members', 'tenant-self-join');
  assert.equal(join?.severity, 'critical');
  assert.match(join.title, /as owner/);
  assert.match(join.fix.sql, /is_admin_of/);
  assert.equal(has('org_members', 'tenant-role-escalation')?.severity, 'critical');
  assert.ok(result.passed.includes('org_members: users outside an organization cannot list its members'));
});

test('organizations: a policy that trusts JWT claims keeps removed members in; one that reads the table does not', () => {
  const f = has('org_files', 'removed-member-access');
  assert.equal(f?.severity, 'critical');
  assert.match(f.detail, /JWT/);
  assert.ok(result.passed.includes('projects: removed members lose access right away'));
  assert.ok(!has('invoices', 'removed-member-access'), 'already open to outsiders: not reported twice');
});

test('organizations: test data is gone and the per-user noise for org tables is folded into one note', () => {
  assert.ok(!result.notes.some((n) => n.startsWith('Could not delete some organization test rows')));
  assert.ok(result.notes.some((n) => n.startsWith('Organizations: tested orgs with members in org_members.org_id')));
  assert.ok(!result.notes.some((n) => /^(projects|invoices|org_files): .*cannot fill/.test(n)));
});
