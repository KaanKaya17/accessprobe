import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { createServer, ANON_KEY } from './mock-supabase.js';
import { scan } from '../src/core/scan.js';
import { scanSource } from '../src/providers/supabase/source.js';

const DUMP = fileURLToPath(new URL('./fixtures/supabase-db-dump.sql', import.meta.url));
let server;
let base;

before(async () => {
  server = createServer();
  await new Promise((r) => server.listen(0, r));
  base = `http://localhost:${server.address().port}`;
});
after(() => server.close());

test('pg_dump / supabase db dump syntax: quoted names, keys and identities added by ALTER TABLE', async () => {
  const s = await scanSource(undefined, [DUMP]);
  const t = s.tables.get('orders');
  assert.ok(t && !t.nameOnly);
  assert.deepEqual([...t.pkCols], ['id']);
  assert.equal(t.columns.get('id').hasDefault, true, 'identity added later counts as a default');
  assert.equal(t.columns.get('user_id').format, 'uuid');
  assert.deepEqual(t.columns.get('user_id').fk, { table: 'auth.users', column: 'id' });
  assert.equal(t.columns.get('status').format, 'order_status');
  assert.equal(t.columns.get('created_at').format, 'timestamp with time zone');
  assert.equal(s.tables.get('orders_feed')?.isView, true);
  assert.ok(!s.tables.has('public'), 'the schema name is never taken for a table');
});

test('a table in migrations/code but not in the live database is reported as drift, not tested', async () => {
  const r = await scan({ url: base, anonKey: ANON_KEY, tables: ['ghost_table'], only: ['ghost_table', 'notes'], quiet: true });
  assert.ok(r.notes.some((n) => n.startsWith('ghost_table: not in the live database')), r.notes.join('\n'));
  assert.ok(!r.findings.some((f) => f.table === 'ghost_table'));
  assert.ok(!r.passed.some((p) => p.startsWith('ghost_table')));
});

test('--schema files are compared with the live API schema', async () => {
  const r = await scan({ url: base, anonKey: ANON_KEY, schemaFiles: [DUMP], only: ['notes'], quiet: true });
  assert.ok(r.notes.some((n) => n.startsWith('Live tables that are not in your migrations:') && n.includes('notes')), r.notes.join('\n'));
  await assert.rejects(scan({ url: base, anonKey: ANON_KEY, schemaFiles: ['nope.sql'], quiet: true }), /--schema file not found/);
});
