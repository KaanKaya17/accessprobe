import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseSchema, buildRow } from '../src/providers/supabase/schema.js';

const doc = (props, required = []) => ({
  definitions: { t: { properties: props, required } },
  paths: { '/t': { get: {}, post: {} } },
});

test('buildRow fills every required type and puts the owner + marker in place', () => {
  const [t] = parseSchema(
    doc(
      {
        id: { format: 'bigint', description: '<pk/>', default: 'x' },
        user_id: { format: 'uuid' },
        ref: { format: 'uuid' },
        n: { format: 'integer' },
        price: { format: 'numeric' },
        ok: { format: 'boolean' },
        at: { format: 'timestamp with time zone' },
        day: { format: 'date' },
        meta: { format: 'jsonb' },
        tags: { format: 'text[]' },
        title: { format: 'text' },
      },
      ['user_id', 'ref', 'n', 'price', 'ok', 'at', 'day', 'meta', 'tags'],
    ),
  ).tables;
  const { row, markerCol } = buildRow(t, { ownerId: 'OWNER', marker: 'M' });
  assert.equal(row.user_id, 'OWNER');
  assert.match(row.ref, /^[0-9a-f-]{36}$/);
  assert.equal(row.n, 1);
  assert.equal(row.ok, false);
  assert.deepEqual(row.meta, {});
  assert.deepEqual(row.tags, []);
  assert.equal(markerCol, 'title');
  assert.equal(row.title, 'M');
  assert.equal('id' in row, false, 'pk with default is left to the database');
});

test('buildRow gives up on a required foreign key it cannot invent', () => {
  const [t] = parseSchema(
    doc({ user_id: { format: 'uuid' }, team_id: { format: 'bigint', description: "<fk table='teams' column='id'/>" } }, ['user_id', 'team_id']),
  ).tables;
  assert.equal(buildRow(t, { ownerId: 'X', marker: 'M' }), null);
});

test('owner guess prefers a column that references auth.users', () => {
  const [t] = parseSchema(
    doc({ user_id: { format: 'bigint', description: '<pk/>' }, auth_id: { format: 'uuid', description: "<fk table='auth.users' column='id'/>" } }),
  ).tables;
  assert.equal(t.owner.name, 'auth_id');
});
