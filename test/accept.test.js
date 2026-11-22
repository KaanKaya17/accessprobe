import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createServer, ANON_KEY } from './mock-supabase.js';
import { scan } from '../src/core/scan.js';
import { grade, markdownReport } from '../src/core/report.js';
import { parseAccept, loadAccept, applyAccept, acceptRecipes, checkCovers } from '../src/core/accept.js';
import { pgtapTests } from '../src/providers/supabase/pgtap.js';

test('parseAccept: resource, optional finding id, reason; bad lines are errors', () => {
  const { entries, errors } = parseAccept('# header\n\nprofiles cross-user-read   # public on purpose\nproducts\n  a b c\n');
  assert.deepEqual(
    entries.map(({ resource, id, reason, line }) => [resource, id, reason, line]),
    [
      ['profiles', 'cross-user-read', 'public on purpose', 3],
      ['products', null, '', 4],
    ],
  );
  assert.equal(errors.length, 1);
  assert.match(errors[0], /^line 5:/);
});

test('loadAccept: finds .accessprobeignore in the source folder; an explicit missing file is an error', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'ap-accept-'));
  assert.deepEqual(await loadAccept({ source: dir }), { file: null, entries: [] });
  writeFileSync(join(dir, '.accessprobeignore'), 'posts # public\n');
  const a = await loadAccept({ source: dir });
  assert.equal(a.entries[0].resource, 'posts');
  await assert.rejects(loadAccept({ file: join(dir, 'nope') }), /Cannot read/);
});

test('applyAccept matches on resource (+ id) across providers', () => {
  const findings = [
    { id: 'cross-user-read', table: 'profiles', severity: 'critical' },
    { id: 'cross-user-update', table: 'profiles', severity: 'critical' },
    { id: 'anon-read', resource: 'posts', severity: 'critical' },
    { id: 'storage-anon-list', bucket: 'avatars', severity: 'warning' },
  ];
  const { entries } = parseAccept('profiles cross-user-read # public\nposts\nunused-table\n');
  const r = applyAccept(findings, entries);
  assert.deepEqual(r.findings.map((f) => f.id), ['cross-user-update', 'storage-anon-list']);
  assert.deepEqual(r.accepted.map((f) => [f.id, f.acceptedBecause]), [
    ['cross-user-read', 'public'],
    ['anon-read', '(no reason given)'],
  ]);
  assert.deepEqual(r.unused.map((e) => e.resource), ['unused-table']);
});

test('checkCovers ties regression checks to finding ids', () => {
  assert.ok(checkCovers('read', 'cross-user-read'));
  assert.ok(!checkCovers('read', 'anon-read-owned'));
  assert.ok(checkCovers('anon-read', 'anon-read-owned'));
  assert.ok(!checkCovers('anon-read', 'anon-auth-read'));
  assert.ok(checkCovers('anon-auth-read', 'anon-auth-read'));
  assert.ok(checkCovers('forge', 'impersonated-insert'));
  assert.ok(checkCovers('list', 'cross-user-list'));
  assert.ok(!checkCovers('read', 'cross-user-list'));
  assert.ok(checkCovers('anon-create', 'anon-insert'));
  assert.ok(!checkCovers('update', 'cross-user-delete'));
});

test('acceptRecipes drops only the failing checks of accepted findings', () => {
  const recipes = [
    { table: 'profiles', checks: [{ check: 'read', ok: false }, { check: 'update', ok: true }, { check: 'delete', ok: false }] },
    { table: 'products', checks: [{ check: 'read', ok: false }] },
    { resource: 'notes', checks: [{ check: 'read', ok: false }] },
  ];
  const { entries } = parseAccept('profiles cross-user-read\nproducts\n');
  const out = acceptRecipes(recipes, entries);
  assert.deepEqual(out.map((r) => r.table ?? r.resource), ['profiles', 'notes']);
  assert.deepEqual(out[0].checks, [{ check: 'update', ok: true }, { check: 'delete', ok: false }]);
});

let server;
let base;
let plain;
let accepted;
before(async () => {
  server = createServer();
  await new Promise((r) => server.listen(0, r));
  base = `http://localhost:${server.address().port}`;
  plain = await scan({ url: base, anonKey: ANON_KEY, quiet: true, freshUsers: true });
  const { entries } = parseAccept('profiles cross-user-read  # profiles are public in this app\nproducts  # public catalog\nghost_table\norders cross-user-read  # shared orders\n');
  accepted = await scan({ url: base, anonKey: ANON_KEY, quiet: true, freshUsers: true, accept: { file: '.accessprobeignore', entries } });
});
after(() => server.close());

test('scan: accepted findings leave the graded list and show up as Accepted', () => {
  assert.ok(plain.findings.some((f) => f.table === 'profiles' && f.id === 'cross-user-read'));
  assert.ok(!accepted.findings.some((f) => f.table === 'profiles' && f.id === 'cross-user-read'));
  assert.ok(!accepted.findings.some((f) => f.table === 'products'));
  assert.ok(accepted.accepted.some((f) => f.table === 'profiles' && f.acceptedBecause === 'profiles are public in this app'));
  const crit = (r) => r.findings.filter((f) => f.severity === 'critical').length;
  const acceptedCrit = plain.findings.filter((f) => f.severity === 'critical' && ['profiles', 'orders'].includes(f.table) && f.id === 'cross-user-read').length;
  assert.equal(acceptedCrit, 2);
  assert.equal(crit(accepted), crit(plain) - acceptedCrit);
  assert.ok(accepted.notes.some((n) => n.startsWith('.accessprobeignore line 3 (ghost_table) matched nothing')));
  const md = markdownReport(accepted);
  assert.match(md, /## Accepted \(open on purpose\)/);
  assert.match(md, /profiles are public in this app/);
  assert.notEqual(grade(plain.findings, plain.stats), undefined);
});

test('scan: pgTAP leaves out the failing check of an accepted finding', () => {
  const sql = pgtapTests(accepted.recipes, { version: 'x', target: base, date: 'today' });
  const before = pgtapTests(plain.recipes, { version: 'x', target: base, date: 'today' });
  const line = "orders: B cannot read A''s rows"; // SQL-quoted
  assert.ok(before.split('\n').some((l) => l.includes(line) && l.includes('FAILS until')));
  assert.ok(!sql.includes(line));
  // other proven leaks on the same table still fail until fixed
  assert.ok(sql.split('\n').some((l) => l.includes('orders:') && l.includes('FAILS until')));
});
