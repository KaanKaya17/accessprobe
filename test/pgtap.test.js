import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createServer } from './mock-supabase.js';
import { scan } from '../src/core/scan.js';
import { pgtapTests, writePgtap } from '../src/providers/supabase/pgtap.js';

let server;
let result;
let sql;

before(async () => {
  server = createServer();
  await new Promise((r) => server.listen(0, r));
  result = await scan({ site: `http://localhost:${server.address().port}`, quiet: true });
  sql = pgtapTests(result.recipes, { version: 't', target: 'x' });
});
after(() => server.close());

const tests = () =>
  [...sql.matchAll(/^select (?:ok|lives_ok)\(.*, '((?:[^']|'')*)'\);(.*)$/gm)].map((m) => ({
    desc: m[1].replace(/''/g, "'"),
    failsNow: /FAILS until the fix/.test(m[2]),
  }));
const find = (d) => tests().find((t) => t.desc === d);

test('pgTAP: one transaction, rolled back, plan matches the tests', () => {
  assert.match(sql, /^begin;$/m);
  assert.match(sql, /^rollback;$/m);
  assert.match(sql, /select \* from finish\(\);/);
  assert.equal(Number(/select plan\((\d+)\)/.exec(sql)[1]), tests().length);
});

test('pgTAP: proven leaks are failing tests, passed checks are passing tests', () => {
  assert.equal(find("orders: B cannot read A's rows")?.failsNow, true);
  assert.equal(find('orders: B cannot insert rows as A')?.failsNow, true);
  assert.equal(find("orders: B cannot delete A's rows")?.failsNow, false);
  assert.equal(find("notes: B cannot read A's rows")?.failsNow, false);
  assert.equal(find('memberships: users cannot change their own is_admin')?.failsNow, true);
  assert.equal(find('subscriptions: users cannot change their own plan')?.failsNow, false);
  assert.equal(find("notes_feed: B cannot read A's private rows through it")?.failsNow, true);
  assert.equal(find("my_notes: B cannot read A's private rows through it")?.failsNow, false);
  // every failing test matches a critical finding of that table
  for (const t of tests().filter((x) => x.failsNow)) {
    const table = t.desc.split(':')[0];
    assert.ok(result.findings.some((f) => f.table === table && f.severity === 'critical'), t.desc);
  }
});

test('pgTAP: uses fixed test users, never the live ones or the run markers', () => {
  const live = result.recipes.flatMap((r) => [r.marker, ...Object.values(r.sent).filter((v) => typeof v === 'string')]);
  assert.ok(result.recipes.length > 0);
  for (const r of result.recipes) assert.ok(!sql.includes(r.marker), 'run markers are replaced');
  assert.ok(!live.some((v) => /^[0-9a-f-]{36}$/.test(v) && sql.includes(v) && !v.startsWith('aaaaaaaa')));
  assert.match(sql, /aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa/);
});

test('pgTAP: writePgtap writes the file and reports how many fail', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'ap-pgtap-'));
  try {
    const file = join(dir, 'supabase', 'tests', 'accessprobe.test.sql');
    const msg = await writePgtap(file, result);
    assert.match(msg, /tests, \d+ of them fail until the leaks are fixed/);
    assert.match(readFileSync(file, 'utf8'), /select plan\(\d+\)/);
    assert.equal(pgtapTests([], {}), null);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
