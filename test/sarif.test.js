import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createServer, ANON_KEY } from './mock-supabase.js';
import { scan } from '../src/core/scan.js';
import { parseAccept } from '../src/core/accept.js';
import { makeLocator, sarifReport } from '../src/core/sarif.js';

const dir = mkdtempSync(join(tmpdir(), 'ap-sarif-'));
mkdirSync(join(dir, '.git'));
mkdirSync(join(dir, 'app', 'supabase', 'migrations'), { recursive: true });
writeFileSync(
  join(dir, 'app', 'supabase', 'migrations', '20240101000000_init.sql'),
  ['create table public.orders (id uuid primary key, user_id uuid);', 'alter table public.orders enable row level security;', 'create policy "read all" on public.orders for select using (true);', ''].join('\n'),
);
writeFileSync(
  join(dir, 'app', 'supabase', 'migrations', '20240201000000_more.sql'),
  ['-- later fix attempt', 'create policy "own rows"', '  on "orders" for select using (auth.uid() = user_id);', 'create table notes (id int);', "create policy p on storage.objects using (bucket_id = 'avatars');", ''].join('\n'),
);
// not a migration: must not win over the migrations (it sorts after them)
writeFileSync(join(dir, 'app', 'supabase', 'seed.sql'), 'create policy seeded on public.orders for select using (true);\n');
writeFileSync(join(dir, 'app', 'firestore.rules'), ["rules_version = '2';", 'service cloud.firestore {', '  match /databases/{db}/documents {', '    match /posts/{id} {', '      allow read: if true;', '    }', '  }', '}', ''].join('\n'));
writeFileSync(join(dir, 'app', 'database.rules.json'), '{\n  "rules": {\n    "chats": {\n      ".read": true\n    }\n  }\n}\n');

test('locator: newest policy for a table, CREATE TABLE otherwise, bucket policies, rules files', async () => {
  const locate = await makeLocator({ source: join(dir, 'app') });
  assert.deepEqual(locate({ platform: 'supabase', table: 'orders' }), { uri: 'app/supabase/migrations/20240201000000_more.sql', line: 2 });
  assert.deepEqual(locate({ platform: 'supabase', table: 'notes' }), { uri: 'app/supabase/migrations/20240201000000_more.sql', line: 4 });
  assert.deepEqual(locate({ platform: 'supabase', bucket: 'avatars' }), { uri: 'app/supabase/migrations/20240201000000_more.sql', line: 5 });
  assert.deepEqual(locate({ platform: 'firebase', resource: 'posts' }), { uri: 'app/firestore.rules', line: 4 });
  assert.deepEqual(locate({ platform: 'firebase', resource: 'chats/$uid' }), { uri: 'app/database.rules.json', line: 3 });
  // unknown table: the first schema file, so the alert still lands in the repo
  assert.equal(locate({ platform: 'supabase', table: 'ghost' }).line, 1);
});

let server;
let result;
before(async () => {
  server = createServer();
  await new Promise((r) => server.listen(0, r));
  const base = `http://localhost:${server.address().port}`;
  const { entries } = parseAccept('products # public catalog\n');
  result = await scan({ url: base, anonKey: ANON_KEY, quiet: true, freshUsers: true, accept: { file: '.accessprobeignore', entries } });
});
after(() => server.close());

test('sarifReport: one result per finding, rules with security-severity, accepted findings left out', async () => {
  const locate = await makeLocator({ source: join(dir, 'app') });
  const s = sarifReport(result, locate);
  assert.equal(s.version, '2.1.0');
  const run = s.runs[0];
  assert.equal(run.tool.driver.name, 'accessprobe');
  assert.equal(run.results.length, result.findings.length);
  assert.ok(result.findings.length > 3);
  const ruleIds = new Set(run.tool.driver.rules.map((r) => r.id));
  for (const r of run.results) {
    assert.ok(ruleIds.has(r.ruleId));
    assert.ok(['error', 'warning', 'note'].includes(r.level));
    assert.equal(r.locations.length, 1, 'GitHub needs a location on every result');
    assert.ok(r.partialFingerprints['accessprobe/v1']);
  }
  for (const rule of run.tool.driver.rules) assert.match(rule.properties['security-severity'], /^\d+\.\d$/);
  assert.ok(!run.results.some((r) => r.properties.resource === 'products'), 'accepted findings are not alerts');
  const order = run.results.find((r) => r.properties.resource === 'orders' && r.ruleId === 'cross-user-read');
  assert.equal(order.level, 'error');
  assert.deepEqual(order.locations[0].physicalLocation, { artifactLocation: { uri: 'app/supabase/migrations/20240201000000_more.sql' }, region: { startLine: 2 } });
  // fingerprints are stable across runs and unique per finding
  const fps = run.results.map((r) => r.partialFingerprints['accessprobe/v1']);
  assert.equal(new Set(fps).size, fps.length);
  assert.deepEqual(sarifReport(result, locate).runs[0].results.map((r) => r.partialFingerprints['accessprobe/v1']), fps);
});
