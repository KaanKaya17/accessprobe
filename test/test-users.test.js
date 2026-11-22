import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createServer } from './mock-supabase.js';
import { scan } from '../src/core/scan.js';
import { usersFile } from '../src/core/test-users.js';

let server;
let base;
let dir;
const saved = process.env.ACCESSPROBE_CACHE_DIR;

before(async () => {
  dir = mkdtempSync(join(tmpdir(), 'ap-users-'));
  process.env.ACCESSPROBE_CACHE_DIR = dir;
  server = createServer();
  await new Promise((r) => server.listen(0, r));
  base = `http://localhost:${server.address().port}`;
});
after(() => {
  server.close();
  process.env.ACCESSPROBE_CACHE_DIR = saved;
  rmSync(dir, { recursive: true, force: true });
});

test('Supabase test users are kept outside the project and reused by the next run', async () => {
  const first = await scan({ site: base, quiet: true });
  assert.equal(server.stats().signups, 2);
  assert.ok(first.notes.some((n) => n.startsWith('Test users kept for the next run')));
  assert.ok(usersFile().startsWith(dir));
  const file = JSON.parse(readFileSync(usersFile(), 'utf8'));
  assert.equal(Object.keys(file).length, 1);

  const second = await scan({ site: base, quiet: true });
  assert.equal(server.stats().signups, 2, 'no new accounts on the second run');
  assert.ok(second.notes.some((n) => n.startsWith('Reused the test users')));
  assert.deepEqual(
    second.findings.map((f) => `${f.table}:${f.id}`).sort(),
    first.findings.map((f) => `${f.table}:${f.id}`).sort(),
    'same findings with reused users',
  );
});

test('--fresh-users signs up new accounts and keeps nothing', async () => {
  const before = server.stats().signups;
  const r = await scan({ site: base, quiet: true, freshUsers: true });
  assert.equal(server.stats().signups, before + 2);
  assert.ok(r.notes.some((n) => n.startsWith('Test users were created')));
});

test('saved users that no longer sign in are replaced', async () => {
  const all = JSON.parse(readFileSync(usersFile(), 'utf8'));
  for (const k of Object.keys(all)) all[k].A.password = 'wrong';
  const { writeFileSync } = await import('node:fs');
  writeFileSync(usersFile(), JSON.stringify(all));
  const before = server.stats().signups;
  const r = await scan({ site: base, quiet: true });
  assert.equal(server.stats().signups, before + 2);
  assert.ok(r.notes.some((n) => n.startsWith('Test users kept for the next run')));
});
