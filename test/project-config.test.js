import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { findProjectConfig } from '../src/providers/supabase/project-config.js';
import { createServer, ANON_KEY, SERVICE_KEY } from './mock-supabase.js';

const BIN = fileURLToPath(new URL('../bin/rlsprobe.js', import.meta.url));
let dir;
let server;
let base;

before(async () => {
  server = createServer();
  await new Promise((r) => server.listen(0, r));
  base = `http://localhost:${server.address().port}`;
  dir = await mkdtemp(join(tmpdir(), 'rlsprobe-proj-'));
  await writeFile(join(dir, 'package.json'), '{"name":"my-app","dependencies":{"@supabase/supabase-js":"2"}}');
  await writeFile(
    join(dir, '.env.local'),
    [
      `VITE_SUPABASE_URL=${base}`,
      `VITE_SUPABASE_ANON_KEY=${ANON_KEY}`,
      `SUPABASE_SERVICE_ROLE_KEY=${SERVICE_KEY}`, // server-only: fine, must not be used
      `VITE_SUPABASE_SERVICE_KEY=${SERVICE_KEY}`, // public prefix: shipped to the browser!
    ].join('\n'),
  );
  await writeFile(join(dir, '.env.example'), 'VITE_SUPABASE_URL=https://your-project.supabase.co\nVITE_SUPABASE_ANON_KEY=your-anon-key\n');
});
after(async () => {
  server.close();
  await rm(dir, { recursive: true, force: true });
});

test('finds URL + anon key in .env files, never picks a secret key, flags public-prefixed secrets', async () => {
  const c = await findProjectConfig(dir);
  assert.deepEqual(c.urls, [base]);
  assert.deepEqual(c.anonKeys, [ANON_KEY]);
  assert.ok(!c.anonKeys.includes(SERVICE_KEY));
  const leak = c.findings.find((f) => f.id === 'leaked-service-role-env');
  assert.ok(leak && leak.severity === 'critical');
  assert.match(leak.title, /VITE_SUPABASE_SERVICE_KEY/);
  assert.ok(!leak.evidence.includes(SERVICE_KEY), 'redacted');
  assert.ok(c.notes.some((n) => n.includes('SUPABASE_SERVICE_ROLE_KEY') && /never uses it/.test(n)));
  assert.equal(c.findings.filter((f) => f.id === 'leaked-service-role-env').length, 1, 'server-only key is not a finding');
});

test('Android local.properties (FitLog style) works too', async () => {
  const d = await mkdtemp(join(tmpdir(), 'rlsprobe-android-'));
  try {
    await mkdir(join(d, 'app'));
    await writeFile(join(d, 'local.properties'), `sdk.dir=C\\:\\\\Android\nSUPABASE_URL=https://abcdefghijklmnopqrst.supabase.co\nSUPABASE_API_KEY=${ANON_KEY}\n`);
    const c = await findProjectConfig(d);
    assert.deepEqual(c.urls, ['https://abcdefghijklmnopqrst.supabase.co']);
    assert.deepEqual(c.anonKeys, [ANON_KEY]);
  } finally {
    await rm(d, { recursive: true, force: true });
  }
});

test('`npx rlsprobe` with no arguments in a project folder runs a full scan', async () => {
  const r = await new Promise((resolve) => {
    const p = spawn(process.execPath, [BIN, '--yes', '--json'], { cwd: dir, env: { ...process.env, NO_COLOR: '1' } });
    let out = '';
    let err = '';
    p.stdout.on('data', (d) => (out += d));
    p.stderr.on('data', (d) => (err += d));
    p.on('close', (code) => resolve({ code, out, err }));
  });
  assert.equal(r.code, 1, r.err); // the mock is full of holes
  const j = JSON.parse(r.out);
  assert.equal(j.platforms[0].id, 'supabase');
  assert.ok(j.findings.some((f) => f.id === 'cross-user-read'));
  assert.ok(j.findings.some((f) => f.id === 'leaked-service-role-env'));
  assert.match(r.err, /testing the project in this folder/);
  assert.ok(r.err.includes(`Target: Supabase project ${base}`), 'the real backend is named before anything is written');
});

test('two different Supabase projects in one folder (.env vs .env.local): refuse to guess', async () => {
  const d = await mkdtemp(join(tmpdir(), 'rlsprobe-two-'));
  try {
    await writeFile(join(d, 'package.json'), '{}');
    await writeFile(join(d, '.env'), `SUPABASE_URL=https://aaaaaaaaaaaaaaaaaaaa.supabase.co\nSUPABASE_ANON_KEY=${ANON_KEY}\n`);
    await writeFile(join(d, '.env.local'), `SUPABASE_URL=http://localhost:54321\nSUPABASE_ANON_KEY=${ANON_KEY}\n`);
    const r = await new Promise((resolve) => {
      const p = spawn(process.execPath, [BIN, '--yes'], { cwd: d, env: { ...process.env, NO_COLOR: '1' } });
      let err = '';
      p.stderr.on('data', (x) => (err += x));
      p.on('close', (code) => resolve({ code, err }));
    });
    assert.equal(r.code, 2);
    assert.match(r.err, /Several Supabase projects are configured in this folder/);
    assert.doesNotMatch(r.err, /Signing in two test users/, 'nothing was written');
  } finally {
    await rm(d, { recursive: true, force: true });
  }
});
