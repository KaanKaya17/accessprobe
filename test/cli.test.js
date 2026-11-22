import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { createServer, ANON_KEY } from './mock-supabase.js';
import { grade } from '../src/core/report.js';

const BIN = fileURLToPath(new URL('../bin/accessprobe.js', import.meta.url));
let server;
let base;

before(async () => {
  server = createServer();
  await new Promise((r) => server.listen(0, r));
  base = `http://localhost:${server.address().port}`;
});
after(() => server.close());

function run(args, { input = '' } = {}) {
  return new Promise((resolve) => {
    const p = spawn(process.execPath, [BIN, ...args], { env: { ...process.env, NO_COLOR: '1' } });
    let out = '';
    let err = '';
    p.stdout.on('data', (d) => (out += d));
    p.stderr.on('data', (d) => (err += d));
    const timer = setTimeout(() => p.kill(), 20000);
    p.on('close', (code) => {
      clearTimeout(timer);
      resolve({ code, out, err });
    });
    p.stdin.end(input);
  });
}

test('--help exits 0, no target exits 2', async () => {
  assert.equal((await run(['--help'])).code, 0);
  assert.equal((await run([])).code, 2);
});

test('without --yes it asks, and "n" (or closed stdin) aborts without touching the target', async () => {
  const r = await run(['--url', base, '--anon-key', ANON_KEY], { input: 'n\n' });
  assert.equal(r.code, 2);
  assert.match(r.err, /Aborted/);
  const closed = await run(['--url', base, '--anon-key', ANON_KEY]);
  assert.equal(closed.code, 2, 'must not hang or proceed when nobody can answer');
});

test('--json prints machine-readable result and exits 1 on critical findings', async () => {
  const r = await run(['--site', base, '--yes', '--json']);
  assert.equal(r.code, 1);
  const j = JSON.parse(r.out);
  assert.equal(j.grade, 'F');
  assert.ok(j.findings.length > 0);
  assert.ok(!('recipes' in j), 'internal pgTAP recipes stay out of --json');
  assert.ok(!('rulesRecipes' in j), 'internal rules-test recipes stay out of --json');
  assert.ok(!r.out.includes(ANON_KEY), 'keys never appear in output');
});

test('unknown flag is a usage error, not a crash trace', async () => {
  const r = await run(['--nope']);
  assert.equal(r.code, 2);
  assert.doesNotMatch(r.err, /at .*node:internal/);
});

test('grade is N/A when nothing was tested', () => {
  assert.equal(grade([], { tables: 0 }), 'N/A');
  assert.equal(grade([], { tables: 3 }), 'A');
});

test('cli: "no backend found" names the folder it looked in', async () => {
  const { execFileSync } = await import('node:child_process');
  const { mkdtempSync } = await import('node:fs');
  const { tmpdir } = await import('node:os');
  const { join } = await import('node:path');
  const empty = mkdtempSync(join(tmpdir(), 'ap-empty-'));
  let err = '';
  try {
    execFileSync(process.execPath, [new URL('../bin/accessprobe.js', import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1'), '--source', empty, '--yes'], { stdio: 'pipe' });
  } catch (e) {
    err = String(e.stderr);
  }
  assert.ok(err.includes(`No supported backend found`), err);
  assert.ok(err.includes(empty), err);
});
