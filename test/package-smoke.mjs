// CI smoke test of the PUBLISHED package: npm pack → install the tarball into an empty
// folder (exactly what `npx rlsprobe` does) → run the installed binary.
// Usage: node test/package-smoke.mjs
import { execFileSync, spawn } from 'node:child_process';
import { mkdtempSync, mkdirSync, readdirSync, existsSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createServer } from './mock-supabase.js';

const root = fileURLToPath(new URL('..', import.meta.url));
const isWin = process.platform === 'win32';
const npm = (args, cwd) => execFileSync(isWin ? 'npm.cmd' : 'npm', args, { cwd, encoding: 'utf8', shell: isWin });
const work = mkdtempSync(join(tmpdir(), 'rlsprobe-pkg-'));
const fail = (m) => {
  console.error(`✖ ${m}`);
  process.exit(1);
};

try {
  const tgz = npm(['pack', '--silent', '--pack-destination', work], root).trim().split('\n').pop();
  console.log(`packed ${tgz}`);
  const app = join(work, 'app');
  mkdirSync(app);
  writeFileSync(join(app, 'package.json'), '{"name":"smoke-app","private":true}');
  npm(['install', '--no-audit', '--no-fund', join(work, tgz)], app);

  const binDir = join(app, 'node_modules', '.bin');
  const bin = join(binDir, isWin ? 'rlsprobe.cmd' : 'rlsprobe');
  if (!existsSync(bin)) fail(`binary not installed at ${bin} (found: ${readdirSync(binDir).join(', ')})`);
  const run = (args, opts = {}) =>
    new Promise((resolve) => {
      const p = spawn(bin, args, { cwd: app, shell: isWin, env: { ...process.env, NO_COLOR: '1' }, ...opts });
      let out = '';
      let err = '';
      p.stdout.on('data', (d) => (out += d));
      p.stderr.on('data', (d) => (err += d));
      p.on('close', (code) => resolve({ code, out, err }));
    });

  const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
  const ver = await run(['--version']);
  if (ver.out.trim() !== pkg.version) fail(`--version printed "${ver.out.trim()}", expected ${pkg.version}`);
  console.log(`✔ --version ${pkg.version}`);

  const sa = await run(['setup-agent']);
  if (sa.code !== 0 || !existsSync(join(app, '.claude', 'skills', 'rlsprobe', 'SKILL.md')) || !existsSync(join(app, 'AGENTS.md')))
    fail(`setup-agent failed: ${sa.err || sa.out}`);
  console.log('✔ setup-agent installed the skill and AGENTS.md');

  // full scan through the installed binary, against the deliberately vulnerable mock
  const server = createServer();
  await new Promise((r) => server.listen(0, r));
  writeFileSync(join(app, '.env'), `VITE_SUPABASE_URL=http://localhost:${server.address().port}\nVITE_SUPABASE_ANON_KEY=${(await import('./mock-supabase.js')).ANON_KEY}\n`);
  const scan = await run(['--yes', '--json']);
  server.close();
  if (scan.code !== 1) fail(`zero-config scan exited ${scan.code}: ${scan.err.slice(-500)}`);
  const j = JSON.parse(scan.out);
  if (!j.findings.some((f) => f.id === 'cross-user-read')) fail('scan through the installed package found nothing');
  console.log(`✔ zero-config scan via installed binary: grade ${j.grade}, ${j.findings.length} findings`);

  const files = npm(['pack', '--dry-run', '--json'], root);
  const list = JSON.parse(files)[0].files.map((f) => f.path);
  for (const leak of list.filter((p) => /(^|\/)(test|private|\.github)\//.test(p) || /report\.md$/.test(p))) fail(`package must not ship ${leak}`);
  console.log(`✔ package contents clean (${list.length} files)`);
} finally {
  rmSync(work, { recursive: true, force: true });
}
