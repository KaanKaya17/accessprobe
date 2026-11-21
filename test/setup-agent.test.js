import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const BIN = fileURLToPath(new URL('../bin/rlsprobe.js', import.meta.url));
const run = (cwd, ...args) => spawnSync(process.execPath, [BIN, 'setup-agent', ...args], { cwd, encoding: 'utf8' });

test('setup-agent installs the Claude Code skill and an AGENTS.md section, idempotently', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'rlsprobe-agent-'));
  try {
    await writeFile(join(dir, 'AGENTS.md'), '# My project\n\nUse pnpm.\n');
    const r1 = run(dir);
    assert.equal(r1.status, 0, r1.stderr);
    const skill = await readFile(join(dir, '.claude', 'skills', 'rlsprobe', 'SKILL.md'), 'utf8');
    assert.match(skill, /^---\r?\nname: rlsprobe\r?\ndescription: /);
    assert.ok(!skill.includes('\r'), 'shipped with LF line endings (see .gitattributes)');
    assert.match(skill, /Ask the user before deploying to production/);
    const agents = await readFile(join(dir, 'AGENTS.md'), 'utf8');
    assert.ok(agents.startsWith('# My project\n\nUse pnpm.'), 'existing content kept');
    assert.equal(agents.match(/## Security checks \(rlsprobe\)/g).length, 1);

    // second run: nothing duplicated or overwritten
    await writeFile(join(dir, '.claude', 'skills', 'rlsprobe', 'SKILL.md'), 'my edits');
    const r2 = run(dir);
    assert.equal(r2.status, 0);
    assert.match(r2.stdout, /kept existing/);
    assert.equal(await readFile(join(dir, '.claude', 'skills', 'rlsprobe', 'SKILL.md'), 'utf8'), 'my edits');
    assert.equal((await readFile(join(dir, 'AGENTS.md'), 'utf8')).match(/## Security checks \(rlsprobe\)/g).length, 1);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('an unknown command is a usage error', () => {
  const r = spawnSync(process.execPath, [BIN, 'nope'], { encoding: 'utf8' });
  assert.equal(r.status, 2);
});
