// `rlsprobe setup-agent`: teach the AI coding agent in this project how to use rlsprobe safely.
//   .claude/skills/rlsprobe/SKILL.md  (Claude Code)
//   AGENTS.md section                 (Codex, Cursor, Copilot agents, … read AGENTS.md)
// Never overwrites: an existing skill file is left alone, the AGENTS.md section is added once.

import { readFile, writeFile, mkdir, access } from 'node:fs/promises';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const pkgRoot = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const MARK = '## Security checks (rlsprobe)';
const exists = (p) => access(p).then(() => true, () => false);

export async function setupAgent(dir = process.cwd(), { force = false } = {}) {
  const done = [];
  const skillSrc = join(pkgRoot, 'integrations', 'claude-code', 'rlsprobe', 'SKILL.md');
  const skillDst = join(dir, '.claude', 'skills', 'rlsprobe', 'SKILL.md');
  if ((await exists(skillDst)) && !force) {
    done.push(`kept existing ${rel(dir, skillDst)} (use --force to replace)`);
  } else {
    await mkdir(dirname(skillDst), { recursive: true });
    await writeFile(skillDst, await readFile(skillSrc, 'utf8'));
    done.push(`wrote ${rel(dir, skillDst)}  (Claude Code skill)`);
  }

  const snippet = await readFile(join(pkgRoot, 'integrations', 'AGENTS.snippet.md'), 'utf8');
  const agents = join(dir, 'AGENTS.md');
  const current = (await exists(agents)) ? await readFile(agents, 'utf8') : null;
  if (current?.includes(MARK)) {
    done.push('AGENTS.md already has the rlsprobe section');
  } else {
    await writeFile(agents, current ? `${current.replace(/\s*$/, '')}\n\n${snippet}` : `# Agent notes\n\n${snippet}`);
    done.push(`${current ? 'added the rlsprobe section to' : 'created'} AGENTS.md  (Codex, Cursor and other agents)`);
  }
  return done;
}

function rel(dir, p) {
  return p.slice(dir.length).replace(/^[\\/]/, '').replace(/\\/g, '/');
}
