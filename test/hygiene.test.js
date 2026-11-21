import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));

test('source files contain no control characters (a stray \\b or \\0 silently breaks a regex)', () => {
  const bad = [];
  for (const dir of ['src', 'bin', 'test']) {
    for (const f of readdirSync(`${root}/${dir}`, { recursive: true })) {
      if (!/\.(js|mjs|json|rules|md|yml)$/.test(f)) continue;
      const t = readFileSync(`${root}/${dir}/${f}`, 'utf8');
      const m = t.match(/[\x00-\x08\x0b\x0c\x0e-\x1f]/);
      if (m) bad.push(`${dir}/${f}: ${JSON.stringify(m[0])}`);
    }
  }
  assert.deepEqual(bad, []);
});
