import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { compare, parseChecksums } from './upstream/bump.mjs';

const pins = JSON.parse(readFileSync(new URL('./versions.json', import.meta.url), 'utf8'));

test('upstream bump: numeric version order, never a downgrade', () => {
  assert.equal(compare('3.3.0', '3.2.0'), 1);
  assert.equal(compare('3.10.0', '3.9.9'), 1);
  assert.equal(compare('2.7.4', '2.7.4'), 0);
  assert.equal(compare('2.7', '2.7.1'), -1);
});

test('upstream bump: PocketBase checksums.txt gives a sum for every pinned platform', () => {
  const keys = Object.keys(pins.pocketbase.sha256);
  const v = pins.pocketbase.version;
  const text = keys.map((k) => `${pins.pocketbase.sha256[k]}  pocketbase_${v}_${k}.zip`).join('\n') + `\n${'0'.repeat(64)}  pocketbase_${v}_freebsd_amd64.zip\n`;
  assert.deepEqual(parseChecksums(text, v, keys), pins.pocketbase.sha256);
  assert.throws(() => parseChecksums(text, v, [...keys, 'plan9_amd64']), /no entry for plan9_amd64/);
  assert.throws(() => parseChecksums(text, '9.9.9', keys), /no entry/);
});
