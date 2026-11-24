// Weekly upstream check (.github/workflows/upstream.yml): finds the newest stable Supabase CLI,
// firebase-tools, Appwrite and PocketBase releases, and rewrites test/versions.json when any of
// them is newer than the pin (PocketBase with the SHA-256 sums from the release's checksums.txt).
//
//   GH_TOKEN=... node test/upstream/bump.mjs [--dry-run]
//
// Writes a Markdown table of what changed to stdout (empty when nothing did), and, on GitHub
// Actions, `changed=<name old→new, …>` to $GITHUB_OUTPUT. Never downgrades.
import { readFileSync, writeFileSync, appendFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

const FILE = new URL('../versions.json', import.meta.url);
const dryRun = process.argv.includes('--dry-run');

async function get(url, { json = true } = {}) {
  const headers = { 'User-Agent': 'accessprobe-upstream-check' };
  if (url.startsWith('https://api.github.com/') && process.env.GH_TOKEN) headers.Authorization = `Bearer ${process.env.GH_TOKEN}`;
  const res = await fetch(url, { headers, redirect: 'follow', signal: AbortSignal.timeout(60000) });
  if (!res.ok) throw new Error(`${res.status} ${url}`);
  return json ? res.json() : res.text();
}

const latestTag = async (repo) => (await get(`https://api.github.com/repos/${repo}/releases/latest`)).tag_name.replace(/^v/, '');

/** 1 when a > b, -1 when a < b, 0 when equal; numeric x.y.z, anything with a pre-release tag is never newer. */
export function compare(a, b) {
  const pa = a.split('.').map(Number);
  const pb = b.split('.').map(Number);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = (pa[i] || 0) - (pb[i] || 0);
    if (d) return Math.sign(d);
  }
  return 0;
}
const stable = (v) => /^\d+(\.\d+)*$/.test(v);

/** checksums.txt lines are "<sha256>  pocketbase_<ver>_<os>_<arch>.zip" */
export function parseChecksums(text, version, keys) {
  const out = {};
  for (const line of text.split('\n')) {
    const m = line.trim().match(/^([0-9a-f]{64})\s+\*?pocketbase_(.+?)_(\w+_\w+)\.zip$/);
    if (m && m[2] === version && keys.includes(m[3])) out[m[3]] = m[1];
  }
  const missing = keys.filter((k) => !out[k]);
  if (missing.length) throw new Error(`PocketBase ${version} checksums.txt has no entry for ${missing.join(', ')}`);
  return out;
}

async function main() {
  const pins = JSON.parse(readFileSync(FILE, 'utf8'));
  const next = structuredClone(pins);
  const latest = {
    'supabase-cli': await latestTag('supabase/cli'),
    'firebase-tools': (await get('https://registry.npmjs.org/firebase-tools/latest')).version,
    appwrite: await latestTag('appwrite/appwrite'),
    pocketbase: await latestTag('pocketbase/pocketbase'),
  };
  const rows = [];
  for (const [name, newest] of Object.entries(latest)) {
    const current = name === 'pocketbase' ? pins.pocketbase.version : pins[name];
    if (!stable(newest) || compare(newest, current) <= 0) continue;
    if (name === 'pocketbase') {
      const sums = await get(`https://github.com/pocketbase/pocketbase/releases/download/v${newest}/checksums.txt`, { json: false });
      next.pocketbase = { version: newest, sha256: parseChecksums(sums, newest, Object.keys(pins.pocketbase.sha256)) };
    } else next[name] = newest;
    rows.push({ name, current, newest });
  }
  if (rows.length) {
    console.log('| | pinned | newest |\n|---|---|---|');
    for (const r of rows) console.log(`| ${r.name} | ${r.current} | **${r.newest}** |`);
    if (!dryRun) writeFileSync(FILE, `${JSON.stringify(next, null, 2)}\n`);
  }
  if (process.env.GITHUB_OUTPUT) {
    appendFileSync(process.env.GITHUB_OUTPUT, `changed=${rows.map((r) => `${r.name} ${r.current}→${r.newest}`).join(', ')}\n`);
  }
}

if (import.meta.url === `file:///${process.argv[1].replace(/\\/g, '/').replace(/^\//, '')}`) {
  main().catch((e) => {
    console.error(e.message);
    process.exit(1);
  });
}
