// What the project folder tells us about a PocketBase app: pb_migrations/*.js (collections
// and API rules), the server URL (new PocketBase("…") or a POCKETBASE_URL env var) and the
// collection names used in code (pb.collection("posts")).

import { readdir, readFile } from 'node:fs/promises';
import { join, extname, basename, relative } from 'node:path';
import { readMigrations } from './migrations.js';

const SKIP_DIRS = new Set(['node_modules', '.git', 'build', 'dist', '.next', '.nuxt', '.svelte-kit', '.idea', '.dart_tool', 'Pods', 'out', 'coverage', 'pb_data']);
const CODE_EXT = new Set(['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.vue', '.svelte', '.astro', '.dart']);

const SDK_URL = /new\s+PocketBase\s*\(\s*["'`](https?:\/\/[^"'`\s]+?)\/?["'`]/g;
const ENV_URL = /^\s*(?:export\s+)?(?:VITE_|NEXT_PUBLIC_|PUBLIC_|REACT_APP_|EXPO_PUBLIC_|NUXT_PUBLIC_)?(?:POCKETBASE|PB)_(?:URL|API_URL|HOST|API)\s*=\s*["']?(https?:\/\/[^\s"'#]+?)\/?["']?\s*$/gm;
const USES_SDK = /from\s+["']pocketbase["']|require\(\s*["']pocketbase["']\s*\)|new\s+PocketBase\s*\(|package:pocketbase\//;
const COLLECTION = /\.collection\(\s*["'`]([\w-]+)["'`]\s*\)/g;

// URLs + collection names in any text (site bundle or source file)
export function fromCode(text) {
  return {
    urls: [...text.matchAll(SDK_URL)].map((m) => m[1]),
    collections: USES_SDK.test(text) ? [...text.matchAll(COLLECTION)].map((m) => m[1]) : [],
    usesSdk: USES_SDK.test(text),
  };
}

export async function scanSource(dir) {
  const out = { urls: new Set(), collections: new Set(), usesSdk: false, migrationFiles: [], migrationsDirs: new Set(), files: 0 };
  const sdkTexts = []; // files that import / construct the SDK
  const otherTexts = []; // files that may only receive the client (pb.collection("x"))
  for (const f of await walk(dir)) {
    out.files++;
    const name = basename(f);
    const parent = basename(join(f, '..'));
    if (parent === 'pb_migrations' && /\.(js|ts)$/.test(name)) {
      out.migrationFiles.push({ name, text: await readFile(f, 'utf8') });
      out.migrationsDirs.add(relative(dir, join(f, '..')).replace(/\\/g, '/') || '.');
      continue;
    }
    if (/^\.env/.test(name)) {
      const text = await readFile(f, 'utf8');
      for (const m of text.matchAll(ENV_URL)) out.urls.add(m[1]);
      continue;
    }
    if (CODE_EXT.has(extname(f))) {
      const text = await readFile(f, 'utf8');
      const c = fromCode(text);
      if (c.usesSdk) out.usesSdk = true;
      c.urls.forEach((u) => out.urls.add(u));
      // collection names only count in files that use the SDK (Firebase has .collection() too)
      if (c.usesSdk) sdkTexts.push(text);
      else if (/\bpb\.collection\(/.test(text)) otherTexts.push(text);
    }
  }
  for (const t of sdkTexts) for (const m of t.matchAll(COLLECTION)) out.collections.add(m[1]);
  // a file that only receives the client (pb.collection("x")) counts once the app uses the SDK
  if (out.usesSdk) for (const t of otherTexts) for (const m of t.matchAll(/\bpb\.collection\(\s*["'`]([\w-]+)["'`]\s*\)/g)) out.collections.add(m[1]);
  return {
    urls: [...out.urls],
    codeCollections: [...out.collections],
    usesSdk: out.usesSdk,
    migrationsDirs: [...out.migrationsDirs],
    migrationCount: out.migrationFiles.length,
    collections: out.migrationFiles.length ? readMigrations(out.migrationFiles) : null,
    files: out.files,
  };
}

async function walk(dir, out = []) {
  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch {
    return out;
  }
  for (const e of entries) {
    const p = join(dir, e.name);
    if (e.isDirectory()) {
      if (!SKIP_DIRS.has(e.name) && !e.name.startsWith('.')) await walk(p, out);
    } else if (e.isFile() && (CODE_EXT.has(extname(p)) || /^\.env/.test(e.name))) out.push(p);
    if (out.length > 20000) break;
  }
  return out;
}
