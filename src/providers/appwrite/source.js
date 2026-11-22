// What the project folder tells us about an Appwrite app: appwrite.json / appwrite.config.json
// (project id, endpoint, databases, collections with attributes and permissions, buckets), the
// endpoint and project from `new Client().setEndpoint("…").setProject("…")` or env vars, and the
// database / collection / bucket ids used in code (databases.createDocument("db", "notes", …)).

import { readdir, readFile } from 'node:fs/promises';
import { join, extname, basename, relative } from 'node:path';
import { readConfig, CONFIG_FILES } from './config.js';

const SKIP_DIRS = new Set(['node_modules', '.git', 'build', 'dist', '.next', '.nuxt', '.svelte-kit', '.idea', '.dart_tool', 'Pods', 'out', 'coverage']);
const CODE_EXT = new Set(['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.vue', '.svelte', '.astro', '.dart', '.kt', '.swift']);
const Q = '["\'`]';
const ID = '([\\w.-]{1,36})';

const ENDPOINT = new RegExp(`\\.setEndpoint\\(\\s*${Q}(https?:\\/\\/[^"'\`\\s]+?)\\/?${Q}\\s*\\)`, 'g');
const PROJECT = new RegExp(`\\.setProject\\(\\s*${Q}${ID}${Q}\\s*\\)`, 'g');
const USES_SDK = /from\s+["'](?:appwrite|node-appwrite|react-native-appwrite)["']|require\(\s*["'](?:appwrite|node-appwrite)["']\s*\)|package:(?:appwrite|dart_appwrite)\/|io\.appwrite\.|import\s+Appwrite\b|\.setProject\(\s*["'`]/;
// databases.createDocument("db", "notes", …), tablesDB.listRows("db", "notes")
const POSITIONAL = new RegExp(`\\.(?:create|list|get|update|upsert|delete)(?:Document|Documents|Row|Rows)\\(\\s*${Q}${ID}${Q}\\s*,\\s*${Q}${ID}${Q}`, 'g');
// the object style of the newer SDKs: createRow({ databaseId: "db", tableId: "notes", … })
const NAMED = new RegExp(`databaseId\\s*:\\s*${Q}${ID}${Q}\\s*,\\s*(collectionId|tableId)\\s*:\\s*${Q}${ID}${Q}`, 'g');
const BUCKET = new RegExp(`\\.(?:createFile|getFile|getFileView|getFilePreview|getFileDownload|listFiles|deleteFile|updateFile)\\(\\s*(?:\\{\\s*bucketId\\s*:\\s*)?${Q}${ID}${Q}`, 'g');
// attribute names A's document can carry: keys of the object passed to createDocument
const CREATE_PAYLOAD = new RegExp(`\\.create(?:Document|Row)\\(\\s*${Q}${ID}${Q}\\s*,\\s*${Q}${ID}${Q}\\s*,\\s*[^,]+,\\s*\\{([^{}]{0,800})\\}`, 'g');

const PREFIX = '(?:VITE_|NEXT_PUBLIC_|PUBLIC_|REACT_APP_|EXPO_PUBLIC_|NUXT_PUBLIC_)?';
const ENV_ENDPOINT = new RegExp(`^\\s*(?:export\\s+)?${PREFIX}APPWRITE_(?:ENDPOINT|URL|API_ENDPOINT|HOST|API_URL)\\s*=\\s*["']?(https?:\\/\\/[^\\s"'#]+?)\\/?["']?\\s*$`, 'gm');
const ENV_PROJECT = new RegExp(`^\\s*(?:export\\s+)?${PREFIX}APPWRITE_PROJECT(?:_ID)?\\s*=\\s*["']?${ID}["']?\\s*$`, 'gm');
const ENV_DB = new RegExp(`^\\s*(?:export\\s+)?${PREFIX}(?:APPWRITE_)?DATABASE(?:_ID)?\\s*=\\s*["']?${ID}["']?\\s*$`, 'gm');
const ENV_COLL = new RegExp(`^\\s*(?:export\\s+)?${PREFIX}(?:APPWRITE_)?(?:\\w+_)?(?:COLLECTION|TABLE)(?:_ID)?(?:_\\w+)?\\s*=\\s*["']?${ID}["']?\\s*$`, 'gm');
const ENV_BUCKET = new RegExp(`^\\s*(?:export\\s+)?${PREFIX}(?:APPWRITE_)?(?:\\w+_)?BUCKET(?:_ID)?(?:_\\w+)?\\s*=\\s*["']?${ID}["']?\\s*$`, 'gm');
// a server API key in a browser-exposed variable
const ENV_PUBLIC_KEY = /^\s*(?:export\s+)?((?:VITE_|NEXT_PUBLIC_|PUBLIC_|REACT_APP_|EXPO_PUBLIC_|NUXT_PUBLIC_)\w*APPWRITE\w*(?:KEY|SECRET)\w*)\s*=\s*["']?([^\s"'#]{20,})["']?\s*$/gm;

const uniq = (a) => [...new Set(a)];

// endpoint, project, collection and bucket ids in any text (site bundle or source file)
export function fromCode(text) {
  const usesSdk = USES_SDK.test(text);
  const out = { endpoints: [], projects: [], collections: [], buckets: [], attributes: {}, usesSdk };
  if (!usesSdk) return out;
  out.endpoints = uniq([...text.matchAll(ENDPOINT)].map((m) => m[1]));
  out.projects = uniq([...text.matchAll(PROJECT)].map((m) => m[1]));
  const coll = [...text.matchAll(POSITIONAL)].map((m) => ({ db: m[1], id: m[2], mode: /Row/.test(m[0]) ? 'rows' : 'documents' }));
  for (const m of text.matchAll(NAMED)) coll.push({ db: m[1], id: m[3], mode: m[2] === 'tableId' ? 'rows' : 'documents' });
  const seen = new Set();
  for (const c of coll) {
    const k = `${c.db}/${c.id}`;
    if (!seen.has(k)) {
      seen.add(k);
      out.collections.push(c);
    }
  }
  out.buckets = uniq([...text.matchAll(BUCKET)].map((m) => m[1]));
  for (const m of text.matchAll(CREATE_PAYLOAD)) {
    // { title: t, done: false } and the shorthand { text, done }
    const keys = m[3].split(',').map((seg) => /^\s*["']?([A-Za-z_]\w{0,35})["']?\s*(?::|$)/.exec(seg)?.[1]).filter(Boolean);
    const k = `${m[1]}/${m[2]}`;
    out.attributes[k] = uniq([...(out.attributes[k] || []), ...keys]);
  }
  return out;
}

export async function scanSource(dir) {
  const out = { endpoints: new Set(), projects: new Set(), collections: new Map(), buckets: new Set(), attributes: {}, usesSdk: false, configs: [], envDb: new Set(), envCollections: new Set(), leakedEnvKeys: [], files: 0 };
  for (const f of await walk(dir)) {
    out.files++;
    const name = basename(f);
    if (CONFIG_FILES.includes(name)) {
      try {
        out.configs.push(readConfig(await readFile(f, 'utf8'), relative(dir, f).replace(/\\/g, '/') || name));
      } catch {
        /* not ours / broken JSON: ignore */
      }
      continue;
    }
    if (/^\.env/.test(name)) {
      const text = await readFile(f, 'utf8');
      for (const m of text.matchAll(ENV_ENDPOINT)) out.endpoints.add(m[1]);
      for (const m of text.matchAll(ENV_PROJECT)) out.projects.add(m[1]);
      for (const m of text.matchAll(ENV_DB)) out.envDb.add(m[1]);
      for (const m of text.matchAll(ENV_COLL)) out.envCollections.add(m[1]);
      for (const m of text.matchAll(ENV_BUCKET)) out.buckets.add(m[1]);
      for (const m of text.matchAll(ENV_PUBLIC_KEY)) out.leakedEnvKeys.push({ file: relative(dir, f).replace(/\\/g, '/'), name: m[1] });
      continue;
    }
    if (CODE_EXT.has(extname(f))) {
      const c = fromCode(await readFile(f, 'utf8'));
      if (!c.usesSdk) continue;
      out.usesSdk = true;
      c.endpoints.forEach((u) => out.endpoints.add(u));
      c.projects.forEach((p) => out.projects.add(p));
      for (const x of c.collections) out.collections.set(`${x.db}/${x.id}`, x);
      c.buckets.forEach((b) => out.buckets.add(b));
      for (const [k, v] of Object.entries(c.attributes)) out.attributes[k] = uniq([...(out.attributes[k] || []), ...v]);
    }
  }
  const cfg = out.configs;
  for (const c of cfg) {
    if (c.endpoint) out.endpoints.add(c.endpoint);
    if (c.projectId) out.projects.add(c.projectId);
  }
  // one database (in the config, or the env) is the default for bare --table names
  const dbs = uniq([...cfg.flatMap((c) => c.databases.map((d) => d.id)), ...cfg.flatMap((c) => c.collections.map((x) => x.db)), ...out.envDb]);
  return {
    endpoints: [...out.endpoints],
    projects: [...out.projects],
    configs: cfg,
    configFiles: cfg.map((c) => c.file),
    collections: cfg.length ? cfg.flatMap((c) => c.collections) : null,
    buckets: cfg.flatMap((c) => c.buckets),
    codeCollections: [...out.collections.values()],
    codeBuckets: [...out.buckets],
    envCollections: [...out.envCollections],
    attributes: out.attributes,
    databases: dbs,
    usesSdk: out.usesSdk,
    leakedEnvKeys: out.leakedEnvKeys,
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
    } else if (e.isFile() && (CODE_EXT.has(extname(p)) || /^\.env/.test(e.name) || CONFIG_FILES.includes(e.name))) out.push(p);
    if (out.length > 20000) break;
  }
  return out;
}
