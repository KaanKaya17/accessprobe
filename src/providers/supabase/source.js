// Schema discovery from the project's own source code.
// Needed because hosted Supabase now serves the OpenAPI schema (/rest/v1/) only to the
// service_role key. Reads supabase/migrations/*.sql for full column info, and app code
// (.from("x"), "rest/v1/x", .rpc("x")) for table names.

import { readdir, readFile } from 'node:fs/promises';
import { join, extname } from 'node:path';

const SKIP_DIRS = new Set(['node_modules', '.git', 'build', 'dist', '.gradle', '.next', '.idea', '.vercel', 'out', 'coverage', '.turbo']);
const CODE_EXT = new Set(['.js', '.jsx', '.ts', '.tsx', '.mjs', '.vue', '.svelte', '.kt', '.java', '.dart', '.swift', '.py', '.go', '.rb', '.php', '.cs']);

export async function scanSource(dir) {
  const files = await walk(dir);
  const tables = new Map(); // name -> {columns, pkCols}
  const names = new Set();
  const rpcs = new Set();
  const sqlFiles = files.filter((f) => extname(f) === '.sql').sort();

  for (const f of sqlFiles) parseSql(await readFile(f, 'utf8'), tables);

  for (const f of files.filter((x) => CODE_EXT.has(extname(x)))) {
    const text = await readFile(f, 'utf8');
    for (const m of text.matchAll(/rest\/v1\/(?!rpc\/)([A-Za-z_]\w*)/g)) names.add(m[1]);
    for (const m of text.matchAll(/\.from\(\s*["'`]([A-Za-z_]\w*)["'`]\s*\)/g)) names.add(m[1]);
    for (const m of text.matchAll(/rest\/v1\/rpc\/([A-Za-z_]\w*)/g)) rpcs.add(m[1]);
    for (const m of text.matchAll(/\.rpc\(\s*["'`]([A-Za-z_]\w*)["'`]/g)) rpcs.add(m[1]);
  }
  for (const f of sqlFiles) {
    const text = await readFile(f, 'utf8');
    for (const m of text.matchAll(/create\s+(?:or\s+replace\s+)?function\s+(?:public\.)?"?(\w+)"?\s*\(/gi)) {
      // only functions granted to API roles are callable; keep the ones not revoked from authenticated
      const fn = m[1];
      if (new RegExp(`grant\\s+execute\\s+on\\s+function\\s+(?:public\\.)?${fn}\\b[^;]*to\\s+[^;]*(authenticated|anon)`, 'i').test(text)) rpcs.add(fn);
    }
  }
  // tables referenced in code but missing from migrations: names only
  for (const n of names) if (!tables.has(n)) tables.set(n, { columns: new Map(), pkCols: new Set(), nameOnly: true });

  return { tables, rpcs: [...rpcs], fileCount: files.length, sqlCount: sqlFiles.length };
}

// Convert to the same shape parseSchema() returns (minus owner, which schema.js guesses)
export function sourceToDefinitions(src) {
  const definitions = {};
  const paths = {};
  for (const [name, t] of src.tables) {
    const properties = {};
    const required = [];
    for (const [col, c] of t.columns) {
      let description = '';
      if (t.pkCols.has(col) || c.pk) description += '<pk/>';
      if (c.fk) description += `<fk table='${c.fk.table}' column='${c.fk.column}'/>`;
      properties[col] = { format: c.format, ...(description && { description }), ...(c.hasDefault && { default: 'db' }) };
      if (c.notNull && !c.hasDefault) required.push(col);
    }
    definitions[name] = { properties, required, 'x-name-only': Boolean(t.nameOnly), 'x-view': Boolean(t.isView) };
    paths[`/${name}`] = t.isView ? { get: {} } : { get: {}, post: {}, patch: {}, delete: {} };
  }
  for (const r of src.rpcs) paths[`/rpc/${r}`] = { post: {} };
  return { definitions, paths };
}

function parseSql(sql, tables) {
  const clean = sql.replace(/--[^\n]*/g, '');
  const createRe = /create\s+table\s+(?:if\s+not\s+exists\s+)?(?:public\.)?"?(\w+)"?\s*\(/gi;
  let m;
  while ((m = createRe.exec(clean))) {
    const body = balanced(clean, createRe.lastIndex - 1);
    if (body == null) continue;
    const t = tables.get(m[1]) || { columns: new Map(), pkCols: new Set() };
    for (const part of splitTop(body)) parseColumnOrConstraint(part.trim(), t);
    tables.set(m[1], t);
  }
  // views: only the name is needed, they are tested by looking for A's rows in their output
  const viewRe = /create\s+(?:or\s+replace\s+)?(?:temp(?:orary)?\s+)?(?:recursive\s+)?view\s+(?:if\s+not\s+exists\s+)?(?:public\.)?"?(\w+)"?/gi;
  while ((m = viewRe.exec(clean))) {
    if (!tables.has(m[1])) tables.set(m[1], { columns: new Map(), pkCols: new Set(), nameOnly: true, isView: true });
  }
  const alterRe = /alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?(?:public\.)?"?(\w+)"?\s+([^;]+);/gi;
  while ((m = alterRe.exec(clean))) {
    const t = tables.get(m[1]);
    if (!t) continue;
    for (const part of splitTop(m[2])) {
      const a = part.trim().match(/^add\s+column\s+(?:if\s+not\s+exists\s+)?(.*)$/is);
      if (a) parseColumnOrConstraint(a[1], t);
    }
  }
}

function parseColumnOrConstraint(def, t) {
  if (!def) return;
  const low = def.toLowerCase();
  const pkTable = low.match(/^(?:constraint\s+\w+\s+)?primary\s+key\s*\(([^)]+)\)/);
  if (pkTable) {
    pkTable[1].split(',').forEach((c) => t.pkCols.add(c.trim().replace(/"/g, '')));
    return;
  }
  const fkTable = def.match(/^(?:constraint\s+\w+\s+)?foreign\s+key\s*\(\s*"?(\w+)"?\s*\)\s*references\s+(?:"?(\w+)"?\.)?"?(\w+)"?\s*\(\s*"?(\w+)"?\s*\)/i);
  if (fkTable) {
    const c = t.columns.get(fkTable[1]);
    if (c) c.fk = { table: fkName(fkTable[2], fkTable[3]), column: fkTable[4] };
    return;
  }
  if (/^(constraint|unique|check|exclude|foreign\s+key)\b/i.test(def)) return;
  const cm = def.match(/^"?(\w+)"?\s+(.+)$/s);
  if (!cm) return;
  const [, name, rest] = cm;
  const r = rest.toLowerCase();
  const ref = rest.match(/references\s+(?:"?(\w+)"?\.)?"?(\w+)"?\s*(?:\(\s*"?(\w+)"?\s*\))?/i);
  t.columns.set(name, {
    format: normalizeType(r),
    notNull: /\bnot\s+null\b/.test(r) || /\bprimary\s+key\b/.test(r),
    hasDefault: /\bdefault\b|\bgenerated\b|^(big|small)?serial\b/.test(r),
    pk: /\bprimary\s+key\b/.test(r),
    fk: ref ? { table: fkName(ref[1], ref[2]), column: ref[3] || 'id' } : null,
  });
}

// public.users -> "users"; auth.users -> "auth.users"
function fkName(schema, table) {
  return !schema || schema.toLowerCase() === 'public' ? table : `${schema}.${table}`;
}

function normalizeType(r) {
  if (/^(big)?serial/.test(r)) return r.startsWith('big') ? 'bigint' : 'integer';
  if (/^(character varying|varchar)/.test(r)) return 'character varying';
  if (/^timestamptz|^timestamp\s+with\s+time\s+zone/.test(r)) return 'timestamp with time zone';
  if (/^timestamp/.test(r)) return 'timestamp without time zone';
  if (/^int8|^bigint/.test(r)) return 'bigint';
  if (/^int4|^integer|^int\b/.test(r)) return 'integer';
  if (/^int2|^smallint/.test(r)) return 'smallint';
  if (/^(float8|double precision)/.test(r)) return 'double precision';
  if (/^(float4|real)/.test(r)) return 'real';
  if (/^(numeric|decimal)/.test(r)) return 'numeric';
  if (/^bool/.test(r)) return 'boolean';
  const w = r.match(/^(\w+)/);
  return w ? w[1] : 'text';
}

function balanced(s, openIdx) {
  let depth = 0;
  for (let i = openIdx; i < s.length; i++) {
    if (s[i] === '(') depth++;
    else if (s[i] === ')') {
      depth--;
      if (depth === 0) return s.slice(openIdx + 1, i);
    }
  }
  return null;
}

function splitTop(s) {
  const out = [];
  let depth = 0;
  let cur = '';
  for (const ch of s) {
    if (ch === '(') depth++;
    if (ch === ')') depth--;
    if (ch === ',' && depth === 0) {
      out.push(cur);
      cur = '';
    } else cur += ch;
  }
  if (cur.trim()) out.push(cur);
  return out;
}

async function walk(dir, out = []) {
  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch {
    return out;
  }
  for (const e of entries) {
    if (e.isDirectory()) {
      if (!SKIP_DIRS.has(e.name) && !e.name.startsWith('.')) await walk(join(dir, e.name), out);
      else if (e.name === '.github') continue;
    } else if (e.isFile()) {
      const p = join(dir, e.name);
      if (CODE_EXT.has(extname(p)) || extname(p) === '.sql') out.push(p);
    }
  }
  return out.filter((p) => p.length < 4096).slice(0, 20000);
}

