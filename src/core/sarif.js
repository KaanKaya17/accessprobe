// --sarif: the findings as SARIF 2.1.0, for GitHub code scanning (github/codeql-action/upload-sarif)
// and other SARIF viewers. Each finding is placed on the line that defines the leaking rule:
// the newest policy (or the CREATE TABLE) for a Supabase table, the `match` block in
// firestore.rules / storage.rules, the node in database.rules.json, the collection in pb_migrations
// or appwrite.json. Accepted findings (.accessprobeignore) are left out.

import { readdir, readFile } from 'node:fs/promises';
import { existsSync, readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join, relative, resolve, dirname, basename } from 'node:path';
import { resourceOf } from './accept.js';

const SKIP = new Set(['node_modules', '.git', 'dist', 'build', '.next', '.svelte-kit', 'coverage', '.turbo', '.vercel']);
const LEVEL = { critical: 'error', warning: 'warning', info: 'note' };
const SECURITY_SEVERITY = { critical: '9.1', warning: '5.3', info: '2.0' };
const RANK = { critical: 3, warning: 2, info: 1 };

const esc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

// what a rules / schema file is for, by its name and folder
function kindOf(path) {
  const name = basename(path);
  const p = path.replace(/\\/g, '/');
  if (name.endsWith('.sql')) return 'sql';
  if (name === 'firestore.rules' || name === 'storage.rules') return 'rules';
  if (name === 'database.rules.json') return 'rtdb';
  if (/(^|\/)pb_migrations\/[^/]+\.(js|ts)$/.test(p)) return 'pb';
  if (name === 'appwrite.json' || name === 'appwrite.config.json') return 'appwrite';
  if (/^\.env/.test(name)) return 'env';
  return null;
}

async function walk(dir, out = [], depth = 0) {
  if (depth > 8) return out;
  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch {
    return out;
  }
  for (const e of entries) {
    if (SKIP.has(e.name)) continue;
    const p = join(dir, e.name);
    if (e.isDirectory()) await walk(p, out, depth + 1);
    else if (kindOf(p)) out.push(p);
  }
  return out;
}

// the repository root, so locations resolve in the checkout (the action may run in a subfolder)
function repoRoot(from) {
  let d = resolve(from);
  for (;;) {
    if (existsSync(join(d, '.git'))) return d;
    const up = dirname(d);
    if (up === d) return resolve(from);
    d = up;
  }
}

// the name to look for: "users/{uid}/notes" → "notes", "public.orders" → "orders", "db/coll" → "coll"
function needle(resource) {
  const parts = String(resource).split('/').filter((s) => s && !/^[{$]/.test(s) && !s.endsWith('}'));
  const last = parts.at(-1) || String(resource);
  return last.replace(/^public\./, '').replace(/"/g, '');
}

// the SQL command a finding is about: a read leak points at the SELECT policy, not the newest one
function commandOf(id = '') {
  if (/delete/.test(id)) return 'delete';
  if (/update|takeover|escalation/.test(id)) return 'update';
  if (/insert|create|forge|impersonat|write|upload/.test(id)) return 'insert';
  if (/read|list|sees|public/.test(id)) return 'select';
  return null;
}

function patternsFor(kind, name, id) {
  const n = esc(name);
  const ident = `(?:[\\w"]+\\.)?"?${n}"?`;
  const policy = `create\\s+policy[^;]{0,300}?\\bon\\s+${ident}(?![\\w"])`;
  const cmd = commandOf(id);
  switch (kind) {
    case 'sql':
      // newest matching policy wins (files are read in migration order, the last match is kept)
      return [
        ...(cmd ? [{ re: new RegExp(`${policy}[^;]{0,120}?\\bfor\\s+(?:${cmd}|all)\\b`, 'i'), last: true }] : []),
        { re: new RegExp(policy, 'i'), last: true },
        { re: new RegExp(`bucket_id\\s*=\\s*'${n}'`, 'i'), last: true },
        { re: new RegExp(`alter\\s+table\\s+(?:only\\s+)?${ident}\\s+enable\\s+row\\s+level\\s+security`, 'i'), last: true },
        { re: new RegExp(`create\\s+(?:or\\s+replace\\s+)?(?:table|view|function)\\s+(?:if\\s+not\\s+exists\\s+)?${ident}(?![\\w"])`, 'i'), last: false },
      ];
    case 'rules':
      return [{ re: new RegExp(`match\\s+/${n}(?:/|\\s|\\{)`), last: false }];
    case 'rtdb':
      return [{ re: new RegExp(`"${n}"\\s*:`), last: false }];
    case 'pb':
    case 'appwrite':
      return [{ re: new RegExp(`["'\`]${n}["'\`]`), last: false }];
    case 'env':
      return [{ re: new RegExp(`^\\s*${n}\\s*=`, 'm'), last: false }];
    default:
      return [];
  }
}

const KINDS = { supabase: ['sql'], firebase: ['rules', 'rtdb'], pocketbase: ['pb'], appwrite: ['appwrite', 'env'] };

function lineOf(text, index) {
  return text.slice(0, index).split('\n').length;
}

export async function makeLocator({ source, extraFiles = [] } = {}) {
  const root = repoRoot(source || '.');
  let found = await walk(resolve(source || '.'));
  // with a migrations folder, other .sql files (seeds, tests, scratch fixes) don't define the schema
  const inMigrations = (p) => /[\\/]migrations[\\/][^\\/]+\.sql$/.test(p);
  if (found.some(inMigrations)) found = found.filter((p) => !p.endsWith('.sql') || inMigrations(p));
  const files = [...found, ...extraFiles.filter(Boolean).map((p) => resolve(p))];
  const unique = [...new Set(files)].sort(); // migrations sort by their timestamp prefix
  const texts = [];
  for (const f of unique) {
    try {
      texts.push({ file: f, kind: kindOf(f) || (f.endsWith('.sql') ? 'sql' : f.endsWith('.json') ? 'rtdb' : 'rules'), text: await readFile(f, 'utf8') });
    } catch {
      /* unreadable: skip */
    }
  }
  const uri = (f) => relative(root, f).replace(/\\/g, '/');
  const fallbackFile = ['package.json', 'README.md'].map((f) => join(root, f)).find((f) => existsSync(f));

  return function locate(f) {
    const res = resourceOf(f);
    const kinds = KINDS[f.platform] || Object.values(KINDS).flat();
    // a leaked key in a file: that file
    if (res && texts.some((t) => uri(t.file) === res || t.file.endsWith(res))) {
      const t = texts.find((x) => uri(x.file) === res || x.file.endsWith(res));
      return { uri: uri(t.file), line: 1 };
    }
    if (res) {
      const name = needle(res);
      const pool = texts.filter((t) => kinds.includes(t.kind));
      for (const kind of kinds) {
        for (const { re, last } of patternsFor(kind, name, f.id)) {
          let hit = null;
          for (const t of pool.filter((x) => x.kind === kind)) {
            const all = [...t.text.matchAll(new RegExp(re.source, re.flags.includes('g') ? re.flags : `${re.flags}g`))];
            const m = last ? all.at(-1) : all[0];
            if (m) {
              hit = { uri: uri(t.file), line: lineOf(t.text, m.index) };
              if (!last) break;
            }
          }
          if (hit) return hit;
        }
      }
    }
    // no resource, or not found: the backend's first schema / rules file, so the alert still lands in the repo
    const first = texts.find((t) => kinds.includes(t.kind)) || (!fallbackFile && texts[0]);
    if (first) return { uri: uri(first.file), line: 1 };
    if (fallbackFile) return { uri: uri(fallbackFile), line: 1 };
    return null;
  };
}

const humanize = (id) => id.replace(/-/g, ' ').replace(/^./, (c) => c.toUpperCase());

export function sarifReport(result, locate) {
  const version = JSON.parse(readFileSync(new URL('../../package.json', import.meta.url), 'utf8')).version;
  const rules = new Map();
  for (const f of result.findings) {
    const r = rules.get(f.id);
    if (!r || RANK[f.severity] > RANK[r.severity]) rules.set(f.id, { severity: f.severity, detail: r?.detail || f.detail });
  }
  const results = result.findings.map((f) => {
    const loc = locate(f);
    const res = resourceOf(f) ?? '';
    const proof = f.evidence ? ` Proof: ${f.evidence}` : '';
    return {
      ruleId: f.id,
      level: LEVEL[f.severity] || 'warning',
      message: { text: `${f.title}. ${f.detail}${proof}` },
      ...(loc && {
        locations: [{ physicalLocation: { artifactLocation: { uri: loc.uri }, region: { startLine: loc.line } } }],
      }),
      partialFingerprints: {
        'accessprobe/v1': createHash('sha256').update(`${f.platform || ''}|${res}|${f.id}`).digest('hex').slice(0, 32),
      },
      properties: { severity: f.severity, ...(f.platform && { platform: f.platform }), ...(res && { resource: res }) },
    };
  });
  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'accessprobe',
            version,
            semanticVersion: version,
            informationUri: 'https://github.com/KaanKaya17/accessprobe',
            rules: [...rules].map(([id, r]) => ({
              id,
              name: id.replace(/(^|-)(\w)/g, (_, _d, c) => c.toUpperCase()),
              shortDescription: { text: humanize(id) },
              fullDescription: { text: r.detail },
              help: {
                text: 'Proven with real requests by two test users. Run accessprobe with --out report.md for the fix (SQL / rules) and a copy-paste AI prompt.',
                markdown: 'Proven with real requests by two test users. Run `accessprobe --out report.md` for the fix (SQL / rules) and a copy-paste AI prompt. To mark it as open on purpose, add it to `.accessprobeignore`.',
              },
              defaultConfiguration: { level: LEVEL[r.severity] || 'warning' },
              properties: { tags: ['security', 'access-control'], 'security-severity': SECURITY_SEVERITY[r.severity] || '5.3' },
            })),
          },
        },
        automationDetails: { id: 'accessprobe/' },
        invocations: [{ executionSuccessful: true, endTimeUtc: result.date }],
        results,
      },
    ],
  };
}
