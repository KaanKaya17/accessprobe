// A small parser for firestore.rules / storage.rules — only what accessprobe needs:
// which paths exist, which allow-conditions apply, and how ownership is expressed.
// It never decides that something is safe; that is what the live tests are for.

export function parseRules(text) {
  const src = stripComments(text);
  const fns = functions(src);
  const matches = [];
  walk(src, 0, src.length, '', matches);
  return matches.map((m) => ({
    path: normalizeRoot(m.path),
    allows: m.allows.map((a) => ({ ...a, cond: inline(a.cond, fns) })),
  }));
}

// function isOwner(uid) { return request.auth.uid == uid; }
function functions(src) {
  const out = {};
  for (const m of src.matchAll(/\bfunction\s+(\w+)\s*\(([^)]*)\)\s*\{\s*return\s+([\s\S]*?);\s*\}/g)) {
    out[m[1]] = { params: m[2].split(',').map((p) => p.trim()).filter(Boolean), body: m[3].replace(/\s+/g, ' ').trim() };
  }
  return out;
}

// replace calls to rule functions by their body (a few passes for nested helpers)
function inline(cond, fns) {
  let c = cond;
  for (let pass = 0; pass < 4; pass++) {
    const before = c;
    for (const [name, f] of Object.entries(fns)) {
      c = c.replace(new RegExp(`\\b${name}\\(([^()]*)\\)`, 'g'), (_, argStr) => {
        const args = argStr.split(',').map((a) => a.trim());
        let body = f.body;
        f.params.forEach((p, i) => {
          body = body.replace(new RegExp(`\\b${p}\\b`, 'g'), args[i] ?? p);
        });
        return `(${body})`;
      });
    }
    if (c === before) break;
  }
  return c;
}

// "/databases/{database}/documents/users/{uid}" -> "/users/{uid}"; storage "/b/{bucket}/o/x" -> "/x"
function normalizeRoot(path) {
  const p = path.replace(/^\/databases\/\{[^}]+\}\/documents/, '').replace(/^\/b\/\{[^}]+\}\/o/, '');
  return p === '' ? '/' : p;
}

function walk(s, from, to, prefix, out) {
  const re = /\bmatch\s+(\/[^\s{]*(?:\{[^}]*\}[^\s{]*)*)\s*\{/g;
  re.lastIndex = from;
  let i = from;
  const own = { path: prefix || '/', allows: [] };
  let m;
  while ((m = re.exec(s)) && m.index < to) {
    collectAllows(s.slice(i, m.index), own);
    const open = m.index + m[0].length - 1;
    const close = matchBrace(s, open);
    if (close < 0 || close > to) break;
    walk(s, open + 1, close, joinPath(prefix, m[1]), out);
    i = close + 1;
    re.lastIndex = i;
  }
  collectAllows(s.slice(i, to), own);
  if (prefix && own.allows.length) out.push(own);
}

function collectAllows(chunk, own) {
  const re = /\ballow\s+([a-z,\s]+?)\s*(?::\s*if\s+([\s\S]*?))?;/g;
  let m;
  while ((m = re.exec(chunk))) {
    const ops = m[1].split(/[\s,]+/).filter(Boolean);
    own.allows.push({ ops, cond: (m[2] ?? 'true').replace(/\s+/g, ' ').trim() });
  }
}

function joinPath(a, b) {
  return (a + b).replace(/\/{2,}/g, '/');
}

function matchBrace(s, open) {
  let depth = 0;
  for (let i = open; i < s.length; i++) {
    if (s[i] === '{') depth++;
    else if (s[i] === '}' && --depth === 0) return i;
  }
  return -1;
}

function stripComments(t) {
  return t.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/[^\n]*/g, '');
}

// ---------- interpretation helpers ----------

// expand "read" -> get,list and "write" -> create,update,delete
export function allowsFor(match, op) {
  const fam = { get: 'read', list: 'read', create: 'write', update: 'write', delete: 'write' }[op];
  return match.allows.filter((a) => a.ops.includes(op) || a.ops.includes(fam)).map((a) => a.cond);
}

// Field that holds the owner's uid, e.g. resource.data.ownerId == request.auth.uid
export function ownerField(match) {
  const conds = match.allows.map((a) => a.cond).join(' || ');
  const m =
    conds.match(/(?:request\.)?resource\.data\.(\w+)\s*==\s*request\.auth\.uid/) ||
    conds.match(/request\.auth\.uid\s*==\s*(?:request\.)?resource\.data\.(\w+)/);
  return m ? m[1] : null;
}

// Path variable that must equal the caller's uid, e.g. match /users/{uid} ... request.auth.uid == uid
export function ownerPathVar(match) {
  const vars = [...match.path.matchAll(/\{(\w+)\}/g)].map((x) => x[1]);
  const conds = match.allows.map((a) => a.cond).join(' || ');
  return (
    vars.find((v) => new RegExp(`request\\.auth\\.uid\\s*==\\s*${v}\\b|\\b${v}\\s*==\\s*request\\.auth\\.uid`).test(conds)) ||
    null
  );
}

// Static red flags we report even without a live proof (clearly labelled)
export function staticFlags(match) {
  const flags = [];
  for (const a of match.allows) {
    if (/request\.time\s*<\s*timestamp\.date\(/.test(a.cond))
      flags.push({ kind: 'test-mode-expiry', ops: a.ops, cond: a.cond });
    if (match.path.includes('=**}') && a.cond === 'true') flags.push({ kind: 'catch-all-open', ops: a.ops, cond: a.cond });
  }
  return flags;
}

// "/users/{uid}/private/{doc}" -> { collectionPath: "users/{uid}/private", docVar: "doc" }
export function collectionOf(match) {
  const parts = match.path.split('/').filter(Boolean);
  if (parts.length < 2 || parts.length % 2 !== 0) return null; // must end in a document segment
  const last = parts[parts.length - 1];
  const dv = last.match(/^\{(\w+)\}$/);
  if (!dv || last.includes('=**')) return null;
  return { collectionPath: parts.slice(0, -1).join('/'), docVar: dv[1] };
}
