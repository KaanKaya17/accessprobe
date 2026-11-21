// Reads collections and their API rules from pb_migrations/*.js — WITHOUT running them.
// Migrations are code; executing a project's files would be unsafe, so this is a small,
// tolerant reader for the shapes PocketBase itself generates (and people write by hand):
//
//   new Collection({ name, type, listRule, …, fields: [...] })        (v0.23+)
//   new Collection({ …, schema: [{ name, type, options: {…} }] })      (v0.22 and older)
//   const c = app.findCollectionByNameOrId("users")                     (also dao.…, $app.…)
//   c.listRule = "…" / null;  unmarshal({ … }, c);  c.fields.add(new TextField({…}))
//   c.fields.removeByName("x");  app.delete(c);  importCollections([...])  (snapshots)
//
// Only the "up" function of each migrate(up, down) call is read. Files are applied in order.

export const RULES = ['listRule', 'viewRule', 'createRule', 'updateRule', 'deleteRule'];
export const USERS_ID = '_pb_users_auth_';

// The users collection every PocketBase app starts with (created by a system migration).
export function defaultCollections() {
  return [
    {
      id: USERS_ID,
      name: 'users',
      type: 'auth',
      listRule: 'id = @request.auth.id',
      viewRule: 'id = @request.auth.id',
      createRule: '',
      updateRule: 'id = @request.auth.id',
      deleteRule: 'id = @request.auth.id',
      fields: [
        { name: 'email', type: 'email' },
        { name: 'emailVisibility', type: 'bool' },
        { name: 'verified', type: 'bool' },
        { name: 'name', type: 'text' },
        { name: 'avatar', type: 'file' },
      ],
      fromMigrations: false,
    },
  ];
}

// ---------------------------------------------------------------- lexing helpers

// index just past the string/comment/template starting at i, or i if none starts there
function skipNonCode(s, i) {
  const c = s[i];
  if (c === '/' && s[i + 1] === '/') {
    const e = s.indexOf('\n', i);
    return e < 0 ? s.length : e + 1;
  }
  if (c === '/' && s[i + 1] === '*') {
    const e = s.indexOf('*/', i + 2);
    return e < 0 ? s.length : e + 2;
  }
  if (c === '"' || c === "'" || c === '`') {
    for (let j = i + 1; j < s.length; j++) {
      if (s[j] === '\\') j++;
      else if (s[j] === c) return j + 1;
    }
    return s.length;
  }
  return i;
}

function skipWs(s, i) {
  for (;;) {
    while (i < s.length && /\s/.test(s[i])) i++;
    if (s[i] === '/' && (s[i + 1] === '/' || s[i + 1] === '*')) i = skipNonCode(s, i);
    else return i;
  }
}

// end of a bracketed group that opens at s[i]
function matchClose(s, i) {
  const open = s[i];
  const close = { '(': ')', '[': ']', '{': '}' }[open];
  let depth = 0;
  for (let j = i; j < s.length; ) {
    const k = skipNonCode(s, j);
    if (k !== j) {
      j = k;
      continue;
    }
    if ('([{'.includes(s[j])) depth++;
    else if (')]}'.includes(s[j])) {
      depth--;
      if (depth === 0) return s[j] === close ? j : -1;
    }
    j++;
  }
  return -1;
}

// ---------------------------------------------------------------- literal parser

function readString(s, i) {
  const q = s[i];
  let out = '';
  let j = i + 1;
  let dynamic = false;
  for (; j < s.length && s[j] !== q; j++) {
    if (s[j] === '\\') {
      const n = s[++j];
      out += { n: '\n', t: '\t', r: '\r', 0: '\0' }[n] ?? n;
    } else {
      if (q === '`' && s[j] === '$' && s[j + 1] === '{') dynamic = true;
      out += s[j];
    }
  }
  return { value: dynamic ? { expr: s.slice(i, j + 1) } : out, end: j + 1 };
}

// Parse a JS value literal at s[i]. Anything that is not a literal becomes { expr: "source" }
// (or { ctor, arg } for `new X({...})`), so unknown code never breaks the reader.
export function parseValue(s, i, scope = {}) {
  i = skipWs(s, i);
  const c = s[i];
  if (c === '{') {
    const obj = {};
    let j = i + 1;
    for (;;) {
      j = skipWs(s, j);
      if (s[j] === '}') return { value: obj, end: j + 1 };
      if (s.startsWith('...', j)) {
        const v = parseValue(s, j + 3, scope);
        if (v.value && typeof v.value === 'object' && !Array.isArray(v.value) && !v.value.expr) Object.assign(obj, v.value);
        j = v.end;
      } else {
        let key;
        if (s[j] === '"' || s[j] === "'") {
          const k = readString(s, j);
          key = k.value;
          j = k.end;
        } else {
          const m = /^[\w$]+/.exec(s.slice(j, j + 200));
          if (!m) return bail(s, i);
          key = m[0];
          j += key.length;
        }
        j = skipWs(s, j);
        if (s[j] === ':') {
          const v = parseValue(s, j + 1, scope);
          obj[key] = v.value;
          j = v.end;
        } else obj[key] = key in scope ? scope[key] : { expr: key }; // shorthand { owner }
      }
      j = skipWs(s, j);
      if (s[j] === ',') j++;
      else if (s[j] === '}') return { value: obj, end: j + 1 };
      else return bail(s, i);
    }
  }
  if (c === '[') {
    const arr = [];
    let j = i + 1;
    for (;;) {
      j = skipWs(s, j);
      if (s[j] === ']') return { value: arr, end: j + 1 };
      if (s.startsWith('...', j)) {
        const v = parseValue(s, j + 3, scope);
        if (Array.isArray(v.value)) arr.push(...v.value);
        j = v.end;
      } else {
        const v = parseValue(s, j, scope);
        arr.push(v.value);
        j = v.end;
      }
      j = skipWs(s, j);
      if (s[j] === ',') j++;
      else if (s[j] === ']') return { value: arr, end: j + 1 };
      else return bail(s, i);
    }
  }
  if (c === '"' || c === "'" || c === '`') {
    const r = readString(s, i);
    // "a" + "b": a concatenation is not a literal
    const after = skipWs(s, r.end);
    if (s[after] === '+') return bail(s, i);
    return r;
  }
  const num = /^-?\d+(\.\d+)?/.exec(s.slice(i, i + 40));
  if (num) return { value: Number(num[0]), end: i + num[0].length };
  const kw = /^(true|false|null|undefined)\b/.exec(s.slice(i, i + 10));
  if (kw) return { value: { true: true, false: false, null: null, undefined: undefined }[kw[1]], end: i + kw[1].length };
  const ctor = /^new\s+([\w$.]+)\s*\(/.exec(s.slice(i, i + 200));
  if (ctor) {
    const open = i + ctor[0].length - 1;
    const close = matchClose(s, open);
    if (close < 0) return { value: { expr: s.slice(i) }, end: s.length };
    const arg = skipWs(s, open + 1) === close ? { value: undefined } : parseValue(s, open + 1, scope);
    return { value: { ctor: ctor[1].split('.').pop(), arg: arg.value }, end: close + 1 };
  }
  const ident = /^[\w$]+$/.test(s.slice(i, exprEnd(s, i)).trim()) ? s.slice(i, exprEnd(s, i)).trim() : null;
  if (ident && ident in scope) return { value: scope[ident], end: i + ident.length };
  return bail(s, i);
}

// end of an arbitrary expression: the next top-level , } ] ) or ;
function exprEnd(s, i) {
  let j = i;
  while (j < s.length) {
    const k = skipNonCode(s, j);
    if (k !== j) {
      j = k;
      continue;
    }
    if ('([{'.includes(s[j])) {
      const e = matchClose(s, j);
      if (e < 0) return s.length;
      j = e + 1;
      continue;
    }
    if (',;)]}'.includes(s[j])) return j;
    if (s[j] === '\n' && /^\s*(const|let|var|return|[\w$]+\.[\w$]+\s*=)/.test(s.slice(j + 1, j + 80))) return j;
    j++;
  }
  return j;
}

function bail(s, i) {
  const e = exprEnd(s, i);
  return { value: { expr: s.slice(i, e).trim() }, end: e };
}

// ---------------------------------------------------------------- migration reader

// The "up" function of migrate(up, down), or the whole file when it has no migrate() call.
export function upBody(text) {
  const m = /\bmigrate\s*\(/.exec(text);
  if (!m) return text;
  const open = m.index + m[0].length - 1;
  let depth = 0;
  for (let j = open; j < text.length; ) {
    const k = skipNonCode(text, j);
    if (k !== j) {
      j = k;
      continue;
    }
    const ch = text[j];
    if ('([{'.includes(ch)) depth++;
    else if (')]}'.includes(ch)) {
      depth--;
      if (depth === 0) return text.slice(open + 1, j);
    } else if (ch === ',' && depth === 1) return text.slice(open + 1, j);
    j++;
  }
  return text.slice(open + 1);
}

const FIELD_CTOR = {
  TextField: 'text',
  EditorField: 'editor',
  NumberField: 'number',
  BoolField: 'bool',
  EmailField: 'email',
  URLField: 'url',
  DateField: 'date',
  AutodateField: 'autodate',
  SelectField: 'select',
  FileField: 'file',
  RelationField: 'relation',
  JSONField: 'json',
  GeoPointField: 'geoPoint',
  PasswordField: 'password',
};

function normField(f) {
  if (!f || typeof f !== 'object') return null;
  if (f.ctor) {
    const type = FIELD_CTOR[f.ctor] || f.arg?.type;
    return normField({ ...(f.arg || {}), type });
  }
  if (typeof f.name !== 'string') return null;
  const o = f.options && typeof f.options === 'object' ? f.options : {};
  return {
    name: f.name,
    type: typeof f.type === 'string' ? f.type : 'text',
    collectionId: f.collectionId ?? o.collectionId ?? null,
    values: f.values ?? o.values ?? null,
    maxSelect: f.maxSelect ?? o.maxSelect ?? null,
    required: Boolean(f.required),
    hidden: Boolean(f.hidden),
    system: Boolean(f.system),
    min: f.min ?? o.min ?? null,
    max: f.max ?? o.max ?? null,
    pattern: f.pattern ?? o.pattern ?? null,
  };
}

// expressions like users.id / app.findCollectionByNameOrId("users").id → a collection id or name
function refName(v, vars) {
  if (typeof v === 'string') return v;
  if (!v || typeof v !== 'object' || typeof v.expr !== 'string') return null;
  const call = /findCollectionByNameOrId\(\s*["'`]([\w-]+)["'`]\s*\)/.exec(v.expr);
  if (call) return call[1];
  const dot = /^([\w$]+)\.(id|name)$/.exec(v.expr);
  if (dot && vars[dot[1]]) return vars[dot[1]];
  return null;
}

export class CollectionSet {
  constructor() {
    this.list = defaultCollections();
  }
  find(ref) {
    if (!ref) return null;
    return this.list.find((c) => c.id === ref || c.name === ref) || null;
  }
  upsert(obj, vars, file) {
    if (!obj || typeof obj !== 'object' || obj.expr) return null;
    const name = typeof obj.name === 'string' ? obj.name : null;
    const id = typeof obj.id === 'string' ? obj.id : null;
    let c = this.find(id) || this.find(name);
    if (!c) {
      if (!name) return null;
      c = { id: id || name, name, type: 'base', listRule: null, viewRule: null, createRule: null, updateRule: null, deleteRule: null, fields: [] };
      this.list.push(c);
    }
    this.merge(c, obj, vars, file);
    return c;
  }
  merge(c, obj, vars, file) {
    if (typeof obj.name === 'string') c.name = obj.name;
    if (typeof obj.type === 'string') c.type = obj.type;
    for (const r of RULES) if (r in obj && (obj[r] === null || typeof obj[r] === 'string')) c[r] = obj[r];
    const fields = Array.isArray(obj.fields) ? obj.fields : Array.isArray(obj.schema) ? obj.schema : null;
    if (fields) {
      const keep = c.type === 'auth' ? c.fields.filter((f) => ['email', 'emailVisibility', 'verified'].includes(f.name)) : [];
      c.fields = [...keep];
      for (const f of fields) this.addField(c, f, vars);
    }
    c.fromMigrations = true;
    if (file) c.file = file;
  }
  addField(c, raw, vars) {
    const f = normField(raw);
    if (!f) return;
    if (f.collectionId && typeof f.collectionId !== 'string') f.collectionId = refName(f.collectionId, vars);
    c.fields = c.fields.filter((x) => x.name !== f.name);
    c.fields.push(f);
  }
  remove(c) {
    this.list = this.list.filter((x) => x !== c);
  }
}

// Apply one migration file's up() to the collection set.
export function applyMigration(set, text, file = null) {
  const body = upBody(text);
  const vars = {}; // variable → collection id it refers to
  const scope = {}; // variable → literal value (e.g. a shared field definition)
  const events = [];
  const handled = new Set(); // positions of `new Collection(` already read through an assignment
  const at = (re, fn) => {
    for (const m of body.matchAll(re)) events.push({ pos: m.index, run: () => fn(m) });
  };
  const coll = (v) => set.find(vars[v]);

  // const x = <literal> / new Collection(...) / ….findCollectionByNameOrId("…")
  at(/\b(?:const|let|var)\s+([\w$]+)\s*=\s*/g, (m) => {
    const start = m.index + m[0].length;
    const rest = body.slice(start, start + 200);
    const find = /^(?:new\s+)?[\w$.()]*findCollectionByNameOrId\(\s*["'`]([\w-]+)["'`]\s*\)/.exec(rest);
    if (find) {
      const c = set.find(find[1]);
      if (c) vars[m[1]] = c.id;
      return;
    }
    if (/^new\s+Collection\s*\(/.test(rest)) {
      const c = set.upsert(parseValue(body, start, scope).value?.arg, vars, file);
      if (c) vars[m[1]] = c.id;
      handled.add(start);
      return;
    }
    if (rest[0] === '{' || rest[0] === '[') {
      const v = parseValue(body, start, scope);
      scope[m[1]] = v.value;
    }
  });
  // inline app.save(new Collection({...}))
  at(/\bnew\s+Collection\s*\(/g, (m) => {
    if (handled.has(m.index)) return;
    set.upsert(parseValue(body, m.index, scope).value?.arg, vars, file);
  });
  // c.listRule = "…"
  at(/\b([\w$]+)\.(listRule|viewRule|createRule|updateRule|deleteRule|name|type)\s*=(?!=)\s*/g, (m) => {
    const c = coll(m[1]);
    if (!c) return;
    const v = parseValue(body, m.index + m[0].length, scope).value;
    if (m[2] === 'name' || m[2] === 'type') {
      if (typeof v === 'string') c[m[2]] = v;
    } else if (v === null || typeof v === 'string') c[m[2]] = v;
  });
  // unmarshal({ … }, c)
  at(/\bunmarshal\s*\(/g, (m) => {
    const v = parseValue(body, m.index + m[0].length, scope);
    const target = /^\s*,\s*([\w$]+)\s*\)/.exec(body.slice(v.end, v.end + 100));
    const c = target && coll(target[1]);
    if (c && v.value && typeof v.value === 'object') set.merge(c, v.value, vars, file);
  });
  // c.fields.add(new TextField({…})) / c.fields.addAt(3, …) / c.schema.addField(new SchemaField({…}))
  at(/\b([\w$]+)\.(?:fields|schema)\.(add|addAt|addField|addMarshaledJSON)\s*\(/g, (m) => {
    const c = coll(m[1]);
    if (!c) return;
    let i = m.index + m[0].length;
    if (m[2] === 'addAt') {
      const first = parseValue(body, i, scope);
      i = skipWs(body, first.end);
      if (body[i] === ',') i++;
    }
    for (;;) {
      const v = parseValue(body, i, scope);
      if (m[2] === 'addMarshaledJSON') break;
      set.addField(c, v.value, vars);
      i = skipWs(body, v.end);
      if (body[i] !== ',') break;
      i++;
    }
  });
  at(/\b([\w$]+)\.(?:fields|schema)\.(?:removeByName|removeField)\s*\(\s*["'`]([\w-]+)["'`]/g, (m) => {
    const c = coll(m[1]);
    if (c) c.fields = c.fields.filter((f) => f.name !== m[2]);
  });
  at(/\b(?:app|dao|\$app|txApp|Dao\([^)]*\))\.(?:delete|deleteCollection)\s*\(\s*([\w$]+)\s*\)/g, (m) => {
    const c = coll(m[1]);
    if (c && c.id !== USERS_ID) set.remove(c);
  });
  // snapshot: importCollections([...]) or importCollections(snapshot)
  at(/\bimportCollections\s*\(\s*/g, (m) => {
    const v = parseValue(body, m.index + m[0].length, scope).value;
    // importCollections(collections) where collections = snapshot.map(...): use the literal array
    const looksLikeSnapshot = (a) => Array.isArray(a) && a.some((x) => x && typeof x.name === 'string' && typeof x.type === 'string');
    const arr = looksLikeSnapshot(v) ? v : Object.values(scope).find(looksLikeSnapshot) || [];
    for (const item of arr) set.upsert(item?.ctor ? item.arg : item, vars, file);
  });

  events.sort((a, b) => a.pos - b.pos);
  for (const e of events) {
    try {
      e.run();
    } catch {
      /* one unreadable statement must not hide the rest of the file */
    }
  }
  return set;
}

// files: [{ name, text }] — applied in file-name order (PocketBase's own order)
export function readMigrations(files) {
  const set = new CollectionSet();
  for (const f of [...files].sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0))) applyMigration(set, f.text, f.name);
  return set.list.filter((c) => !c.name.startsWith('_'));
}
