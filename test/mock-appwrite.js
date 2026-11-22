// A fake Appwrite server (Account, Databases, TablesDB, Storage subset) that applies
// permissions the way Appwrite documents them. The schema and permissions come from an
// appwrite.json (by default the fixture app's), so the server is exactly what that file says.
//
//   roles: guests → any, guests;  signed-in users → any, users, user:<id>
//   collection permissions apply to every document; document permissions only count when
//   documentSecurity (rowSecurity / fileSecurity) is on.
//   get:    not readable (also with security off and no collection read) → 404 document_not_found
//   list:   no collection read and security off → 401; else only the readable documents
//   create: needs collection create → else 401. Without permissions, a user gets read/update/delete
//           on its own document; a guest gets none. Permissions may only name the caller's roles.
//   update/delete: document missing → 404; not allowed → 401 user_unauthorized
//   an Origin header that is not a registered platform → 403 general_unknown_origin
//   (checked against a real Appwrite 2.7.4 by test/appwrite/behaviour.mjs in the real-appwrite CI job)
//
// Run directly: node test/mock-appwrite.js [port]   (then: npx accessprobe --url http://localhost:<port>/v1 --project-id accessprobe-test --source test/appwrite/app)

import { randomBytes } from 'node:crypto';
import http from 'node:http';
import { readFileSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';

export const PROJECT_ID = 'accessprobe-test';
export const FIXTURE_DIR = fileURLToPath(new URL('./appwrite/app/', import.meta.url));
const FIXTURE = new URL('./appwrite/app/appwrite.json', import.meta.url);
const uid = () => randomBytes(10).toString('hex');

const parsePerm = (p) => {
  const m = /^(read|create|update|delete|write)\("([^"]+)"\)$/.exec(p);
  return m ? { action: m[1], role: m[2] } : null;
};
const grants = (perms, action, roles) =>
  (perms || []).some((p) => {
    const x = parsePerm(p);
    return x && (x.action === action || (x.action === 'write' && action !== 'read')) && roles.includes(x.role);
  });

function loadConfig(config) {
  const j = config || JSON.parse(readFileSync(FIXTURE, 'utf8'));
  const containers = new Map(); // "documents:main/notes" → {...}
  for (const c of j.collections || []) containers.set(`documents:${c.databaseId}/${c.$id}`, { perms: c.$permissions || [], security: c.documentSecurity === true, attrs: c.attributes || [], docs: new Map() });
  for (const t of j.tables || []) containers.set(`rows:${t.databaseId}/${t.$id}`, { perms: t.$permissions || [], security: t.rowSecurity === true, attrs: t.columns || [], docs: new Map() });
  const buckets = new Map();
  for (const b of j.buckets || []) buckets.set(b.$id, { perms: b.$permissions || [], security: b.fileSecurity === true, files: new Map() });
  const dbs = new Set([...(j.databases || []), ...(j.tablesDB || [])].map((d) => d.$id));
  return { containers, buckets, dbs };
}

const MODES = {
  documents: { idKey: 'documentId', listKey: 'documents', notFound: 'document_not_found', containerNotFound: 'collection_not_found', noun: 'document' },
  rows: { idKey: 'rowId', listKey: 'rows', notFound: 'row_not_found', containerNotFound: 'table_not_found', noun: 'row' },
};

// options: { config (an appwrite.json object), signupOpen = true, legacyQueries = false, noTablesDb = false }
export function createServer({ config, signupOpen = true, noTablesDb = false } = {}) {
  const state = { users: new Map(), sessions: new Map(), ...loadConfig(config), requests: [] };

  const server = http.createServer(async (req, res) => {
    const chunks = [];
    for await (const c of req) chunks.push(c);
    const raw = Buffer.concat(chunks);
    const url = new URL(req.url, 'http://x');
    const path = url.pathname;
    state.requests.push({ method: req.method, path, headers: req.headers });
    const send = (status, body, headers = {}) => {
      res.writeHead(status, { ...(body !== undefined && { 'Content-Type': typeof body === 'string' ? 'text/plain' : 'application/json' }), ...headers });
      res.end(body === undefined ? undefined : typeof body === 'string' ? body : JSON.stringify(body));
    };
    const error = (code, type, message) => send(code, { message, code, type, version: '1.6.1' });

    if (req.method === 'GET' && path === '/v1/health/version') return send(200, { version: '1.6.1' });
    if (!path.startsWith('/v1/')) return error(404, 'general_route_not_found', 'Route not found');
    if (req.headers['x-appwrite-key']) return error(500, 'test_failure', 'accessprobe must never send an API key');
    if (req.headers['x-appwrite-project'] !== PROJECT_ID) return error(404, 'project_not_found', 'Project with the requested ID could not be found.');
    // no web platforms are registered: a browser Origin is refused, a server-side client sends none
    if (req.headers.origin) return error(403, 'general_unknown_origin', `Invalid Origin. Register your new client (${req.headers.origin}) as a new Web platform on your project console dashboard`);

    // ---- who is calling
    let user = null;
    const cookies = Object.fromEntries((req.headers.cookie || '').split(/;\s*/).filter(Boolean).map((c) => c.split('=')));
    let fallback = {};
    try {
      fallback = JSON.parse(req.headers['x-fallback-cookies'] || '{}');
    } catch {
      /* ignore */
    }
    const secret = cookies[`a_session_${PROJECT_ID}`] || fallback[`a_session_${PROJECT_ID}`] || req.headers['x-appwrite-session'];
    if (secret) {
      const s = state.sessions.get(secret);
      if (!s) return error(401, 'user_session_not_found', 'The current user session could not be found.');
      user = state.users.get(s.userId);
      if (!user || user.status === false) return error(401, 'user_blocked', 'The current user has been blocked.');
    }
    // test users never verify their email: Appwrite adds the /unverified dimension
    const roles = user ? ['any', 'users', `user:${user.$id}`, `user:${user.$id}/unverified`, 'users/unverified'] : ['any', 'guests'];
    let body = {};
    const ctype = req.headers['content-type'] || '';
    if (ctype.startsWith('application/json') && raw.length) {
      try {
        body = JSON.parse(raw.toString('utf8'));
      } catch {
        return error(400, 'general_argument_invalid', 'Invalid JSON');
      }
    } else if (ctype.startsWith('multipart/form-data')) body = parseMultipart(raw, ctype);
    const checkPerms = (perms) => {
      for (const p of perms) {
        const x = parsePerm(p);
        if (!x) return `Invalid permission string: ${p}`;
        if (!roles.includes(x.role)) return `Permissions must be one of: (${roles.join(', ')})`;
      }
      return null;
    };
    const userJson = (u) => ({ $id: u.$id, name: u.name, email: u.email, status: u.status, labels: [], prefs: {} });

    // ---- account
    if (path === '/v1/account' && req.method === 'POST') {
      if (!signupOpen) return error(501, 'user_auth_method_unsupported', 'Current auth method is disabled.');
      if (!body.email || !body.password || body.password.length < 8) return error(400, 'general_argument_invalid', 'Invalid `password` param');
      if ([...state.users.values()].some((u) => u.email === body.email)) return error(409, 'user_already_exists', 'A user with the same id, email, or phone already exists in this project.');
      const id = body.userId === 'unique()' ? uid() : body.userId;
      const u = { $id: id, email: body.email, password: body.password, name: body.name || '', status: true };
      state.users.set(id, u);
      return send(201, userJson(u));
    }
    if (path === '/v1/account/sessions/email' && req.method === 'POST') {
      const u = [...state.users.values()].find((x) => x.email === body.email && x.password === body.password);
      if (!u) return error(401, 'user_invalid_credentials', 'Invalid credentials. Please check the email and password.');
      if (u.status === false) return error(401, 'user_blocked', 'The current user has been blocked.');
      const s = randomBytes(24).toString('hex');
      state.sessions.set(s, { userId: u.$id });
      const name = `a_session_${PROJECT_ID}`;
      return send(201, { $id: uid(), userId: u.$id, secret: '', provider: 'email' }, { 'Set-Cookie': [`${name}=${s}; path=/; httponly`, `${name}_legacy=${s}; path=/; httponly`], 'X-Fallback-Cookies': JSON.stringify({ [name]: s }) });
    }
    if (path.startsWith('/v1/account')) {
      if (!user) return error(401, 'general_unauthorized_scope', 'User (role: guests) missing scope (account)');
      if (path === '/v1/account' && req.method === 'GET') return send(200, userJson(user));
      if (path === '/v1/account/status' && req.method === 'PATCH') {
        user.status = false;
        for (const [k, s] of state.sessions) if (s.userId === user.$id) state.sessions.delete(k);
        return send(200, userJson(user));
      }
      if (path === '/v1/account/sessions/current' && req.method === 'DELETE') {
        state.sessions.delete(secret);
        return send(204);
      }
      return error(404, 'general_route_not_found', 'Route not found');
    }

    // ---- databases / tablesdb
    let m = /^\/v1\/databases\/([^/]+)\/collections\/([^/]+)\/documents(?:\/([^/]+))?$/.exec(path);
    let mode = 'documents';
    if (!m && !noTablesDb) {
      m = /^\/v1\/tablesdb\/([^/]+)\/tables\/([^/]+)\/rows(?:\/([^/]+))?$/.exec(path);
      mode = 'rows';
    }
    if (m) {
      const M = MODES[mode];
      const [db, coll, docId] = [m[1], m[2], m[3]].map((x) => x && decodeURIComponent(x));
      if (!state.dbs.has(db)) return error(404, 'database_not_found', 'Database not found');
      const c = state.containers.get(`${mode}:${db}/${coll}`);
      if (!c) return error(404, M.containerNotFound, `${mode === 'rows' ? 'Table' : 'Collection'} with the requested ID could not be found.`);
      const can = (action, doc) => grants(c.perms, action, roles) || (c.security && doc && grants(doc.$permissions, action, roles));
      const unauthorized = () => error(401, 'user_unauthorized', 'The current user is not authorized to perform the requested action.');
      const out = (d) => ({ ...d.data, $id: d.$id, [mode === 'rows' ? '$tableId' : '$collectionId']: coll, $databaseId: db, $permissions: d.$permissions });

      if (req.method === 'GET' && !docId) {
        if (!c.security && !grants(c.perms, 'read', roles)) return unauthorized();
        let limit = 25;
        let equal = null;
        for (const q of url.searchParams.getAll('queries[]')) {
          let x;
          try {
            x = JSON.parse(q);
          } catch {
            return error(400, 'general_query_invalid', `Invalid query: ${q}`);
          }
          if (x.method === 'limit') limit = x.values[0];
          else if (x.method === 'equal' && x.attribute === '$id') equal = x.values;
          else return error(400, 'general_query_invalid', `Invalid query method: ${x.method}`);
        }
        const all = [...c.docs.values()].filter((d) => can('read', d) && (!equal || equal.includes(d.$id)));
        return send(200, { total: all.length, [M.listKey]: all.slice(0, limit).map(out) });
      }
      if (req.method === 'POST' && !docId) {
        if (!grants(c.perms, 'create', roles)) return error(401, 'user_unauthorized', user ? "No permissions provided for action 'create'" : `Missing "create" permission for role "users". Only "${JSON.stringify(roles)}" scopes are allowed and "[\"users\"]" was given.`);
        const data = body.data || {};
        // like Appwrite's Structure validator: required attributes first, then unknown ones, then values
        for (const a of c.attrs) if (a.required && (data[a.key] === undefined || data[a.key] === null)) return error(400, 'document_invalid_structure', `Invalid document structure: Missing required attribute "${a.key}"`);
        for (const k of Object.keys(data)) if (!c.attrs.some((a) => a.key === k)) return error(400, 'document_invalid_structure', `Invalid document structure: Unknown attribute: "${k}"`);
        for (const a of c.attrs) {
          const v = data[a.key];
          if (v === undefined) continue;
          const bad = invalid(a, v);
          if (bad) return error(400, 'document_invalid_structure', `Invalid document structure: Attribute "${a.key}" has invalid format. ${bad}`);
        }
        let perms = body.permissions;
        if (perms) {
          const bad = checkPerms(perms);
          if (bad) return error(401, 'user_unauthorized', bad);
        } else perms = user ? ['read', 'update', 'delete'].map((x) => `${x}("user:${user.$id}")`) : [];
        const id = !body[M.idKey] || body[M.idKey] === 'unique()' ? uid() : body[M.idKey];
        const d = { $id: id, data: { ...data }, $permissions: perms };
        c.docs.set(id, d);
        return send(201, out(d));
      }
      const d = docId && c.docs.get(docId);
      if (req.method === 'GET' && docId) {
        if (!d || !can('read', d)) return error(404, M.notFound, `${M.noun} with the requested ID could not be found.`);
        return send(200, out(d));
      }
      if (req.method === 'PATCH' && docId) {
        if (!d) return error(404, M.notFound, `${M.noun} with the requested ID could not be found.`);
        if (!can('update', d)) return unauthorized();
        if (!body.data && !body.permissions) return error(400, 'document_missing_payload', 'The document data and permissions are missing.');
        for (const k of Object.keys(body.data || {})) {
          const a = c.attrs.find((x) => x.key === k);
          if (!a) return error(400, 'document_invalid_structure', `Invalid document structure: Unknown attribute: "${k}"`);
          const bad = invalid(a, body.data[k]);
          if (bad) return error(400, 'document_invalid_structure', `Invalid document structure: Attribute "${k}" has invalid format. ${bad}`);
        }
        if (body.permissions) {
          const bad = checkPerms(body.permissions);
          if (bad) return error(401, 'user_unauthorized', bad);
          d.$permissions = body.permissions;
        }
        Object.assign(d.data, body.data || {});
        return send(200, out(d));
      }
      if (req.method === 'DELETE' && docId) {
        if (!d) return error(404, M.notFound, `${M.noun} with the requested ID could not be found.`);
        if (!can('delete', d)) return unauthorized();
        c.docs.delete(docId);
        return send(204);
      }
      return error(404, 'general_route_not_found', 'Route not found');
    }

    // ---- storage
    m = /^\/v1\/storage\/buckets\/([^/]+)\/files(?:\/([^/]+))?(\/download|\/view)?$/.exec(path);
    if (m) {
      const b = state.buckets.get(decodeURIComponent(m[1]));
      if (!b) return error(404, 'storage_bucket_not_found', 'Storage bucket with the requested ID could not be found.');
      const fid = m[2] && decodeURIComponent(m[2]);
      const can = (action, f) => grants(b.perms, action, roles) || (b.security && f && grants(f.$permissions, action, roles));
      const unauthorized = () => error(401, 'user_unauthorized', 'The current user is not authorized to perform the requested action.');
      const meta = (f) => ({ $id: f.$id, bucketId: m[1], name: f.name, sizeOriginal: f.content.length, mimeType: 'text/plain', $permissions: f.$permissions });
      if (req.method === 'GET' && !fid) {
        if (!b.security && !grants(b.perms, 'read', roles)) return unauthorized();
        let equal = null;
        for (const q of url.searchParams.getAll('queries[]')) {
          const x = JSON.parse(q);
          if (x.method === 'equal' && x.attribute === '$id') equal = x.values;
        }
        const all = [...b.files.values()].filter((f) => can('read', f) && (!equal || equal.includes(f.$id)));
        return send(200, { total: all.length, files: all.map(meta) });
      }
      if (req.method === 'POST' && !fid) {
        if (!grants(b.perms, 'create', roles)) return unauthorized();
        if (!body.file) return error(400, 'storage_file_empty', 'Empty file passed to the endpoint.');
        let perms = body.permissions;
        if (perms?.length) {
          const bad = checkPerms(perms);
          if (bad) return error(401, 'user_unauthorized', bad);
        } else perms = user ? ['read', 'update', 'delete'].map((x) => `${x}("user:${user.$id}")`) : [];
        const id = !body.fileId || body.fileId === 'unique()' ? uid() : body.fileId;
        const f = { $id: id, name: body.file.filename, content: body.file.content, $permissions: perms };
        b.files.set(id, f);
        return send(201, meta(f));
      }
      const f = fid && b.files.get(fid);
      if (req.method === 'GET' && fid) {
        if (!b.security && !grants(b.perms, 'read', roles)) return unauthorized();
        if (!f || !can('read', f)) return error(404, 'storage_file_not_found', 'The requested file could not be found.');
        return m[3] ? send(200, f.content) : send(200, meta(f));
      }
      if (req.method === 'PUT' && fid) {
        if (!f) return error(404, 'storage_file_not_found', 'The requested file could not be found.');
        if (!can('update', f)) return unauthorized();
        if (body.permissions) {
          const bad = checkPerms(body.permissions);
          if (bad) return error(401, 'user_unauthorized', bad);
          f.$permissions = body.permissions;
        }
        if (body.name) f.name = body.name;
        return send(200, meta(f));
      }
      if (req.method === 'DELETE' && fid) {
        if (!f) return error(404, 'storage_file_not_found', 'The requested file could not be found.');
        if (!can('delete', f)) return unauthorized();
        b.files.delete(fid);
        return send(204);
      }
    }
    return error(404, 'general_route_not_found', 'Route not found');
  });
  server.state = state;
  return server;
}

function invalid(a, v) {
  const vals = a.array ? (Array.isArray(v) ? v : null) : [v];
  if (!vals) return 'Value must be an array';
  for (const x of vals) {
    if (['string', 'varchar', 'text'].includes(a.type)) {
      if (typeof x !== 'string') return 'Value must be a valid string';
      if (a.size && x.length > a.size) return `Value must be a valid string and no longer than ${a.size} chars`;
      if (a.format === 'email' && !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(x)) return 'Value must be a valid email address';
      if (a.format === 'enum' && !a.elements.includes(x)) return `Value must be one of (${a.elements.join(', ')})`;
    } else if (a.type === 'integer') {
      if (!Number.isInteger(x)) return 'Value must be a valid integer';
      if ((a.min != null && x < a.min) || (a.max != null && x > a.max)) return `Value must be a valid range between ${a.min} and ${a.max}`;
    } else if (a.type === 'boolean' && typeof x !== 'boolean') return 'Value must be a valid boolean';
  }
  return null;
}

// just enough multipart/form-data for fileId, permissions[] and file
function parseMultipart(raw, ctype) {
  const boundary = /boundary=(?:"([^"]+)"|([^;]+))/.exec(ctype);
  const sep = `--${boundary[1] || boundary[2]}`;
  const out = { permissions: [] };
  for (const part of raw.toString('utf8').split(sep).slice(1)) {
    if (part.startsWith('--')) break;
    const [head, ...rest] = part.replace(/^\r\n/, '').split('\r\n\r\n');
    const value = rest.join('\r\n\r\n').replace(/\r\n$/, '');
    const name = /name="([^"]+)"/.exec(head)?.[1];
    const filename = /filename="([^"]*)"/.exec(head)?.[1];
    if (name === 'file') out.file = { filename, content: value };
    else if (name === 'permissions[]') out.permissions.push(value);
    else if (name) out[name] = value;
  }
  return out;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const port = Number(process.argv[2]) || 54398;
  createServer().listen(port, () => console.log(`fake Appwrite on http://localhost:${port}/v1 (project ${PROJECT_ID})`));
}
