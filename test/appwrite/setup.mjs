// FIXTURE SETUP ONLY (CI e2e): on a fresh self-hosted Appwrite, create the console root account,
// a team, the project "accessprobe-test" and a server API key, then exactly the databases,
// collections, attributes, tables and buckets in test/appwrite/app/appwrite.json.
// The API key is used only here and by check.mjs (to verify cleanup); accessprobe itself gets
// nothing but the endpoint and the project id.
//
// Usage: node test/appwrite/setup.mjs [endpoint]   (default http://localhost/v1)
// Writes appwrite-setup.json ({ endpoint, projectId, key }) into the current directory.
import { readFileSync, writeFileSync } from 'node:fs';
import { randomUUID } from 'node:crypto';

const endpoint = (process.argv[2] || process.env.APPWRITE_ENDPOINT || 'http://localhost/v1').replace(/\/+$/, '');
const config = JSON.parse(readFileSync(new URL('./app/appwrite.json', import.meta.url), 'utf8'));
const projectId = config.projectId;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function call(method, path, { project = 'console', cookie, key, body, headers = {}, allow = [] } = {}) {
  const h = { 'X-Appwrite-Project': project, ...headers };
  if (cookie) h.Cookie = cookie;
  if (key) h['X-Appwrite-Key'] = key;
  if (body !== undefined) h['Content-Type'] = 'application/json';
  const res = await fetch(endpoint + path, { method, headers: h, body: body === undefined ? undefined : JSON.stringify(body) });
  const text = await res.text();
  let data = text;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    /* keep text */
  }
  if (!res.ok && !allow.includes(res.status)) throw new Error(`${method} ${path} → ${res.status} ${typeof data === 'string' ? data.slice(0, 300) : JSON.stringify(data)}`);
  return { status: res.status, data, res };
}

// ---- console: root account, session, team, project, key
const email = `root-${randomUUID().slice(0, 8)}@example.com`;
const password = `Root-${randomUUID()}`;
await call('POST', '/account', { body: { userId: 'unique()', email, password, name: 'ci root' } });
const s = await call('POST', '/account/sessions/email', { body: { email, password } });
const cookie = (s.res.headers.getSetCookie?.() || []).map((c) => c.split(';')[0]).filter((c) => c.startsWith('a_session_')).join('; ');
if (!cookie) throw new Error(`no console session cookie: ${JSON.stringify([...s.res.headers])}`);
const team = await call('POST', '/teams', { cookie, body: { teamId: 'unique()', name: 'ci' } });
const teamId = team.data.$id;
await call('POST', '/projects', { cookie, body: { projectId, name: 'accessprobe e2e', teamId, region: 'default' } });
console.log(`project ${projectId} created (team ${teamId})`);

const scopes = ['users.read', 'databases.read', 'databases.write', 'collections.read', 'collections.write', 'attributes.read', 'attributes.write', 'documents.read', 'documents.write', 'tables.read', 'tables.write', 'columns.read', 'columns.write', 'rows.read', 'rows.write', 'buckets.read', 'buckets.write', 'files.read', 'files.write'];
let keyRes = await call('POST', `/organization/projects/${projectId}/keys`, { cookie, headers: { 'X-Appwrite-Organization': teamId }, body: { keyId: 'unique()', name: 'ci setup', scopes }, allow: [400, 401, 404] });
if (keyRes.status >= 400) {
  console.log(`organization key route answered ${keyRes.status} ${JSON.stringify(keyRes.data)}; trying /projects/:id/keys`);
  keyRes = await call('POST', `/projects/${projectId}/keys`, { cookie, body: { keyId: 'unique()', name: 'ci setup', scopes } });
}
const key = keyRes.data.secret;
if (!key) throw new Error(`no key secret in ${JSON.stringify(keyRes.data)}`);
const api = (method, path, body, allow) => call(method, path, { project: projectId, key, body, allow });

// ---- schema from appwrite.json
const dbs = new Map([...(config.databases || []), ...(config.tablesDB || [])].map((d) => [d.$id, d]));
for (const d of dbs.values()) await api('POST', '/databases', { databaseId: d.$id, name: d.name || d.$id });

function attrRequest(a) {
  const base = { key: a.key, required: Boolean(a.required), array: Boolean(a.array) };
  if (!a.required && a.default !== undefined && a.default !== null) base.default = a.default;
  if (a.type === 'string' && a.format === 'email') return ['email', base];
  if (a.type === 'string' && a.format === 'enum') return ['enum', { ...base, elements: a.elements }];
  if (a.type === 'string' || a.type === 'varchar') return [a.type, { ...base, size: a.size }];
  if (a.type === 'integer') return ['integer', { ...base, ...(a.min != null && { min: a.min }), ...(a.max != null && { max: a.max }) }];
  if (a.type === 'boolean') return ['boolean', base];
  throw new Error(`setup.mjs: attribute type ${a.type} not supported`);
}

async function waitAvailable(listPath, listKey) {
  for (let i = 0; i < 120; i++) {
    const r = await api('GET', listPath);
    const items = r.data[listKey] || [];
    if (items.some((x) => x.status === 'failed')) throw new Error(`attribute failed: ${JSON.stringify(items)}`);
    if (items.every((x) => x.status === 'available')) return;
    await sleep(500);
  }
  throw new Error(`attributes of ${listPath} never became available`);
}

for (const c of config.collections || []) {
  const base = `/databases/${c.databaseId}/collections`;
  await api('POST', base, { collectionId: c.$id, name: c.name.slice(0, 128), permissions: c.$permissions, documentSecurity: c.documentSecurity, enabled: c.enabled !== false });
  for (const a of c.attributes || []) {
    const [type, body] = attrRequest(a);
    await api('POST', `${base}/${c.$id}/attributes/${type}`, body);
  }
  await waitAvailable(`${base}/${c.$id}/attributes`, 'attributes');
  console.log(`collection ${c.databaseId}/${c.$id} ready`);
}
for (const t of config.tables || []) {
  const base = `/tablesdb/${t.databaseId}/tables`;
  await api('POST', base, { tableId: t.$id, name: t.name.slice(0, 128), permissions: t.$permissions, rowSecurity: t.rowSecurity, enabled: t.enabled !== false });
  for (const a of t.columns || []) {
    const [type, body] = attrRequest(a);
    await api('POST', `${base}/${t.$id}/columns/${type}`, body);
  }
  await waitAvailable(`${base}/${t.$id}/columns`, 'columns');
  console.log(`table ${t.databaseId}/${t.$id} ready`);
}
for (const b of config.buckets || []) {
  await api('POST', '/storage/buckets', { bucketId: b.$id, name: b.name, permissions: b.$permissions, fileSecurity: b.fileSecurity, enabled: b.enabled !== false });
  console.log(`bucket ${b.$id} ready`);
}

writeFileSync('appwrite-setup.json', JSON.stringify({ endpoint, projectId, key }, null, 2));
console.log('setup done → appwrite-setup.json');
