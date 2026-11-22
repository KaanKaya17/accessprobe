// Records how a REAL Appwrite answers the requests accessprobe's Appwrite adapter relies on, and
// fails when an answer differs from what the adapter (and test/mock-appwrite.js) assume.
// Runs in the real-appwrite CI job after setup.mjs. Two throwaway users act like browser clients;
// the setup's server key is used only to clean up afterwards.
// Usage: node test/appwrite/behaviour.mjs [appwrite-setup.json]
import { readFileSync } from 'node:fs';
import { randomUUID } from 'node:crypto';

const setup = JSON.parse(readFileSync(process.argv[2] || 'appwrite-setup.json', 'utf8'));
const { endpoint, projectId, key } = setup;
const rows = [];
const errors = [];

async function call(method, path, { cookie, body, headers = {}, form } = {}) {
  const h = { 'X-Appwrite-Project': projectId, ...headers };
  if (cookie) h.Cookie = cookie;
  if (body !== undefined) h['Content-Type'] = 'application/json';
  const res = await fetch(endpoint + path, { method, headers: h, body: form || (body === undefined ? undefined : JSON.stringify(body)) });
  const text = await res.text();
  let data = text;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    /* keep text */
  }
  return { status: res.status, type: data?.type, message: data?.message, data, headers: res.headers };
}
const record = (what, r, ok) => {
  rows.push({ what, status: r.status, type: r.type || '', message: (r.message || '').slice(0, 140), ok });
  if (!ok) errors.push(what);
};
const admin = (method, path, body) => call(method, path, { headers: { 'X-Appwrite-Key': key }, body });

const users = [];
for (const label of ['a', 'b']) {
  const email = `behaviour-${randomUUID().slice(0, 6)}-${label}@example.com`;
  const password = `Bh-${randomUUID()}`;
  const u = await call('POST', '/account', { body: { userId: 'unique()', email, password } });
  const s = await call('POST', '/account/sessions/email', { body: { email, password } });
  const setCookies = s.headers.getSetCookie();
  const cookie = setCookies.map((c) => c.split(';')[0]).filter((c) => c.startsWith('a_session_')).join('; ');
  if (label === 'a') {
    record(`session: Set-Cookie names ${setCookies.map((c) => c.split('=')[0]).join(', ')}`, s, setCookies.some((c) => c.startsWith(`a_session_${projectId}=`)));
    record(`session: X-Fallback-Cookies header ${s.headers.get('x-fallback-cookies') ? 'present' : 'absent'}`, s, true);
    record(`session: body secret ${s.data?.secret ? 'non-empty' : 'empty'}`, s, true);
  }
  users.push({ id: u.data.$id, cookie });
}
const [A, B] = users;
const docs = (c, id = '') => `/databases/main/collections/${c}/documents${id ? `/${id}` : ''}`;
const q = (x) => `queries[]=${encodeURIComponent(JSON.stringify(x))}`;

try {
  const me = await call('GET', '/account', { cookie: A.cookie });
  record('GET /v1/account with the session cookie', me, me.status === 200 && me.data.$id === A.id);
  const origin = await call('GET', '/account', { cookie: A.cookie, headers: { Origin: 'https://not-registered.example' } });
  record('unregistered Origin header (adapter never sends one)', origin, true);

  // defaults for a client-created document
  const n = await call('POST', docs('notes'), { cookie: A.cookie, body: { documentId: 'unique()', data: { text: 'behaviour-test' } } });
  const want = ['read', 'update', 'delete'].map((x) => `${x}("user:${A.id}")`);
  record(`client create without permissions → ${JSON.stringify(n.data?.$permissions)}`, n, n.status === 201 && want.every((p) => n.data.$permissions.includes(p)) && n.data.$permissions.length === 3);
  const id = n.data.$id;
  const hiddenGet = await call('GET', docs('notes', id), { cookie: B.cookie });
  record('notes (document security on): B reads A\'s document', hiddenGet, hiddenGet.status === 404 && hiddenGet.type === 'document_not_found');
  const hiddenList = await call('GET', `${docs('notes')}?${q({ method: 'equal', attribute: '$id', values: [id] })}`, { cookie: B.cookie });
  record('notes: B lists with a JSON equal query', hiddenList, hiddenList.status === 200 && hiddenList.data.total === 0);
  const legacy = await call('GET', `${docs('notes')}?queries[]=${encodeURIComponent(`equal("$id", ["${id}"])`)}`, { cookie: A.cookie });
  record('legacy string query syntax', legacy, true);
  const bUpd = await call('PATCH', docs('notes', id), { cookie: B.cookie, body: { data: { text: 'behaviour-tamper' } } });
  record('notes: B updates A\'s document', bUpd, bUpd.status === 401 && bUpd.type === 'user_unauthorized');
  const bPerm = await call('PATCH', docs('notes', id), { cookie: B.cookie, body: { permissions: [`read("user:${B.id}")`] } });
  record('notes: B rewrites A\'s $permissions', bPerm, bPerm.status === 401 && bPerm.type === 'user_unauthorized');
  const bDel = await call('DELETE', docs('notes', id), { cookie: B.cookie });
  record('notes: B deletes A\'s document', bDel, bDel.status === 401 && bDel.type === 'user_unauthorized');
  const anCreate = await call('POST', docs('notes'), { body: { documentId: 'unique()', data: { text: 'x' } } });
  record('notes: guest creates (no create("any"))', anCreate, anCreate.status === 401 && anCreate.type === 'user_unauthorized');
  const foreignPerm = await call('POST', docs('notes'), { cookie: B.cookie, body: { documentId: 'unique()', data: { text: 'x' }, permissions: [`read("user:${A.id}")`] } });
  record('B creates a document naming user A in its permissions', foreignPerm, foreignPerm.status === 401 && foreignPerm.type === 'user_unauthorized');
  await call('DELETE', docs('notes', id), { cookie: A.cookie });

  // document security off: collection permissions only
  const s = await call('POST', docs('shared_docs'), { cookie: A.cookie, body: { documentId: 'unique()', data: { content: 'x' } } });
  const anGet = await call('GET', docs('shared_docs', s.data.$id));
  record('shared_docs (security off, read("users")): guest reads', anGet, anGet.status === 401 || anGet.status === 404);
  const anList = await call('GET', docs('shared_docs'));
  record('shared_docs: guest lists', anList, anList.status === 401 && anList.type === 'user_unauthorized');
  const anDel = await call('DELETE', docs('shared_docs', s.data.$id));
  record('shared_docs: guest deletes', anDel, anDel.status === 401 && anDel.type === 'user_unauthorized');
  await call('DELETE', docs('shared_docs', s.data.$id), { cookie: A.cookie });
  const roList = await call('GET', docs('admin_reports'));
  record('admin_reports (security off, read("users")): guest lists', roList, roList.status === 401 && roList.type === 'user_unauthorized');
  const roCreate = await call('POST', docs('admin_reports'), { cookie: A.cookie, body: { documentId: 'unique()', data: { summary: 'x' } } });
  record('admin_reports: user creates (no create permission)', roCreate, roCreate.status === 401 && roCreate.type === 'user_unauthorized');

  // B rewriting permissions where it may update
  const t = await call('POST', docs('tasks'), { cookie: A.cookie, body: { documentId: 'unique()', data: { title: 'x', status: 'open' } } });
  const take = await call('PATCH', docs('tasks', t.data.$id), { cookie: B.cookie, body: { permissions: ['read', 'update', 'delete'].map((x) => `${x}("user:${B.id}")`) } });
  record('tasks (update("users")): B rewrites A\'s $permissions', take, take.status === 200);
  await admin('DELETE', docs('tasks', t.data.$id));

  // guest create with delete("any"), then guest delete
  const g = await call('POST', docs('guestbook'), { body: { documentId: 'unique()', data: { message: 'x' }, permissions: ['delete("any")'] } });
  record('guestbook (create("any")): guest creates with delete("any")', g, g.status === 201);
  if (g.status === 201) {
    const gd = await call('DELETE', docs('guestbook', g.data.$id));
    record('guestbook: guest deletes its own document', gd, gd.status === 204);
  }

  // schema errors that drive attribute guessing
  const unknown = await call('POST', docs('shared_docs'), { cookie: A.cookie, body: { documentId: 'unique()', data: { title: 'x' } } });
  record('unknown attribute', unknown, unknown.status === 400 && /unknown attribute[:\s]*"title"/i.test(unknown.message));
  const missing = await call('POST', docs('guestbook'), { cookie: A.cookie, body: { documentId: 'unique()', data: { title: 'x' } } });
  record('missing required + unknown in one request (which is reported?)', missing, missing.status === 400 && /missing required attribute[:\s]*"message"|unknown attribute[:\s]*"title"/i.test(missing.message));
  const badEnum = await call('POST', docs('tasks'), { cookie: A.cookie, body: { documentId: 'unique()', data: { title: 'x', status: 'accessprobe-x' } } });
  record('invalid enum value', badEnum, badEnum.status === 400 && /attribute "status" has invalid (format|type)/i.test(badEnum.message));
  const wrongRoute = await call('GET', '/databases/main/collections/nope/documents');
  record('missing collection', wrongRoute, wrongRoute.status === 404 && wrongRoute.type === 'collection_not_found');
  const rows404 = await call('GET', '/tablesdb/main/tables/todos/rows/nope', { cookie: A.cookie });
  record('TablesDB missing row', rows404, rows404.status === 404 && rows404.type === 'row_not_found');

  // storage
  const form = new FormData();
  form.append('fileId', 'unique()');
  form.append('file', new Blob(['behaviour'], { type: 'text/plain' }), 'behaviour.txt');
  const up = await call('POST', '/storage/buckets/avatars/files', { cookie: A.cookie, form });
  record(`client upload without permissions → ${JSON.stringify(up.data?.$permissions)}`, up, up.status === 201 && up.data.$permissions.length === 3);
  const fb = await call('GET', `/storage/buckets/avatars/files/${up.data.$id}/download`, { cookie: B.cookie });
  record('avatars: B downloads A\'s file', fb, fb.status === 404 && fb.type === 'storage_file_not_found');
  const fu = await call('PUT', `/storage/buckets/avatars/files/${up.data.$id}`, { cookie: B.cookie, body: { name: 'x.txt' } });
  record('avatars: B renames A\'s file', fu, fu.status === 401 && fu.type === 'user_unauthorized');
  await call('DELETE', `/storage/buckets/avatars/files/${up.data.$id}`, { cookie: A.cookie });
} finally {
  for (const u of users) await admin('DELETE', `/users/${u.id}`);
}

const w = Math.max(...rows.map((r) => r.what.length));
for (const r of rows) console.log(`${r.ok ? 'ok  ' : 'FAIL'} ${r.what.padEnd(w)}  ${r.status} ${r.type} ${r.message}`);
if (errors.length) {
  console.log(`\n${errors.length} answer(s) differ from what the adapter assumes`);
  process.exit(1);
}
