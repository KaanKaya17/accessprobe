// Appwrite adapter without live attacks: appwrite.json parsing, code discovery, detection and
// the --project-id / --url flag rules shared with Firebase, Supabase and PocketBase.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createServer as createAppwrite, FIXTURE_DIR, PROJECT_ID } from './mock-appwrite.js';
import { createServer as createSupabase } from './mock-supabase.js';
import { readConfig, parsePermission, rolesFor } from '../src/providers/appwrite/config.js';
import { scanSource, fromCode } from '../src/providers/appwrite/source.js';
import { normalizeEndpoint, API } from '../src/providers/appwrite/client.js';
import { schemaPayload } from '../src/providers/appwrite/probes.js';
import { permissionFix, bucketFix } from '../src/providers/appwrite/fixes.js';
import { buildTargets, ownsProjectId } from '../src/providers/appwrite/scan.js';
import { plan } from '../src/core/scan.js';
import { providers } from '../src/providers/index.js';
import { toOptions } from '../src/mcp/server.js';

let aw;
let awUrl;
let sb;
let sbUrl;
const dirs = [];
const tmp = (files) => {
  const d = mkdtempSync(join(tmpdir(), 'accessprobe-aw-'));
  dirs.push(d);
  for (const [f, text] of Object.entries(files)) {
    mkdirSync(join(d, f, '..'), { recursive: true });
    writeFileSync(join(d, f), text);
  }
  return d;
};

before(async () => {
  aw = createAppwrite();
  await new Promise((r) => aw.listen(0, '127.0.0.1', r));
  awUrl = `http://127.0.0.1:${aw.address().port}/v1`;
  sb = createSupabase();
  await new Promise((r) => sb.listen(0, r));
  sbUrl = `http://localhost:${sb.address().port}`;
});
after(() => {
  aw.close();
  sb.close();
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

const ids = async (opts) => (await plan(opts)).chosen.map((p) => p.id);
// detection only (describe() would also need a project id)
const detected = async (opts) => {
  const out = [];
  for (const p of providers) if (await p.detect(opts, { site: null })) out.push(p.id);
  return out;
};

test('appwrite.json: project, endpoint, collections (attributes, permissions, documentSecurity), tables and buckets', async () => {
  const src = await scanSource(FIXTURE_DIR);
  assert.deepEqual(src.configFiles, ['appwrite.json']);
  assert.deepEqual(src.projects, [PROJECT_ID]);
  assert.deepEqual(src.endpoints, ['http://localhost/v1']);
  assert.deepEqual(src.databases, ['main']);
  const by = (id) => src.collections.find((c) => c.id === id);
  assert.equal(src.collections.length, 7);
  assert.deepEqual(by('notes').permissions, ['create("users")']);
  assert.equal(by('notes').security, true);
  assert.equal(by('shared_docs').security, false);
  assert.deepEqual(by('notes').attributes.map((a) => [a.key, a.type, a.required, a.size]), [['text', 'string', true, 255], ['done', 'boolean', false, null]]);
  assert.deepEqual(by('tasks').attributes[1].elements, ['open', 'done']);
  assert.equal(by('todos').mode, 'rows', 'TablesDB tables use the rows API');
  assert.equal(by('todos').security, true, 'rowSecurity');
  assert.deepEqual(src.buckets.map((b) => [b.id, b.security, b.permissions]), [['avatars', true, ['create("users")']], ['uploads', true, ['create("users")', 'read("any")']]]);
  // from the code: names, a bucket, and the attribute names of createDocument's payload
  assert.deepEqual(src.codeCollections.map((c) => `${c.db}/${c.id}`).sort(), ['main/notes', 'main/tasks']);
  assert.deepEqual(src.codeBuckets, ['avatars']);
  assert.deepEqual(src.attributes['main/notes'], ['text', 'done']);
});

test('readConfig tolerates comments and trailing commas; permissions parse into roles', () => {
  const c = readConfig(`{
    // hand edited
    "projectId": "p1",
    "collections": [{ "$id": "c", "databaseId": "d", "documentSecurity": false, "$permissions": ["read(\\"any\\")", "write(\\"users\\")",], }],
  }`);
  assert.equal(c.projectId, 'p1');
  assert.equal(c.collections[0].security, false);
  assert.deepEqual(parsePermission('update("user:abc")'), { action: 'update', role: 'user:abc' });
  assert.equal(parsePermission('nonsense'), null);
  assert.deepEqual(rolesFor(c.collections[0].permissions, 'read'), ['any']);
  assert.deepEqual(rolesFor(c.collections[0].permissions, 'delete'), ['users'], 'write = create + update + delete');
});

test('code discovery: Client().setEndpoint().setProject(), positional and object-style calls, env vars', async () => {
  const c = fromCode(`
    import { Client, Databases, TablesDB } from "appwrite";
    const client = new Client().setEndpoint("https://fra.cloud.appwrite.io/v1").setProject("6650abc");
    db.listDocuments('app', 'orders', [Query.equal('owner', uid)]);
    tablesDB.createRow({ databaseId: 'app', tableId: 'invoices', rowId: ID.unique(), data });
    storage.getFileView('receipts', id);
  `);
  assert.deepEqual(c.endpoints, ['https://fra.cloud.appwrite.io/v1']);
  assert.deepEqual(c.projects, ['6650abc']);
  assert.deepEqual(c.collections, [{ db: 'app', id: 'orders', mode: 'documents' }, { db: 'app', id: 'invoices', mode: 'rows' }]);
  assert.deepEqual(c.buckets, ['receipts']);
  assert.deepEqual(fromCode('db.collection("x").createDocument("a", "b")').collections, [], 'nothing without the SDK');

  const dir = tmp({
    '.env': 'VITE_APPWRITE_ENDPOINT=https://cloud.appwrite.io/v1\nVITE_APPWRITE_PROJECT_ID=envproj\nVITE_APPWRITE_DATABASE_ID=maindb\nVITE_APPWRITE_COLLECTION_ID_POSTS=posts\nVITE_APPWRITE_API_KEY=standard_0123456789abcdef0123456789abcdef\n',
    'src/lib.js': 'import { Client } from "appwrite";',
  });
  const src = await scanSource(dir);
  assert.deepEqual(src.endpoints, ['https://cloud.appwrite.io/v1']);
  assert.deepEqual(src.projects, ['envproj']);
  assert.deepEqual(src.databases, ['maindb']);
  assert.deepEqual(src.envCollections, ['posts']);
  assert.deepEqual(src.leakedEnvKeys.map((k) => k.name), ['VITE_APPWRITE_API_KEY']);
  const notes = [];
  assert.deepEqual(buildTargets(src, {}, notes).targets.map((t) => `${t.db}/${t.id}`), ['maindb/posts'], 'env collection ids use the env database');
});

test('--table needs a database: db/collection, or the only database in appwrite.json; --only filters', async () => {
  const src = await scanSource(FIXTURE_DIR);
  const notes = [];
  const { targets, buckets } = buildTargets(src, { tables: ['extra', 'other/thing'], only: ['notes', 'extra', 'other/thing', 'avatars'] }, notes);
  assert.deepEqual(targets.map((t) => `${t.db}/${t.id}`), ['main/notes', 'main/extra', 'other/thing']);
  assert.deepEqual(buckets.map((b) => b.id), ['avatars']);
  const noDb = [];
  buildTargets({ databases: ['a', 'b'] }, { tables: ['loose'] }, noDb);
  assert.match(noDb[0], /Not tested: loose — Appwrite collection ids need their database id\. Pass --table <database>\/<collection> \(databases in appwrite\.json: a, b\)/);
  // one collection id in two databases → db/id in the report
  const two = buildTargets({ codeCollections: [{ db: 'a', id: 'x', mode: 'documents' }, { db: 'b', id: 'x', mode: 'documents' }] }, {}, []);
  assert.deepEqual(two.targets.map((t) => t.name), ['a/x', 'b/x']);
});

test('detection: GET /v1/health/version → Appwrite, never Supabase', async () => {
  assert.deepEqual(await detected({ url: awUrl }), ['appwrite']);
  assert.deepEqual(await detected({ url: awUrl.replace(/\/v1$/, '') }), ['appwrite'], 'with or without /v1');
  assert.deepEqual(await detected({ url: sbUrl }), ['supabase'], 'a Supabase URL is not taken for Appwrite');
  await assert.rejects(plan({ url: awUrl }), /Appwrite project id not found\. Pass it with --project-id/);
  assert.equal(normalizeEndpoint('https://cloud.appwrite.io/v1/'), 'https://cloud.appwrite.io');
});

test('--project-id: Appwrite with --url or --platform appwrite, Firebase otherwise — never both', async () => {
  // --url + --project-id (no Firebase --api-key): Appwrite, even before the server answers
  assert.equal(await ownsProjectId({ url: 'https://unreachable.invalid/v1', projectId: 'p' }), true);
  assert.deepEqual(await ids({ url: awUrl, projectId: PROJECT_ID }), ['appwrite']);
  assert.deepEqual(await ids({ platform: 'appwrite', url: awUrl, projectId: PROJECT_ID }), ['appwrite']);
  const p = await plan({ url: awUrl, projectId: PROJECT_ID });
  assert.deepEqual(p.targets.map((t) => t.target), [`Appwrite ${awUrl.replace(/\/v1$/, '')} (project ${PROJECT_ID})`]);
  // Firebase flags stay Firebase
  assert.deepEqual(await ids({ projectId: 'my-firebase', apiKey: 'AIzaFake' }), ['firebase']);
  assert.deepEqual(await ids({ projectId: 'my-firebase' }), ['firebase']);
  assert.equal(await ownsProjectId({ projectId: 'x', apiKey: 'AIza', url: awUrl }), false);
  assert.equal(await ownsProjectId({ projectId: 'x', platform: 'firebase', url: awUrl }), false);
  // the id in appwrite.json: Appwrite only, with the endpoint from --url
  assert.deepEqual(await ids({ source: FIXTURE_DIR, projectId: PROJECT_ID }), ['appwrite']);
  // --platform appwrite: --project-id is the Appwrite project even when it differs from appwrite.json
  const forced = await plan({ platform: 'appwrite', url: awUrl, projectId: 'other-project', source: FIXTURE_DIR });
  assert.match(forced.targets[0].target, /\(project other-project\)$/);
});

test('detection from a folder: appwrite.json, or the SDK with setProject(); several endpoints need --url', async () => {
  assert.deepEqual(await ids({ source: FIXTURE_DIR }), ['appwrite']);
  const sdk = tmp({ 'src/a.ts': 'import { Client } from "appwrite";\nnew Client().setEndpoint("https://cloud.appwrite.io/v1").setProject("p1");' });
  assert.deepEqual(await ids({ source: sdk }), ['appwrite']);
  const p = await plan({ source: sdk });
  assert.equal(p.targets[0].target, 'Appwrite https://cloud.appwrite.io (project p1)');
  const two = tmp({ 'src/a.ts': 'import { Client } from "appwrite";\nnew Client().setEndpoint("http://localhost/v1").setProject("p1");\nnew Client().setEndpoint("https://cloud.appwrite.io/v1").setProject("p1");' });
  await assert.rejects(plan({ source: two }), /Several Appwrite endpoints are configured in this folder[\s\S]*--url/);
  const noProject = tmp({ 'appwrite.json': '{"endpoint":"https://cloud.appwrite.io/v1"}' });
  await assert.rejects(plan({ source: noProject }), /Appwrite project id not found\. Pass it with --project-id/);
});

test('MCP: project_id and platform appwrite reach the same options as the CLI', () => {
  const { opts } = toOptions({ url: 'https://cloud.appwrite.io/v1', project_id: 'p1', platform: 'appwrite' }, tmpdir());
  assert.equal(opts.projectId, 'p1');
  assert.equal(opts.platform, 'appwrite');
});

test('payload from attributes: marker in a string attribute, required ones filled, unfillable ones listed', () => {
  const marker = 'accessprobe-abc123';
  const p = schemaPayload(
    [
      { key: 'code', type: 'string', size: 4, required: true },
      { key: 'title', type: 'string', size: 100, required: true },
      { key: 'email', type: 'string', format: 'email', required: true },
      { key: 'status', type: 'string', format: 'enum', elements: ['open', 'done'], required: true },
      { key: 'age', type: 'integer', min: 13, max: 120, required: true },
      { key: 'tags', type: 'string', array: true, required: true, size: 2 },
      { key: 'optional', type: 'integer', required: false },
    ],
    marker,
  );
  assert.equal(p.markerField, 'title');
  assert.equal(p.data.code, 'acce');
  assert.match(p.data.email, /@example\.com$/);
  assert.equal(p.data.status, 'open');
  assert.equal(p.data.age, 13);
  assert.deepEqual(p.data.tags, ['ac']);
  assert.ok(!('optional' in p.data));
  assert.deepEqual(schemaPayload([{ key: 'owner', type: 'relationship', required: true }], marker).missing, ['owner (relationship)']);
});

test('path layer: documents and TablesDB rows', () => {
  assert.equal(API.documents.base('main', 'notes'), '/v1/databases/main/collections/notes/documents');
  assert.equal(API.rows.base('main', 'todos'), '/v1/tablesdb/main/tables/todos/rows');
});

test('fixes: permission strings, appwrite.json snippet only when the project has one, SDK snippet', () => {
  const t = { db: 'main', id: 'notes', mode: 'documents', config: { permissions: ['create("any")', 'read("users")'], security: false } };
  const code = permissionFix(t, ['read', 'create'], { configFile: 'appwrite.json' });
  assert.match(code, /Document security:\s+ON/);
  assert.match(code, /create\("users"\) only/);
  assert.match(code, /now: create\("any"\), read\("users"\); document security off/);
  assert.match(code, /create\("any"\) lets visitors/);
  assert.match(code, /appwrite\.json → collections → "notes"/);
  assert.match(code, /"documentSecurity": true/);
  assert.match(code, /Permission\.delete\(Role\.user\(user\.\$id\)\)/);
  const bare = permissionFix({ db: 'main', id: 'todos', mode: 'rows', config: null }, ['read'], {});
  assert.doesNotMatch(bare, /appwrite\.json/);
  assert.match(bare, /Row security:\s+ON/);
  assert.match(bare, /tablesDB\.createRow\(\{ databaseId: 'main', tableId: 'todos'/);
  assert.match(bucketFix({ id: 'up', config: null }, ['read']), /storage\.createFile\('up', ID\.unique\(\), file/);
});
