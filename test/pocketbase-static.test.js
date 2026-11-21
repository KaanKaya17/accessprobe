// PocketBase adapter without a server: reading pb_migrations, owner / privilege detection,
// detection from a project folder, and the fix rule strings.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { createServer } from 'node:http';
import { scan } from '../src/core/scan.js';
import { readMigrations, upBody } from '../src/providers/pocketbase/migrations.js';
import { authCollection, ownerFieldOf, privilegeRefs, privilegedByName } from '../src/providers/pocketbase/rules.js';
import { scanSource, fromCode } from '../src/providers/pocketbase/source.js';
import { ownerRules } from '../src/providers/pocketbase/fixes.js';
import * as pocketbase from '../src/providers/pocketbase/index.js';
import { byId } from '../src/providers/index.js';

const APP = fileURLToPath(new URL('./pocketbase/app/', import.meta.url));
const byName = (list, n) => list.find((c) => c.name === n);

test('fixture migrations: collections, rules and fields are read without running the code', async () => {
  const src = await scanSource(APP);
  assert.equal(src.migrationCount, 2);
  assert.deepEqual(src.urls, ['http://127.0.0.1:8090']);
  assert.deepEqual(src.codeCollections.sort(), ['messages', 'notes']);
  const notes = byName(src.collections, 'notes');
  assert.equal(notes.createRule, '@request.auth.id != "" && @request.body.user = @request.auth.id');
  assert.deepEqual(notes.fields.map((f) => f.name), ['text', 'user'], 'a shared field variable (owner) is resolved');
  assert.equal(byName(src.collections, 'admin_reports').createRule, null);
  assert.equal(byName(src.collections, 'posts').listRule, '');
  const users = byName(src.collections, 'users');
  assert.equal(users.updateRule, 'id = @request.auth.id && @request.body.plan:isset = false');
  assert.ok(users.fields.some((f) => f.name === 'role' && f.type === 'select' && f.values.includes('admin')));
});

test('v0.22 migrations (schema/options, Dao, unmarshal) and later rule assignments', () => {
  const files = [
    {
      name: '1690000000_created_todos.js',
      text: `migrate((db) => {
        const collection = new Collection({
          "id": "abc123", "name": "todos", "type": "base", "system": false,
          "schema": [
            { "name": "title", "type": "text", "required": true, "options": { "min": null, "max": null } },
            { "name": "owner", "type": "relation", "options": { "collectionId": "_pb_users_auth_", "maxSelect": 1 } }
          ],
          "listRule": "@request.auth.id != ''", "viewRule": null, "createRule": "", "updateRule": null, "deleteRule": null,
        });
        return Dao(db).saveCollection(collection);
      }, (db) => { const c = new Dao(db).findCollectionByNameOrId("abc123"); return new Dao(db).deleteCollection(c); })`,
    },
    {
      name: '1690000100_updated_todos.js',
      text: `migrate((db) => {
        const dao = new Dao(db)
        const collection = dao.findCollectionByNameOrId("abc123")
        unmarshal({ "viewRule": "owner = @request.auth.id" }, collection)
        collection.deleteRule = 'owner = @request.auth.id' // set by hand
        return dao.saveCollection(collection)
      }, (db) => { const collection = new Dao(db).findCollectionByNameOrId("abc123"); collection.viewRule = null; })`,
    },
  ];
  const todos = byName(readMigrations(files), 'todos');
  assert.equal(todos.listRule, "@request.auth.id != ''");
  assert.equal(todos.viewRule, 'owner = @request.auth.id', 'down() is not applied');
  assert.equal(todos.deleteRule, 'owner = @request.auth.id');
  assert.equal(todos.createRule, '');
  assert.equal(ownerFieldOf(todos, authCollection(readMigrations(files))), 'owner');
});

test('snapshot migrations and deleted collections', () => {
  const list = readMigrations([
    {
      name: '1_snapshot.js',
      text: `migrate((app) => {
        const snapshot = [
          { id: "pbc_1", name: "posts", type: "base", listRule: "", fields: [{ name: "author", type: "relation", collectionId: "_pb_users_auth_" }] },
          { id: "pbc_2", name: "old", type: "base", fields: [] },
        ];
        return app.importCollections(snapshot, false);
      }, (app) => {})`,
    },
    { name: '2_drop.js', text: 'migrate((app) => { const c = app.findCollectionByNameOrId("old"); app.delete(c); }, (app) => {})' },
  ]);
  assert.ok(byName(list, 'posts'));
  assert.equal(byName(list, 'old'), undefined);
  assert.equal(ownerFieldOf(byName(list, 'posts'), authCollection(list)), 'author');
});

test('upBody reads only the first migrate() argument, even with commas and parens in strings', () => {
  const body = upBody('migrate((app) => { const r = "a, b)"; f(1, 2); }, (app) => { DOWN(); })');
  assert.match(body, /f\(1, 2\)/);
  assert.doesNotMatch(body, /DOWN/);
});

test('privilege fields: @request.auth.<field> and @collection.<x>.<field> comparisons', () => {
  const cols = [
    { name: 'users', type: 'auth', fields: [] },
    { name: 'reports', listRule: '@request.auth.role = "admin" || @request.auth.isAdmin = true', fields: [] },
    { name: 'docs', viewRule: '@request.auth.id != "" && @collection.members.user ?= @request.auth.id && @collection.members.level = 9', fields: [] },
    { name: 'mine', listRule: 'user = @request.auth.id && @request.auth.verified = true', fields: [] },
  ];
  const refs = privilegeRefs(cols, authCollection(cols));
  assert.deepEqual(refs.get('users').map((r) => [r.field, r.value]), [['role', 'admin'], ['isAdmin', true], ['verified', true]]);
  assert.deepEqual(refs.get('members').map((r) => [r.field, r.value]), [['level', 9]]);
  // no rules visible: privilege-like names on the user's own record
  const byName = privilegedByName(null, { id: 'x', name: '', plan: 'free', isAdmin: false, credits: 3 }, []);
  assert.deepEqual(byName.map((f) => [f.field, f.value]), [['plan', 'pro'], ['isAdmin', true], ['credits', 1003]]);
});

test('owner field: the relation the rules compare with @request.auth.id wins over other relations', () => {
  const auth = { id: '_pb_users_auth_', name: 'users', type: 'auth' };
  const c = {
    name: 'tasks',
    listRule: 'assignee = @request.auth.id',
    fields: [
      { name: 'createdBy', type: 'relation', collectionId: '_pb_users_auth_' },
      { name: 'assignee', type: 'relation', collectionId: 'users' },
    ],
  };
  assert.equal(ownerFieldOf(c, auth), 'assignee');
  assert.equal(ownerFieldOf({ name: 'x', fields: [{ name: 'author', type: 'text' }] }, auth), 'author');
});

test('detection: SDK usage and URL in code / site bundles; Supabase does not claim a PocketBase-only folder', async () => {
  assert.deepEqual(fromCode('import PocketBase from "pocketbase"; const pb = new PocketBase("https://pb.example.com/");').urls, ['https://pb.example.com']);
  assert.equal(await pocketbase.detect({ source: APP }, { site: null }), true);
  assert.equal(await byId('supabase').detect({ source: APP }, { site: null }), false);
  assert.equal(await byId('firebase').detect({ source: APP }, { site: null }), false);
  assert.equal(await pocketbase.describe({ source: APP }, { site: null }), 'PocketBase http://127.0.0.1:8090');
  const site = { sources: [{ where: 'app.js', text: 'var e=new PocketBase("https://api.example.org");' }] };
  assert.equal(await pocketbase.detect({}, { site }), true);
});

test('fix rules use PocketBase rule syntax', () => {
  const r = ownerRules('user');
  assert.equal(r.listRule, 'user = @request.auth.id');
  assert.equal(r.createRule, '@request.auth.id != "" && @request.body.user = @request.auth.id');
  assert.equal(r.updateRule, 'user = @request.auth.id && (@request.body.user:isset = false || @request.body.user = @request.auth.id)');
  assert.equal(pocketbase.fixStyle.lang, 'js');
});

test('sign-up closed (users create rule superusers-only): a clear error, nothing else is touched', async () => {
  const seen = [];
  const server = createServer((req, res) => {
    seen.push(`${req.method} ${req.url}`);
    res.setHeader('Content-Type', 'application/json');
    if (req.url === '/api/health') return res.end('{"message":"API is healthy.","code":200,"data":{}}');
    res.statusCode = 403;
    res.end('{"data":{},"message":"Only superusers can perform this action.","status":403}');
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  try {
    await assert.rejects(scan({ url: `http://127.0.0.1:${server.address().port}`, quiet: true }), (e) => {
      assert.match(e.message, /Sign-up is closed/);
      assert.match(e.message, /--user-a email:password --user-b email:password/);
      return true;
    });
    assert.deepEqual(seen.filter((s) => s !== 'GET /api/health'), ['POST /api/collections/users/records']);
  } finally {
    server.close();
  }
});
