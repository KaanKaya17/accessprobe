// Asserts accessprobe's result against a REAL Appwrite set up by setup.mjs from the fixture's
// appwrite.json, and (with the setup's server key) that nothing was left behind.
// Usage: node test/appwrite/check.mjs result.json [appwrite-setup.json]
import { readFileSync } from 'node:fs';

const r = JSON.parse(readFileSync(process.argv[2], 'utf8'));
const setup = JSON.parse(readFileSync(process.argv[3] || 'appwrite-setup.json', 'utf8'));
const config = JSON.parse(readFileSync(new URL('./app/appwrite.json', import.meta.url), 'utf8'));
const errors = [];
const expect = (ok, what) => {
  if (!ok) errors.push(what);
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${what}`);
};
const ids = (res) => r.findings.filter((f) => f.resource === res).map((f) => f.id).sort();
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const passed = (line) => r.passed.includes(line);

expect(same(r.platforms.map((p) => p.id), ['appwrite']), 'only Appwrite was tested');

expect(same(ids('notes'), []), 'notes: document security + create("users") only → no findings');
for (const p of ["B cannot read A's documents", "B cannot list A's documents", "anonymous visitors cannot read A's documents", "anonymous visitors cannot list A's documents", "B cannot modify A's documents", 'anonymous visitors cannot create documents', "B cannot delete A's documents", "B cannot change the permissions of A's documents"])
  expect(passed(`notes: ${p}`), `notes: ${p} (passed)`);

expect(same(ids('profiles'), ['anon-list', 'anon-read', 'cross-user-list', 'cross-user-read']), 'profiles: read("any") → B and anonymous read + list');
expect(passed("profiles: B cannot modify A's documents"), "profiles: B cannot modify A's documents (passed)");
expect(same(ids('tasks'), ['cross-user-takeover', 'cross-user-update']), 'tasks: update("users") → B modifies and takes over');
expect(passed("tasks: B cannot read A's documents"), "tasks: B cannot read A's documents (passed: 404 + control read)");
expect(same(ids('guestbook'), ['anon-create']), 'guestbook: create("any") → anonymous create');
expect(same(ids('shared_docs'), ['cross-user-delete', 'cross-user-list', 'cross-user-read', 'cross-user-takeover', 'cross-user-update']), 'shared_docs: document security off → B reads, lists, modifies, takes over, deletes');
expect(passed("shared_docs: anonymous visitors cannot read A's documents"), 'shared_docs: anonymous read refused (passed)');
expect(same(ids('admin_reports'), []) && passed('admin_reports: users cannot create documents (no create permission for users)'), 'admin_reports: read-only for users');
expect(same(ids('todos'), []) && passed("todos: B cannot read A's rows") && passed("todos: B cannot delete A's rows"), 'todos (TablesDB rows): no findings, attacks refused');
expect(same(ids('bucket avatars'), []) && passed("bucket avatars: B cannot download A's files") && passed("bucket avatars: B cannot delete A's files"), 'bucket avatars: no findings');
expect(same(ids('bucket uploads'), ['storage-anon-read', 'storage-cross-user-list', 'storage-cross-user-read']), 'bucket uploads: read("any") → downloads and listing');
expect(r.stats.fullyTested + r.stats.readOnly === r.stats.resources, `coverage: ${r.stats.fullyTested}+${r.stats.readOnly} of ${r.stats.resources}`);
expect(!r.notes.some((n) => /Could not|inconclusive/.test(n)), 'no cleanup failures and no inconclusive tests in the notes');
for (const f of r.findings) expect(/→ 20\d/.test(f.evidence), `${f.resource} ${f.id}: evidence is a successful request`);

// ---- what is left on the server (server key: verification only)
const get = async (path) => {
  const res = await fetch(setup.endpoint + path, { headers: { 'X-Appwrite-Project': setup.projectId, 'X-Appwrite-Key': setup.key } });
  return res.json();
};
for (const c of config.collections) {
  const j = await get(`/databases/${c.databaseId}/collections/${c.$id}/documents`);
  expect(j.total === 0, `cleanup: ${c.$id} has no documents left (${j.total ?? JSON.stringify(j)})`);
}
for (const t of config.tables) {
  const j = await get(`/tablesdb/${t.databaseId}/tables/${t.$id}/rows`);
  expect(j.total === 0, `cleanup: ${t.$id} has no rows left (${j.total ?? JSON.stringify(j)})`);
}
for (const b of config.buckets) {
  const j = await get(`/storage/buckets/${b.$id}/files`);
  expect(j.total === 0, `cleanup: bucket ${b.$id} has no files left (${j.total ?? JSON.stringify(j)})`);
}
const users = await get('/users');
expect(users.total === 2 && users.users.every((u) => u.status === false), `the 2 test users blocked themselves (${JSON.stringify((users.users || []).map((u) => [u.email, u.status]))})`);
expect(users.users?.every((u) => r.notes.some((n) => n.includes(u.email))), 'the report lists the test users for deletion');

if (errors.length) {
  console.log('\nFindings:', JSON.stringify(r.findings.map((f) => [f.resource, f.id, f.severity]), null, 1));
  console.log('Passed:', JSON.stringify(r.passed, null, 1));
  console.log('Notes:', JSON.stringify(r.notes, null, 1));
  process.exit(1);
}
console.log(`\nAll ${r.findings.length} findings and ${r.passed.length} passes match the fixture; nothing was left behind.`);
