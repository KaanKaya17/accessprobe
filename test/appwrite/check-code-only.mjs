// Real Appwrite, no appwrite.json: collection ids from --table only, attributes guessed from
// Appwrite's error answers. Usage: node test/appwrite/check-code-only.mjs code-only.json
import { readFileSync } from 'node:fs';

const r = JSON.parse(readFileSync(process.argv[2], 'utf8'));
const errors = [];
const expect = (ok, what) => {
  if (!ok) errors.push(what);
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${what}`);
};
const ids = (res) => r.findings.filter((f) => f.resource === res).map((f) => f.id).sort();
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);

expect(r.notes.some((n) => /No appwrite\.json found/.test(n)), 'the report says the schema was guessed');
expect(same(ids('shared_docs'), ['cross-user-delete', 'cross-user-list', 'cross-user-read', 'cross-user-takeover', 'cross-user-update']), 'shared_docs: optional "content" found by guessing → every leak proven');
expect(same(ids('guestbook'), ['anon-create']), 'guestbook: required "message" learned from the error answer → anonymous create proven');
expect(r.passed.includes("guestbook: B cannot read A's documents"), 'guestbook: read refused (passed)');
expect(!r.passed.some((p) => p.startsWith('tasks:')) && r.notes.some((n) => n.startsWith('tasks: write tests skipped')), 'tasks: required enum cannot be guessed → noted, never passed');
expect(!r.passed.some((p) => p.startsWith('profiles:')) && r.notes.some((n) => n.startsWith('profiles: write tests skipped')), 'profiles: required integer cannot be guessed → noted, never passed');
expect(!r.notes.some((n) => /Could not delete/.test(n)), 'cleanup removed every test document');

if (errors.length) {
  console.log('\nFindings:', JSON.stringify(r.findings.map((f) => [f.resource, f.id]), null, 1));
  console.log('Passed:', JSON.stringify(r.passed, null, 1));
  console.log('Notes:', JSON.stringify(r.notes, null, 1));
  process.exit(1);
}
console.log('\nCode-only run matches.');
