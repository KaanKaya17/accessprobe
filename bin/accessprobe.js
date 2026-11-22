#!/usr/bin/env node
import { parseArgs } from 'node:util';
import { writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { createInterface } from 'node:readline/promises';
import { scan, plan } from '../src/core/scan.js';
import { printReport, markdownReport, grade, color } from '../src/core/report.js';
import { loadAccept } from '../src/core/accept.js';

const HELP = `
accessprobe — prove your backend's access rules actually work (Supabase, Firebase, PocketBase, Appwrite)

Usage
  npx accessprobe                  test the project in this folder (finds the config itself)
  npx accessprobe setup-agent      teach Claude Code / Codex / Cursor in this project to use accessprobe
  npx accessprobe mcp              run as an MCP server (stdio) for coding agents
  npx accessprobe --site https://your-app.com --source .
  npx accessprobe --url https://xyz.supabase.co --anon-key eyJ... --source .
  npx accessprobe --project-id my-app --api-key AIza... --source .
  npx accessprobe --url https://pb.your-app.com --source .
  npx accessprobe --url https://cloud.appwrite.io/v1 --project-id 6650abc --source .

Options
  --site <url>           Your deployed app. Finds the backend config in its JS
                         and checks the bundle for leaked secret keys.
  --source <dir>         Your project folder. Supabase: supabase/migrations/*.sql and
                         table names in code. Firebase: firestore.rules, storage.rules,
                         database.rules.json, google-services.json, collection names.
                         PocketBase: pb_migrations/*.js (collections + API rules),
                         new PocketBase("…") and pb.collection("…") in code.
                         Appwrite: appwrite.json (collections, attributes, permissions,
                         buckets), setEndpoint/setProject and createDocument("db", "…").
  --platform <name>      Force a backend (default: auto-detect): supabase, firebase,
                         pocketbase, appwrite

Supabase
  --url <url>            Supabase project URL (skip discovery)
  --anon-key <key>       Public anon / publishable key
  --schema <file.sql>    The live schema, when migrations don't match production
                         (repeatable): supabase db dump -f schema.sql

PocketBase
  --url <url>            PocketBase server URL. Never pass admin / superuser
                         credentials: test users sign up through "users".

Appwrite
  --url <url>            Appwrite endpoint (https://cloud.appwrite.io/v1 or your server;
                         detected through the public /v1/health/version)
  --project-id <id>      Appwrite project id. With --url (and no --api-key) or
                         --platform appwrite, --project-id means the Appwrite project.
                         Never pass an API key: test users sign up through the Account API.
  --table <db>/<coll>    Appwrite collection ids need their database id (a bare name
                         uses the only database in appwrite.json)

Firebase
  --project-id <id>      Firebase project id (skip discovery)
  --api-key <key>        Web API key (AIza…, public by design)
  --emulator             Test against the local Firebase Emulator Suite (default ports)
  --database-rules <f>   Rules exported from the console, if they are not in --source:
  --firestore-rules <f>    firebase database:get /.settings/rules > database.rules.json
  --storage-rules <f>
  --rules-tests <file>   Also write the checks as Security Rules tests for the Emulator
                         Suite (e.g. test/accessprobe.rules.test.mjs, node:test +
                         @firebase/rules-unit-testing). Leaks found now fail until fixed.

Common
  --user-a <email:pw>    Existing test user A (default: sign up a new one)
  --user-b <email:pw>    Existing test user B
  --email-domain <d>     Domain for auto-created test users (default: example.com)
  --fresh-users          Supabase / Appwrite: sign up new test users and keep none.
                         By default the two test users are saved outside your project
                         (~/.cache/accessprobe) and reused, so runs don't pile up accounts.
  --read-only            Send no request that could change anything: no sign-ups, rows,
                         files or RPC calls. Needs --user-a and --user-b. Checks what
                         anonymous visitors and user B can read of the data already
                         there; write checks are skipped (for production, or tables
                         with triggers / webhooks you don't want to fire).
  --ignore-file <f>      Findings that are open on purpose (default: .accessprobeignore
                         in --source or this folder). One per line:
                           profiles  cross-user-read   # public profiles, by design
                         They are listed as "Accepted" and don't count for the grade
                         or the exit code, or fail the --pgtap / --rules-tests files.
  --cleanup-rpc <fn>     At the end, call this RPC as each test user to delete them
                         (e.g. delete_my_account). Also applies to --user-a/--user-b!
  --table <name>         Also test this table / collection (repeatable; for when the
                         schema is hidden; Appwrite: database/collection)
  --only <name>          Test only this table / collection (repeatable)
  --bucket <name>        Also test this storage bucket (repeatable)
  --out <file.md>        Write a Markdown report with fix SQL + AI prompts
  --pgtap <file.sql>     Supabase: also write the checks as pgTAP tests for
                         "supabase test db" (e.g. supabase/tests/accessprobe.test.sql).
                         Leaks found now fail until fixed; then they guard CI.
  --json                 Print the raw result as JSON
  --yes                  Skip the "I own this app" confirmation (for CI)
  -q, --quiet            Less output
  -v, --version
  -h, --help

What it does
  Signs up two test users, has user A create rows/files, then checks whether
  user B (and an anonymous visitor) can read, change or delete them.
  Firebase with Anonymous sign-in enabled: an anonymous-auth user attacks too
  (its token passes "request.auth != null").
  Exit codes: 0 ok, 1 critical issue found, 2 usage error, 3 nothing could be tested.

Only test apps you own or are authorized to test.
`;

const OPTIONS = {
  site: { type: 'string' },
  url: { type: 'string' },
  'anon-key': { type: 'string' },
  schema: { type: 'string', multiple: true },
  'user-a': { type: 'string' },
  'user-b': { type: 'string' },
  'email-domain': { type: 'string' },
  'fresh-users': { type: 'boolean' },
  'cleanup-rpc': { type: 'string' },
  'read-only': { type: 'boolean' },
  'ignore-file': { type: 'string' },
  source: { type: 'string' },
  platform: { type: 'string' },
  'project-id': { type: 'string' },
  'api-key': { type: 'string' },
  emulator: { type: 'boolean' },
  'database-rules': { type: 'string' },
  'firestore-rules': { type: 'string' },
  'storage-rules': { type: 'string' },
  table: { type: 'string', multiple: true },
  only: { type: 'string', multiple: true },
  bucket: { type: 'string', multiple: true },
  out: { type: 'string' },
  pgtap: { type: 'string' },
  'rules-tests': { type: 'string' },
  json: { type: 'boolean' },
  yes: { type: 'boolean' },
  quiet: { type: 'boolean', short: 'q' },
  help: { type: 'boolean', short: 'h' },
  version: { type: 'boolean', short: 'v' },
};

let v;
let positionals = [];
try {
  ({ values: v, positionals } = parseArgs({ options: { ...OPTIONS, force: { type: 'boolean' } }, allowPositionals: true }));
} catch (e) {
  console.error(`${e.message}\nRun accessprobe --help for usage.`);
  process.exit(2);
}

if (positionals[0] === 'mcp') {
  const { serveStdio } = await import('../src/mcp/server.js');
  serveStdio();
  await new Promise(() => {}); // the server exits itself when stdin closes
} else if (positionals[0] === 'setup-agent') {
  const { setupAgent } = await import('../src/core/setup-agent.js');
  for (const line of await setupAgent(process.cwd(), { force: v.force })) console.log(`  ✔ ${line}`);
  console.log('\nYour coding agent can now run accessprobe. Try asking it: "check my database rules with accessprobe".');
  process.exit(0);
} else if (positionals.length) {
  console.error(`Unknown command "${positionals[0]}". Run accessprobe --help for usage.`);
  process.exit(2);
}

if (v.version) {
  const { readFileSync } = await import('node:fs');
  console.log(JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')).version);
  process.exit(0);
}

// `npx accessprobe` inside a project folder: test that project
if (!v.help && !v.site && !v.url && !v['project-id'] && !v.source && looksLikeProject(process.cwd())) {
  v.source = '.';
  console.error(color.dim(`No target given — testing the project in this folder (${process.cwd()}).`));
}

const target = v.site || v.url || (v['project-id'] && `project ${v['project-id']}`) || (v.source && `the project in ${v.source === '.' ? process.cwd() : v.source}`);
if (v.help || !target) {
  console.log(HELP);
  process.exit(v.help ? 0 : 2);
}

function looksLikeProject(dir) {
  return [
    'package.json', 'supabase', 'pb_migrations', 'appwrite.json', 'appwrite.config.json', 'firebase.json', 'firestore.rules', 'database.rules.json', 'pubspec.yaml',
    'build.gradle', 'build.gradle.kts', 'settings.gradle', 'settings.gradle.kts', 'local.properties', '.env', '.env.local',
  ].some((f) => existsSync(join(dir, f)));
}

if (v['read-only'] && !(v['user-a'] && v['user-b'])) {
  console.error('--read-only needs two existing test accounts: --user-a email:password --user-b email:password\n(signing up new users would be a write).');
  process.exit(2);
}

let accept;
try {
  accept = await loadAccept({ file: v['ignore-file'], source: v.source });
} catch (e) {
  console.error(color.red(`Error: ${e.message}`));
  process.exit(2);
}
if (accept.file && !v.quiet && !v.json) console.error(color.dim(`Accepted findings: ${accept.entries.length} in ${accept.file}`));

const opts = {
  site: v.site,
  readOnly: v['read-only'],
  accept,
  url: v.url,
  anonKey: v['anon-key'],
  schemaFiles: v.schema,
  userA: v['user-a'],
  userB: v['user-b'],
  emailDomain: v['email-domain'],
  freshUsers: v['fresh-users'],
  cleanupRpc: v['cleanup-rpc'],
  source: v.source,
  platform: v.platform,
  projectId: v['project-id'],
  apiKey: v['api-key'],
  emulator: v.emulator,
  databaseRules: v['database-rules'],
  firestoreRules: v['firestore-rules'],
  storageRules: v['storage-rules'],
  tables: v.table,
  only: v.only,
  buckets: v.bucket,
  quiet: v.quiet || v.json,
};

// Resolve exactly which backend projects would be touched BEFORE asking — the user (or an agent
// running with --yes) approves the real targets, not just a folder name.
let prepared;
try {
  prepared = await plan(opts, { log: opts.quiet ? () => {} : (m) => console.error(m) });
} catch (e) {
  console.error(color.red(`\nError: ${e.message}`));
  process.exit(2);
}
const targets = prepared.targets.map((t) => t.target);
console.error(`Target: ${targets.join(' + ')}`);

if (!v.yes) {
  console.error(
    color.yellow(
      v['read-only']
        ? 'Read-only: accessprobe signs in as your two test users and only reads; nothing is created, changed or deleted.'
        : 'accessprobe creates two test users and test rows/files in the target project, then removes the test data.\n' +
            'Inserts fire your triggers and webhooks like real ones; use --read-only where that matters.',
    ),
  );
  const rl = createInterface({ input: process.stdin, output: process.stderr });
  // closed stdin (CI without --yes) must abort, not hang
  const a = await new Promise((resolve) => {
    rl.once('close', () => resolve(''));
    rl.question(`Do you own (or have permission to test) ${targets.join(' and ')}? [y/N] `).then(resolve, () => resolve(''));
  });
  rl.close();
  if (!/^y(es)?$/i.test(a.trim())) {
    console.error('Aborted.');
    process.exit(2);
  }
}

try {
  const result = await scan(opts, prepared);
  const { recipes, rulesRecipes, ...shown } = result;
  if (v.json) console.log(JSON.stringify({ grade: grade(result.findings, result.stats), ...shown }, null, 2));
  else printReport(result, { wroteFile: Boolean(v.out) });
  if (v.out) {
    await writeFile(v.out, markdownReport(result), 'utf8');
    if (!v.json) console.log(`Report written to ${v.out}`);
  }
  if (v.pgtap) {
    const { writePgtap } = await import('../src/providers/supabase/pgtap.js');
    const msg = await writePgtap(v.pgtap, result);
    console.error(msg);
  }
  if (v['rules-tests']) {
    const { writeRulesTests } = await import('../src/providers/firebase/rules-tests.js');
    const rulesFiles = { firestore: v['firestore-rules'], database: v['database-rules'], storage: v['storage-rules'] };
    console.error(await writeRulesTests(v['rules-tests'], result, { source: v.source, rulesFiles }));
  }
  if (result.findings.some((f) => f.severity === 'critical')) process.exit(1);
  process.exit(grade(result.findings, result.stats) === 'N/A' ? 3 : 0);
} catch (e) {
  console.error(color.red(`\nError: ${e.message}`));
  process.exit(2);
}
