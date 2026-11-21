#!/usr/bin/env node
import { parseArgs } from 'node:util';
import { writeFile } from 'node:fs/promises';
import { createInterface } from 'node:readline/promises';
import { scan } from '../src/core/scan.js';
import { printReport, markdownReport, grade, color } from '../src/core/report.js';

const HELP = `
rlsprobe — prove your backend's access rules actually work (Supabase, Firebase)

Usage
  npx rlsprobe --site https://your-app.com --source .
  npx rlsprobe --url https://xyz.supabase.co --anon-key eyJ... --source .
  npx rlsprobe --project-id my-app --api-key AIza... --source .

Options
  --site <url>           Your deployed app. Finds the backend config in its JS
                         and checks the bundle for leaked secret keys.
  --source <dir>         Your project folder. Supabase: supabase/migrations/*.sql and
                         table names in code. Firebase: firestore.rules, storage.rules,
                         database.rules.json, google-services.json, collection names.
  --platform <name>      Force a backend (default: auto-detect): supabase, firebase

Supabase
  --url <url>            Supabase project URL (skip discovery)
  --anon-key <key>       Public anon / publishable key

Firebase
  --project-id <id>      Firebase project id (skip discovery)
  --api-key <key>        Web API key (AIza…, public by design)
  --emulator             Test against the local Firebase Emulator Suite (default ports)

Common
  --user-a <email:pw>    Existing test user A (default: sign up a new one)
  --user-b <email:pw>    Existing test user B
  --email-domain <d>     Domain for auto-created test users (default: example.com)
  --cleanup-rpc <fn>     At the end, call this RPC as each test user to delete them
                         (e.g. delete_my_account). Also applies to --user-a/--user-b!
  --table <name>         Also test this table (repeatable; for when the schema is hidden)
  --only <name>          Test only this table (repeatable)
  --bucket <name>        Also test this storage bucket (repeatable)
  --out <file.md>        Write a Markdown report with fix SQL + AI prompts
  --json                 Print the raw result as JSON
  --yes                  Skip the "I own this app" confirmation (for CI)
  -q, --quiet            Less output
  -h, --help

What it does
  Signs up two test users, has user A create rows/files, then checks whether
  user B (and an anonymous visitor) can read, change or delete them.
  Exit codes: 0 ok, 1 critical issue found, 2 usage error, 3 nothing could be tested.

Only test apps you own or are authorized to test.
`;

const OPTIONS = {
  site: { type: 'string' },
  url: { type: 'string' },
  'anon-key': { type: 'string' },
  'user-a': { type: 'string' },
  'user-b': { type: 'string' },
  'email-domain': { type: 'string' },
  'cleanup-rpc': { type: 'string' },
  source: { type: 'string' },
  platform: { type: 'string' },
  'project-id': { type: 'string' },
  'api-key': { type: 'string' },
  emulator: { type: 'boolean' },
  table: { type: 'string', multiple: true },
  only: { type: 'string', multiple: true },
  bucket: { type: 'string', multiple: true },
  out: { type: 'string' },
  json: { type: 'boolean' },
  yes: { type: 'boolean' },
  quiet: { type: 'boolean', short: 'q' },
  help: { type: 'boolean', short: 'h' },
};

let v;
try {
  ({ values: v } = parseArgs({ options: OPTIONS }));
} catch (e) {
  console.error(`${e.message}\nRun rlsprobe --help for usage.`);
  process.exit(2);
}

const target = v.site || v.url || (v['project-id'] && `Firebase project ${v['project-id']}`) || v.source;
if (v.help || !target) {
  console.log(HELP);
  process.exit(v.help ? 0 : 2);
}

if (!v.yes) {
  console.error(color.yellow('rlsprobe creates two test users and test rows/files in the target project, then removes the test data.'));
  const rl = createInterface({ input: process.stdin, output: process.stderr });
  // closed stdin (CI without --yes) must abort, not hang
  const a = await new Promise((resolve) => {
    rl.once('close', () => resolve(''));
    rl.question(`Do you own (or have permission to test) ${target}? [y/N] `).then(resolve, () => resolve(''));
  });
  rl.close();
  if (!/^y(es)?$/i.test(a.trim())) {
    console.error('Aborted.');
    process.exit(2);
  }
}

try {
  const result = await scan({
    site: v.site,
    url: v.url,
    anonKey: v['anon-key'],
    userA: v['user-a'],
    userB: v['user-b'],
    emailDomain: v['email-domain'],
    cleanupRpc: v['cleanup-rpc'],
    source: v.source,
    platform: v.platform,
    projectId: v['project-id'],
    apiKey: v['api-key'],
    emulator: v.emulator,
    tables: v.table,
    only: v.only,
    buckets: v.bucket,
    quiet: v.quiet || v.json,
  });
  if (v.json) console.log(JSON.stringify({ grade: grade(result.findings, result.stats), ...result }, null, 2));
  else printReport(result, { wroteFile: Boolean(v.out) });
  if (v.out) {
    await writeFile(v.out, markdownReport(result), 'utf8');
    if (!v.json) console.log(`Report written to ${v.out}`);
  }
  if (result.findings.some((f) => f.severity === 'critical')) process.exit(1);
  process.exit(grade(result.findings, result.stats) === 'N/A' ? 3 : 0);
} catch (e) {
  console.error(color.red(`\nError: ${e.message}`));
  process.exit(2);
}
