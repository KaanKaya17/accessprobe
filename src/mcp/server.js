// `accessprobe mcp`: a Model Context Protocol server over stdio (newline-delimited JSON-RPC 2.0),
// so coding agents (Claude Code, Cursor, Codex, …) can run accessprobe after they change tables,
// policies or rules. No dependencies. stdout carries protocol messages only; logs go to stderr.

import { createInterface } from 'node:readline';
import { readFileSync, existsSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { writeFile } from 'node:fs/promises';
import { scan, plan } from '../core/scan.js';
import { markdownReport, grade } from '../core/report.js';
import { fixCode } from '../core/prompt.js';
import { loadAccept, resourceOf } from '../core/accept.js';
import { writePgtap } from '../providers/supabase/pgtap.js';
import { writeRulesTests } from '../providers/firebase/rules-tests.js';

const VERSION = JSON.parse(readFileSync(new URL('../../package.json', import.meta.url), 'utf8')).version;
const PROTOCOLS = ['2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05'];

const TARGET_PROPS = {
  directory: { type: 'string', description: 'Project folder (default: the folder the server was started in). Relative paths below resolve against it.' },
  source: { type: 'string', description: 'Folder with supabase/migrations, firestore.rules, pb_migrations, appwrite.json, … (default: directory, when no site/url/project_id is given).' },
  site: { type: 'string', description: 'Deployed app URL. accessprobe finds the backend config in its JavaScript and checks the bundle for leaked secret keys.' },
  url: { type: 'string', description: 'Supabase project URL, PocketBase server URL or Appwrite endpoint (https://cloud.appwrite.io/v1).' },
  anon_key: { type: 'string', description: 'Supabase anon / publishable key (public by design). Never pass the service_role key.' },
  schema_files: { type: 'array', items: { type: 'string' }, description: 'Supabase: SQL schema dumps of the live database (supabase db dump -f schema.sql), when migrations do not match production.' },
  project_id: { type: 'string', description: 'Firebase project id, or the Appwrite project id when url is an Appwrite endpoint (or platform is appwrite).' },
  api_key: { type: 'string', description: 'Firebase Web API key (AIza…, public by design).' },
  emulator: { type: 'boolean', description: 'Test against the local Firebase Emulator Suite (default ports).' },
  platform: { type: 'string', enum: ['supabase', 'firebase', 'pocketbase', 'appwrite'], description: 'Force a backend (default: auto-detect).' },
  firestore_rules: { type: 'string', description: 'firestore.rules file, if it is not in source.' },
  storage_rules: { type: 'string', description: 'storage.rules file, if it is not in source.' },
  database_rules: { type: 'string', description: 'Realtime Database rules JSON, if it is not in source.' },
  tables: { type: 'array', items: { type: 'string' }, description: 'Also test these tables / collections.' },
  only: { type: 'array', items: { type: 'string' }, description: 'Test only these tables / collections.' },
  buckets: { type: 'array', items: { type: 'string' }, description: 'Also test these storage buckets.' },
};

const SCAN_PROPS = {
  owner_confirmed: {
    type: 'boolean',
    description: 'true only after the user has confirmed in this conversation that they own (or may test) the target from accessprobe_plan.',
  },
  ...TARGET_PROPS,
  user_a: { type: 'string', description: 'Existing test user A as email:password (default: sign up a new one).' },
  user_b: { type: 'string', description: 'Existing test user B as email:password.' },
  email_domain: { type: 'string', description: 'Domain for auto-created test users (default: example.com).' },
  fresh_users: { type: 'boolean', description: 'Supabase / Appwrite: sign up new test users instead of reusing the ones saved by an earlier run.' },
  read_only: {
    type: 'boolean',
    description:
      'Send no request that could change anything (no sign-ups, rows, files, RPC calls); needs user_a and user_b. Only reads are tested, write checks are skipped. Use it for production or tables with triggers / webhooks.',
  },
  ignore_file: {
    type: 'string',
    description:
      'Findings that are open on purpose (default: .accessprobeignore in the project). Lines like "profiles cross-user-read  # public by design". They are reported as accepted and not graded. Only add entries the user confirmed are intended.',
  },
  cleanup_rpc: { type: 'string', description: 'Supabase RPC each test user calls at the end to delete itself (e.g. delete_my_account).' },
  report_file: { type: 'string', description: 'Also write the Markdown report to this file (relative to directory).' },
  pgtap_file: {
    type: 'string',
    description:
      'Supabase: also write the checks as pgTAP tests for `supabase test db` (e.g. supabase/tests/accessprobe.test.sql). Tests for proven leaks fail until fixed, then guard against regressions.',
  },
  rules_tests_file: {
    type: 'string',
    description:
      'Firebase: also write the checks as Security Rules tests for the Emulator Suite (e.g. test/accessprobe.rules.test.mjs; node:test + @firebase/rules-unit-testing, run with firebase emulators:exec "node --test <file>"). Tests for proven leaks fail until fixed.',
  },
};

export const TOOLS = [
  {
    name: 'accessprobe_plan',
    title: 'Show what accessprobe would test',
    description:
      'Read-only. Works out which backend (Supabase, Firebase, PocketBase, Appwrite) and exactly which project / URL accessprobe_scan would touch. ' +
      'Nothing is written. Call this first and show the targets to the user before asking whether they own them.',
    inputSchema: { type: 'object', properties: TARGET_PROPS, additionalProperties: false },
    annotations: { readOnlyHint: true, openWorldHint: true },
  },
  {
    name: 'accessprobe_scan',
    title: 'Prove whether access rules hold',
    description:
      'Tests Supabase RLS, Firebase Security Rules, PocketBase API rules or Appwrite permissions with two real test users: A creates data, then B and an anonymous visitor ' +
      'try to read, change, forge and delete it. Only proven leaks are reported as critical, each with evidence and a fix. ' +
      'It creates two test users and test rows/files in the target and removes the test data afterwards, so only run it on apps the user owns: ' +
      'show them the targets from accessprobe_plan, get a clear yes, then set owner_confirmed. Prefer a local or staging backend ' +
      '(supabase start, the Firebase Emulator Suite, a local PocketBase or Appwrite) over production. Items in notes were NOT tested; never call them safe.',
    inputSchema: { type: 'object', properties: SCAN_PROPS, required: ['owner_confirmed'], additionalProperties: false },
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
  },
];

const PROJECT_MARKERS = ['package.json', 'supabase', 'pb_migrations', 'appwrite.json', 'appwrite.config.json', 'firebase.json', 'firestore.rules', 'database.rules.json', 'pubspec.yaml', '.env', '.env.local'];

// MCP arguments (snake_case) → the options scan() takes. Paths resolve against `directory`.
export function toOptions(args = {}, cwd = process.cwd()) {
  const dir = resolve(cwd, args.directory || '.');
  const path = (p) => (p ? resolve(dir, p) : undefined);
  let source = path(args.source);
  if (!source && !args.site && !args.url && !args.project_id) {
    if (!PROJECT_MARKERS.some((f) => existsSync(join(dir, f)))) {
      throw new Error(`${dir} does not look like a project folder. Pass directory, source, site, url or project_id.`);
    }
    source = dir;
  }
  const list = (x) => (Array.isArray(x) && x.length ? x.map(String) : undefined);
  return {
    dir,
    opts: {
      site: args.site,
      url: args.url,
      anonKey: args.anon_key,
      schemaFiles: list(args.schema_files)?.map((f) => resolve(dir, f)),
      userA: args.user_a,
      userB: args.user_b,
      emailDomain: args.email_domain,
      freshUsers: args.fresh_users,
      cleanupRpc: args.cleanup_rpc,
      readOnly: args.read_only === true,
      source,
      platform: args.platform,
      projectId: args.project_id,
      apiKey: args.api_key,
      emulator: args.emulator,
      databaseRules: path(args.database_rules),
      firestoreRules: path(args.firestore_rules),
      storageRules: path(args.storage_rules),
      tables: list(args.tables),
      only: list(args.only),
      buckets: list(args.buckets),
      quiet: true,
    },
  };
}

function exitCode(result) {
  if (result.findings.some((f) => f.severity === 'critical')) return 1;
  return grade(result.findings, result.stats) === 'N/A' ? 3 : 0;
}

async function callTool(name, args, cwd) {
  if (name === 'accessprobe_plan') {
    const { opts } = toOptions(args, cwd);
    const p = await plan(opts);
    const targets = p.targets.map((t) => ({ platform: t.provider.id, target: t.target }));
    const text =
      `accessprobe_scan would test:\n${targets.map((t) => `- ${t.target} (${t.platform})`).join('\n')}\n\n` +
      'It signs up two test users there and creates test rows/files, then deletes the test data. ' +
      'Ask the user whether they own (or may test) these targets before running accessprobe_scan.';
    return { content: [{ type: 'text', text }], structuredContent: { targets } };
  }
  if (name === 'accessprobe_scan') {
    if (args.owner_confirmed !== true) {
      return toolError(
        'Not run: owner_confirmed is not true. Call accessprobe_plan, show the targets to the user, and ask whether they own (or may test) them. ' +
          'Set owner_confirmed only after a clear yes.',
      );
    }
    const { dir, opts } = toOptions(args, cwd);
    if (opts.readOnly && !(opts.userA && opts.userB)) return toolError('read_only needs user_a and user_b: signing up new test users would be a write.');
    opts.accept = await loadAccept({ file: args.ignore_file && resolve(dir, args.ignore_file), source: opts.source || dir });
    const result = await scan(opts);
    const md = markdownReport(result);
    if (args.report_file) await writeFile(resolve(dir, args.report_file), md, 'utf8');
    const pgtapNote = args.pgtap_file ? `${await writePgtap(resolve(dir, args.pgtap_file), result)}\n\n` : '';
    const rulesNote = args.rules_tests_file
      ? `${await writeRulesTests(resolve(dir, args.rules_tests_file), result, { source: opts.source || dir, rulesFiles: { firestore: opts.firestoreRules, database: opts.databaseRules, storage: opts.storageRules } })}\n\n`
      : '';
    const g = grade(result.findings, result.stats);
    const code = exitCode(result);
    const summary = {
      grade: g,
      exitCode: code,
      target: result.target,
      critical: result.findings.filter((f) => f.severity === 'critical').length,
      warnings: result.findings.filter((f) => f.severity === 'warning').length,
      findings: result.findings.map((f) => ({
        id: f.id,
        severity: f.severity,
        platform: f.platform,
        table: f.table,
        title: f.title,
        evidence: f.evidence,
        fix: fixCode(f) ?? undefined,
        fixSteps: f.fix?.steps,
      })),
      accepted: (result.accepted || []).map((f) => ({ id: f.id, platform: f.platform, resource: resourceOf(f), title: f.title, reason: f.acceptedBecause })),
      passed: result.passed,
      notes: result.notes,
      stats: result.stats,
    };
    const head =
      code === 3
        ? 'Nothing could be tested. This is NOT a clean bill of health; see Notes.'
        : code === 1
          ? `Grade ${g}: ${summary.critical} proven critical problem(s). Each one below has evidence and a fix. Show the user before changing rules, and ask before deploying.`
          : `Grade ${g}: no critical findings. Anything under Notes was not tested.`;
    return { content: [{ type: 'text', text: `${head}\n\n${pgtapNote}${rulesNote}${md}` }], structuredContent: summary };
  }
  return null;
}

function toolError(text) {
  return { content: [{ type: 'text', text }], isError: true };
}

export function createServer({ write = (m) => process.stdout.write(`${JSON.stringify(m)}\n`), cwd = process.cwd() } = {}) {
  let queue = Promise.resolve(); // one scan at a time: test users and rows must not interleave

  async function handle(msg) {
    if (!msg || typeof msg !== 'object' || msg.jsonrpc !== '2.0' || typeof msg.method !== 'string') {
      return msg && 'id' in msg ? err(msg.id ?? null, -32600, 'Invalid request') : null;
    }
    const isRequest = 'id' in msg && msg.id !== null;
    if (!isRequest) return null; // notifications (initialized, cancelled, …) need no answer
    const { id, method, params = {} } = msg;
    switch (method) {
      case 'initialize': {
        const asked = params.protocolVersion;
        return ok(id, {
          protocolVersion: PROTOCOLS.includes(asked) ? asked : PROTOCOLS[0],
          capabilities: { tools: { listChanged: false } },
          serverInfo: { name: 'accessprobe', title: 'accessprobe', version: VERSION },
          instructions:
            'accessprobe proves whether Supabase RLS, Firebase Security Rules, PocketBase API rules and Appwrite permissions hold, using two real test users. ' +
            'Run it after changing tables, policies, rules or data access code. Always call accessprobe_plan first and ask the user to ' +
            'confirm they own the targets before accessprobe_scan.',
        });
      }
      case 'ping':
        return ok(id, {});
      case 'tools/list':
        return ok(id, { tools: TOOLS });
      case 'tools/call': {
        const name = params.name;
        if (!TOOLS.some((t) => t.name === name)) return err(id, -32602, `Unknown tool: ${name}`);
        const run = queue.then(async () => {
          try {
            return await callTool(name, params.arguments || {}, cwd);
          } catch (e) {
            return toolError(`accessprobe failed: ${e.message}`);
          }
        });
        queue = run.catch(() => {});
        return ok(id, await run);
      }
      default:
        return err(id, -32601, `Method not found: ${method}`);
    }
  }

  async function receive(line) {
    if (!line.trim()) return;
    let msg;
    try {
      msg = JSON.parse(line);
    } catch {
      write(err(null, -32700, 'Parse error'));
      return;
    }
    if (Array.isArray(msg)) {
      const replies = (await Promise.all(msg.map(handle))).filter(Boolean);
      if (replies.length) write(replies);
      return;
    }
    const reply = await handle(msg);
    if (reply) write(reply);
  }

  return { receive, handle };
}

const ok = (id, result) => ({ jsonrpc: '2.0', id, result });
const err = (id, code, message) => ({ jsonrpc: '2.0', id, error: { code, message } });

export function serveStdio() {
  // anything printed to stdout outside the protocol would break the client
  console.log = console.error;
  console.info = console.error;
  const server = createServer();
  const rl = createInterface({ input: process.stdin, crlfDelay: Infinity });
  const pending = new Set();
  rl.on('line', (line) => {
    const p = server.receive(line).finally(() => pending.delete(p));
    pending.add(p);
  });
  rl.on('close', async () => {
    await Promise.allSettled([...pending]);
    process.exit(0);
  });
  console.error(`accessprobe MCP server ${VERSION} ready (stdio)`);
}
