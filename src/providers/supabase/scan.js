import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { SupabaseClient, decodeJwt } from './client.js';
import { looksLikePocketBase } from '../pocketbase/client.js';
import { claimsUrl as appwriteClaimsUrl } from '../appwrite/scan.js';
import { findProjectConfig } from './project-config.js';
import { withReusableUsers, saveUsers, forgetUsers, usersFile } from '../../core/test-users.js';
import { extract } from './discover.js';
import { parseSchema } from './schema.js';
import { scanSource, sourceToDefinitions } from './source.js';
import { setupUsers, resolveIdentities, probeTables, probeStorage, rpcReview, cleanupRows, msg } from './probes.js';
import { parseFunctions, probeFunctions, definerFindings } from './functions.js';
import { probeGraphql } from './graphql.js';

const CLEANUP_RPC_HINT = /^(delete_(my_)?(own_)?(account|user|profile)|delete_me)$/i;

export const id = 'supabase';
export const label = 'Supabase';

// project folder config is looked up once per run and shared by detect() and scan()
const projectCache = new Map();
const projectConfig = (dir) => {
  if (!projectCache.has(dir)) projectCache.set(dir, findProjectConfig(dir));
  return projectCache.get(dir);
};

// Is this app a Supabase app? Explicit flags, config in the site bundle, a supabase/ folder,
// or a Supabase URL/anon key somewhere in the project (.env, local.properties, client code).
export async function detect(opts, { site }) {
  if (opts.anonKey) return true;
  // --url is shared with PocketBase and Appwrite: a server that answers like one of them is not Supabase
  if (opts.url) return !(await looksLikePocketBase(opts.url)) && !(await appwriteClaimsUrl(opts));
  if (site && extract(site.sources).anonKeys.length) return true;
  if (opts.source) {
    if (existsSync(join(opts.source, 'supabase'))) return true;
    const cfg = await projectConfig(opts.source);
    return cfg.urls.length > 0 && cfg.anonKeys.length > 0;
  }
  return false;
}

// Which Supabase project will be touched — shared by describe() (shown before asking for
// consent) and scan(), so what the user approves is exactly what gets tested.
async function resolveTarget(opts, site) {
  const findings = [];
  const notes = [];
  let { url, anonKey } = opts;
  if (site) {
    const d = extract(site.sources);
    findings.push(...d.findings);
    url ||= d.urls[0];
    anonKey ||= d.anonKeys[0];
    if (d.urls.length > 1) notes.push(`Multiple Supabase URLs found in the site, using ${url}: ${d.urls.join(', ')}`);
  }
  if (opts.source) {
    const pc = await projectConfig(opts.source);
    findings.push(...pc.findings);
    notes.push(...pc.notes);
    if (!url && pc.urls.length > 1) {
      // e.g. .env (production) and .env.local (local): never guess which one to write test users to
      throw new Error(`Several Supabase projects are configured in this folder: ${pc.urls.join(', ')}\n  Pass --url to choose which one to test.`);
    }
    url ||= pc.urls[0];
    anonKey ||= pc.anonKeys[0];
  }
  if (!url || !anonKey) {
    throw new Error('Supabase URL / anon key not found. Pass them with --url and --anon-key (the public anon key, never the service_role key).');
  }
  const payload = decodeJwt(anonKey);
  if (payload?.role === 'service_role' || anonKey.startsWith('sb_secret_')) {
    throw new Error('That is a service_role / secret key. Pass the public anon key — the tool must see what an attacker sees.');
  }
  return { url: url.replace(/\/+$/, ''), anonKey, findings, notes };
}

export async function describe(opts, { site }) {
  const { url } = await resolveTarget(opts, site);
  return `Supabase project ${url}`;
}

export async function scan(opts, { site, log }) {
  const t0 = Date.now();
  const passed = [];
  const { url, anonKey, findings, notes } = await resolveTarget(opts, site);
  if (site) log(`→ Supabase config from ${site.url}`);
  if (!opts.url && opts.source) log(`  Supabase project: ${url}`);

  const client = new SupabaseClient({ url, anonKey, readOnly: opts.readOnly });

  // 2. two test users
  log('→ Signing in two test users (A and B)');
  const { users, reuse } = await withReusableUsers({ platform: 'supabase', target: url, opts, log }, (userA, userB) =>
    setupUsers(client, { userA, userB, emailDomain: opts.emailDomain, log }),
  );

  const created = []; // test rows, cleaned up in finally even if a probe throws
  try {
    // 3. schema — as anon AND as a signed-in user: PostgREST only lists what the role may touch
    log(`→ Reading API schema from ${url}/rest/v1/`);
    const schema = await loadSchema(client, users[0].token, notes, opts.source, log, opts.schemaFiles);
    for (const name of opts.tables || []) {
      if (!schema.tables.find((t) => t.name === name)) {
        schema.tables.push({ name, columns: [], pk: null, owner: null, writable: true, isView: false, nameOnly: true });
      }
    }
    if (opts.only?.length) schema.tables = schema.tables.filter((t) => opts.only.includes(t.name));
    log(`  ${schema.tables.length} tables, ${schema.rpcs.length} functions exposed`);
    const noOwner = schema.tables.filter((t) => !t.owner && !t.isView).map((t) => t.name);
    if (noOwner.length) notes.push(`No owner column detected for: ${noOwner.join(', ')} (looked for user_id, owner_id, created_by, …)`);

    await resolveIdentities(client, schema, users);

    // 4. probes
    log('→ Testing tables');
    const tables = await probeTables(client, schema, users, { log, created });
    findings.push(...tables.findings);
    passed.push(...tables.passed);

    log('→ Testing storage');
    const storage = await probeStorage(client, users, { extraBuckets: opts.buckets || [], log });
    findings.push(...storage.findings);
    passed.push(...storage.passed);
    if (!storage.count) notes.push('No storage buckets visible to the test users (pass --bucket <name> to test one anyway).');

    log('→ Testing database functions');
    const fnSkipped = [];
    const rpcs = opts.only?.length ? schema.rpcs.filter((r) => opts.only.includes(r)) : schema.rpcs;
    const proven = await probeFunctions(client, rpcs, tables.protectedRows, users, { findings, passed, skipped: fnSkipped, defs: schema.functions });
    findings.push(...definerFindings(schema.functions, { exposed: new Set(schema.rpcs), proven }));

    await probeGraphql(client, { findings, passed, skipped: fnSkipped, only: opts.only });

    notes.push(...tables.skipped, ...storage.skipped, ...fnSkipped);
    findings.push(...rpcReview(schema));

    const hint = schema.rpcs.find((r) => CLEANUP_RPC_HINT.test(r));
    if (!opts.cleanupRpc && hint && users.some((u) => u.created)) {
      notes.push(`Tip: your API has "${hint}" — pass --cleanup-rpc ${hint} and accessprobe will delete its test users with it.`);
    }

    return {
      target: opts.site || url,
      date: new Date().toISOString(),
      findings,
      passed,
      notes,
      recipes: tables.recipes,
      stats: {
        resources: schema.tables.length,
        resourceLabel: 'tables',
        summary: [
          [schema.tables.length, 'tables'],
          [storage.count, 'buckets'],
          [schema.rpcs.length, 'functions'],
        ],
        tables: schema.tables.length,
        fullyTested: tables.fullyTested,
        readOnly: tables.readOnly,
        buckets: storage.count,
        rpcs: schema.rpcs.length,
        seconds: ((Date.now() - t0) / 1000).toFixed(1),
      },
    };
  } finally {
    // 5. test rows, then 6. test users — always, even if a probe crashed
    log('→ Cleaning up test data');
    const left = await cleanupRows(client, created, users);
    if (left.length) notes.push(`Could not delete some test rows, remove them manually: ${left.join('; ')}`);
    await cleanupUsers(client, users, opts.cleanupRpc, notes, reuse ? url : null);
  }
}

async function loadSchema(client, token, notes, sourceDir, log, schemaFiles = []) {
  const merged = { tables: new Map(), rpcs: new Set() };
  let functions = new Map();
  let anyOk = false;
  const fromSql = new Set(); // tables with columns from migrations / --schema files
  const live = new Set(); // tables the live API reports
  for (const f of schemaFiles) if (!existsSync(f)) throw new Error(`--schema file not found: ${f}`);
  if (sourceDir || schemaFiles.length) {
    const src = await scanSource(sourceDir, schemaFiles);
    functions = parseFunctions(src.sql);
    for (const [name, t] of src.tables) if (!t.nameOnly) fromSql.add(name);
    const s = parseSchema(sourceToDefinitions(src));
    for (const t of s.tables) merged.tables.set(t.name, t);
    s.rpcs.forEach((x) => merged.rpcs.add(x));
    const full = s.tables.filter((t) => !t.nameOnly).length;
    log(`  source: ${src.sqlCount} SQL + ${src.fileCount - src.sqlCount} code files → ${full} tables with columns, ${s.tables.length - full} by name only`);
    if (s.tables.length) anyOk = true;
  }
  for (const [who, tok] of [
    ['anon', undefined],
    ['user', token],
  ]) {
    const r = await client.openapi({ token: tok });
    if (!r.ok) {
      if (who === 'user' && r.status === 401 && !sourceDir)
        notes.push('This project only serves its API schema to the service_role key (new Supabase default). Pass --source <your project folder> so accessprobe can read tables from your migrations and code.');
      continue;
    }
    anyOk = true;
    const s = parseSchema(r.data);
    for (const t of s.tables) {
      live.add(t.name);
      const prev = merged.tables.get(t.name);
      if (prev?.sourceView) t.sourceView = true; // the migrations know it is a view; the API may not
      if (!prev || prev.nameOnly || t.columns.length > prev.columns.length) merged.tables.set(t.name, t); // live API wins
    }
    s.rpcs.forEach((x) => merged.rpcs.add(x));
    if (who === 'anon' && s.tables.length === 0) notes.push('The anon role sees no tables in the API schema — good. Tables were discovered as a signed-in user.');
  }
  if (!anyOk) notes.push('Could not read the API schema. Pass tables with --table to test them.');
  // the live schema and the migrations disagree: say so, the user may be auditing the wrong picture
  if (live.size && fromSql.size) {
    const notDeployed = [...fromSql].filter((n) => !live.has(n));
    const untracked = [...live].filter((n) => !fromSql.has(n));
    if (notDeployed.length) notes.push(`In your migrations / schema files but not in the live API: ${notDeployed.join(', ')} (not deployed, renamed, or not exposed to the API).`);
    if (untracked.length)
      notes.push(`Live tables that are not in your migrations: ${untracked.join(', ')} (created in the dashboard?). They were tested from the live schema; \`supabase db pull\` brings them into migrations.`);
  }
  return { tables: [...merged.tables.values()], rpcs: [...merged.rpcs], functions };
}

async function cleanupUsers(client, users, rpc, notes, reuseKey) {
  if (!rpc && users.some((u) => u.reused)) notes.push(`Reused the test users from an earlier run (${users.map((u) => u.email).join(', ')}); no new accounts were created.`);
  const created = users.filter((u) => u.created || rpc);
  if (!created.length) return;
  if (rpc) {
    if (reuseKey) forgetUsers('supabase', reuseKey);
    for (const u of created) {
      const r = await client.request('POST', `/rest/v1/rpc/${encodeURIComponent(rpc)}`, { token: u.token, body: {} });
      if (r.ok) notes.push(`Test user ${u.email} deleted with ${rpc}().`);
      else notes.push(`Could not delete test user ${u.email} with ${rpc}() (${r.status} ${msg(r.data)}) — delete it in Dashboard → Authentication → Users.`);
    }
    return;
  }
  if (reuseKey && saveUsers('supabase', reuseKey, users)) {
    notes.push(
      `Test users kept for the next run: ${created.map((u) => u.email).join(', ')}. They are saved outside your project (${usersFile()}), ` +
        'so later runs sign in with them instead of creating new accounts. Delete them in Dashboard → Authentication → Users when you no longer need them.',
    );
    return;
  }
  notes.push(`Test users were created: ${created.map((u) => u.email).join(', ')} — delete them in Dashboard → Authentication → Users.`);
}
