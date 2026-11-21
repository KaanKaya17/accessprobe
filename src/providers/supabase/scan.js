import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { SupabaseClient, decodeJwt } from './client.js';
import { findProjectConfig } from './project-config.js';
import { extract } from './discover.js';
import { parseSchema } from './schema.js';
import { scanSource, sourceToDefinitions } from './source.js';
import { setupUsers, resolveIdentities, probeTables, probeStorage, rpcReview, cleanupRows, msg } from './probes.js';

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
  if (opts.url || opts.anonKey) return true;
  if (site && extract(site.sources).anonKeys.length) return true;
  if (opts.source) {
    if (existsSync(join(opts.source, 'supabase'))) return true;
    const cfg = await projectConfig(opts.source);
    return cfg.urls.length > 0 && cfg.anonKeys.length > 0;
  }
  return false;
}

export async function scan(opts, { site, log }) {
  const t0 = Date.now();
  const findings = [];
  const passed = [];
  const notes = [];
  let { url, anonKey } = opts;

  // 1. config from the live site (already fetched by core)
  if (site) {
    log(`→ Looking for Supabase config in ${site.url}`);
    const d = extract(site.sources);
    findings.push(...d.findings);
    url ||= d.urls[0];
    anonKey ||= d.anonKeys[0];
    if (d.urls.length > 1) notes.push(`Multiple Supabase URLs found, using ${url}: ${d.urls.join(', ')}`);
  }
  // 1b. config from the project folder (.env, local.properties, client code)
  if (opts.source) {
    const pc = await projectConfig(opts.source);
    findings.push(...pc.findings);
    notes.push(...pc.notes);
    if (!url && pc.urls[0]) {
      url = pc.urls[0];
      log(`  found Supabase URL in the project: ${url}`);
    }
    if (!anonKey && pc.anonKeys[0]) anonKey = pc.anonKeys[0];
    if (pc.urls.length > 1 && !opts.url) notes.push(`Several Supabase URLs in the project, using ${url} (pass --url to choose): ${pc.urls.join(', ')}`);
  }
  if (!url || !anonKey) {
    throw new Error('Supabase URL / anon key not found. Pass them with --url and --anon-key (the public anon key, never the service_role key).');
  }
  const payload = decodeJwt(anonKey);
  if (payload?.role === 'service_role' || anonKey.startsWith('sb_secret_')) {
    throw new Error('That is a service_role / secret key. Pass the public anon key — the tool must see what an attacker sees.');
  }

  const client = new SupabaseClient({ url, anonKey });

  // 2. two test users
  log('→ Signing in two test users (A and B)');
  const users = await setupUsers(client, { userA: opts.userA, userB: opts.userB, emailDomain: opts.emailDomain, log });

  try {
    // 3. schema — as anon AND as a signed-in user: PostgREST only lists what the role may touch
    log(`→ Reading API schema from ${url}/rest/v1/`);
    const schema = await loadSchema(client, users[0].token, notes, opts.source, log);
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
    const tables = await probeTables(client, schema, users, { log });
    findings.push(...tables.findings);
    passed.push(...tables.passed);

    log('→ Testing storage');
    const storage = await probeStorage(client, users, { extraBuckets: opts.buckets || [], log });
    findings.push(...storage.findings);
    passed.push(...storage.passed);
    if (!storage.count) notes.push('No storage buckets visible to the test users (pass --bucket <name> to test one anyway).');

    notes.push(...tables.skipped, ...storage.skipped);
    findings.push(...rpcReview(schema));

    // 5. cleanup rows
    log('→ Cleaning up test data');
    const left = await cleanupRows(client, tables.created, users);
    if (left.length) notes.push(`Could not delete some test rows, remove them manually: ${left.join('; ')}`);

    const hint = schema.rpcs.find((r) => CLEANUP_RPC_HINT.test(r));
    if (!opts.cleanupRpc && hint && users.some((u) => u.created)) {
      notes.push(`Tip: your API has "${hint}" — pass --cleanup-rpc ${hint} and rlsprobe will delete its test users with it.`);
    }

    return {
      target: opts.site || url,
      date: new Date().toISOString(),
      findings,
      passed,
      notes,
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
    // 6. test users — always, even if a probe crashed
    await cleanupUsers(client, users, opts.cleanupRpc, notes);
  }
}

async function loadSchema(client, token, notes, sourceDir, log) {
  const merged = { tables: new Map(), rpcs: new Set() };
  let anyOk = false;
  if (sourceDir) {
    const src = await scanSource(sourceDir);
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
        notes.push('This project only serves its API schema to the service_role key (new Supabase default). Pass --source <your project folder> so rlsprobe can read tables from your migrations and code.');
      continue;
    }
    anyOk = true;
    const s = parseSchema(r.data);
    for (const t of s.tables) {
      const prev = merged.tables.get(t.name);
      if (!prev || prev.nameOnly || t.columns.length > prev.columns.length) merged.tables.set(t.name, t); // live API wins
    }
    s.rpcs.forEach((x) => merged.rpcs.add(x));
    if (who === 'anon' && s.tables.length === 0) notes.push('The anon role sees no tables in the API schema — good. Tables were discovered as a signed-in user.');
  }
  if (!anyOk) notes.push('Could not read the API schema. Pass tables with --table to test them.');
  return { tables: [...merged.tables.values()], rpcs: [...merged.rpcs] };
}

async function cleanupUsers(client, users, rpc, notes) {
  const created = users.filter((u) => u.created || rpc);
  if (!created.length) return;
  if (rpc) {
    for (const u of created) {
      const r = await client.request('POST', `/rest/v1/rpc/${encodeURIComponent(rpc)}`, { token: u.token, body: {} });
      if (r.ok) notes.push(`Test user ${u.email} deleted with ${rpc}().`);
      else notes.push(`Could not delete test user ${u.email} with ${rpc}() (${r.status} ${msg(r.data)}) — delete it in Dashboard → Authentication → Users.`);
    }
    return;
  }
  notes.push(`Test users were created: ${created.map((u) => u.email).join(', ')} — delete them in Dashboard → Authentication → Users.`);
}
