import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { PocketBaseClient, looksLikePocketBase } from './client.js';
import { scanSource, fromCode } from './source.js';
import { authCollection, ownerFieldOf, privilegeRefs } from './rules.js';
import { setupUsers, deleteUsers, probeCollections, probeUsers } from './probes.js';

export const id = 'pocketbase';
export const label = 'PocketBase';

const sourceCache = new Map();
const sourceOf = (dir) => {
  if (!sourceCache.has(dir)) sourceCache.set(dir, scanSource(dir));
  return sourceCache.get(dir);
};

// PocketBase when: --url answers like a PocketBase server, the site bundle constructs the SDK
// with a URL, or the project folder has pb_migrations/ or uses the pocketbase SDK.
export async function detect(opts, { site }) {
  if (opts.url && !opts.anonKey && (await looksLikePocketBase(opts.url))) return true;
  if (site && site.sources.some(({ text }) => fromCode(text).urls.length)) return true;
  if (opts.source) {
    if (existsSync(join(opts.source, 'pb_migrations'))) return true;
    const src = await sourceOf(opts.source);
    return src.migrationCount > 0 || src.usesSdk;
  }
  return false;
}

// Which server will be touched — shared by describe() (shown before asking for consent) and scan().
async function resolveTarget(opts, site) {
  const notes = [];
  let url = opts.url;
  if (!url && site) {
    const urls = [...new Set(site.sources.flatMap(({ text }) => fromCode(text).urls))];
    if (urls.length > 1) notes.push(`Several PocketBase URLs found in the site, using ${urls[0]}: ${urls.join(', ')}`);
    url = urls[0];
  }
  if (!url && opts.source) {
    const src = await sourceOf(opts.source);
    if (src.urls.length > 1) {
      // e.g. a local dev server and production: never guess which one gets test users
      throw new Error(`Several PocketBase URLs are configured in this folder: ${src.urls.join(', ')}\n  Pass --url to choose which one to test.`);
    }
    url = src.urls[0];
  }
  if (!url) throw new Error('PocketBase URL not found. Pass it with --url https://your-pocketbase.example.com (no admin credentials needed).');
  if (!/^https?:\/\//i.test(url)) throw new Error(`--url must start with http:// or https:// (got "${url}")`);
  return { url: url.replace(/\/+$/, '').replace(/\/_\/?$/, ''), notes };
}

export async function describe(opts, { site }) {
  const { url } = await resolveTarget(opts, site);
  return `PocketBase ${url}`;
}

// What to test: collections from pb_migrations (with rules and fields), plus names from code.
function buildTargets(src, opts, notes) {
  const collections = src.collections || [];
  const auth = authCollection(collections);
  const targets = [];
  const seen = new Set();
  for (const c of collections) {
    if (c.type === 'auth' && c.name === auth.name) continue;
    seen.add(c.name);
    targets.push({ name: c.name, coll: c, type: c.type || 'base', fields: c.fields, ownerField: ownerFieldOf(c, auth) });
  }
  for (const name of [...(src.codeCollections || []), ...(opts.tables || [])]) {
    if (seen.has(name) || name === auth.name || name.startsWith('_')) continue;
    seen.add(name);
    targets.push({ name, coll: null, type: 'base', fields: null, ownerField: null });
  }
  let list = targets;
  if (opts.only?.length) list = targets.filter((t) => opts.only.includes(t.name));
  const usersTarget = !opts.only?.length || opts.only.includes(auth.name)
    ? { name: auth.name, coll: collections.find((c) => c.name === auth.name) || null, type: 'auth', fields: collections.find((c) => c.name === auth.name)?.fields || null, ownerField: 'id' }
    : null;
  // collections users cannot write to (createRule null) hold no per-user data to protect
  const noOwner = list.filter((t) => t.fields && t.type === 'base' && !t.ownerField && t.coll?.createRule !== null).map((t) => t.name);
  if (noOwner.length) notes.push(`No owner field detected for: ${noOwner.join(', ')} (looked for a relation to ${auth.name} used in the rules, or user, owner, author, createdBy…)`);
  return { targets: list, usersTarget, auth, refs: privilegeRefs(collections, auth) };
}

export async function scan(opts, { site, log }) {
  const t0 = Date.now();
  const findings = [];
  const passed = [];
  const { url, notes } = await resolveTarget(opts, site);
  const src = opts.source ? await sourceOf(opts.source) : { collections: null, codeCollections: [], urls: [], migrationCount: 0 };
  if (site) for (const { text } of site.sources) src.codeCollections = [...new Set([...src.codeCollections, ...fromCode(text).collections])];
  if (opts.source) {
    log(src.migrationCount ? `  source: ${src.migrationCount} migration file(s) in ${src.migrationsDirs.join(', ')} → ${src.collections.length} collections with API rules` : '  source: no pb_migrations folder; collection names come from the app code');
  }
  if (!src.migrationCount) {
    notes.push(
      src.codeCollections.length || opts.tables?.length
        ? 'No pb_migrations found: collection names come from the app code (or --table), and their fields and rules were guessed from the API answers. Pass --source <folder with pb_migrations> for exact results.'
        : 'No pb_migrations and no pb.collection("…") calls found — pass --source <project folder> (or --table <name>) so accessprobe knows which collections to test. PocketBase only lists collections to superusers, and accessprobe never uses those.',
    );
  }
  const { targets, usersTarget, auth, refs } = buildTargets(src, opts, notes);
  const client = new PocketBaseClient({ url, readOnly: opts.readOnly });

  log(`→ Signing in two test users (A and B) through the "${auth.name}" collection on ${url}`);
  const users = await setupUsers(client, auth.name, { userA: opts.userA, userB: opts.userB, emailDomain: opts.emailDomain, log });
  try {
    log('→ Testing collections');
    const cols = await probeCollections(client, targets, users, { log, refs, auth });
    let usr = { findings: [], passed: [], skipped: [], fullyTested: 0 };
    if (usersTarget) usr = await probeUsers(client, usersTarget, users, { log, refs });

    // test users' ids are noise in a report: show who, not which id
    const anon = (x) => users.reduce((s, u) => s.split(u.id).join(`<user ${u.label} id>`), x);
    for (const part of [cols, usr]) {
      findings.push(...part.findings.map((f) => ({ ...f, evidence: anon(f.evidence) })));
      passed.push(...part.passed);
      notes.push(...part.skipped);
    }
    if (cols.left.length) notes.push(`Could not delete some test records, remove them manually: ${cols.left.join('; ')}`);

    const resources = targets.length + (usersTarget ? 1 : 0);
    return {
      target: opts.site || url,
      findings,
      passed,
      notes,
      stats: {
        resources,
        resourceLabel: 'collections',
        summary: [[resources, 'collections']],
        fullyTested: cols.fullyTested + usr.fullyTested,
        readOnly: cols.readOnly,
        seconds: ((Date.now() - t0) / 1000).toFixed(1),
      },
    };
  } finally {
    log('→ Cleaning up test users');
    await deleteUsers(client, auth.name, users, notes);
  }
}
