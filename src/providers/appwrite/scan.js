import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { AppwriteClient, looksLikeAppwrite, normalizeEndpoint } from './client.js';
import { scanSource, fromCode } from './source.js';
import { CONFIG_FILES } from './config.js';
import { setupUsers, deleteUsers, probeCollections, probeBuckets } from './probes.js';

export const id = 'appwrite';
export const label = 'Appwrite';

const sourceCache = new Map();
const sourceOf = (dir) => {
  if (!sourceCache.has(dir)) sourceCache.set(dir, scanSource(dir));
  return sourceCache.get(dir);
};

// --project-id is shared with Firebase. It is the APPWRITE project id when:
//   --platform appwrite, or
//   it comes with --url and without the Firebase / Supabase keys (Firebase never takes --url), or
//   it is the project id in the folder's appwrite.json / setProject("…").
// Firebase's detect() asks this first, so one --project-id never starts two backends.
export async function ownsProjectId(opts) {
  if (!opts.projectId) return false;
  if (opts.platform) return opts.platform === 'appwrite';
  if (opts.apiKey || opts.emulator || opts.anonKey) return false;
  if (opts.url) return true;
  if (opts.source) return (await sourceOf(opts.source)).projects.includes(opts.projectId);
  return false;
}

// Is this --url an Appwrite server (or claimed for Appwrite by --project-id)? Supabase's
// detect() asks this, since --url is shared too.
export async function claimsUrl(opts) {
  if (!opts.url || opts.anonKey) return false;
  return (await ownsProjectId(opts)) || looksLikeAppwrite(opts.url);
}

const siteInfo = (site) => (site ? site.sources.map(({ text }) => fromCode(text)) : []);

// Appwrite when: --url answers /v1/health/version (or comes with an Appwrite --project-id), the
// site bundle configures the SDK, or the folder has appwrite.json / uses the SDK with setProject().
export async function detect(opts, { site }) {
  if (await claimsUrl(opts)) return true;
  if (siteInfo(site).some((c) => c.endpoints.length && c.projects.length)) return true;
  if (opts.source) {
    if (CONFIG_FILES.some((f) => existsSync(join(opts.source, f)))) return true;
    const src = await sourceOf(opts.source);
    return src.configs.length > 0 || (src.usesSdk && src.projects.length > 0);
  }
  return false;
}

// Which server and project will be touched — shared by describe() (shown before asking for
// consent) and scan(). Never a guess: several endpoints or projects need --url / --project-id.
async function resolveTarget(opts, site) {
  const notes = [];
  const fromSite = siteInfo(site);
  const src = opts.source ? await sourceOf(opts.source) : null;
  const pick = (what, flag, given, siteList, srcList) => {
    if (given) return given;
    const s = [...new Set(siteList)];
    if (s.length > 1) notes.push(`Several Appwrite ${what}s found in the site, using ${s[0]}: ${s.join(', ')}`);
    if (s.length) return s[0];
    const f = [...new Set(srcList)];
    if (f.length > 1) throw new Error(`Several Appwrite ${what}s are configured in this folder: ${f.join(', ')}\n  Pass ${flag} to choose which one to test.`);
    return f[0];
  };
  const url = pick('endpoint', '--url', opts.url, fromSite.flatMap((c) => c.endpoints), src?.endpoints || []);
  if (!url) throw new Error('Appwrite endpoint not found. Pass it with --url https://cloud.appwrite.io/v1 (plus --project-id; no API key needed).');
  if (!/^https?:\/\//i.test(url)) throw new Error(`--url must start with http:// or https:// (got "${url}")`);
  const given = (await ownsProjectId(opts)) ? opts.projectId : null;
  const projectId = pick('project', '--project-id', given, fromSite.flatMap((c) => c.projects), src?.projects || []);
  if (!projectId) throw new Error('Appwrite project id not found. Pass it with --project-id <id> (Console → Settings; it is public, like in setProject("…")).');
  return { url: normalizeEndpoint(url), projectId, notes };
}

export async function describe(opts, { site }) {
  const { url, projectId } = await resolveTarget(opts, site);
  return `Appwrite ${url} (project ${projectId})`;
}

// What to test: collections from appwrite.json (attributes + permissions), ids from code, --table.
export function buildTargets(src, opts, notes) {
  const config = src.collections || [];
  const dbs = src.databases || [];
  const defaultDb = dbs.length === 1 ? dbs[0] : null;
  const list = [];
  const seen = new Set();
  const add = (t) => {
    const k = `${t.db}/${t.id}`;
    if (seen.has(k)) return;
    seen.add(k);
    list.push({ ...t, codeAttributes: src.attributes?.[k] || [] });
  };
  for (const c of config) add({ db: c.db, id: c.id, mode: c.mode, config: c });
  for (const c of src.codeCollections || []) add({ db: c.db, id: c.id, mode: c.mode, config: null });
  const bare = [];
  for (const raw of [...(defaultDb ? src.envCollections || [] : []), ...(opts.tables || [])]) {
    const m = /^([^/]+)\/([^/]+)$/.exec(raw);
    if (m) add({ db: m[1], id: m[2], mode: 'documents', config: null });
    else if (defaultDb) add({ db: defaultDb, id: raw, mode: 'documents', config: null });
    else bare.push(raw);
  }
  if (bare.length) {
    notes.push(`Not tested: ${bare.join(', ')} — Appwrite collection ids need their database id. Pass --table <database>/<collection>${dbs.length > 1 ? ` (databases in appwrite.json: ${dbs.join(', ')})` : ''}.`);
  }
  // short names in the report, unless one collection id lives in several databases
  const count = new Map();
  for (const t of list) count.set(t.id, (count.get(t.id) || 0) + 1);
  for (const t of list) t.name = count.get(t.id) > 1 ? `${t.db}/${t.id}` : t.id;
  const only = opts.only?.length ? opts.only : null;
  const targets = only ? list.filter((t) => only.includes(t.id) || only.includes(`${t.db}/${t.id}`)) : list;

  const bucketCfg = src.buckets || [];
  const bucketIds = [...new Set([...bucketCfg.map((b) => b.id), ...(src.codeBuckets || []), ...(opts.buckets || [])])];
  const buckets = bucketIds
    .filter((b) => !only || only.includes(b) || opts.buckets?.includes(b))
    .map((b) => ({ id: b, config: bucketCfg.find((x) => x.id === b) || null }));
  return { targets, buckets };
}

export async function scan(opts, { site, log }) {
  const t0 = Date.now();
  const findings = [];
  const passed = [];
  const { url, projectId, notes } = await resolveTarget(opts, site);
  const src = opts.source ? await sourceOf(opts.source) : { collections: null, codeCollections: [], codeBuckets: [], buckets: [], databases: [], attributes: {}, configs: [], configFiles: [], envCollections: [], leakedEnvKeys: [] };
  if (site) {
    const seen = new Set(src.codeCollections.map((c) => `${c.db}/${c.id}`));
    const extra = siteInfo(site).flatMap((c) => c.collections).filter((c) => !seen.has(`${c.db}/${c.id}`) && seen.add(`${c.db}/${c.id}`));
    src.codeCollections = [...src.codeCollections, ...extra];
    src.codeBuckets = [...new Set([...src.codeBuckets, ...siteInfo(site).flatMap((c) => c.buckets)])];
  }
  const configFile = src.configFiles[0] || 'appwrite.json';
  if (opts.source) {
    log(src.configs.length ? `  source: ${src.configFiles.join(', ')} → ${src.collections.length} collections/tables, ${src.buckets.length} buckets with permissions` : '  source: no appwrite.json; collection ids come from the app code');
  }
  for (const k of src.leakedEnvKeys || []) {
    findings.push({
      id: 'leaked-appwrite-api-key-env',
      severity: 'critical',
      resource: k.file,
      title: `Appwrite API key in a browser-exposed variable (${k.name})`,
      detail: 'Variables with this prefix are compiled into the client bundle, so every visitor gets an API key — API keys skip all collection, document and bucket permissions.',
      evidence: `${k.file}: ${k.name}=…`,
      fix: { steps: ['Delete the key now: Appwrite Console → Overview → Integrations → API keys.', 'Rename the variable without the public prefix and only read it in server code or Appwrite Functions.'] },
    });
  }
  if (!src.configs.length) {
    notes.push(
      src.codeCollections.length || opts.tables?.length
        ? 'No appwrite.json found: collection ids come from the app code (or --table), and their attributes were guessed. Run `appwrite pull collections` (or pass --source <folder with appwrite.json>) for exact results.'
        : 'No appwrite.json and no databases.createDocument("<db>", "<collection>", …) calls found — pass --source <project folder> or --table <database>/<collection>. Appwrite only lists collections to API keys, and accessprobe never uses those.',
    );
  }
  const { targets, buckets } = buildTargets(src, opts, notes);
  const client = new AppwriteClient({ url, projectId });

  log(`→ Signing in two test users (A and B) on Appwrite project "${projectId}" (${url})`);
  const users = await setupUsers(client, { userA: opts.userA, userB: opts.userB, emailDomain: opts.emailDomain, log });
  try {
    log('→ Testing collections');
    const cols = await probeCollections(client, targets, users, { log, configFile });
    let bks = { findings: [], passed: [], skipped: [], left: [], fullyTested: 0, readOnly: 0 };
    if (buckets.length) {
      log('→ Testing storage buckets');
      bks = await probeBuckets(client, buckets, users, { log, configFile });
    }

    // test users' ids are noise in a report: show who, not which id
    const anon = (x) => users.reduce((s, u) => (u.id ? s.split(u.id).join(`<user ${u.label} id>`) : s), x);
    for (const part of [cols, bks]) {
      findings.push(...part.findings.map((f) => ({ ...f, evidence: anon(f.evidence) })));
      passed.push(...part.passed);
      notes.push(...part.skipped.map(anon));
    }
    const left = [...cols.left, ...bks.left];
    if (left.length) notes.push(`Could not delete some test documents / files, remove them in the Appwrite Console: ${left.join('; ')}`);

    const resources = targets.length + buckets.length;
    return {
      target: opts.site || `${url} (project ${projectId})`,
      findings,
      passed,
      notes,
      stats: {
        resources,
        resourceLabel: 'collections/buckets',
        summary: [
          [targets.length, 'collections'],
          ...(buckets.length ? [[buckets.length, 'buckets']] : []),
        ],
        fullyTested: cols.fullyTested + bks.fullyTested,
        readOnly: cols.readOnly + bks.readOnly,
        seconds: ((Date.now() - t0) / 1000).toFixed(1),
      },
    };
  } finally {
    log('→ Cleaning up test users');
    await deleteUsers(client, users, notes);
  }
}
