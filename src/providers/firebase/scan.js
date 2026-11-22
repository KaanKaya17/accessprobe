import { existsSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { FirebaseClient, DEFAULT_EMULATOR } from './client.js';
import { extract } from './discover.js';
import { scanSource } from './source.js';
import { setupUsers, deleteUsers, setupAnonAuth, probeFirestore } from './probes.js';
import { probeRtdb, probeStorage } from './rtdb-storage.js';
import { ownsProjectId as appwriteOwnsProjectId } from '../appwrite/scan.js';

export const id = 'firebase';
export const label = 'Firebase';

const COLLECTION_IN_BUNDLE = /\bcollection(?:Group)?\(\s*(?:[\w$.]+\s*,\s*)?["'`]([A-Za-z_][\w-]*)["'`]/g;

const sourceCache = new Map();
const sourceOf = (dir) => {
  if (!sourceCache.has(dir)) sourceCache.set(dir, scanSource(dir));
  return sourceCache.get(dir);
};

// A google-services.json alone is not enough: many apps only use Firebase for push or analytics.
// Firebase is tested when the project actually uses one of its databases or Storage.
export async function detect(opts, { site }) {
  if (opts.apiKey) return true;
  // --project-id is shared with Appwrite (with --url, or when it is the id in appwrite.json)
  if (opts.projectId && !(await appwriteOwnsProjectId(opts))) return true;
  if (site && extract(site.sources).configs.length) return true;
  if (opts.source) {
    if (['firestore.rules', 'database.rules.json', 'storage.rules'].some((f) => existsSync(join(opts.source, f)))) return true;
    const src = await sourceOf(opts.source);
    return src.configs.length > 0 && (src.collections.length > 0 || src.rtdbCodePaths.length > 0 || Boolean(src.firestoreRules || src.databaseRules || src.storageRules));
  }
  return false;
}

// One project, never a guess: several DIFFERENT Firebase projects in one folder (dev + prod
// google-services.json, say) need --project-id.
function pickConfig(configs, opts) {
  const ids = [...new Set(configs.map((c) => c.projectId))];
  if (opts.projectId) return configs.find((c) => c.projectId === opts.projectId) || configs[0] || null;
  if (ids.length > 1) throw new Error(`Several Firebase projects are configured here: ${ids.join(', ')}\n  Pass --project-id to choose which one to test.`);
  return configs[0] || null;
}

// an Appwrite project id (see appwrite/scan.js) is never used as the Firebase project
const ownOpts = async (opts) => ((await appwriteOwnsProjectId(opts)) ? { ...opts, projectId: undefined } : opts);

export async function describe(opts, { site }) {
  opts = await ownOpts(opts);
  const fromSite = site ? extract(site.sources).configs : [];
  const src = opts.source ? await sourceOf(opts.source) : { configs: [] };
  const cfg = pickConfig([...fromSite, ...src.configs], opts);
  const id = opts.projectId || cfg?.projectId;
  if (!id) throw new Error('Firebase apiKey / projectId not found. Pass --api-key and --project-id, or --site / --source.');
  return `Firebase project "${id}"${opts.emulator ? ' (local emulator)' : ''}`;
}

export async function scan(opts, { site, log }) {
  opts = await ownOpts(opts);
  const t0 = Date.now();
  const findings = [];
  const passed = [];
  const notes = [];

  // 1. config: flags > site bundle > project files
  let cfg = null;
  const fromSite = site ? extract(site.sources) : { configs: [], findings: [] };
  findings.push(...fromSite.findings);
  const src = opts.source ? { ...(await sourceOf(opts.source)) } : { configs: [], collections: [] };
  // rules exported from the console (e.g. firebase database:get /.settings/rules) override files in --source
  for (const [flag, key] of [
    ['databaseRules', 'databaseRules'],
    ['firestoreRules', 'firestoreRules'],
    ['storageRules', 'storageRules'],
  ]) {
    if (opts[flag]) src[key] = await readFile(opts[flag], 'utf8');
  }
  cfg = pickConfig([...fromSite.configs, ...src.configs], opts);
  if (opts.projectId && cfg && cfg.projectId !== opts.projectId) {
    // the found config belongs to ANOTHER project: its database URL / bucket would point at the
    // wrong store (in the emulator: a fresh, rule-less namespace that makes everything look open)
    notes.push(`--project-id "${opts.projectId}" differs from the config found (${cfg.projectId}); its databaseURL and storageBucket were ignored.`);
    cfg = { apiKey: cfg.apiKey, projectId: opts.projectId };
  }
  if (opts.apiKey || opts.projectId) cfg = { ...(cfg || {}), ...(opts.apiKey && { apiKey: opts.apiKey }), ...(opts.projectId && { projectId: opts.projectId }) };
  if (!cfg?.apiKey || !cfg?.projectId) throw new Error('Firebase apiKey / projectId not found. Pass --api-key and --project-id, or --site / --source.');

  // collection names also survive minification in the site bundle
  if (site) {
    const names = new Set(src.collections);
    for (const { text } of site.sources) for (const m of text.matchAll(COLLECTION_IN_BUNDLE)) names.add(m[1]);
    src.collections = [...names];
  }
  if (!src.firestoreRules && !src.collections.length) {
    notes.push('No firestore.rules and no collection names found — pass --source <project folder> so accessprobe knows what to test.');
  }

  const emulator = opts.emulator ? (typeof opts.emulator === 'object' ? opts.emulator : DEFAULT_EMULATOR) : null;
  if (emulator) notes.push('Ran against the Firebase Emulator Suite: token checks, App Check and API-key restrictions are not enforced there.');
  const client = new FirebaseClient(cfg, { emulator, readOnly: opts.readOnly });

  // 2. users
  log(`→ Signing in two test users (A and B) on Firebase project "${cfg.projectId}"`);
  const users = await setupUsers(client, { userA: opts.userA, userB: opts.userB, emailDomain: opts.emailDomain, log });
  let anonC = null; // anonymous-auth user C, when the project allows anonymous sign-in

  try {
    const anonAuth = await setupAnonAuth(client, users, { log });
    anonC = anonAuth.user;
    passed.push(...anonAuth.passed);
    notes.push(...anonAuth.notes);
    const actors = [...users, anonC];
    log('→ Testing Firestore');
    const fs = await probeFirestore(client, src, actors, { log });
    log('→ Testing Realtime Database');
    const db = await probeRtdb(client, src, actors, { log });
    log('→ Testing Storage');
    const st = await probeStorage(client, src, actors, { log });

    // test users' ids are noise in a report: show who, not which uid
    const anon = (x) => [...users, anonC].filter(Boolean).reduce((t, u) => t.split(u.id).join(`<user ${u.label} id>`), x);
    for (const part of [fs, db, st]) {
      findings.push(...part.findings.map((f) => ({ ...f, evidence: anon(f.evidence) })));
      passed.push(...part.passed);
      notes.push(...part.skipped);
    }
    const left = [...fs.left, ...db.left, ...st.left];
    if (left.length) notes.push(`Could not delete some test data, remove it manually: ${left.join('; ')}`);

    const resources = fs.count + db.count + st.count;
    return {
      target: opts.site || `firebase:${cfg.projectId}`,
      findings,
      passed,
      notes,
      // Security Rules regression recipes, used by --rules-tests (rules-tests.js)
      recipes: [...fs.recipes, ...db.recipes, ...st.recipes].map((r) => ({ ...r, projectId: cfg.projectId })),
      stats: {
        resources,
        resourceLabel: 'paths',
        summary: [
          [fs.count, 'collections'],
          [db.count, 'database paths'],
          [st.count, 'storage paths'],
        ],
        fullyTested: fs.fullyTested + db.fullyTested + st.fullyTested,
        seconds: ((Date.now() - t0) / 1000).toFixed(1),
      },
    };
  } finally {
    if (anonC) await deleteUsers(client, [anonC], notes);
    await deleteUsers(client, users, notes); // Firebase users can delete themselves
  }
}
