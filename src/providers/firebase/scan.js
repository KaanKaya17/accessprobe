import { existsSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { FirebaseClient, DEFAULT_EMULATOR } from './client.js';
import { extract } from './discover.js';
import { scanSource } from './source.js';
import { setupUsers, deleteUsers, probeFirestore } from './probes.js';
import { probeRtdb, probeStorage } from './rtdb-storage.js';

export const id = 'firebase';
export const label = 'Firebase';

const COLLECTION_IN_BUNDLE = /\bcollection(?:Group)?\(\s*(?:[\w$.]+\s*,\s*)?["'`]([A-Za-z_][\w-]*)["'`]/g;

export async function detect(opts, { site }) {
  if (opts.apiKey || opts.projectId) return true;
  if (site && extract(site.sources).configs.length) return true;
  if (opts.source) {
    return ['firebase.json', 'firestore.rules', 'google-services.json', join('app', 'google-services.json')].some((f) => existsSync(join(opts.source, f)));
  }
  return false;
}

export async function scan(opts, { site, log }) {
  const t0 = Date.now();
  const findings = [];
  const passed = [];
  const notes = [];

  // 1. config: flags > site bundle > project files
  let cfg = null;
  const fromSite = site ? extract(site.sources) : { configs: [], findings: [] };
  findings.push(...fromSite.findings);
  const src = opts.source ? await scanSource(opts.source) : { configs: [], collections: [] };
  // rules exported from the console (e.g. firebase database:get /.settings/rules) override files in --source
  for (const [flag, key] of [
    ['databaseRules', 'databaseRules'],
    ['firestoreRules', 'firestoreRules'],
    ['storageRules', 'storageRules'],
  ]) {
    if (opts[flag]) src[key] = await readFile(opts[flag], 'utf8');
  }
  cfg = fromSite.configs[0] || src.configs[0] || null;
  if (opts.apiKey || opts.projectId) cfg = { ...(cfg || {}), ...(opts.apiKey && { apiKey: opts.apiKey }), ...(opts.projectId && { projectId: opts.projectId }) };
  if (!cfg?.apiKey || !cfg?.projectId) throw new Error('Firebase apiKey / projectId not found. Pass --api-key and --project-id, or --site / --source.');
  if (fromSite.configs.length + src.configs.length > 1) notes.push(`Several Firebase configs found, using project "${cfg.projectId}".`);

  // collection names also survive minification in the site bundle
  if (site) {
    const names = new Set(src.collections);
    for (const { text } of site.sources) for (const m of text.matchAll(COLLECTION_IN_BUNDLE)) names.add(m[1]);
    src.collections = [...names];
  }
  if (!src.firestoreRules && !src.collections.length) {
    notes.push('No firestore.rules and no collection names found — pass --source <project folder> so rlsprobe knows what to test.');
  }

  const emulator = opts.emulator ? (typeof opts.emulator === 'object' ? opts.emulator : DEFAULT_EMULATOR) : null;
  if (emulator) notes.push('Ran against the Firebase Emulator Suite: token checks, App Check and API-key restrictions are not enforced there.');
  const client = new FirebaseClient(cfg, { emulator });

  // 2. users
  log(`→ Signing in two test users (A and B) on Firebase project "${cfg.projectId}"`);
  const users = await setupUsers(client, { userA: opts.userA, userB: opts.userB, emailDomain: opts.emailDomain, log });

  try {
    log('→ Testing Firestore');
    const fs = await probeFirestore(client, src, users, { log });
    log('→ Testing Realtime Database');
    const db = await probeRtdb(client, src, users, { log });
    log('→ Testing Storage');
    const st = await probeStorage(client, src, users, { log });

    // test users' ids are noise in a report: show who, not which uid
    const anon = (x) => users.reduce((t, u) => t.split(u.id).join(`<user ${u.label} id>`), x);
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
    await deleteUsers(client, users, notes); // Firebase users can delete themselves
  }
}
