// Firebase web config in site bundles, and secrets that must never reach a client.

import { redact, dedupe } from '../../core/site.js';

const q = `["'\`]`;
const field = (name, value) => new RegExp(`["']?${name}["']?\\s*:\\s*${q}(${value})${q}`, 'g');

const RE = {
  apiKey: field('apiKey', 'AIza[0-9A-Za-z_-]{35}'),
  projectId: field('projectId', '[a-z0-9][a-z0-9-]{4,29}'),
  databaseURL: field('databaseURL', 'https://[^"\'`\\s]+?(?:firebaseio\\.com|firebasedatabase\\.app)/?'),
  storageBucket: field('storageBucket', '[a-z0-9][a-z0-9._-]*\\.(?:appspot\\.com|firebasestorage\\.app)'),
  authDomain: field('authDomain', '[a-z0-9.-]+'),
};
const SERVICE_ACCOUNT_RE = /"type"\s*:\s*"service_account"[\s\S]{0,400}?"private_key"\s*:\s*"-----BEGIN/g;
const FCM_SERVER_KEY_RE = /AAAA[A-Za-z0-9_-]{7}:APA91b[A-Za-z0-9_-]{100,}/g;

export function extract(sources) {
  const configs = [];
  const findings = [];
  for (const { where, text } of sources) {
    // configs come as object literals; group the fields that sit near each apiKey
    for (const m of text.matchAll(RE.apiKey)) {
      const win = text.slice(Math.max(0, m.index - 600), m.index + 900);
      const pick = (re) => [...win.matchAll(new RegExp(re.source, 'g'))].map((x) => x[1])[0] || null;
      const cfg = {
        apiKey: m[1],
        projectId: pick(RE.projectId),
        databaseURL: pick(RE.databaseURL)?.replace(/\/+$/, '') || null,
        storageBucket: pick(RE.storageBucket),
        authDomain: pick(RE.authDomain),
        where,
      };
      if (cfg.projectId && !configs.some((c) => c.apiKey === cfg.apiKey && c.projectId === cfg.projectId)) configs.push(cfg);
    }
    for (const m of text.matchAll(SERVICE_ACCOUNT_RE)) {
      findings.push({
        id: 'leaked-firebase-service-account',
        severity: 'critical',
        title: 'A Google service account private key is shipped to the client',
        detail: 'Service accounts bypass ALL Firebase Security Rules: full access to Firestore, Realtime Database and Storage.',
        evidence: `Found in ${where}: ${redact(m[0])}`,
        fix: {
          steps: [
            'Delete the key NOW: Google Cloud Console → IAM & Admin → Service Accounts → Keys.',
            'Remove the JSON file from the app and its git history.',
            'Do admin work in Cloud Functions, never in the client.',
          ],
        },
      });
    }
    for (const m of text.matchAll(FCM_SERVER_KEY_RE)) {
      findings.push({
        id: 'leaked-fcm-server-key',
        severity: 'critical',
        title: 'Firebase Cloud Messaging server key is shipped to the client',
        detail: 'Anyone can send push notifications to all of your users with it.',
        evidence: `Found in ${where}: ${redact(m[0])}`,
        fix: { steps: ['Delete the legacy server key in the Firebase console and move to the FCM v1 API from a backend.'] },
      });
    }
  }
  return { configs, findings: dedupe(findings) };
}

// Android google-services.json
export function fromGoogleServicesJson(text) {
  try {
    const j = JSON.parse(text);
    const p = j.project_info || {};
    const key = j.client?.[0]?.api_key?.[0]?.current_key;
    if (!p.project_id || !key) return null;
    return {
      apiKey: key,
      projectId: p.project_id,
      databaseURL: p.firebase_url || null,
      storageBucket: p.storage_bucket || null,
      authDomain: null,
      where: 'google-services.json',
    };
  } catch {
    return null;
  }
}

// iOS GoogleService-Info.plist
export function fromPlist(text) {
  const get = (k) => text.match(new RegExp(`<key>${k}</key>\\s*<string>([^<]+)</string>`))?.[1] || null;
  const apiKey = get('API_KEY');
  const projectId = get('PROJECT_ID');
  if (!apiKey || !projectId) return null;
  return {
    apiKey,
    projectId,
    databaseURL: get('DATABASE_URL'),
    storageBucket: get('STORAGE_BUCKET'),
    authDomain: null,
    where: 'GoogleService-Info.plist',
  };
}
