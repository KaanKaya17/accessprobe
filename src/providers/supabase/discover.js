// Finds the Supabase URL + public key in already-fetched site sources,
// and flags Supabase keys that must never ship to the browser.

import { decodeJwt } from './client.js';
import { redact, dedupe } from '../../core/site.js';

const JWT_RE = /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g;
const PUBLISHABLE_RE = /sb_publishable_[A-Za-z0-9_-]{20,}/g;
const SECRET_RE = /sb_secret_[A-Za-z0-9_-]{20,}/g;
const SUPABASE_URL_RE = /https:\/\/[a-z0-9]{20}\.supabase\.co/g;
// createClient("http://localhost:54321", "...") — also catches self-hosted / custom domains
const CREATE_CLIENT_RE = /createClient\(\s*["'`](https?:\/\/[^"'`]+)["'`]/g;

const ROTATE = [
  'Rotate the key NOW: Supabase Dashboard → Project Settings → API (roll the service_role / secret key).',
  'Remove it from all client code and VITE_/NEXT_PUBLIC_ env vars. Only the anon / publishable key belongs in the browser.',
  'Move any code that needs it into an Edge Function or your server.',
];

export function extract(sources) {
  const urls = new Set();
  const nearby = new Set();
  const fromRef = new Set();
  const anonKeys = new Set();
  const findings = [];

  for (const { where, text } of sources) {
    for (const m of text.matchAll(SUPABASE_URL_RE)) urls.add(m[0]);
    for (const m of text.matchAll(CREATE_CLIENT_RE)) urls.add(m[1].replace(/\/+$/, ''));
    for (const m of text.matchAll(PUBLISHABLE_RE)) anonKeys.add(m[0]);

    for (const m of text.matchAll(JWT_RE)) {
      const payload = decodeJwt(m[0]);
      if (!payload) continue;
      if (payload.role === 'anon') {
        anonKeys.add(m[0]);
        // minified bundles: createClient is renamed, but the URL literal sits right before the key
        const before = text.slice(Math.max(0, m.index - 300), m.index);
        const lit = [...before.matchAll(/["'`](https?:\/\/[^"'`\s]+)["'`]/g)].pop();
        if (lit) nearby.add(lit[1].replace(/\/+$/, ''));
        if (payload.ref && /^[a-z0-9]{20}$/.test(payload.ref)) fromRef.add(`https://${payload.ref}.supabase.co`);
      }
      if (payload.role === 'service_role') {
        findings.push({
          id: 'leaked-service-role-key',
          severity: 'critical',
          title: 'service_role key is shipped to the browser',
          detail:
            'Anyone visiting the site can copy this key. It bypasses ALL Row Level Security: full read/write/delete on every table and bucket.',
          evidence: `Found in ${where}: ${redact(m[0])} (JWT role = "service_role")`,
          fix: { steps: ROTATE },
        });
      }
    }
    for (const m of text.matchAll(SECRET_RE)) {
      findings.push({
        id: 'leaked-supabase-secret-key',
        severity: 'critical',
        title: 'Supabase secret key (sb_secret_…) is shipped to the browser',
        detail: 'It bypasses ALL Row Level Security. Anyone visiting the site can copy it.',
        evidence: `Found in ${where}: ${redact(m[0])}`,
        fix: { steps: ROTATE },
      });
    }
  }

  // priority: explicit *.supabase.co / createClient literal → literal next to the key → ref inside the key
  return { urls: [...new Set([...urls, ...nearby, ...fromRef])], anonKeys: [...anonKeys], findings: dedupe(findings) };
}
