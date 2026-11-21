// Finds the Supabase URL + public key in a deployed site's JS bundles,
// and flags secrets that must never ship to the browser.

import { decodeJwt } from './client.js';

const MAX_BUNDLES = 25;

const SECRET_PATTERNS = [
  { id: 'supabase-secret-key', name: 'Supabase secret key (sb_secret_…)', re: /sb_secret_[A-Za-z0-9_-]{20,}/g },
  { id: 'stripe-live-secret', name: 'Stripe live secret key', re: /sk_live_[A-Za-z0-9]{20,}/g },
  { id: 'openai-key', name: 'OpenAI API key', re: /sk-(?:proj-)?[A-Za-z0-9_-]{32,}/g },
  { id: 'anthropic-key', name: 'Anthropic API key', re: /sk-ant-[A-Za-z0-9_-]{32,}/g },
  { id: 'aws-access-key', name: 'AWS access key id', re: /AKIA[0-9A-Z]{16}/g },
  { id: 'github-token', name: 'GitHub token', re: /gh[pousr]_[A-Za-z0-9]{36,}/g },
];

const JWT_RE = /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g;
const PUBLISHABLE_RE = /sb_publishable_[A-Za-z0-9_-]{20,}/g;
const SUPABASE_URL_RE = /https:\/\/[a-z0-9]{20}\.supabase\.co/g;
// createClient("http://localhost:54321", "...") — also catches self-hosted / custom domains
const CREATE_CLIENT_RE = /createClient\(\s*["'`](https?:\/\/[^"'`]+)["'`]/g;

export async function discover(siteUrl, { log = () => {} } = {}) {
  const result = { siteUrl, urls: new Set(), anonKeys: new Set(), findings: [], scanned: [] };

  const html = await fetchText(siteUrl);
  if (html == null) throw new Error(`Could not fetch ${siteUrl}`);
  result.scanned.push(siteUrl);
  const sources = [{ where: siteUrl, text: html }];

  const scriptSrcs = [...html.matchAll(/<script[^>]+src=["']([^"']+)["']/gi)].map((m) => m[1]);
  const preload = [...html.matchAll(/<link[^>]+href=["']([^"']+\.js)["']/gi)].map((m) => m[1]);
  const bundleUrls = [...new Set([...scriptSrcs, ...preload])]
    .map((s) => safeUrl(s, siteUrl))
    .filter(Boolean)
    .slice(0, MAX_BUNDLES);

  for (const u of bundleUrls) {
    log(`  fetching ${u}`);
    const text = await fetchText(u);
    if (text != null) {
      sources.push({ where: u, text });
      result.scanned.push(u);
    }
  }

  const nearby = new Set();
  const fromRef = new Set();
  for (const { where, text } of sources) {
    for (const m of text.matchAll(SUPABASE_URL_RE)) result.urls.add(m[0]);
    for (const m of text.matchAll(CREATE_CLIENT_RE)) result.urls.add(m[1].replace(/\/+$/, ''));
    for (const m of text.matchAll(PUBLISHABLE_RE)) result.anonKeys.add(m[0]);

    for (const m of text.matchAll(JWT_RE)) {
      const payload = decodeJwt(m[0]);
      if (!payload) continue;
      if (payload.role === 'anon') {
        result.anonKeys.add(m[0]);
        // minified bundles: createClient is renamed, but the URL literal sits right before the key
        const before = text.slice(Math.max(0, m.index - 300), m.index);
        const lit = [...before.matchAll(/["'`](https?:\/\/[^"'`\s]+)["'`]/g)].pop();
        if (lit) nearby.add(lit[1].replace(/\/+$/, ''));
        if (payload.ref && /^[a-z0-9]{20}$/.test(payload.ref)) fromRef.add(`https://${payload.ref}.supabase.co`);
      }
      if (payload.role === 'service_role') {
        result.findings.push({
          id: 'leaked-service-role-key',
          severity: 'critical',
          title: 'service_role key is shipped to the browser',
          detail:
            'Anyone visiting the site can copy this key. It bypasses ALL Row Level Security: full read/write/delete on every table and bucket.',
          evidence: `Found in ${where}: ${redact(m[0])} (JWT role = "service_role")`,
          fix: {
            sql: null,
            steps: [
              'Rotate the key NOW: Supabase Dashboard → Project Settings → API → roll the service_role / JWT secret.',
              'Remove it from all client code and VITE_/NEXT_PUBLIC_ env vars. Only the anon / publishable key belongs in the browser.',
              'Move any code that needs it into an Edge Function or your server.',
            ],
          },
        });
      }
    }

    for (const p of SECRET_PATTERNS) {
      for (const m of text.matchAll(p.re)) {
        result.findings.push({
          id: `leaked-${p.id}`,
          severity: 'critical',
          title: `${p.name} is shipped to the browser`,
          detail: 'Secrets in client-side JavaScript are public. Anyone can extract and abuse them.',
          evidence: `Found in ${where}: ${redact(m[0])}`,
          fix: {
            sql: null,
            steps: [
              'Revoke / rotate this key at the provider immediately.',
              'Call that API from an Edge Function or backend instead of the browser.',
            ],
          },
        });
      }
    }
  }

  // priority: explicit *.supabase.co / createClient literal → literal next to the key → ref inside the key
  const urls = [...new Set([...result.urls, ...nearby, ...fromRef])];
  return {
    ...result,
    urls,
    anonKeys: [...result.anonKeys],
    findings: dedupe(result.findings),
  };
}

async function fetchText(url) {
  try {
    const res = await fetch(url, { signal: AbortSignal.timeout(15000), headers: { 'User-Agent': 'rlsprobe' } });
    if (!res.ok) return null;
    return await res.text();
  } catch {
    return null;
  }
}

function safeUrl(src, base) {
  try {
    return new URL(src, base).toString();
  } catch {
    return null;
  }
}

export function redact(secret) {
  if (secret.length <= 16) return '***';
  return `${secret.slice(0, 10)}…${secret.slice(-4)}`;
}

function dedupe(findings) {
  const seen = new Set();
  return findings.filter((f) => {
    const k = f.id + f.evidence;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}
