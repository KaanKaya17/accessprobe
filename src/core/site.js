// Fetches a deployed site and its JS bundles once, so every platform adapter can
// look for its own config in the same text. Also flags generic secrets in the bundle.

const MAX_BUNDLES = 25;

const SECRET_PATTERNS = [
  { id: 'stripe-live-secret', name: 'Stripe live secret key', re: /sk_live_[A-Za-z0-9]{20,}/g },
  { id: 'openai-key', name: 'OpenAI API key', re: /sk-(?!ant-)(?:proj-)?[A-Za-z0-9_-]{32,}/g },
  { id: 'anthropic-key', name: 'Anthropic API key', re: /sk-ant-[A-Za-z0-9_-]{32,}/g },
  { id: 'aws-access-key', name: 'AWS access key id', re: /AKIA[0-9A-Z]{16}/g },
  { id: 'github-token', name: 'GitHub token', re: /gh[pousr]_[A-Za-z0-9]{36,}/g },
  { id: 'appwrite-api-key', name: 'Appwrite API key', re: /standard_[0-9a-f]{128,}/g },
];

export async function fetchSite(siteUrl, { log = () => {} } = {}) {
  const html = await fetchText(siteUrl);
  if (html == null) throw new Error(`Could not fetch ${siteUrl}`);
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
    if (text != null) sources.push({ where: u, text });
  }
  return { url: siteUrl, sources, scanned: sources.map((s) => s.where) };
}

export function genericSecrets(sources) {
  const findings = [];
  for (const { where, text } of sources) {
    for (const p of SECRET_PATTERNS) {
      for (const m of text.matchAll(p.re)) {
        findings.push({
          id: `leaked-${p.id}`,
          severity: 'critical',
          title: `${p.name} is shipped to the browser`,
          detail: 'Secrets in client-side JavaScript are public. Anyone can extract and abuse them.',
          evidence: `Found in ${where}: ${redact(m[0])}`,
          fix: {
            steps: [
              'Revoke / rotate this key at the provider immediately.',
              'Call that API from a serverless function or backend instead of the browser.',
            ],
          },
        });
      }
    }
  }
  return dedupe(findings);
}

export function redact(secret) {
  if (secret.length <= 16) return '***';
  return `${secret.slice(0, 10)}…${secret.slice(-4)}`;
}

export function dedupe(findings) {
  const seen = new Set();
  return findings.filter((f) => {
    const k = f.id + f.evidence;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}

async function fetchText(url) {
  try {
    const res = await fetch(url, { signal: AbortSignal.timeout(15000), headers: { 'User-Agent': 'accessprobe' } });
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
