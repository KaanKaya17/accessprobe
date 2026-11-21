// Orchestrates one run: fetch the site once, pick the platform adapter(s),
// run them, merge their results into one report.

import { fetchSite, genericSecrets } from './site.js';
import { providers, byId } from '../providers/index.js';

export async function scan(opts) {
  const log = opts.quiet ? () => {} : (m) => console.error(m);
  const t0 = Date.now();

  let site = null;
  if (opts.site) {
    log(`→ Fetching ${opts.site}`);
    site = await fetchSite(opts.site, { log });
  }

  let chosen;
  if (opts.platform) {
    const p = byId(opts.platform);
    if (!p) throw new Error(`Unknown platform "${opts.platform}". Supported: ${providers.map((x) => x.id).join(', ')}`);
    chosen = [p];
  } else {
    chosen = [];
    for (const p of providers) if (await p.detect(opts, { site })) chosen.push(p);
  }
  if (!chosen.length) {
    throw new Error(
      `No supported backend found (${providers.map((p) => p.label).join(', ')}).\n` +
        '  Pass --platform, or the project details (e.g. --url and --anon-key for Supabase).',
    );
  }

  const results = [];
  for (const p of chosen) {
    const r = await p.scan(opts, { site, log });
    results.push({ provider: p, result: r });
  }

  const findings = [];
  const passed = [];
  const notes = [];
  const many = results.length > 1;
  if (site) {
    const generic = genericSecrets(site.sources);
    findings.push(...generic);
    const anyLeak = generic.length || results.some(({ result }) => result.findings.some((f) => f.id.startsWith('leaked-')));
    if (!anyLeak) passed.push(`No secret keys found in ${site.scanned.length} file(s) of the site's JavaScript`);
  }
  for (const { provider: p, result: r } of results) {
    const pre = many ? `[${p.label}] ` : '';
    findings.push(...r.findings.map((f) => ({ ...f, platform: p.id, platformLabel: p.label })));
    passed.push(...r.passed.map((x) => pre + x));
    notes.push(...r.notes.map((x) => pre + x));
  }

  const sum = (k) => results.reduce((n, { result }) => n + (result.stats?.[k] || 0), 0);
  return {
    target: opts.site || results[0].result.target,
    date: new Date().toISOString(),
    platforms: results.map(({ provider: p, result: r }) => ({ id: p.id, label: p.label, stats: r.stats })),
    findings,
    passed,
    notes,
    fixStyles: Object.fromEntries(results.map(({ provider: p }) => [p.id, p.fixStyle])),
    stats: {
      resources: sum('resources'),
      fullyTested: sum('fullyTested'),
      readOnly: sum('readOnly'),
      seconds: ((Date.now() - t0) / 1000).toFixed(1),
    },
  };
}
