// Orchestrates one run: fetch the site once, pick the platform adapter(s),
// run them, merge their results into one report.

import { fetchSite, genericSecrets } from './site.js';
import { providers, byId } from '../providers/index.js';
import { applyAccept, acceptRecipes } from './accept.js';

// Work out WHAT will be tested before anything is written: which backends, and exactly which
// project / URL each one would touch. The CLI shows this in the "do you own it?" question.
export async function plan(opts, { log = () => {} } = {}) {
  let site = null;
  if (opts.site) {
    log(`→ Fetching ${opts.site}`);
    site = await fetchSite(opts.site, { log });
  }
  const chosen = await choose(opts, site);
  const targets = [];
  for (const p of chosen) targets.push({ provider: p, target: p.describe ? await p.describe(opts, { site }) : p.label });
  return { site, chosen, targets };
}

export async function scan(opts, prepared) {
  const log = opts.quiet ? () => {} : (m) => console.error(m);
  const t0 = Date.now();
  const { site, chosen } = prepared || (await plan(opts, { log }));

  const results = [];
  const failures = [];
  for (const p of chosen) {
    try {
      results.push({ provider: p, result: await p.scan(opts, { site, log }) });
    } catch (e) {
      // one backend failing must not throw away another backend's results — and its full
      // message is kept (it may list test users that still need deleting)
      if (chosen.length === 1) throw e;
      failures.push(`[${p.label}] not tested: ${e.message.replace(/\n\s*/g, ' ')}`);
      log(`  ${p.label} skipped: ${e.message.split('\n')[0]}`);
    }
  }
  if (!results.length) throw new Error(failures.join('\n'));
  return merge(opts, site, results, failures, t0);
}

async function choose(opts, site) {
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
  return chosen;
}

function merge(opts, site, results, failures, t0) {
  const findings = [];
  const passed = [];
  const notes = [];
  const many = results.length > 1 || failures.length > 0;
  notes.push(...failures);
  if (site) {
    const generic = genericSecrets(site.sources);
    findings.push(...generic);
    const anyLeak = generic.length || results.some(({ result }) => result.findings.some((f) => f.id.startsWith('leaked-')));
    if (!anyLeak) passed.push(`No secret keys found in ${site.scanned.length} file(s) of the site's JavaScript`);
  }
  for (const { provider: p, result: r } of results) {
    const pre = many ? `[${p.label}] ` : '';
    findings.push(...r.findings.map((f) => ({ ...f, platform: p.id, platformLabel: p.label })));
    // several targets can share a parent node and prove the same thing: report it once
    for (const x of r.passed) if (!passed.includes(pre + x)) passed.push(pre + x);
    for (const x of r.notes) if (!notes.includes(pre + x)) notes.push(pre + x);
  }

  // one clear line instead of one "… inconclusive (0 rate limited …)" per check
  const throttled = new Map(); // resource → checks
  let throttledCount = 0;
  for (let i = notes.length - 1; i >= 0; i--) {
    if (!notes[i].includes('rate limited (HTTP 429')) continue;
    const m = notes[i].match(/^(.+?): (.+?) (?:test|check)\b/);
    const [res, check] = m ? [m[1], m[2]] : [notes[i].split(' (')[0], null];
    if (!throttled.has(res)) throttled.set(res, new Set());
    if (check) throttled.get(res).add(check);
    throttledCount++;
    notes.splice(i, 1);
  }
  if (throttledCount) {
    const list = [...throttled].reverse().map(([res, checks]) => (checks.size ? `${res} (${[...checks].join(', ')})` : res));
    notes.unshift(
      `Rate limited: the backend answered HTTP 429 for ${throttledCount} check(s) even after retrying. They were not tested and are not counted as passed: ${list.join('; ')}. ` +
        'Run again in a few minutes, or with --only <table> to send fewer requests.',
    );
  }
  if (opts.readOnly) {
    // one line instead of one "write test skipped … not sent (--read-only)" per table
    const skippedWrites = [];
    for (let i = notes.length - 1; i >= 0; i--) {
      if (!notes[i].includes('not sent (--read-only)')) continue;
      skippedWrites.unshift(notes[i].split(':')[0]);
      notes.splice(i, 1);
    }
    if (skippedWrites.length) notes.unshift(`Write tests not run (--read-only): ${[...new Set(skippedWrites)].join(', ')}`);
    notes.unshift('Read-only run: nothing was written, so every write check (create, change, delete, upload) was skipped. Reads were tested with the data already there; a clean result here is not full coverage.');
  }
  const entries = opts.accept?.entries || [];
  const acc = applyAccept(findings, entries);
  if (!opts.only?.length) {
    for (const e of acc.unused) {
      notes.push(`${opts.accept.file} line ${e.line} (${e.resource}${e.id ? ` ${e.id}` : ''}) matched nothing in this run — remove it if that issue is gone`);
    }
  }

  const sum = (k) => results.reduce((n, { result }) => n + (result.stats?.[k] || 0), 0);
  return {
    target: opts.site || results[0].result.target,
    date: new Date().toISOString(),
    platforms: results.map(({ provider: p, result: r }) => ({ id: p.id, label: p.label, stats: r.stats })),
    findings: acc.findings,
    // open on purpose (listed in .accessprobeignore): shown, but not graded
    accepted: acc.accepted,
    passed,
    notes,
    fixStyles: Object.fromEntries(results.map(({ provider: p }) => [p.id, p.fixStyle])),
    // pgTAP regression recipes (Supabase only), used by --pgtap; not part of the JSON output
    recipes: acceptRecipes(results.flatMap(({ provider: p, result: r }) => (p.id === 'supabase' && r.recipes) || []), entries),
    // Security Rules regression recipes (Firebase only), used by --rules-tests; not part of the JSON output
    rulesRecipes: acceptRecipes(results.flatMap(({ provider: p, result: r }) => (p.id === 'firebase' && r.recipes) || []), entries),
    stats: {
      resources: sum('resources'),
      fullyTested: sum('fullyTested'),
      readOnly: sum('readOnly'),
      seconds: ((Date.now() - t0) / 1000).toFixed(1),
    },
  };
}
