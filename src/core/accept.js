// Accepted findings: things that are open on purpose (a public profiles table, a shared
// catalog). Listed in .accessprobeignore, they move out of the findings into "Accepted", stop
// counting towards the grade and exit code, and their failing checks are left out of the
// --pgtap / --rules-tests files, so CI stays green until something NEW opens up.
//
// One entry per line:   <table / collection / bucket / path>  [finding id]  # reason
//   profiles  cross-user-read   # profiles are public on purpose
//   products                    # the whole catalog is public
// Without a finding id, every finding on that resource is accepted.

import { readFile } from 'node:fs/promises';
import { join } from 'node:path';

export const ACCEPT_FILE = '.accessprobeignore';

export function parseAccept(text) {
  const entries = [];
  const errors = [];
  String(text)
    .split(/\r?\n/)
    .forEach((raw, i) => {
      const hash = raw.indexOf('#');
      const reason = hash >= 0 ? raw.slice(hash + 1).trim() : '';
      const parts = (hash >= 0 ? raw.slice(0, hash) : raw).trim().split(/\s+/).filter(Boolean);
      if (!parts.length) return;
      if (parts.length > 2) {
        errors.push(`line ${i + 1}: expected "<resource> [finding id]  # reason", got "${raw.trim()}"`);
        return;
      }
      entries.push({ resource: parts[0], id: parts[1] || null, reason, line: i + 1 });
    });
  return { entries, errors };
}

// file: explicit path (must exist); otherwise <source>/.accessprobeignore or ./.accessprobeignore
export async function loadAccept({ file, source } = {}) {
  const candidates = file ? [file] : [...new Set([source && join(source, ACCEPT_FILE), ACCEPT_FILE].filter(Boolean))];
  for (const f of candidates) {
    let text;
    try {
      text = await readFile(f, 'utf8');
    } catch (e) {
      if (file) throw new Error(`Cannot read ${file}: ${e.code || e.message}`);
      continue;
    }
    const { entries, errors } = parseAccept(text);
    if (errors.length) throw new Error(`${f}: ${errors.join('; ')}`);
    return { file: f, entries };
  }
  return { file: null, entries: [] };
}

export const resourceOf = (f) => f.table ?? f.resource ?? f.bucket ?? f.collectionPath ?? f.path ?? null;

const matches = (e, f) => e.resource === resourceOf(f) && (!e.id || e.id === f.id);

// → { findings, accepted, unused } ; accepted findings carry acceptedBecause
export function applyAccept(findings, entries) {
  const kept = [];
  const accepted = [];
  const used = new Set();
  for (const f of findings) {
    const e = entries.find((x) => matches(x, f));
    if (e) {
      used.add(e);
      accepted.push({ ...f, acceptedBecause: e.reason || '(no reason given)' });
    } else kept.push(f);
  }
  return { findings: kept, accepted, unused: entries.filter((e) => !used.has(e)) };
}

// Does a regression check (pgtap.js / rules-tests.js recipe) test what this finding id reports?
// check names: read, list, anon-read, anon-auth-read, update, takeover, forge, delete,
// anon-create, anon-auth-create
export function checkCovers(check, id) {
  const who = (s) => (s.startsWith('anon-auth') ? 'anon-auth' : s.startsWith('anon') ? 'anon' : 'user');
  if (who(check) !== who(id)) return false;
  const verb = check.split('-').pop();
  if (verb === 'forge') return /impersonated|forge/.test(id);
  if (verb === 'create') return /create|insert|write/.test(id);
  if (verb === 'read') return /read|public/.test(id) && !/list/.test(id);
  return id.includes(verb);
}

// Drop the failing checks of accepted findings from regression recipes, so the generated tests
// don't fail forever on something that is open on purpose. A whole-resource entry drops the
// resource's recipe entirely.
export function acceptRecipes(recipes, entries) {
  const out = [];
  for (const r of recipes || []) {
    const res = r.table ?? r.resource;
    const mine = entries.filter((e) => e.resource === res);
    if (!mine.length) {
      out.push(r);
      continue;
    }
    if (mine.some((e) => !e.id)) continue;
    const checks = r.checks.filter((c) => c.ok || !mine.some((e) => checkCovers(c.check, e.id)));
    out.push({ ...r, checks });
  }
  return out;
}
