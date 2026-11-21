// Find the Supabase URL + PUBLIC anon key in a project folder, so `npx accessprobe` works with no flags.
// Looks at env files (.env, .env.local, …), local.properties (Android), app.json / app.config.*
// (Expo) and client code. Secret keys are never used — and are reported when they sit somewhere
// that ends up in the browser or the app bundle.

import { readdir, readFile } from 'node:fs/promises';
import { join, extname, basename } from 'node:path';
import { extract } from './discover.js';
import { decodeJwt } from './client.js';
import { redact } from '../../core/site.js';

const SKIP_DIRS = new Set(['node_modules', '.git', 'build', 'dist', '.gradle', '.next', '.idea', '.vercel', 'out', 'coverage', '.turbo', '.expo', 'Pods', '.dart_tool']);
const CODE_EXT = new Set(['.js', '.jsx', '.ts', '.tsx', '.mjs', '.vue', '.svelte', '.kt', '.java', '.dart', '.swift']);
const CONFIG_FILE = /^(\.env(\..+)?|local\.properties|app\.json|app\.config\.(js|ts|json)|eas\.json|.*\.xcconfig)$/;
// prefixes whose values are compiled into the client bundle
const PUBLIC_PREFIX = /^(VITE_|NEXT_PUBLIC_|EXPO_PUBLIC_|REACT_APP_|PUBLIC_|NUXT_PUBLIC_|GATSBY_|VUE_APP_)/;
const ASSIGN = /^\s*(?:export\s+)?([A-Z0-9_]+)\s*[=:]\s*["']?([^"'\s#]+)/gm;

export async function findProjectConfig(dir) {
  const files = await walk(dir);
  const sources = [];
  const findings = [];
  const notes = [];
  const envUrls = []; // SUPABASE_URL=http://… (unquoted, self-hosted or local too)
  for (const f of files) {
    const text = await readFile(f, 'utf8').catch(() => null);
    if (text == null || !/supabase|eyJ|sb_publishable|sb_secret/i.test(text)) continue;
    const name = basename(f);
    const shown = f.slice(dir.length).replace(/^[\\/]/, '').replace(/\\/g, '/');
    if (CONFIG_FILE.test(name)) {
      for (const m of text.matchAll(ASSIGN)) {
        const [, key, value] = m;
        if (/SUPABASE.*URL/.test(key) && /^https?:\/\/[^\s"']+$/.test(value) && !/example|your[-_]?project|<|xxxx/i.test(value)) envUrls.push(value.replace(/\/+$/, ''));
        const secret = value.startsWith('sb_secret_') || decodeJwt(value)?.role === 'service_role';
        if (!secret) continue;
        if (PUBLIC_PREFIX.test(key)) {
          findings.push({
            id: 'leaked-service-role-env',
            severity: 'critical',
            title: `Supabase secret key in a browser-exposed variable (${key})`,
            detail: `Variables starting with ${key.match(PUBLIC_PREFIX)[1]} are compiled into the client bundle, so every visitor gets a key that bypasses ALL Row Level Security.`,
            evidence: `${shown}: ${key}=${redact(value)}`,
            fix: {
              steps: [
                'Rotate the key now: Supabase Dashboard → Project Settings → API.',
                `Rename the variable without the public prefix and only read it in server code / Edge Functions.`,
              ],
            },
          });
        } else {
          notes.push(`${shown}: a secret Supabase key is set in ${key} — fine for server code, accessprobe never uses it.`);
        }
      }
      // only feed non-secret values to the URL/key extractor
      sources.push({ where: shown, text: text.replace(ASSIGN, (line, key, value) => (decodeJwt(value)?.role === 'service_role' || value.startsWith('sb_secret_') ? '' : line)) });
    } else {
      sources.push({ where: shown, text }); // client code: a literal service key here IS a leak
    }
  }
  const x = extract(sources);
  const codeLeaks = x.findings.map((f) => ({ ...f, title: f.title.replace('is shipped to the browser', 'is hard-coded in the app source'), detail: `${f.detail} Anything in client code ends up in the app or browser bundle.` }));
  // an explicit SUPABASE_URL wins; otherwise fall back to URLs found in code / derived from the key
  return { urls: envUrls.length ? [...new Set(envUrls)] : x.urls, anonKeys: x.anonKeys, findings: [...findings, ...codeLeaks], notes, files: files.length };
}

async function walk(dir, out = [], depth = 0) {
  if (depth > 8) return out;
  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch {
    return out;
  }
  for (const e of entries) {
    const p = join(dir, e.name);
    if (e.isDirectory()) {
      if (!SKIP_DIRS.has(e.name) && !e.name.startsWith('.')) await walk(p, out, depth + 1);
    } else if (e.isFile() && (CONFIG_FILE.test(e.name) || CODE_EXT.has(extname(e.name)))) {
      out.push(p);
    }
    if (out.length > 20000) break;
  }
  return out;
}
