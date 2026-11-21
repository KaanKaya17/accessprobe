// What the project folder tells us about a Firebase app: config files, rules files,
// and collection names used in code (Firestore gives clients no collection list).

import { readdir, readFile } from 'node:fs/promises';
import { join, extname, basename } from 'node:path';
import { fromGoogleServicesJson, fromPlist, extract } from './discover.js';
import { rtdbPathsFromCode } from './rtdb-code.js';

const SKIP_DIRS = new Set(['node_modules', '.git', 'build', 'dist', '.gradle', '.next', '.idea', '.dart_tool', 'Pods', 'out', 'coverage']);
const CODE_EXT = new Set(['.js', '.jsx', '.ts', '.tsx', '.mjs', '.vue', '.svelte', '.kt', '.java', '.dart', '.swift', '.py']);

export async function scanSource(dir) {
  const files = await walk(dir);
  const out = { configs: [], firestoreRules: null, storageRules: null, databaseRules: null, collections: new Set(), files: files.length };
  const codeTexts = [];

  for (const f of files) {
    const name = basename(f);
    if (name === 'google-services.json') {
      const c = fromGoogleServicesJson(await readFile(f, 'utf8'));
      if (c) out.configs.push(c);
    } else if (name === 'GoogleService-Info.plist') {
      const c = fromPlist(await readFile(f, 'utf8'));
      if (c) out.configs.push(c);
    } else if (name === 'firestore.rules') out.firestoreRules ??= await readFile(f, 'utf8');
    else if (name === 'storage.rules') out.storageRules ??= await readFile(f, 'utf8');
    else if (name === 'database.rules.json') out.databaseRules ??= await readFile(f, 'utf8');
    else if (CODE_EXT.has(extname(f))) {
      const text = await readFile(f, 'utf8');
      if (/getReference|DatabaseReference/.test(text)) codeTexts.push(text);
      // web apps: initializeApp({ apiKey: "AIza…", projectId: … }) in client code
      if (/AIza[0-9A-Za-z_-]{35}/.test(text)) {
        const shown = f.slice(dir.length).replace(/^[\\/]/, '').replace(/\\/g, '/');
        for (const c of extract([{ where: shown, text }]).configs) out.configs.push(c);
      }
      // collection(db, "orders") / db.collection("orders") / .collection('orders') / collectionGroup("x")
      for (const m of text.matchAll(/\bcollection(?:Group)?\(\s*(?:[\w.]+\s*,\s*)?["'`]([A-Za-z_][\w-]*)["'`]/g)) out.collections.add(m[1]);
      // doc(db, "users", uid) — first segment is a collection
      for (const m of text.matchAll(/\bdoc\(\s*[\w.]+\s*,\s*["'`]([A-Za-z_][\w-]*)["'`]/g)) out.collections.add(m[1]);
    }
  }
  return { ...out, collections: [...out.collections], rtdbCodePaths: rtdbPathsFromCode(codeTexts) };
}

async function walk(dir, out = []) {
  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch {
    return out;
  }
  for (const e of entries) {
    const p = join(dir, e.name);
    if (e.isDirectory()) {
      if (!SKIP_DIRS.has(e.name) && !e.name.startsWith('.')) await walk(p, out);
    } else if (e.isFile()) {
      if (CODE_EXT.has(extname(p)) || /^(google-services\.json|GoogleService-Info\.plist|firestore\.rules|storage\.rules|database\.rules\.json)$/.test(e.name))
        out.push(p);
    }
    if (out.length > 20000) break;
  }
  return out;
}
