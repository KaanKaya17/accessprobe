// Turns one accessprobe run into a Security Rules test file for the Firebase Emulator Suite, so
// every check it made keeps running in CI without a live project. It is the Firebase counterpart
// of supabase/pgtap.js: each test states the SECURE behaviour, checks that passed stay green, and
// checks behind a proven leak fail until the fix is applied.
//
// Recipes come from probes.js / rtdb-storage.js: the document, value or file user A created, and
// which checks gave a clear verdict. The file uses @firebase/rules-unit-testing (installed by the
// user's project, never by accessprobe) with node:test, and loads the rules from the project files.

import { writeFile, mkdir } from 'node:fs/promises';
import { readFileSync } from 'node:fs';
import { dirname, relative, resolve, isAbsolute } from 'node:path';
import { pathToFileURL } from 'node:url';

const A_ID = 'accessprobe-user-a';
const B_ID = 'accessprobe-user-b';
const C_ID = 'accessprobe-anon-c';
const FAILS = ' // FAILS until the fix from the accessprobe report is applied';

// same-length variant, like the live test (a length check in the rules must not fake a pass)
const tamper = (m) => `${m.slice(0, -1)}${m.endsWith('x') ? 'y' : 'x'}`;

// a JS expression for a recipe value: "{A}" becomes user A's id, "{marker}" this test's marker
function js(v, marker) {
  if (typeof v === 'string') {
    const s = v.split('{marker}').join(marker);
    if (!s.includes('{A}')) return JSON.stringify(s);
    return `\`${s.replace(/[`\\$]/g, '\\$&').split('{A}').join('${A}')}\``;
  }
  if (v instanceof Date) return `new Date(${JSON.stringify(v.toISOString())})`;
  if (Array.isArray(v)) return `[${v.map((x) => js(x, marker)).join(', ')}]`;
  if (v && typeof v === 'object') return `{ ${Object.entries(v).map(([k, x]) => `${JSON.stringify(k)}: ${js(x, marker)}`).join(', ')} }`;
  return JSON.stringify(v ?? null);
}

export function rulesTests(recipes, { version = '', target = '', date = new Date().toISOString(), root = '../', file = 'accessprobe.rules.test.mjs', files = {} } = {}) {
  const usable = (recipes || []).filter((r) => r.checks?.length);
  if (!usable.length) return null;
  let n = 0;
  const body = [];
  const seen = new Set();
  const used = new Set();
  const test = (desc, ok, lines) => {
    if (seen.has(desc)) return;
    seen.add(desc);
    body.push('', `test(${JSON.stringify(desc)}, async () => {${ok ? '' : FAILS}`, ...lines.map((l) => `  ${l}`), '});');
  };

  for (const r of usable) {
    const has = (check) => r.checks.filter((c) => c.check === check);
    if (r.service === 'firestore') {
      used.add('firestore');
      const res = r.resource;
      for (const c of r.checks) {
        const id = `accessprobe-t${(n++).toString(36)}`;
        const marker = id;
        const docId = r.docId === '{A}' ? '{A}' : id;
        const path = js(`${r.collection}/${docId}`, marker);
        const seedLines = [
          `const path = ${path};`,
          `await seed((ctx) => ctx.firestore().doc(path).set(${js(r.payload, marker)}));`,
          'await assertSucceeds(as.A().firestore().doc(path).get()); // control: the owner reads its document',
        ];
        const forged = (suffix) => js({ ...r.payload, ...(r.markerField ? { [r.markerField]: `{marker}-${suffix}` } : {}) }, marker);
        const newDoc = (who, suffix) => `await assertFails(as.${who}().firestore().doc(${js(`${r.collection}/${id}-${suffix}`, marker)}).set(${forged(suffix)}));`;
        if (c.check === 'read') test(`${res}: B cannot read A's documents`, c.ok, [...seedLines, 'await assertFails(as.B().firestore().doc(path).get());']);
        else if (c.check === 'list')
          test(`${res}: B cannot list other users' documents`, c.ok, [...seedLines, `await assertFails(as.B().firestore().collection(${js(r.collection, marker)}).get());`]);
        else if (c.check === 'anon-read') test(`${res}: anonymous visitors cannot read A's documents`, c.ok, [...seedLines, 'await assertFails(as.anon().firestore().doc(path).get());']);
        else if (c.check === 'anon-auth-read')
          test(`${res}: anonymous-auth users cannot read A's documents`, c.ok, [...seedLines, 'await assertFails(as.anonAuth().firestore().doc(path).get());']);
        else if (c.check === 'update') {
          const patch = r.markerField ? { [r.markerField]: tamper(marker) } : { [r.ownerField]: '{A}' };
          test(`${res}: B cannot modify A's documents`, c.ok, [...seedLines, `await assertFails(as.B().firestore().doc(path).update(${js(patch, marker)}));`]);
        } else if (c.check === 'takeover')
          test(`${res}: B cannot reassign A's documents to itself`, c.ok, [...seedLines, `await assertFails(as.B().firestore().doc(path).update({ ${JSON.stringify(r.ownerField)}: B }));`]);
        else if (c.check === 'forge') test(`${res}: B cannot create documents as A`, c.ok, [...seedLines, newDoc('B', 'fake')]);
        else if (c.check === 'anon-create') test(`${res}: anonymous visitors cannot create documents`, c.ok, [...seedLines, newDoc('anon', 'anon')]);
        else if (c.check === 'anon-auth-create') test(`${res}: anonymous-auth users cannot create documents`, c.ok, [...seedLines, newDoc('anonAuth', 'anonauth')]);
        else if (c.check === 'delete') test(`${res}: B cannot delete A's documents`, c.ok, [...seedLines, 'await assertFails(as.B().firestore().doc(path).delete());']);
        else if (c.check === 'escalation')
          test(`${res}: users cannot set their own ${c.field}`, c.ok, [...seedLines, `await assertFails(as.A().firestore().doc(path).update({ ${JSON.stringify(c.field)}: ${js(c.value, marker)} }));`]);
      }
    } else if (r.service === 'database') {
      used.add('database');
      const db = (who) => `as.${who}().database()`;
      if (r.kind === 'root') {
        for (const c of has('anon-read')) test('Realtime Database: anonymous visitors cannot read the root', c.ok, [`await assertFails(${db('anon')}.ref('/').once('value'));`]);
        for (const c of has('anon-auth-read')) test('Realtime Database: anonymous-auth users cannot read the root', c.ok, [`await assertFails(${db('anonAuth')}.ref('/').once('value'));`]);
        continue;
      }
      const ref = (p, marker) => js(p, marker);
      for (const [check, who, desc] of [
        ['anon-list', 'anon', 'anonymous visitors'],
        ['anon-auth-list', 'anonAuth', 'anonymous-auth users'],
        ['list', 'B', 'signed-in users'],
      ])
        for (const c of has(check)) test(`Realtime Database /${r.parent}: ${desc} cannot list all entries`, c.ok, [`await assertFails(${db(who)}.ref(${JSON.stringify(r.parent)}).once('value'));`]);
      for (const [check, who, desc] of [
        ['anon-write', 'anon', 'anonymous visitors'],
        ['anon-auth-write', 'anonAuth', 'anonymous-auth users'],
      ])
        for (const c of has(check)) {
          const id = `accessprobe_t${(n++).toString(36)}`;
          test(`Realtime Database /${r.resource}: ${desc} cannot write`, c.ok, [`await assertFails(${db(who)}.ref(${JSON.stringify(`${r.node}/${id}`)}).set('accessprobe test entry'));`]);
        }
      if (!r.path) continue;
      for (const [check, desc, act] of [
        ['read', "B cannot read A's data", () => `await assertFails(${db('B')}.ref(path).once('value'));`],
        ['write', "B cannot write to A's data", (marker) => `await assertFails(${db('B')}.ref(path).set(${js(r.tampered, marker)}));`],
        ['anon-read', 'anonymous visitors cannot read', () => `await assertFails(${db('anon')}.ref(path).once('value'));`],
        ['anon-auth-read', 'anonymous-auth users cannot read', () => `await assertFails(${db('anonAuth')}.ref(path).once('value'));`],
      ])
        for (const c of has(check)) {
          const marker = `accessprobe_t${(n++).toString(36)}`;
          test(`Realtime Database /${r.resource}: ${desc}`, c.ok, [
            `const path = ${ref(r.path, marker)};`,
            `await seed((ctx) => ctx.database().ref(path).set(${js(r.value, marker)}));`,
            `await assertSucceeds(${db('A')}.ref(path).once('value')); // control: the owner reads its entry`,
            act(marker),
          ]);
        }
    } else if (r.service === 'storage') {
      used.add('storage');
      for (const c of r.checks) {
        const name = `accessprobe-t${(n++).toString(36)}.txt`;
        const path = js(r.path.replace(/[^/]+$/, name), name);
        const lines = [
          `const path = ${path};`,
          "await seed((ctx) => ctx.storage().ref(path).putString('accessprobe test file'));",
          'await assertSucceeds(as.A().storage().ref(path).getMetadata()); // control: the owner reads its file',
        ];
        const res = `Storage ${r.resource}`;
        if (c.check === 'read') test(`${res}: B cannot download A's files`, c.ok, [...lines, 'await assertFails(as.B().storage().ref(path).getMetadata());']);
        else if (c.check === 'list') test(`${res}: B cannot list A's files`, c.ok, [...lines, "await assertFails(as.B().storage().ref(path.replace(/[^/]+$/, '')).listAll());"]);
        else if (c.check === 'anon-read') test(`${res}: anonymous visitors cannot download`, c.ok, [...lines, 'await assertFails(as.anon().storage().ref(path).getMetadata());']);
        else if (c.check === 'anon-auth-read') test(`${res}: anonymous-auth users cannot download`, c.ok, [...lines, 'await assertFails(as.anonAuth().storage().ref(path).getMetadata());']);
        else if (c.check === 'delete') test(`${res}: B cannot delete A's files`, c.ok, [...lines, 'await assertFails(as.B().storage().ref(path).delete());']);
      }
    }
  }
  if (!seen.size) return null;

  const projectId = usable.map((r) => r.projectId).find((p) => p?.startsWith('demo-')) || 'demo-accessprobe';
  const only = ['firestore', 'database', 'storage'].filter((s) => used.has(s));
  const emu = { firestore: ['FIRESTORE_EMULATOR_HOST', 8080, 'firestore.rules'], database: ['FIREBASE_DATABASE_EMULATOR_HOST', 9000, 'database.rules.json'], storage: ['FIREBASE_STORAGE_EMULATOR_HOST', 9199, 'storage.rules'] };
  return [
    `// accessprobe Security Rules regression tests${version ? ` (accessprobe ${version})` : ''}`,
    `// Generated ${date.slice(0, 10)} from a run against ${target || 'a Firebase project'}.`,
    '//',
    '// Run them against the Firebase Emulator Suite:',
    '//   npm i -D @firebase/rules-unit-testing',
    `//   firebase emulators:exec --only ${only.join(',')} "node --test ${file}"`,
    '//',
    '// Every test states the secure behaviour. Tests marked "FAILS until the fix" belong to leaks',
    '// accessprobe proved; they turn green once the fix from its report is applied, and then keep the',
    '// leak from coming back. The rules are loaded from your project files (paths from firebase.json',
    '// when present) and the test data only ever lives in the emulators.',
    '// Re-generate after rules changes: npx accessprobe --source . --emulator --rules-tests <this file>',
    '',
    "import { test, before, after } from 'node:test';",
    "import { readFileSync, existsSync } from 'node:fs';",
    "import { initializeTestEnvironment, assertFails, assertSucceeds } from '@firebase/rules-unit-testing';",
    '',
    `const ROOT = new URL(${JSON.stringify(root)}, import.meta.url); // the project folder accessprobe tested`,
    `const PROJECT_ID = process.env.GCLOUD_PROJECT || ${JSON.stringify(projectId)};`,
    `const A = ${JSON.stringify(A_ID)};`,
    `const B = ${JSON.stringify(B_ID)};`,
    `const C = ${JSON.stringify(C_ID)}; // an anonymous sign-in user`,
    '',
    'const firebaseJson = existsSync(new URL(\'firebase.json\', ROOT)) ? JSON.parse(readFileSync(new URL(\'firebase.json\', ROOT), \'utf8\')) : {};',
    'const rulesOf = (service, fallback) => {',
    '  const c = firebaseJson[service];',
    '  return readFileSync(new URL((Array.isArray(c) ? c[0]?.rules : c?.rules) || fallback, ROOT), \'utf8\');',
    '};',
    '// firebase emulators:exec sets the hosts (FIREBASE_EMULATOR_HUB); otherwise firebase.json or the defaults',
    'const at = (service, envVar, port) => {',
    '  if (process.env.FIREBASE_EMULATOR_HUB || process.env[envVar]) return {};',
    '  const e = firebaseJson.emulators?.[service] || {};',
    "  return { host: e.host || '127.0.0.1', port: e.port || port };",
    '};',
    '',
    'let env;',
    'before(async () => {',
    '  env = await initializeTestEnvironment({',
    '    projectId: PROJECT_ID,',
    ...only.map((s) => `    ${s}: { rules: rulesOf('${s}', ${JSON.stringify(files[s] || emu[s][2])}), ...at('${s}', '${emu[s][0]}', ${emu[s][1]}) },`),
    '  });',
    '});',
    'after(async () => {',
    '  await env?.cleanup();',
    '});',
    '',
    '// owner A and user B (email accounts), an unauthenticated visitor, and an anonymous-auth user',
    'const as = {',
    "  A: () => env.authenticatedContext(A, { email: 'accessprobe-a@example.test', firebase: { sign_in_provider: 'password', identities: {} } }),",
    "  B: () => env.authenticatedContext(B, { email: 'accessprobe-b@example.test', firebase: { sign_in_provider: 'password', identities: {} } }),",
    '  anon: () => env.unauthenticatedContext(),',
    "  anonAuth: () => env.authenticatedContext(C, { firebase: { sign_in_provider: 'anonymous', identities: {} } }),",
    '};',
    'const seed = (fn) => env.withSecurityRulesDisabled(fn);',
    ...body,
    '',
  ].join('\n');
}

const VERSION = JSON.parse(readFileSync(new URL('../../../package.json', import.meta.url), 'utf8')).version;

// where the generated file finds the project: a path relative to the test file (a file URL
// when there is none, e.g. another drive on Windows)
function rootFor(file, source) {
  const rel = relative(dirname(resolve(file)), resolve(source || '.'));
  if (isAbsolute(rel)) return pathToFileURL(`${resolve(source || '.')}/`).href;
  return rel ? `${rel.replace(/\\/g, '/')}/` : './';
}

// writes the file and returns a one-line message for the user
export async function writeRulesTests(file, result, { source, rulesFiles = {} } = {}) {
  const root = resolve(source || '.');
  const files = Object.fromEntries(Object.entries(rulesFiles).filter(([, f]) => f).map(([k, f]) => [k, relative(root, resolve(f)).replace(/\\/g, '/')]));
  const shown = relative(process.cwd(), resolve(file)).replace(/\\/g, '/') || file;
  const code = rulesTests(result.rulesRecipes, { version: VERSION, target: result.target, date: result.date, root: rootFor(file, source), file: shown, files });
  if (!code) return `No rules tests written to ${file}: no Firestore, Realtime Database or Storage check could be replayed (user A must be able to create and read its own data).`;
  await mkdir(dirname(file), { recursive: true });
  await writeFile(file, code, 'utf8');
  const tests = (code.match(/^test\(/gm) || []).length;
  const failing = (code.match(/^test\(.*FAILS until the fix/gm) || []).length;
  const only = /emulators:exec --only (\S+)/.exec(code)[1];
  return `Rules tests written to ${file}: ${tests} tests${failing ? `, ${failing} of them fail until the leaks are fixed` : ''}. Run them with: npm i -D @firebase/rules-unit-testing && firebase emulators:exec --only ${only} "node --test ${shown}"`;
}
