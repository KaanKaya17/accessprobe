// Appwrite permission strings for findings, plus how reports/prompts present them.

export const fixStyle = {
  lang: 'js',
  codeLabel: 'Fix (Appwrite permissions — Console → Databases / Storage → Settings → Permissions, or appwrite.json)',
  fixWhere: 'Please fix this in the Appwrite collection / bucket permissions, not in the frontend.',
  codeIntro: 'Change these permissions (adjust ids if needed), in the Appwrite Console or in appwrite.json (then `appwrite push`):',
  dont: 'Do not grant read, update or delete to Role.any() or Role.users() at collection level for user data, and never ship an API key to the client. Afterwards show me the collection permissions and the document security setting so I can review them.',
  secretMove: 'Move every call that needs this API key into an Appwrite Function or a server route.',
};

const q = (s) => `'${String(s).replace(/\\/g, '\\\\').replace(/'/g, "\\'")}'`;

// which: the actions the finding is about ('read', 'update', 'delete', 'create')
// t: { db, id, mode, config }   (config = the collection from appwrite.json, or null)
export function permissionFix(t, which, { configFile } = {}) {
  const rows = t.mode === 'rows';
  const sec = rows ? 'Row security' : 'Document security';
  const secKey = rows ? 'rowSecurity' : 'documentSecurity';
  const container = rows ? 'table' : 'collection';
  const current = t.config?.permissions?.length ? t.config.permissions.join(', ') : null;
  const lines = [
    `// "${t.id}" (database "${t.db}") → Console → Databases → ${t.db} → ${t.id} → Settings`,
    `//   ${sec}:  ON`,
    `//   Permissions (${container} level):  create("users") only — no read / update / delete for "any" or "users"`,
  ];
  if (current) lines.push(`//   (now: ${current}${t.config.security ? '' : `; ${sec.toLowerCase()} off`})`);
  if (which.includes('create')) lines.push('//   create("any") lets visitors who are not signed in write here: use create("users")');
  lines.push('//   Each document then belongs to the users its own permissions name.');
  if (configFile) {
    lines.push(
      '',
      `// ${configFile} → ${rows ? 'tables' : 'collections'} → "${t.id}"  (then: appwrite push ${rows ? 'tables' : 'collections'})`,
      `//   "${secKey}": true,`,
      '//   "$permissions": ["create(\\"users\\")"],',
    );
  }
  lines.push(
    '',
    "// app code: give every new document its owner's permissions (a client SDK already does",
    '// this when you pass none; passing them makes it explicit)',
    "import { ID, Permission, Role } from 'appwrite';",
    'const perms = [',
    '  Permission.read(Role.user(user.$id)),',
    '  Permission.update(Role.user(user.$id)),',
    '  Permission.delete(Role.user(user.$id)),',
    '];',
    rows
      ? `await tablesDB.createRow({ databaseId: ${q(t.db)}, tableId: ${q(t.id)}, rowId: ID.unique(), data, permissions: perms });`
      : `await databases.createDocument(${q(t.db)}, ${q(t.id)}, ID.unique(), data, perms);`,
  );
  return lines.join('\n');
}

export function bucketFix(b, which, { configFile } = {}) {
  const current = b.config?.permissions?.length ? b.config.permissions.join(', ') : null;
  const lines = [
    `// bucket "${b.id}" → Console → Storage → ${b.id} → Settings`,
    '//   File security:  ON',
    '//   Permissions (bucket level):  create("users") only — no read / update / delete for "any" or "users"',
  ];
  if (current) lines.push(`//   (now: ${current}${b.config.security ? '' : '; file security off'})`);
  if (which.includes('create')) lines.push('//   create("any") lets visitors who are not signed in upload: use create("users")');
  if (configFile) {
    lines.push('', `// ${configFile} → buckets → "${b.id}"  (then: appwrite push buckets)`, '//   "fileSecurity": true,', '//   "$permissions": ["create(\\"users\\")"],');
  }
  lines.push(
    '',
    "import { ID, Permission, Role } from 'appwrite';",
    `await storage.createFile(${q(b.id)}, ID.unique(), file, [`,
    '  Permission.read(Role.user(user.$id)),',
    '  Permission.update(Role.user(user.$id)),',
    '  Permission.delete(Role.user(user.$id)),',
    ']);',
  );
  return lines.join('\n');
}
