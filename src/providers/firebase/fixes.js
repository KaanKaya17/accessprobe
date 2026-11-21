// Security Rules snippets for findings, plus how reports/prompts present them.

export const fixStyle = {
  lang: 'js',
  codeLabel: 'Fix (Security Rules — firebase deploy --only firestore:rules,storage,database)',
  fixWhere: 'Please fix this in Firebase Security Rules, not in the app code.',
  codeIntro: 'Apply these rules (adjust names if needed) and deploy them:',
  dont: 'Do not use "if true" or "if request.auth != null" alone for user data. Afterwards show me the complete rules file so I can review it.',
  secretMove: 'Move every call that needs this secret into a Cloud Function.',
};

// matchPath like "/orders/{id}" or "/users/{uid}/private/{doc}"
export function ownerOnlyRules(matchPath, field, pathVar) {
  const p = matchPath && !matchPath.includes('=**') ? matchPath : '/<collection>/{docId}';
  if (pathVar) {
    return [
      `// ${p}: only the user whose uid is in the path`,
      `match ${p} {`,
      `  allow read, write: if request.auth != null && request.auth.uid == ${pathVar};`,
      `}`,
    ].join('\n');
  }
  const f = field || 'ownerId';
  return [
    `// ${p}: only the owner (${f} == request.auth.uid)`,
    `match ${p} {`,
    `  allow get, update, delete: if request.auth != null && resource.data.${f} == request.auth.uid;`,
    `  // list: queries must filter on ${f}, e.g. where("${f}", "==", currentUser.uid)`,
    `  allow list: if request.auth != null && resource.data.${f} == request.auth.uid;`,
    `  allow create: if request.auth != null && request.resource.data.${f} == request.auth.uid;`,
    `  // on update, also stop the owner field from being changed:`,
    `  // && request.resource.data.${f} == resource.data.${f}`,
    `}`,
    ...(field ? [] : ['// rlsprobe could not find the owner field name; replace ownerId with yours']),
  ].join('\n');
}

export function storageOwnerRules(matchPath, pathVar) {
  const v = pathVar || 'uid';
  const p = pathVar ? matchPath : '/<folder>/{uid}/{fileName}';
  return [
    `// storage.rules — each user only touches files under its own folder`,
    `match ${p} {`,
    `  allow read, write: if request.auth != null && request.auth.uid == ${v};`,
    `}`,
  ].join('\n');
}

export function rtdbOwnerRules(base) {
  const b = base || 'users';
  return JSON.stringify({ rules: { '.read': false, '.write': false, [b]: { $uid: { '.read': 'auth != null && auth.uid === $uid', '.write': 'auth != null && auth.uid === $uid' } } } }, null, 2);
}

export function rtdbLockNode(path) {
  return `// database.rules.json — "/${path}" should not be writable by everyone:\n"${path.split('/').pop()}": { ".read": "auth != null", ".write": false }`;
}
