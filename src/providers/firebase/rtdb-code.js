// Realtime Database paths from app code, for projects without database.rules.json.
//   db.getReference("rooms").child(roomCode)            -> rooms/$roomCode
//   ref = getReference(DUEL_INVITES_REF); ref.child(targetUserId).child(inviteId)
//                                                       -> duel_invites/$targetUserId
// Only chains that start from a database reference are used (DataSnapshot.child() is
// ignored). Templates stop right after the first variable segment: that is the node
// a record is keyed by, which is what access rules usually protect.

const CONST_RE = /(?:static\s+final\s+String|const\s+val|private\s+val|val|const|final\s+String|String)\s+([A-Z_a-z]\w*)\s*(?::\s*String)?\s*=\s*"([^"\n]{1,80})"/g;
const REF_ASSIGN_RE = /\b(\w+)\s*(?::\s*DatabaseReference\s*)?=\s*[\w.()]*?getReference\(\s*([^()]*?)\s*\)\s*((?:\.child\([^()]*(?:\([^()]*\))?[^()]*\))*)\s*;?/g;
const CHAIN_RE = /\b(\w+)((?:\s*\.child\([^()]*(?:\([^()]*\))?[^()]*\))+)/g;
const DIRECT_RE = /getReference\(\s*([^()]*?)\s*\)((?:\s*\.child\([^()]*(?:\([^()]*\))?[^()]*\))+)/g;
const CHILD_ARG_RE = /\.child\(\s*([^()]*(?:\([^()]*\))?[^()]*?)\s*\)/g;

export const OWNER_VAR = /uid|user_?id|userid|owner|account_?id/i;

export function rtdbPathsFromCode(texts) {
  const consts = {};
  for (const t of texts) for (const m of t.matchAll(CONST_RE)) consts[m[1]] ??= m[2];

  const resolve = (arg) => {
    const a = arg.trim();
    if (!a) return '';
    const lit = a.match(/^["'`]([^"'`]+)["'`]$/);
    if (lit) return lit[1];
    if (consts[a] !== undefined) return consts[a];
    const id = a.match(/(\w+)\s*(?:\(\s*\))?$/); // userId, user.getUid(), auth.uid
    return `$${id ? id[1].replace(/^get/, '').replace(/^./, (c) => c.toLowerCase()) : 'id'}`;
  };
  const argsOf = (chain) => [...chain.matchAll(CHILD_ARG_RE)].map((m) => resolve(m[1]));
  // what follows a chain: .setValue(/.push(/.updateChildren(/.removeValue( means the app WRITES there
  const writesAfter = (t, end) => /^\s*(?:\.child\([^()]*\))*\s*\.(?:setValue|push|updateChildren|removeValue|runTransaction)\(/.test(t.slice(end, end + 160));

  const refs = {}; // variable -> base segments
  const templates = new Set();
  const written = new Set(); // templates the app writes through
  const add = (segs, isWrite = false) => {
    const clean = segs.flatMap((s) => s.split('/')).filter(Boolean);
    if (!clean.length || clean[0].startsWith('.') || clean[0].startsWith('$')) return;
    const i = clean.findIndex((s) => s.startsWith('$'));
    const tpl = (i === -1 ? clean : clean.slice(0, i + 1)).join('/');
    templates.add(tpl);
    if (isWrite) written.add(tpl);
  };

  for (const t of texts) {
    for (const m of t.matchAll(REF_ASSIGN_RE)) {
      const base = [resolve(m[2]), ...argsOf(m[3] || '')].filter((x) => x !== '');
      refs[m[1]] = base;
      if (base.length) add(base, writesAfter(t, m.index + m[0].length));
    }
  }
  for (const t of texts) {
    for (const m of t.matchAll(DIRECT_RE)) add([resolve(m[1]), ...argsOf(m[2])], writesAfter(t, m.index + m[0].length));
    for (const m of t.matchAll(CHAIN_RE)) {
      if (!(m[1] in refs)) continue; // snapshot.child(...) etc.
      add([...refs[m[1]], ...argsOf(m[2])], writesAfter(t, m.index + m[0].length));
    }
  }
  // One template per node: "backups/$code" and "backups/$upperCode" are the same node.
  // Ranking: a recipient-style variable the app WRITES through (an inbox: others write
  // into your node) > a user-id variable that is written > any user-id variable > anything.
  const rank = (x) => {
    const recipient = RECIPIENT_VAR.test(x);
    if (recipient && written.has(x)) return 3;
    if (ownerVarOf(x) && !recipient && written.has(x)) return 2;
    if (ownerVarOf(x)) return 1;
    return 0;
  };
  const byParent = new Map();
  for (const p of templates) {
    const parent = p.includes('$') ? p.slice(0, p.lastIndexOf('/$')) : p;
    const prev = byParent.get(parent);
    if (!prev || rank(p) > rank(prev)) byParent.set(parent, p);
  }
  const all = [...byParent.values()];
  const paths = all.filter((p) => !all.some((q) => q !== p && q.startsWith(`${p}/`) && !p.includes('$'))).sort();
  // inboxes: nodes keyed by the recipient that other users write into
  paths.inboxes = paths.filter((p) => rank(p) === 3);
  return paths;
}

// $targetUserId, $toUid, $recipientId … : someone ELSE's id
export const RECIPIENT_VAR = /\$(target|to[A-Z_]|recipient|receiver|invitee)/;

export function ownerVarOf(template) {
  const v = template.split('/').find((s) => s.startsWith('$'));
  return v && OWNER_VAR.test(v) ? v : null;
}
