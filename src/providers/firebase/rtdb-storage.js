// Realtime Database + Cloud Storage live tests (same rules as probes.js:
// A proves its own write+read first; only explicit refusals count as PASS).

import { parseRules, ownerPathVar } from './rules.js';
import { ownerVarOf } from './rtdb-code.js';
import * as fix from './fixes.js';

const rand = () => Math.random().toString(36).slice(2, 8);
const ok = (r) => r && r.ok;
const deniedRtdb = (r) => r && r.status === 401 && /Permission denied/i.test(JSON.stringify(r.data ?? ''));
const deniedStorage = (r) => r && r.status === 403 && /No \w+ permission|Permission denied/i.test(JSON.stringify(r.data ?? ''));
// node names that usually hold intentionally shared data
const PUBLIC_HINT = /leaderboard|ranking|scores?|highscores?|public|presence|online|status|lobby/i;
// record keys that act like passwords when the key itself is the secret
const SECRET_KEY = /code|token|secret|pin|backup|invite|key/i;
const STRONG_SECRET = /backup|secret|token|\bpin|password|recovery/i;
const short = (d) => (typeof d === 'string' ? d : JSON.stringify(d ?? '')).trim().slice(0, 120);

// ---------------------------------------------------------------- RTDB

// database.rules.json -> [{ path: "users/$uid", read, write, ownerVar }]
export function rtdbTargets(text) {
  let rules;
  try {
    rules = JSON.parse(text.replace(/\/\/[^\n]*/g, '')).rules;
  } catch {
    return [];
  }
  const out = [];
  const walk = (node, path) => {
    if (!node || typeof node !== 'object') return;
    const read = node['.read'];
    const write = node['.write'];
    if ((read !== undefined || write !== undefined) && path.length) {
      const vars = path.filter((p) => p.startsWith('$'));
      const conds = `${read ?? ''} ${write ?? ''}`;
      const ownerVar = vars.find((v) => new RegExp(`auth\\.uid\\s*===?\\s*\\${v}\\b|\\${v}\\s*===?\\s*auth\\.uid`).test(conds)) || null;
      out.push({ path: path.join('/'), read, write, ownerVar, validate: node['.validate'] || null });
    }
    for (const [k, v] of Object.entries(node)) if (!k.startsWith('.')) walk(v, [...path, k]);
  };
  walk(rules, []);
  return out;
}

export async function probeRtdb(client, src, [A, B], { log }) {
  const findings = [];
  const passed = [];
  const skipped = [];
  const left = [];
  let fullyTested = 0;
  if (!client.ep.database) return { findings, passed, skipped, left, fullyTested, count: 0 };

  // the whole database, anonymously (shallow: keys only, never values)
  const root = await client.rtdbGet('', { shallow: true });
  if (ok(root) && root.data && typeof root.data === 'object') {
    findings.push({
      id: 'rtdb-anon-root',
      resource: '/',
      severity: 'critical',
      title: `Anyone (not logged in) can read the ENTIRE Realtime Database (${Object.keys(root.data).length} top-level keys)`,
      detail: 'The root rule allows ".read" for everyone.',
      evidence: `anonymous: ${root.evidence}`,
      fix: { code: fix.rtdbOwnerRules('users') },
    });
  } else if (deniedRtdb(root)) passed.push('Realtime Database: anonymous visitors cannot read the root');

  const targets = mergeTargets(src.databaseRules ? rtdbTargets(src.databaseRules) : [], src.rtdbCodePaths || []);
  const fromCode = targets.filter((t) => t.fromCode).length;
  if (!src.databaseRules) {
    if (targets.length) skipped.push(`Realtime Database: no database.rules.json, so ${targets.length} path(s) were taken from the app code`);
    else skipped.push('Realtime Database: no database.rules.json and no paths found in code — only the root was tested');
  } else if (fromCode) skipped.push(`Realtime Database: ${fromCode} path(s) from the app code were added to the ones in database.rules.json`);

  for (const t of targets) {
    log(`  rtdb ${t.path}`);
    const publicHint = PUBLIC_HINT.test(t.path.split('/')[0]);
    const fill = (u) => t.path.replace(/\$\w+/g, (v) => (v === t.ownerVar ? u.id : `rlsprobe_${v.slice(1)}`));
    const key = `rlsprobe_${rand()}`;
    const marker = `rlsprobe-${rand()}`;
    // ".validate": "newData.hasChildren([...])" on the user's node → write a record of that shape
    // at the node itself; otherwise a plain value under a fresh child key
    const shape = t.ownerVar ? shapeFromValidate(t.validate, marker) : null;
    const aPath = shape ? fill(A) : `${fill(A)}/${key}`;
    const value = shape ? shape.value : marker;
    // RTDB returns object keys sorted, so compare canonically, not by insertion order
    const same = (v) => canonical(v) === canonical(value);
    const tf = (f) => findings.push({ resource: t.path, ...f });
    const ownerRules = () => fix.rtdbOwnerRules(t.path.split('/$')[0]);

    // 1) A writes its own entry and reads it back — nothing B does counts without this.
    //    Only under A's own key: in shared nodes (rooms/$roomCode) rules are often
    //    create-only, so a test entry there could not be removed again.
    const aw = t.ownerVar ? await client.rtdbPut(aPath, value, { token: A.token }) : null;
    const ar = ok(aw) ? await client.rtdbGet(aPath, { token: A.token }) : null;
    const aOk = ok(aw) && ok(ar) && same(ar.data);
    if (aOk) fullyTested++;

    // 2) can someone enumerate every record under this node? (keys only, never values)
    if (t.path.includes('/$')) {
      const parent = t.path.slice(0, t.path.indexOf('/$'));
      const keyVar = t.path.split('/').find((s) => s.startsWith('$'));
      // listing user-keyed nodes or nodes keyed by a secret (backup code, token, pin) is critical
      const sensitive = Boolean(t.ownerVar) || STRONG_SECRET.test(`${parent} ${keyVar}`);
      for (const [who, token] of [
        ['anonymous', undefined],
        ['as user B', B.token],
      ]) {
        const r = await client.rtdbGet(parent, { token, shallow: true });
        if (ok(r) && r.data && typeof r.data === 'object' && Object.keys(r.data).length) {
          // don't count rlsprobe's own test entries as other people's data
          const n = Object.keys(r.data).filter((k) => k !== A.id && k !== B.id && !k.startsWith('rlsprobe')).length;
          const what = n ? `all ${n} entr${n === 1 ? 'y' : 'ies'}` : 'every entry (only the test entry exists yet)';
          findings.push({
            id: who === 'anonymous' ? 'rtdb-anon-list' : 'rtdb-list',
            resource: parent,
            severity: publicHint ? 'warning' : sensitive ? 'critical' : 'warning',
            title: `${who === 'anonymous' ? 'Anyone (not logged in)' : 'Any signed-in user'} can list ${what} under "/${parent}"`,
            detail: SECRET_KEY.test(keyVar)
              ? `Entries are keyed by ${keyVar} — if that is meant to be secret (a backup or invite code), listing the node hands out every code.`
              : t.ownerVar
                ? "Entries are keyed by user id: listing reveals every user's id."
                : publicHint
                  ? 'Looks like public data (leaderboard / presence). Fine if intended.'
                  : 'Anyone can enumerate every record here. Fine only if this data is meant to be public.',
            evidence: `${who}: ${r.evidence} → ${n} keys besides the test users`,
            fix: { code: ownerRules() },
          });
          break; // anonymous already implies signed-in
        } else if (deniedRtdb(r) && who === 'as user B') passed.push(`Realtime Database /${parent}: signed-in users cannot list all entries`);
        else if (!deniedRtdb(r) && who === 'as user B' && !aOk) skipped.push(`Realtime Database /${parent}: list test inconclusive (${r.status}, no test entry)`);
      }
    }

    // 3) shared / fixed nodes: can a stranger write here?
    if (!t.ownerVar) {
      const anPath = `${fill(A)}/${key}_anon`;
      const an = await client.rtdbPut(anPath, marker);
      if (ok(an)) {
        if (!ok(await client.rtdbDelete(anPath))) left.push(anPath);
        tf({
          id: 'rtdb-anon-write',
          severity: 'critical',
          title: `Anyone (not logged in) can write to "/${t.path}" in the Realtime Database`,
          detail: 'Proven: an unauthenticated PUT succeeded.',
          evidence: `anonymous: ${an.evidence}`,
          fix: { code: fix.rtdbLockNode(t.path) },
        });
      } else if (deniedRtdb(an)) passed.push(`Realtime Database /${t.path}: anonymous visitors cannot write`);
    }

    // 4) user-keyed nodes: B and anonymous against A's entry
    if (t.ownerVar) {
      if (!aOk) {
        skipped.push(`Realtime Database /${t.path}: user A could not write and read back its own node (${aw.status} ${short(aw.data)})`);
        continue;
      }
      const br = await client.rtdbGet(aPath, { token: B.token });
      if (ok(br) && same(br.data)) {
        tf({
          id: 'rtdb-cross-user-read',
          severity: publicHint ? 'warning' : 'critical',
          title: `User B can read user A's data at "/${t.path}" in the Realtime Database`,
          detail: publicHint
            ? `Proven: B read an entry A wrote under its own ${t.ownerVar}. The node name suggests public data (leaderboard / presence) — fine if intended.`
            : `Proven: A wrote under its own ${t.ownerVar}, B read it back. Typical cause: ".read": "auth != null".`,
          evidence: `as user B: ${br.evidence}`,
          fix: { code: ownerRules() },
        });
      } else if (deniedRtdb(br)) passed.push(`Realtime Database /${t.path}: B cannot read A's data`);
      else skipped.push(`Realtime Database /${t.path}: read test inconclusive (${br.status})`);

      // an inbox keyed by the RECIPIENT that the app's code writes into (duel_invites/$targetUserId):
      // other users are meant to write here. Public-looking names (presence, leaderboard) only
      // soften READ findings — someone else overwriting your presence or score is still critical.
      const inbox = Boolean(t.inbox);
      // same shape as A's accepted record, one string changed: only the access rule can refuse it
      const bw = await client.rtdbPut(aPath, shape ? shape.tampered : `${marker}-x`, { token: B.token });
      if (ok(bw)) {
        tf({
          id: 'rtdb-cross-user-write',
          severity: inbox ? 'warning' : 'critical',
          title: `User B can overwrite user A's data at "/${t.path}" in the Realtime Database`,
          detail: inbox
            ? `Proven: B overwrote an entry in A's node. Other users are expected to write here (it is keyed by the recipient), but they should only be able to CREATE new entries — not overwrite or delete existing ones (".write": "!data.exists()").`
            : 'Proven: B overwrote a value A wrote.',
          evidence: `as user B: ${bw.evidence}`,
          fix: { code: ownerRules() },
        });
      } else if (deniedRtdb(bw)) passed.push(`Realtime Database /${t.path}: B cannot write to A's data`);

      const an = await client.rtdbGet(aPath);
      if (ok(an) && an.data !== null) {
        tf({
          id: 'rtdb-anon-read',
          severity: publicHint ? 'warning' : 'critical',
          title: `Anyone (not logged in) can read user data at "/${t.path}"`,
          detail: "Proven: an unauthenticated request read A's value.",
          evidence: `anonymous: ${an.evidence}`,
          fix: { code: ownerRules() },
        });
      } else if (deniedRtdb(an)) passed.push(`Realtime Database /${t.path}: anonymous visitors cannot read`);
    }

    if (ok(aw) && !ok(await client.rtdbDelete(aPath, { token: A.token }))) left.push(aPath);
  }
  return { findings, passed, skipped, left, fullyTested, count: targets.length };
}

export function canonical(v) {
  if (Array.isArray(v)) return `[${v.map(canonical).join(',')}]`;
  if (v && typeof v === 'object') return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canonical(v[k])}`).join(',')}}`;
  return JSON.stringify(v);
}

// Rules paths win (they carry ownership and .validate); code paths add the keyed
// structure rules often omit, e.g. rules say "duel_invites": {".write": "auth != null"}
// while the code writes duel_invites/$targetUserId.
export function mergeTargets(ruleTargets, codePaths) {
  const norm = (p) => p.replace(/\$\w+/g, '$');
  const out = [...ruleTargets];
  const inboxes = codePaths.inboxes || [];
  for (const path of codePaths) {
    const inbox = inboxes.includes(path);
    const same = out.find((r) => norm(r.path) === norm(path));
    if (same) {
      same.ownerVar ||= ownerVarOf(same.path);
      same.inbox ||= inbox;
      continue;
    }
    out.push({ path, ownerVar: ownerVarOf(path), fromCode: true, validate: null, inbox });
  }
  return out;
}

// "newData.hasChildren(['score','level','nickname']) && newData.child('score').isNumber()"
//   -> { value: { score: 1, level: 1, nickname: marker }, tampered: {..., nickname: marker-x} }
export function shapeFromValidate(validate, marker) {
  if (!validate) return null;
  const kids = validate.match(/newData\.hasChildren\(\s*\[([^\]]*)\]\s*\)/);
  if (!kids) return null;
  const names = kids[1].split(',').map((k) => k.trim().replace(/^['"]|['"]$/g, '')).filter(Boolean);
  const typeOf = (k) => {
    const m = validate.match(new RegExp(`newData\\.child\\(\\s*['"]${k}['"]\\s*\\)\\.is(Number|String|Boolean)\\(\\)`));
    return m ? m[1] : null;
  };
  const value = {};
  let markerKey = null;
  for (const k of names) {
    const t = typeOf(k);
    if (t === 'Number') value[k] = 1;
    else if (t === 'Boolean') value[k] = false;
    else if (t === 'String' || /name|title|text|nick/i.test(k)) {
      value[k] = marker;
      markerKey ??= k;
    } else value[k] = /time|date|at$/i.test(k) ? Date.now() : { rlsprobe: marker };
  }
  if (!markerKey) {
    value.rlsprobe = marker; // extra child: only safe if the rule does not forbid unknown keys
    markerKey = 'rlsprobe';
  }
  return { value, tampered: { ...value, [markerKey]: `${marker}-x` } };
}

// ---------------------------------------------------------------- Storage

// storage.rules -> [{ dir: "avatars/{uid}", ownerVar, match }]
export function storageTargets(text) {
  const out = [];
  for (const m of parseRules(text)) {
    const parts = m.path.split('/').filter(Boolean);
    const last = parts[parts.length - 1] || '';
    if (!/^\{\w+(=\*\*)?\}$/.test(last) || parts.length < 2) continue;
    out.push({ dir: parts.slice(0, -1).join('/'), ownerVar: ownerPathVar(m), match: m });
  }
  return out;
}

export async function probeStorage(client, src, [A, B], { log }) {
  const findings = [];
  const passed = [];
  const skipped = [];
  const left = [];
  let fullyTested = 0;
  if (!src.storageRules) {
    if (client.cfg.storageBucket) skipped.push('Storage: no storage.rules found in --source, so no paths could be tested');
    return { findings, passed, skipped, left, fullyTested, count: 0 };
  }
  const targets = storageTargets(src.storageRules);

  for (const t of targets) {
    log(`  storage ${t.dir}`);
    const tf = (f) => findings.push({ resource: t.dir, ...f });
    const dirFor = (u) => t.dir.replace(/\{(\w+)\}/g, (_, v) => (v === t.ownerVar ? u.id : `rlsprobe-${v}`));
    const aDir = dirFor(A);
    const path = `${aDir}/rlsprobe-${rand()}.txt`;
    const shown = path.replace(A.id, '<user A id>');
    const rules = () => fix.storageOwnerRules(t.match.path, t.ownerVar);

    const up = await client.upload(path, 'rlsprobe test file — safe to delete', { token: A.token });
    const aGet = ok(up) ? await client.download(path, { token: A.token }) : null;
    if (!ok(up) || !ok(aGet)) {
      skipped.push(`Storage ${t.dir}: user A could not upload and read back a test file (${up.status} ${short(up.data)})`);
      continue;
    }
    fullyTested++;

    const bGet = await client.download(path, { token: B.token });
    if (ok(bGet) && t.ownerVar) {
      tf({
        id: 'storage-cross-user-read',
        severity: 'critical',
        title: `User B can download user A's files in "${t.dir}"`,
        detail: `Proven: A uploaded into its own folder, B downloaded the file. Typical cause: "allow read: if request.auth != null".`,
        evidence: `as user B: GET …/o/${shown}?alt=media → ${bGet.status}`,
        fix: { code: rules() },
      });
    } else if (ok(bGet)) {
      tf({
        id: 'storage-shared',
        severity: 'warning',
        title: `Files in "${t.dir}" are readable by every signed-in user`,
        detail: 'No per-user folder in this path — fine only for shared content.',
        evidence: `as user B: GET …/o/${shown}?alt=media → ${bGet.status}`,
        fix: { code: rules() },
      });
    } else if (deniedStorage(bGet)) passed.push(`Storage ${t.dir}: B cannot download A's files`);

    // list exactly like the SDK's listAll() does (delimiter=/), see API-NOTES trap 6
    const bList = await client.listFiles(`${aDir}/`, { token: B.token });
    if (ok(bList) && (bList.data?.items || []).length && t.ownerVar) {
      tf({
        id: 'storage-cross-user-list',
        severity: 'warning',
        title: `User B can list user A's files in "${t.dir}"`,
        detail: 'File names alone often leak private information (document titles, dates, IDs).',
        evidence: `as user B: GET …/o?prefix=${shown.replace(/[^/]+$/, '')}&delimiter=/ → ${bList.status}`,
        fix: { code: rules() },
      });
    } else if (deniedStorage(bList)) passed.push(`Storage ${t.dir}: B cannot list A's files`);

    const anGet = await client.download(path);
    if (ok(anGet)) {
      tf({
        id: 'storage-anon-read',
        severity: t.ownerVar ? 'critical' : 'warning',
        title: `Anyone (not logged in) can download files in "${t.dir}"`,
        detail: 'Proven: an unauthenticated request downloaded A\'s file.',
        evidence: `anonymous: GET …/o/${shown}?alt=media → ${anGet.status}`,
        fix: { code: rules() },
      });
    } else if (deniedStorage(anGet)) passed.push(`Storage ${t.dir}: anonymous visitors cannot download`);

    const bDel = await client.removeFile(path, { token: B.token });
    if (ok(bDel)) {
      tf({
        id: 'storage-cross-user-delete',
        severity: 'critical',
        title: `User B can delete user A's files in "${t.dir}"`,
        detail: 'Proven: B deleted a file A uploaded.',
        evidence: `as user B: DELETE …/o/${shown} → ${bDel.status}`,
        fix: { code: rules() },
      });
    } else {
      if (deniedStorage(bDel)) passed.push(`Storage ${t.dir}: B cannot delete A's files`);
      if (!ok(await client.removeFile(path, { token: A.token }))) left.push(path);
    }
  }
  return { findings, passed, skipped, left, fullyTested, count: targets.length };
}
