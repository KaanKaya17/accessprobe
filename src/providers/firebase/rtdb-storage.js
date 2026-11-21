// Realtime Database + Cloud Storage live tests (same rules as probes.js:
// A proves its own write+read first; only explicit refusals count as PASS).

import { parseRules, ownerPathVar } from './rules.js';
import * as fix from './fixes.js';

const rand = () => Math.random().toString(36).slice(2, 8);
const ok = (r) => r && r.ok;
const deniedRtdb = (r) => r && r.status === 401 && /Permission denied/i.test(JSON.stringify(r.data ?? ''));
const deniedStorage = (r) => r && r.status === 403 && /No \w+ permission|Permission denied/i.test(JSON.stringify(r.data ?? ''));
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
      out.push({ path: path.join('/'), read, write, ownerVar });
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

  const targets = src.databaseRules ? rtdbTargets(src.databaseRules) : [];
  if (!src.databaseRules) skipped.push('Realtime Database: no database.rules.json found, only the root was tested');

  for (const t of targets) {
    log(`  rtdb ${t.path}`);
    const fill = (u) => t.path.replace(/\$\w+/g, (v) => (v === t.ownerVar ? u.id : `rlsprobe_${v.slice(1)}`));
    const key = `rlsprobe_${rand()}`;
    const marker = `rlsprobe-${rand()}`;
    const aPath = `${fill(A)}/${key}`;
    const tf = (f) => findings.push({ resource: t.path, ...f });

    if (!t.ownerVar) {
      // a fixed node: can a stranger write here?
      const an = await client.rtdbPut(aPath, marker);
      if (ok(an)) {
        const back = await client.rtdbDelete(aPath);
        if (!ok(back)) left.push(aPath);
        tf({
          id: 'rtdb-anon-write',
          severity: 'critical',
          title: `Anyone (not logged in) can write to "/${t.path}" in the Realtime Database`,
          detail: 'Proven: an unauthenticated PUT succeeded.',
          evidence: `anonymous: ${an.evidence}`,
          fix: { code: fix.rtdbLockNode(t.path) },
        });
      } else if (deniedRtdb(an)) passed.push(`Realtime Database /${t.path}: anonymous visitors cannot write`);
      continue;
    }

    const aw = await client.rtdbPut(aPath, marker, { token: A.token });
    const ar = ok(aw) ? await client.rtdbGet(aPath, { token: A.token }) : null;
    if (!ok(aw) || !ok(ar) || ar.data !== marker) {
      skipped.push(`Realtime Database /${t.path}: user A could not write and read back its own node (${aw.status} ${short(aw.data)})`);
      continue;
    }
    fullyTested++;

    const br = await client.rtdbGet(aPath, { token: B.token });
    if (ok(br) && br.data === marker) {
      tf({
        id: 'rtdb-cross-user-read',
        severity: 'critical',
        title: `User B can read user A's data at "/${t.path}" in the Realtime Database`,
        detail: `Proven: A wrote under its own ${t.ownerVar}, B read it back. Typical cause: ".read": "auth != null".`,
        evidence: `as user B: ${br.evidence}`,
        fix: { code: fix.rtdbOwnerRules(t.path.split('/$')[0]) },
      });
    } else if (deniedRtdb(br)) passed.push(`Realtime Database /${t.path}: B cannot read A's data`);
    else skipped.push(`Realtime Database /${t.path}: read test inconclusive (${br.status})`);

    const bw = await client.rtdbPut(aPath, `${marker}-x`, { token: B.token });
    if (ok(bw)) {
      tf({
        id: 'rtdb-cross-user-write',
        severity: 'critical',
        title: `User B can overwrite user A's data at "/${t.path}" in the Realtime Database`,
        detail: 'Proven: B overwrote a value A wrote.',
        evidence: `as user B: ${bw.evidence}`,
        fix: { code: fix.rtdbOwnerRules(t.path.split('/$')[0]) },
      });
    } else if (deniedRtdb(bw)) passed.push(`Realtime Database /${t.path}: B cannot write to A's data`);

    const an = await client.rtdbGet(aPath);
    if (ok(an) && an.data !== null) {
      tf({
        id: 'rtdb-anon-read',
        severity: 'critical',
        title: `Anyone (not logged in) can read user data at "/${t.path}"`,
        detail: 'Proven: an unauthenticated request read A\'s value.',
        evidence: `anonymous: ${an.evidence}`,
        fix: { code: fix.rtdbOwnerRules(t.path.split('/$')[0]) },
      });
    } else if (deniedRtdb(an)) passed.push(`Realtime Database /${t.path}: anonymous visitors cannot read`);

    if (!ok(await client.rtdbDelete(aPath, { token: A.token }))) left.push(aPath);
  }
  return { findings, passed, skipped, left, fullyTested, count: targets.length };
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
