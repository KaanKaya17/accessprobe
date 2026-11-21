// The actual tests. Every "critical" finding here is PROVEN with a real request
// against rows/files the test users created themselves — no pattern guessing.
// We never print other people's data: only counts and column names.

import { randomUUID } from 'node:crypto';
import { buildRow } from './schema.js';
import { ownerPolicies, enableRls, noOwnerColumn, storagePolicies } from './fixes.js';

const rand = () => Math.random().toString(36).slice(2, 8);

export async function setupUsers(client, { userA, userB, emailDomain = 'example.com', log }) {
  const run = rand();
  const specs = [
    { label: 'A', cred: userA, email: `rlsprobe-${run}-a@${emailDomain}` },
    { label: 'B', cred: userB, email: `rlsprobe-${run}-b@${emailDomain}` },
  ];
  const users = [];
  const madeSoFar = [];
  const fail = (m) => {
    const left = madeSoFar.length
      ? `\n  Test users already created (delete them in Dashboard → Authentication → Users): ${madeSoFar.join(', ')}`
      : '';
    return new Error(m + left);
  };
  for (const s of specs) {
    let email;
    let password;
    let created = false;
    if (s.cred) {
      const i = s.cred.indexOf(':');
      if (i < 1) throw new Error(`--user-${s.label.toLowerCase()} must look like email:password`);
      email = s.cred.slice(0, i);
      password = s.cred.slice(i + 1);
    } else {
      email = s.email;
      password = `Rp-${randomUUID()}`;
      const r = await client.signUp(email, password);
      if (!r.ok) throw fail(`Sign-up of test user ${s.label} failed (${r.status}): ${msg(r.data)}`);
      created = true;
      madeSoFar.push(email);
      log(`  created test user ${s.label}: ${email}`);
    }
    const r = await client.signIn(email, password);
    if (!r.ok || !r.data?.access_token) {
      if (created)
        throw fail(
          'Sign-up worked but sign-in did not — "Confirm email" is probably enabled.\n' +
            '  Create two test users yourself (Dashboard → Authentication → Add user, auto-confirm)\n' +
            '  and pass them with --user-a email:password --user-b email:password',
        );
      throw fail(`Sign-in of user ${s.label} failed (${r.status}): ${msg(r.data)}`);
    }
    users.push({ label: s.label, email, id: r.data.user.id, token: r.data.access_token, created, ids: {} });
  }
  return users;
}

// Many apps keep their own users/profiles table and point user_id at ITS id
// (e.g. bigint users.user_id) instead of auth.uid(). Find each test user's row there.
export async function resolveIdentities(client, schema, users) {
  const targets = new Map(); // table -> column other tables point at
  for (const t of schema.tables) {
    if (t.owner?.fk) targets.set(t.owner.fk.table, t.owner.fk.column);
  }
  for (const t of schema.tables) {
    if (/^(users?|profiles?|accounts?|members?)$/i.test(t.name) && !targets.has(t.name) && t.pk) targets.set(t.name, t.pk.name);
  }
  for (const [tname, col] of targets) {
    const table = schema.tables.find((t) => t.name === tname);
    if (!table) continue;
    const uuidCols = table.columns.filter((c) => /uuid/.test(c.format));
    for (const u of users) {
      for (const c of uuidCols) {
        const r = await client.select(tname, { token: u.token, filter: `${c.name}=eq.${u.id}`, limit: 1 });
        if (r.ok && Array.isArray(r.data) && r.data[0] && r.data[0][col] !== undefined) {
          u.ids[tname] = r.data[0][col];
          table.identity = { authCol: c.name, keyCol: col };
          break;
        }
      }
    }
  }
}

// value that marks a row as "owned by u" in table t
export function ownerValue(t, u) {
  const o = t.owner;
  if (!o) return null;
  if (o.fk && u.ids[o.fk.table] !== undefined) return u.ids[o.fk.table];
  if (u.ids[t.name] !== undefined && o.pk) return u.ids[t.name];
  if (/uuid/.test(o.format)) return u.id;
  const found = Object.values(u.ids);
  return found.length === 1 ? found[0] : null;
}

// how a fix policy should spell "me" for this table's owner column
function meExpr(t, schema) {
  const fk = t.owner?.fk;
  const target = fk && schema.tables.find((x) => x.name === fk.table);
  if (target?.identity) {
    const { authCol, keyCol } = target.identity;
    return `(select "${keyCol}" from public."${target.name}" where "${authCol}" = (select auth.uid()))`;
  }
  if (t.identity && t.owner?.pk) return null; // the identity table itself: policy goes on authCol
  return '(select auth.uid())';
}

export async function probeTables(client, schema, [A, B], { log, created = [] }) {
  const findings = [];
  const passed = [];
  const skipped = [];
  // rows to clean up — owned by the caller, so cleanup still runs if a probe throws
  let fullyTested = 0; // tables where A created a row and B attacked it
  let readOnly = 0; // tables users can't write to at all (no INSERT grant)

  for (const t of schema.tables) {
    log(`  table ${t.name}`);
    const tf = (f) => findings.push({ table: t.name, ...f });
    const me = meExpr(t, schema);
    const pol = (ops) =>
      me === null ? ownerPolicies(t.name, t.identity.authCol, ops) : ownerPolicies(t.name, t.owner.name, ops, me);
    const aVal = ownerValue(t, A);
    const bVal = ownerValue(t, B);
    const hide = (evidence) =>
      t.owner && aVal !== null
        ? evidence.split(`"${t.owner.name}":${JSON.stringify(aVal)}`).join(`"${t.owner.name}":"<user A id>"`)
        : evidence;

    // 1) anonymous read
    const anon = await client.select(t.name);
    const anonCount = anon.ok ? (anon.total ?? (Array.isArray(anon.data) ? anon.data.length : 0)) : 0;

    // 2) anonymous write. Insert alone can be intended (guestbook, waitlist);
    //    insert + delete by a stranger means RLS is effectively off.
    let anonWrite = false; // RLS effectively off -> skip the user tests
    let anonTried = false;
    let anonBlocked = false;
    if (!t.isView && !t.nameOnly) {
      const built = buildRow(t, { ownerId: aVal, marker: `rlsprobe-anon-${rand()}` });
      if (built && (built.markerCol || (t.pkCols || []).length)) {
        anonTried = true;
        const r = await insertWithRetry(client, t, built.row, undefined);
        if (inserted(r)) {
          const row = { table: t, row: r.data[0], markerCol: built.markerCol, marker: built.row[built.markerCol] };
          const del = await client.remove(t.name, filterFor(row));
          if (inserted(del)) {
            anonWrite = true;
            tf({
              id: 'anon-write',
              severity: 'critical',
              title: `Anyone (not logged in) can create AND delete rows in "${t.name}"`,
              detail: "The public anon key — visible in your app's code — has full write access to this table. RLS is most likely disabled.",
              evidence: `${hide(r.evidence)}, then ${del.evidence}`,
              fix: { sql: enableRls(t.name) },
            });
          } else {
            created.push(row);
            tf({
              id: 'anon-insert',
              severity: t.owner ? 'critical' : 'warning',
              title: `Anyone (not logged in) can create rows in "${t.name}"`,
              detail: t.owner
                ? `Rows carry an owner (${t.owner.name}), yet a stranger could create one in user A's name.`
                : 'Fine for a guestbook, contact form or waitlist. Not fine for anything else: require sign-in or add rate limits.',
              evidence: hide(r.evidence),
              fix: { sql: t.owner ? pol(['insert']) : enableRls(t.name) },
            });
          }
        } else anonBlocked = policyDenied(r);
      }
    }

    if (anonCount > 0 && !anonWrite) {
      if (t.owner) {
        tf({
          id: 'anon-read-owned',
          severity: 'critical',
          title: `Anyone (not logged in) can read "${t.name}" — ${anonCount} row(s)`,
          detail: `Rows have an owner column (${t.owner.name}) so they look like private user data, but the anon key can read them.`,
          evidence: `${anon.evidence} — ${anonCount} rows, columns: ${t.columns.map((c) => c.name).join(', ')}`,
          fix: { sql: pol() },
        });
      } else {
        tf({
          id: 'anon-read-public',
          severity: 'warning',
          title: `"${t.name}" is publicly readable (${anonCount} row(s))`,
          detail: 'Fine for a public catalog (products, blog posts). Not fine if it holds anything personal.',
          evidence: `${anon.evidence} — columns: ${t.columns.map((c) => c.name).join(', ')}`,
          fix: { sql: enableRls(t.name) },
        });
      }
    } else if (anonCount > 0 && anonWrite) {
      findings[findings.length - 1].detail += ` It is also readable: ${anonCount} row(s) visible to anyone.`;
    }
    // "0 rows" and "blocked by RLS" look identical, so anon reads are only claimed safe
    // when proven: privilege error here, or A's own row invisible to anon (step 4b).
    const anonNoAccess = privilegeDenied(anon);
    const anonCanInsert = findings.some((f) => f.table === t.name && f.id === 'anon-insert');
    if (!anonWrite) {
      if (anonNoAccess && anonCanInsert) passed.push(`${t.name}: anonymous visitors can't read`);
      else if (anonNoAccess) passed.push(`${t.name}: anonymous visitors have no access (privileges revoked)`);
      else if (anonBlocked) passed.push(`${t.name}: anonymous visitors can't insert`);
      else if (!anonTried && !t.nameOnly && !t.isView) skipped.push(`${t.name}: anonymous insert not tested (required columns rlsprobe cannot fill)`);
    }

    // RLS is off: every user test would just repeat the same root cause
    if (anonWrite) continue;

    if (t.isView) {
      skipped.push(`${t.name}: view (read-only) — only the anonymous read check applies`);
      continue;
    }

    if (t.nameOnly) {
      await freshUserCheck(client, t, B, { tf, passed, skipped, anonCount });
      skipped.push(`${t.name}: write tests skipped — columns unknown (found in code or --table, not in migrations)`);
      continue;
    }

    if (t.owner && (aVal === null || bVal === null)) {
      skipped.push(
        `${t.name}: user tests skipped — could not work out which ${t.owner.name} belongs to the test users ` +
          '(no row for them in a users/profiles table?)',
      );
      continue;
    }

    // 3) user A creates a row of their own
    const marker = `rlsprobe-${rand()}`;
    const built = buildRow(t, { ownerId: aVal, marker });
    let mine = null;
    let insertErr = built ? null : 'required columns that rlsprobe cannot fill (foreign keys)';
    let denied = false;
    if (built && !built.markerCol && !(t.pkCols || []).length) {
      insertErr = 'no primary key and no text column, so a test row could not be targeted safely';
    } else if (built) {
      const r = await insertWithRetry(client, t, built.row, A.token);
      if (inserted(r)) {
        mine = { table: t, row: r.data[0], markerCol: built.markerCol, marker, sent: built.row };
        if (!filterFor(mine)) {
          // representation lacked the key columns: we could not target it again, so don't keep it
          skipped.push(`${t.name}: test row could not be targeted (no key values returned); tests skipped`);
          mine = null;
        } else created.push(mine);
      } else {
        insertErr = `${r.status} ${msg(r.data)}`;
        denied = privilegeDenied(r);
      }
    }

    if (!mine) {
      // fallback: can B see rows that belong to other users? (real rows → counts only, a warning)
      if (t.owner) {
        const r = await client.select(t.name, { token: B.token, filter: `${t.owner.name}=neq.${bVal}`, limit: 1 });
        if (privilegeDenied(r)) {
          passed.push(`${t.name}: signed-in users have no direct access at all (privileges revoked)`);
        } else if (!r.ok) {
          skipped.push(`${t.name}: read check failed (${r.status} ${msg(r.data)})`);
        } else {
          const n = r.total ?? (Array.isArray(r.data) ? r.data.length : 0);
          if (n > 0 && !(anonCount > 0)) {
            tf({
              id: 'cross-user-read-existing',
              severity: 'warning',
              title: `Logged-in user B can read ${n} row(s) of OTHER users in "${t.name}"`,
              detail: `B owns nothing here but sees rows where ${t.owner.name} ≠ B. Not proven with test data (rlsprobe could not create a test row), so check whether this table is meant to be shared. Typical cause: using (auth.role() = 'authenticated') or using (true).`,
              evidence: `as user B: ${r.evidence} — ${n} foreign rows visible`,
              fix: { sql: pol() },
            });
          } else if (n === 0) {
            skipped.push(`${t.name}: B sees no other users' rows — not proven (no test row; the table may simply be empty)`);
          }
        }
      }
      if (!t.owner) await freshUserCheck(client, t, B, { tf, passed, skipped, anonCount });
      if (!anonNoAccess && !(anonCount > 0)) skipped.push(`${t.name}: anonymous visitors see no rows — not proven (no test row)`);
      if (denied) {
        readOnly++;
        passed.push(`${t.name}: users cannot insert rows directly (no INSERT privilege)`);
      } else skipped.push(`${t.name}: write tests skipped — user A could not insert a test row (${insertErr})`);
      continue;
    }

    // control: A reads its own row back through the exact filter every attack uses.
    // Without this, an empty answer to B could mean "wrong filter" instead of "protected".
    const aRow = async () => {
      const r = await client.select(t.name, { token: A.token, filter: filterFor(mine) });
      return r.ok && Array.isArray(r.data) && r.data.length === 1 ? r.data[0] : null;
    };
    if (!(await aRow())) {
      skipped.push(`${t.name}: user A cannot read back its own test row, so B's results would prove nothing`);
      continue;
    }
    fullyTested++;
    // PostgREST hides rows instead of erroring: 200 [] (or an explicit 401/403/42501) is a refusal
    const refusedOrHidden = (r) => policyDenied(r) || (r.ok && Array.isArray(r.data) && r.data.length === 0);
    const unchanged = async () => {
      const row = await aRow();
      return Boolean(row) && (!mine.markerCol || row[mine.markerCol] === mine.marker) && (!t.owner || String(row[t.owner.name]) === String(aVal));
    };
    const publicHint = PUBLIC_TABLE.test(t.name);

    // 4) B reads A's row
    const bRead = await client.select(t.name, { token: B.token, filter: filterFor(mine) });
    const bSees = bRead.ok && Array.isArray(bRead.data) && bRead.data.length > 0;
    if (bSees && t.owner) {
      const total = await client.select(t.name, { token: B.token, filter: `${t.owner.name}=neq.${bVal}`, limit: 1 });
      const n = total.total ?? '?';
      tf({
        id: 'cross-user-read',
        severity: publicHint ? 'warning' : 'critical',
        title: `User B can read user A's rows in "${t.name}"`,
        detail: publicHint
          ? `Proven: A created a row, B fetched it (B can see ${n} row(s) of other users). The table name suggests content meant for everyone (posts, comments, products…) — fine if intended.`
          : `Proven: A created a row, B fetched it. In total B can see ${n} row(s) that belong to other users.`,
        evidence: `as user B: ${bRead.evidence} → returned A's row`,
        fix: { sql: pol() },
      });
    } else if (bSees && !t.owner) {
      tf({
        id: 'shared-no-owner',
        severity: 'warning',
        title: `Rows in "${t.name}" are shared between all users`,
        detail:
          'A row created by A is visible to B, and the table has no owner column — so per-user privacy is impossible. Fine only if this data is meant to be shared.',
        evidence: `as user B: ${bRead.evidence} → returned A's row`,
        fix: { sql: noOwnerColumn(t.name) },
      });
    } else if (refusedOrHidden(bRead)) passed.push(`${t.name}: B cannot read A's rows`);
    else skipped.push(`${t.name}: read test inconclusive (${bRead.status} ${msg(bRead.data)})`);

    // 4b) anonymous visitor reads A's row (proves what an empty anon SELECT could not)
    if (!anonNoAccess && !(anonCount > 0)) {
      const aRead = await client.select(t.name, { filter: filterFor(mine) });
      if (inserted(aRead)) {
        tf({
          id: t.owner ? 'anon-read-owned' : 'anon-read-public',
          severity: t.owner && !publicHint ? 'critical' : 'warning',
          title: t.owner ? `Anyone (not logged in) can read user rows in "${t.name}"` : `"${t.name}" is publicly readable`,
          detail: t.owner
            ? 'Proven: A created a row, an anonymous request fetched it.'
            : 'Fine for public content (catalog, guestbook, blog). Not fine if it holds anything personal.',
          evidence: `anonymous: ${aRead.evidence} → returned A's row`,
          fix: { sql: t.owner ? pol(['select']) : enableRls(t.name) },
        });
      } else if (refusedOrHidden(aRead)) passed.push(`${t.name}: anonymous visitors cannot read A's rows`);
      else skipped.push(`${t.name}: anonymous read test inconclusive (${aRead.status} ${msg(aRead.data)})`);
    }

    // 5) B updates A's row (marker column — same length, so length limits can't fake a PASS)
    const patch = updatePatch(t, mine);
    if (patch) {
      const bUpd = await client.update(t.name, filterFor(mine), patch, { token: B.token });
      if (inserted(bUpd)) {
        if (mine.markerCol && mine.markerCol in patch) mine.marker = patch[mine.markerCol];
        Object.assign(mine.row, bUpd.data[0]);
        tf({
          id: 'cross-user-update',
          severity: 'critical',
          title: `User B can MODIFY user A's rows in "${t.name}"`,
          detail: 'Proven: B changed a row that A created.',
          evidence: `as user B: ${bUpd.evidence}`,
          fix: { sql: t.owner ? pol(['update']) : noOwnerColumn(t.name) },
        });
      } else if (refusedOrHidden(bUpd) && (await unchanged())) passed.push(`${t.name}: B cannot modify A's rows`);
      else skipped.push(`${t.name}: modify test inconclusive (${bUpd.status} ${msg(bUpd.data)})`);
    }

    // 5b) B reassigns A's row to itself (USING lets it in, WITH CHECK only checks the NEW owner)
    let takenOver = false;
    if (t.owner && !t.owner.pk && bVal !== null) {
      const bTake = await client.update(t.name, filterFor(mine), { [t.owner.name]: bVal }, { token: B.token });
      if (inserted(bTake)) {
        takenOver = true;
        Object.assign(mine.row, bTake.data[0]);
        tf({
          id: 'cross-user-takeover',
          severity: 'critical',
          title: `User B can take over user A's rows in "${t.name}"`,
          detail: `Proven: B set ${t.owner.name} of A's row to itself. The UPDATE policy's USING clause lets B reach other users' rows; WITH CHECK only looks at the new value.`,
          evidence: `as user B: ${bTake.evidence.split(JSON.stringify(bVal)).join('"<user B id>"')}`,
          fix: { sql: pol(['update']) },
        });
      } else if (refusedOrHidden(bTake) && (await unchanged())) passed.push(`${t.name}: B cannot reassign A's rows to itself`);
      else skipped.push(`${t.name}: takeover test inconclusive (${bTake.status} ${msg(bTake.data)})`);
    }

    // 6) B inserts a row pretending to be A
    if (t.owner) {
      // same values A used successfully, so only a policy can make this fail
      const fakeMarker = `rlsprobe-${rand()}`;
      const row = { ...mine.sent };
      if (mine.markerCol) row[mine.markerCol] = fakeMarker;
      const r = await client.insert(t.name, row, { token: B.token });
      if (inserted(r)) {
        created.push({ table: t, row: r.data[0], markerCol: mine.markerCol, marker: fakeMarker });
        tf({
          id: 'impersonated-insert',
          severity: 'critical',
          title: `User B can create rows in "${t.name}" in user A's name`,
          detail: `The INSERT policy does not check ${t.owner.name} against the signed-in user, so anyone can forge data for another user (fake orders, messages, reviews…).`,
          evidence: `as user B: ${hide(r.evidence)}`,
          fix: { sql: pol(['insert']) },
        });
      } else if (policyDenied(r)) {
        passed.push(`${t.name}: B cannot insert rows as A`);
      } else {
        skipped.push(`${t.name}: forged-insert test inconclusive (${r.status} ${msg(r.data)})`);
      }
    }

    // 7) B deletes A's row (last, it destroys the test row)
    if (takenOver) {
      skipped.push(`${t.name}: delete test skipped — B already took the row over`);
    } else {
      const bDel = await client.remove(t.name, filterFor(mine), { token: B.token });
      if (inserted(bDel)) {
        mine.deleted = true;
        tf({
          id: 'cross-user-delete',
          severity: 'critical',
          title: `User B can DELETE user A's rows in "${t.name}"`,
          detail: 'Proven: B deleted a row that A created.',
          evidence: `as user B: ${bDel.evidence}`,
          fix: { sql: t.owner ? pol(['delete']) : noOwnerColumn(t.name) },
        });
      } else if (refusedOrHidden(bDel) && (await aRow())) passed.push(`${t.name}: B cannot delete A's rows`);
      else skipped.push(`${t.name}: delete test inconclusive (${bDel.status} ${msg(bDel.data)})`);
    }
  }

  return { findings, passed, skipped, created, fullyTested, readOnly };
}

export async function cleanupRows(client, created, users) {
  const left = [];
  for (const c of created) {
    if (c.deleted) continue;
    let gone = false;
    for (const token of [...users.map((u) => u.token), undefined]) {
      const r = await client.remove(c.table.name, filterFor(c), { token });
      if (r.ok && Array.isArray(r.data) && r.data.length) {
        gone = true;
        break;
      }
    }
    if (!gone) left.push(`${c.table.name} where ${filterFor(c)}`);
  }
  return left;
}

export async function probeStorage(client, [A, B], { extraBuckets = [], log }) {
  const findings = [];
  const passed = [];
  const skipped = [];
  const names = new Set(extraBuckets);
  const isPublic = new Set();
  for (const token of [undefined, A.token]) {
    const r = await client.listBuckets({ token });
    if (r.ok && Array.isArray(r.data))
      r.data.forEach((b) => {
        names.add(b.name || b.id);
        if (b.public) isPublic.add(b.name || b.id);
      });
  }

  for (const bucket of names) {
    log(`  bucket ${bucket}`);
    const bf = (f) => findings.push({ bucket, ...f });

    const anonList = await client.listObjects(bucket);
    if (anonList.ok && Array.isArray(anonList.data) && anonList.data.length) {
      bf({
        id: 'storage-anon-list',
        severity: 'warning',
        title: `Anyone can list files in bucket "${bucket}" (${anonList.data.length}+ entries)`,
        detail: 'Listing lets strangers enumerate every file name — and download them if the bucket is public.',
        evidence: anonList.evidence,
        fix: { sql: storagePolicies(bucket) },
      });
    }

    const path = `${A.id}/rlsprobe-${rand()}.txt`;
    const up = await client.upload(bucket, path, 'rlsprobe test file — safe to delete', { token: A.token });
    if (!up.ok) {
      skipped.push(`${bucket}: cross-user file tests skipped — user A cannot upload to "<user id>/…"`);
      continue;
    }
    const shown = path.replace(A.id, '<user A id>');
    // control: A can download its own file — otherwise B's refusal could just mean "wrong path"
    const aGet = await client.download(bucket, path, { token: A.token });
    const aCan = aGet.ok;
    if (!aCan) skipped.push(`${bucket}: user A cannot download its own file (${aGet.status}), so B's download result proves nothing`);

    if (isPublic.has(bucket)) {
      // public buckets serve every file at /object/public/… to anyone: never a "B cannot download" PASS
      const pub = await client.downloadPublic(bucket, path);
      bf({
        id: 'storage-public-bucket',
        severity: 'info',
        title: `Bucket "${bucket}" is public — every file in it can be downloaded by URL`,
        detail: pub.ok
          ? 'Proven: an anonymous request fetched the test file through the public URL. That is what public buckets are for (avatars, product images). Never put private uploads in it.'
          : 'Marked public = true, so files are meant to be fetched by URL. Never put private uploads in it.',
        evidence: pub.ok ? `anonymous: GET /storage/v1/object/public/${bucket}/${shown} → ${pub.status}` : `bucket "${bucket}" has public = true`,
        fix: null,
      });
    } else {
      const bGet = await client.download(bucket, path, { token: B.token });
      if (bGet.ok) {
        bf({
          id: 'storage-cross-user-read',
          severity: 'critical',
          title: `User B can download user A's private files in "${bucket}"`,
          detail: 'Proven: A uploaded a file into its own folder, B downloaded it.',
          evidence: `as user B: GET /storage/v1/object/authenticated/${bucket}/${shown} → ${bGet.status}`,
          fix: { sql: storagePolicies(bucket) },
        });
      } else if (aCan && bGet.status >= 400 && bGet.status < 500) passed.push(`${bucket}: B cannot download A's files`);
      else if (aCan) skipped.push(`${bucket}: download test inconclusive (${bGet.status} ${msg(bGet.data)})`);
    }

    const bDel = await client.deleteObjects(bucket, [path], { token: B.token });
    let deleted = false;
    if (bDel.ok && Array.isArray(bDel.data) && bDel.data.length) {
      deleted = true;
      bf({
        id: 'storage-cross-user-delete',
        severity: 'critical',
        title: `User B can delete user A's files in "${bucket}"`,
        detail: 'Proven: B deleted a file A uploaded.',
        evidence: `as user B: DELETE /storage/v1/object/${bucket} {"prefixes":["${shown}"]} → ${bDel.status}`,
        fix: { sql: storagePolicies(bucket) },
      });
    } else {
      // Storage, like PostgREST, answers a hidden delete with 200 []: confirm the file survived
      const still = aCan ? await client.download(bucket, path, { token: A.token }) : null;
      if ((bDel.ok || (bDel.status >= 400 && bDel.status < 500)) && still?.ok) passed.push(`${bucket}: B cannot delete A's files`);
      else skipped.push(`${bucket}: delete test inconclusive (${bDel.status} ${msg(bDel.data)})`);
    }

    if (!deleted) {
      const rm = await client.deleteObjects(bucket, [path], { token: A.token });
      if (!(rm.ok && Array.isArray(rm.data) && rm.data.length)) skipped.push(`${bucket}: could not delete the test file ${shown} — remove it manually`);
    }
  }
  return { findings, passed, skipped, count: names.size };
}

export function rpcReview(schema) {
  if (!schema.rpcs.length) return [];
  return [
    {
      id: 'rpc-review',
      severity: 'info',
      title: `${schema.rpcs.length} database function(s) are callable over the API`,
      detail:
        'rlsprobe does not call them (they may have side effects). SECURITY DEFINER functions skip RLS — make sure each one checks auth.uid() itself, or revoke execute from anon.',
      evidence: schema.rpcs.map((r) => `POST /rest/v1/rpc/${r}`).join(', '),
      fix: {
        sql: schema.rpcs.map((r) => `-- if "${r}" should not be public:\nrevoke execute on function public.${r} from anon;`).join('\n'),
      },
    },
  ];
}

const inserted = (r) => r && r.ok && Array.isArray(r.data) && r.data.length > 0;
// 42501 = insufficient_privilege: RLS "new row violates" AND missing GRANTs both use it
const policyDenied = (r) => r.status === 401 || r.status === 403 || r.data?.code === '42501';
const privilegeDenied = (r) => policyDenied(r) && /permission denied/i.test(msg(r.data));
const NUMERIC = /^(integer|bigint|smallint|numeric|real|double precision)$/;

// CHECK constraints (e.g. weight between 20 and 400) reject our dummy 1 — try other numbers
async function insertWithRetry(client, t, row, token) {
  let r = await client.insert(t.name, row, { token });
  for (const n of [50, 100, 1000, 0]) {
    if (inserted(r) || r.data?.code !== '23514') break;
    for (const c of t.columns) {
      if (row[c.name] !== undefined && NUMERIC.test(c.format) && c !== t.owner && !c.pk && !c.fk) row[c.name] = n;
    }
    r = await client.insert(t.name, row, { token });
  }
  return r;
}

// tables whose rows are usually meant for every signed-in user (softens READ findings only)
const PUBLIC_TABLE = /^(posts?|comments?|articles?|products?|reviews?|listings?|events?|categories|tags?|public_.*|announcements?)$/i;

// same-length variant of a marker: varchar(n) limits can't make B's update fail for the wrong reason
export const tamper = (m) => `${m.slice(0, -1)}${m.endsWith('x') ? 'y' : 'x'}`;

function updatePatch(t, mine) {
  if (mine.markerCol) return { [mine.markerCol]: tamper(mine.marker) };
  // no text column: write back a plain column's current value — a no-op for the data,
  // but PostgREST still only returns the row if the UPDATE policy allowed it
  const c = t.columns.find((x) => !x.pk && x !== t.owner && !x.fk && mine.row[x.name] !== undefined && mine.row[x.name] !== null);
  return c ? { [c.name]: mine.row[c.name] } : null;
}

// B is a brand-new user and owns nothing, so anything it sees (other than a row
// about itself) belongs to someone else or is public data.
async function freshUserCheck(client, t, B, { tf, passed, skipped, anonCount }) {
  const r = await client.select(t.name, { token: B.token, limit: 20 });
  if (!r.ok) {
    if (privilegeDenied(r)) passed.push(`${t.name}: signed-in users have no direct access at all (privileges revoked)`);
    else skipped.push(`${t.name}: read check failed (${r.status} ${msg(r.data)})`);
    return;
  }
  const mineVals = new Set([B.id, ...Object.values(B.ids || {})].map(String));
  const foreign = (Array.isArray(r.data) ? r.data : []).filter((row) => !Object.values(row).some((v) => mineVals.has(String(v))));
  if (!foreign.length) {
    // an empty answer proves nothing without a row we know exists
    skipped.push(`${t.name}: a new user sees no foreign rows — not proven (the table may simply be empty)`);
    return;
  }
  if (anonCount > 0) return; // already reported as publicly readable
  tf({
    id: 'fresh-user-sees-rows',
    severity: 'warning',
    title: `A brand-new user can see ${r.total ?? foreign.length} row(s) in "${t.name}"`,
    detail:
      'Test user B was created seconds ago and owns nothing here. Either this table is meant to be shared, or its SELECT policy is too broad.',
    evidence: `as user B: ${r.evidence} — columns: ${Object.keys(foreign[0]).join(', ')}`,
    fix: null,
  });
}

// A filter that can only ever match the test row: EVERY primary-key column (composite keys
// included) plus the marker. Returns null when the row cannot be pinned down — callers must
// then not send UPDATE/DELETE at all.
export function filterFor(c) {
  const parts = [];
  const pkCols = c.table.pkCols?.length ? c.table.pkCols : c.table.pk ? [c.table.pk] : [];
  for (const col of pkCols) {
    const v = c.row?.[col.name];
    if (v === undefined || v === null) return null; // partial key: could match other rows
    parts.push(`${col.name}=eq.${encodeURIComponent(v)}`);
  }
  if (c.markerCol && c.marker !== undefined) parts.push(`${c.markerCol}=eq.${encodeURIComponent(c.marker)}`);
  return parts.length ? parts.join('&') : null;
}

export function msg(d) {
  if (!d) return '';
  if (typeof d === 'string') return d.slice(0, 200);
  return d.msg || d.message || d.error_description || d.error || JSON.stringify(d).slice(0, 200);
}
