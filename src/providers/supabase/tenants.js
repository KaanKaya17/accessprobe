// Teams / organizations (multi-tenant apps). Most SaaS rules are not "is it my row" but "am I a
// member of this org, and with which role". Found automatically from the schema:
//   tenant table      orgs / teams / workspaces …            (what org_id points to)
//   membership table  org_members (org_id, user_id[, role])
//   tenant tables     every other table with the same org_id column
//
// A creates a test organization, becomes its member and writes a row into each tenant table. Then:
//   1. B, an OUTSIDER, tries to read / change / delete those rows, read the member list, and add
//      itself to A's organization (as owner, then as a plain member);
//   2. A adds B as a plain MEMBER: B tries to raise its own role to admin / owner;
//   3. A REMOVES B: B, with the same session, tries to read the rows again.
// Everything is deleted at the end. Skipped under --read-only (it needs writes).

import { buildRow } from './schema.js';
import { ownerValue, filterFor, tamper, msg } from './probes.js';

const TENANT_COL = /^(org|organization|organisation|team|workspace|tenant|company|account|group|club|household|space)_id$/i;
const MEMBER_NAME = /member|membership|_users$|^users_|user_(orgs?|teams?|workspaces?)|(orgs?|teams?|workspaces?)_users/i;
const ROLE_COL = /^(role|member_role|access|access_level|permission|level|type)$/i;
const ADMIN_ROLE = /^(owner|admin|administrator|superadmin|manager|organizer|organiser|moderator|captain|founder|lead|kaptan|yonetici|yönetici|sahip)$/i;
const MEMBER_ROLE = /^(member|viewer|reader|user|guest|editor|basic|read|player|participant|contributor|oyuncu|uye|üye)$/i;

const rand = () => Math.random().toString(36).slice(2, 8);
const denied = (r) => r.status === 401 || r.status === 403 || r.data?.code === '42501';
const rows = (r) => (r.ok && Array.isArray(r.data) ? r.data : null);

const plural = (s) => [s, `${s}s`, `${s}es`, s.replace(/y$/, 'ies'), { org: 'organizations', organisation: 'organisations' }[s]].filter(Boolean);

// → { tenant, members, col, userCol, roleCol, scoped } or null
export function findTenancy(schema) {
  const tables = schema.tables.filter((t) => !t.isView && !t.sourceView && !t.nameOnly);
  const byName = new Map(tables.map((t) => [t.name, t]));
  const candidates = [];
  for (const m of tables) {
    if (!m.owner) continue; // a membership row names a user
    for (const c of m.columns) {
      if (!TENANT_COL.test(c.name) || c.name === m.owner.name) continue;
      const prefix = c.name.replace(/_id$/i, '').toLowerCase();
      const tenant = (c.fk && byName.get(c.fk.table)) || plural(prefix).map((n) => byName.get(n)).find(Boolean);
      if (!tenant || tenant === m) continue;
      const score = (MEMBER_NAME.test(m.name) ? 2 : 0) + (m.columns.some((x) => ROLE_COL.test(x.name)) ? 1 : 0) + (m.columns.length <= 8 ? 1 : 0);
      if (score >= 2) candidates.push({ m, c, tenant, score });
    }
  }
  if (!candidates.length) return null;
  candidates.sort((a, b) => b.score - a.score);
  const { m, c, tenant } = candidates[0];
  const role = m.columns.find((x) => ROLE_COL.test(x.name) && x.name !== c.name) || null;
  const scoped = tables.filter((t) => t !== m && t !== tenant && t.columns.some((x) => x.name === c.name));
  return { tenant, members: m, col: c.name, userCol: m.owner.name, roleCol: role?.name || null, roleEnum: role?.enum || null, scoped };
}

// allowed values come from an enum type or a CHECK (role in (…)) in the migrations; null = leave
// the column to its default (usually the lowest role)
function roleValues(enumValues) {
  if (enumValues?.length) {
    const member = enumValues.filter((v) => MEMBER_ROLE.test(v));
    const admin = enumValues.filter((v) => ADMIN_ROLE.test(v));
    return {
      // unknown names: any value that is not a plain member role counts as "more than a member"
      admin: admin.length ? admin : enumValues.filter((v) => !member.includes(v)),
      member: [...member, null],
    };
  }
  return { admin: ['owner', 'admin'], member: ['member', 'viewer', 'user', 'player', null] };
}

const q = (s) => (/^[a-z_][a-z0-9_]*$/.test(s) ? s : `"${s.replace(/"/g, '""')}"`);

function memberFix(ten) {
  const { members: m, col, userCol, roleCol } = ten;
  const admin = roleCol ? ` and ${q(roleCol)} in ('owner', 'admin')` : '';
  return (
    `-- helpers that read the membership without hitting the members table's own RLS (no recursion)\n` +
    `create or replace function public.is_member_of(_org ${colType(ten)}) returns boolean\n` +
    `  language sql stable security definer set search_path = ''\n` +
    `  as $$ select exists (select 1 from public.${q(m.name)} where ${q(col)} = _org and ${q(userCol)} = (select auth.uid())) $$;\n` +
    `create or replace function public.is_admin_of(_org ${colType(ten)}) returns boolean\n` +
    `  language sql stable security definer set search_path = ''\n` +
    `  as $$ select exists (select 1 from public.${q(m.name)} where ${q(col)} = _org and ${q(userCol)} = (select auth.uid())${admin}) $$;\n`
  );
}

function colType(ten) {
  const c = ten.members.columns.find((x) => x.name === ten.col);
  return /uuid/.test(c?.format || '') ? 'uuid' : /bigint|integer|smallint/.test(c?.format || '') ? 'bigint' : 'text';
}

function scopedFix(ten, t) {
  const n = `public.${q(t.name)}`;
  const c = q(ten.col);
  return (
    memberFix(ten) +
    `\nalter table ${n} enable row level security;\n` +
    `create policy "members read" on ${n} for select to authenticated using ((select public.is_member_of(${c})));\n` +
    `create policy "members insert" on ${n} for insert to authenticated with check ((select public.is_member_of(${c})));\n` +
    `create policy "members update" on ${n} for update to authenticated using ((select public.is_member_of(${c}))) with check ((select public.is_member_of(${c})));\n` +
    `create policy "admins delete" on ${n} for delete to authenticated using ((select public.is_admin_of(${c})));`
  );
}

function joinFix(ten) {
  const n = `public.${q(ten.members.name)}`;
  return (
    memberFix(ten) +
    `\n-- only admins of the organization add members (or do it in an invite function):\n` +
    `create policy "admins add members" on ${n} for insert to authenticated with check ((select public.is_admin_of(${q(ten.col)})));\n` +
    `-- and drop any policy that lets a user insert a row with their own ${ten.userCol} for any ${ten.col}`
  );
}

function roleFix(ten) {
  const n = `public.${q(ten.members.name)}`;
  return (
    `-- members must not change their own role. Roles change through an admin-only function:\n` +
    `revoke update on ${n} from authenticated;\n` +
    `-- or keep UPDATE but only for admins:\n` +
    memberFix(ten) +
    `create policy "admins change roles" on ${n} for update to authenticated using ((select public.is_admin_of(${q(ten.col)})));`
  );
}

export async function probeTenants(client, schema, [A, B], { log, findings, passed, skipped, readOnly }) {
  const ten = findTenancy(schema);
  if (!ten) return null;
  const { tenant: T, members: M, col, userCol, roleCol } = ten;
  const label = `${T.name} / ${M.name}`;
  if (readOnly) {
    skipped.push(`Organizations (${label}): not tested (--read-only; the tests need a test organization)`);
    return ten;
  }
  log(`  organizations: ${T.name}, members in ${M.name}.${col}, ${ten.scoped.length} table(s) scoped by ${col}`);
  const roles = roleValues(ten.roleEnum);
  const mine = []; // our rows, newest first, for cleanup
  const track = (table, row, markerCol, marker) => {
    const c = { table, row, markerCol, marker };
    mine.unshift(c);
    return c;
  };

  try {
    // --- A creates an organization and makes sure it is a member (owner) of it
    const orgMarker = `accessprobe-org-${rand()}`;
    const ob = buildRow(T, { ownerId: ownerValue(T, A), marker: orgMarker });
    const orgIns = ob && (await client.insert(T.name, ob.row, { token: A.token }));
    const org = rows(orgIns)?.[0];
    const pkName = T.pk?.name || 'id';
    if (!org || org[pkName] === undefined) {
      skipped.push(`Organizations (${label}): A could not create a test organization in "${T.name}" (${orgIns ? `${orgIns.status} ${msg(orgIns.data)}` : 'no insertable columns'}), so team rules were not tested. If organizations are created by a function, that path is not covered yet.`);
      return ten;
    }
    const orgId = org[pkName];
    track(T, org, ob.markerCol, ob.markerCol ? orgMarker : undefined);
    const aMemberVal = ownerValue(M, A);
    const bMemberVal = ownerValue(M, B);
    const memberFilter = (who) => `${col}=eq.${encodeURIComponent(orgId)}&${userCol}=eq.${encodeURIComponent(who)}`;
    const memberRow = (who) => ({ table: M, row: { [col]: orgId, [userCol]: who }, markerCol: null, marker: undefined, filter: memberFilter(who) });
    // insert a membership. RETURNING has to pass the SELECT policy, and a policy like
    // is_member_of(org_id) can't see the new row inside the same statement: then insert without
    // RETURNING and look the row up as A (an owner sees the member list)
    const addMember = async (row, token, who) => {
      const r = await client.insert(M.name, row, { token });
      if (rows(r)?.length) return { ok: true, r };
      if (!denied(r)) return { ok: false, r };
      const m = await client.insert(M.name, row, { token, minimal: true });
      if (!m.ok) return { ok: false, r: m.status ? m : r };
      const seen = rows(await client.select(M.name, { token: A.token, filter: memberFilter(who) }))?.length > 0;
      return { ok: seen, r: m };
    };

    const aIsMember = rows(await client.select(M.name, { token: A.token, filter: memberFilter(aMemberVal) }))?.length > 0;
    if (!aIsMember) {
      let ok = false;
      let last = null;
      for (const role of roleCol ? roles.admin.length ? roles.admin : [null] : [null]) {
        const b = buildRow(M, { ownerId: aMemberVal, marker: `accessprobe-${rand()}`, fixed: { [col]: orgId, ...(roleCol && role && { [roleCol]: role }) } });
        if (!b) break;
        const res = await addMember(b.row, A.token, aMemberVal);
        last = res.r;
        if (res.ok) {
          ok = true;
          break;
        }
      }
      if (!ok) {
        skipped.push(`Organizations (${label}): A created an organization but could not make itself a member of it (${last ? `${last.status} ${msg(last.data)}` : 'no insertable row'}), so team rules were not tested (maybe a trigger or function does that).`);
        return ten;
      }
    }
    ten.tested = true; // from here on the organization tests run
    mine.push(memberRow(aMemberVal)); // A's membership goes last (after the org rows, before the org itself is gone)

    // --- A writes one row into every table scoped by the organization
    // Tables that point at another scoped table (match_players → matches) are filled with the row A
    // just created there; a second user column (ratings.ratee_id) gets B. A row without a text column
    // is recognized by its primary key.
    const targets = [];
    const made = new Map(); // table name → A's row
    const userTables = /^(auth\.users|users|profiles)$/;
    const fill = (t) => {
      const fixed = { [col]: orgId };
      for (const c of t.columns) {
        if (!c.required || c.hasDefault || c.name in fixed || !c.fk || c.name === t.owner?.name) continue;
        if (made.has(c.fk.table)) fixed[c.name] = made.get(c.fk.table)[c.fk.column];
        else if (userTables.test(c.fk.table)) fixed[c.name] = ownerValue({ ...t, owner: c }, B) ?? B.id;
        else return null; // points at something we did not create
      }
      return fixed;
    };
    const pending = [...ten.scoped];
    for (let progress = true; pending.length && progress; ) {
      progress = false;
      for (const t of [...pending]) {
        const fixed = fill(t);
        if (!fixed) continue;
        pending.splice(pending.indexOf(t), 1);
        progress = true;
        const marker = `accessprobe-${rand()}`;
        const b = buildRow(t, { ownerId: ownerValue(t, A), marker, fixed });
        if (!b) {
          skipped.push(`${t.name}: organization tests skipped — required columns accessprobe cannot fill`);
          continue;
        }
        const r = await client.insert(t.name, b.row, { token: A.token });
        const row = rows(r)?.[0];
        if (!row) {
          skipped.push(`${t.name}: A, a member, could not add a row to its own organization (${r.status} ${msg(r.data)}), so it was not tested for other organizations`);
          continue;
        }
        const c = track(t, row, b.markerCol, b.markerCol ? marker : undefined);
        if (!filterFor(c)) {
          skipped.push(`${t.name}: organization tests need a text column or a primary key to recognize the test row`);
          continue;
        }
        made.set(t.name, row);
        targets.push({ t, c });
      }
    }
    for (const t of pending) skipped.push(`${t.name}: organization tests skipped — it references a table accessprobe did not create a row in`);
    const readBack = async (x, token) => rows(await client.select(x.t.name, { token, filter: filterFor(x.c) }));

    // --- 1. B is an outsider
    for (const x of targets) {
      const tf = (f) => findings.push({ table: x.t.name, ...f });
      const r = await client.select(x.t.name, { token: B.token, filter: filterFor(x.c) });
      if (rows(r)?.length) {
        x.outsiderReads = true;
        tf({
          id: 'cross-tenant-read',
          severity: 'critical',
          title: `A user outside the organization can read its rows in "${x.t.name}"`,
          detail: `Proven: A created an organization and a row in "${x.t.name}" for it; B, who is not a member, fetched that row. Rows scoped by ${col} must only be visible to members.`,
          evidence: `as user B (not a member): ${r.evidence} → returned the organization's row`,
          fix: { sql: scopedFix(ten, x.t) },
        });
      } else if (denied(r) || rows(r)) passed.push(`${x.t.name}: users outside the organization cannot read its rows`);
      else skipped.push(`${x.t.name}: outsider read test inconclusive (${r.status} ${msg(r.data)})`);

      // no text column to change: the change test needs one (read and delete are still tested)
      const upd = x.c.markerCol ? await client.update(x.t.name, filterFor(x.c), { [x.c.markerCol]: tamper(x.c.marker) }, { token: B.token }) : null;
      if (!upd) {
        /* skipped */
      } else if (rows(upd)?.length) {
        x.c.marker = tamper(x.c.marker);
        tf({
          id: 'cross-tenant-update',
          severity: 'critical',
          title: `A user outside the organization can change its rows in "${x.t.name}"`,
          detail: 'Proven: B, not a member, changed a row that belongs to A\'s organization.',
          evidence: `as user B (not a member): ${upd.evidence} → changed the row`,
          fix: { sql: scopedFix(ten, x.t) },
        });
      } else if ((denied(upd) || rows(upd)) && (await readBack(x, A.token))?.length) passed.push(`${x.t.name}: users outside the organization cannot change its rows`);

      const del = await client.remove(x.t.name, filterFor(x.c), { token: B.token });
      if (rows(del)?.length) {
        x.c.deleted = true;
        tf({
          id: 'cross-tenant-delete',
          severity: 'critical',
          title: `A user outside the organization can delete its rows in "${x.t.name}"`,
          detail: "Proven: B, not a member, deleted a row that belongs to A's organization.",
          evidence: `as user B (not a member): ${del.evidence} → deleted the row`,
          fix: { sql: scopedFix(ten, x.t) },
        });
      } else if ((denied(del) || rows(del)) && (await readBack(x, A.token))?.length) passed.push(`${x.t.name}: users outside the organization cannot delete its rows`);
    }

    const list = await client.select(M.name, { token: B.token, filter: `${col}=eq.${encodeURIComponent(orgId)}` });
    if (rows(list)?.length) {
      findings.push({
        table: M.name,
        id: 'cross-tenant-members-read',
        severity: 'warning',
        title: `A user outside the organization can list its members in "${M.name}"`,
        detail: `B, not a member, read the member list of A's organization (${rows(list).length} row(s): user ids${roleCol ? ' and roles' : ''}). Usually only members should see who else is in an organization.`,
        evidence: `as user B (not a member): ${list.evidence} → ${rows(list).length} member row(s)`,
        fix: { sql: `${memberFix(ten)}\ncreate policy "members see members" on public.${q(M.name)} for select to authenticated using ((select public.is_member_of(${q(col)})));` },
      });
    } else if (denied(list) || rows(list)) passed.push(`${M.name}: users outside an organization cannot list its members`);

    // B adds itself to A's organization: as admin first (the worst case), then as a plain member
    let joined = null;
    for (const role of roleCol ? [...roles.admin, ...roles.member] : [null]) {
      const b = buildRow(M, { ownerId: bMemberVal, marker: `accessprobe-${rand()}`, fixed: { [col]: orgId, ...(roleCol && role && { [roleCol]: role }) } });
      if (!b) break;
      const { ok, r } = await addMember(b.row, B.token, bMemberVal);
      if (ok) {
        joined = { role, r };
        break;
      }
      if (!denied(r) && !(r.status === 400 || r.status === 409 || r.status === 422)) {
        skipped.push(`${M.name}: self-join test inconclusive (${r.status} ${msg(r.data)})`);
        joined = false;
        break;
      }
    }
    if (joined) {
      findings.push({
        table: M.name,
        id: 'tenant-self-join',
        severity: 'critical',
        title: `Any user can add themselves to someone else's organization${joined.role && ADMIN_ROLE.test(joined.role) ? ` as ${joined.role}` : ''} ("${M.name}")`,
        detail: `Proven: B inserted a membership row for itself into A's organization${joined.role ? ` with ${roleCol} = '${joined.role}'` : ''}. From then on B sees and changes everything the organization's members can. The insert policy on "${M.name}" probably only checks ${userCol} = auth.uid().`,
        evidence: `as user B: ${joined.r.evidence.replace(String(orgId), "<A's org id>")} → B is now a member`,
        fix: { sql: joinFix(ten) },
      });
      const rm = await client.remove(M.name, memberFilter(bMemberVal), { token: A.token });
      if (!rows(rm)?.length) await client.remove(M.name, memberFilter(bMemberVal), { token: B.token });
    } else if (joined === null) passed.push(`${M.name}: users cannot add themselves to another user's organization`);

    // --- 2. A adds B as a plain member
    let added = null;
    for (const role of roleCol ? (roles.member.length ? roles.member : [null]) : [null]) {
      const b = buildRow(M, { ownerId: bMemberVal, marker: `accessprobe-${rand()}`, fixed: { [col]: orgId, ...(roleCol && role && { [roleCol]: role }) } });
      if (!b) break;
      if ((await addMember(b.row, A.token, bMemberVal)).ok) {
        added = { role };
        break;
      }
    }
    if (!added) {
      skipped.push(`Organizations (${label}): A could not add B as a member (maybe invites go through a function), so the member and removed-member tests were not run`);
      return ten;
    }
    const bMembership = memberRow(bMemberVal);
    mine.unshift(bMembership);
    // a fresh session as a member: policies that read the membership from JWT claims see it only now
    const fresh = B.password ? await client.signIn(B.email, B.password) : null;
    const bTok = fresh?.ok && fresh.data?.access_token ? fresh.data.access_token : B.token;
    const memberSees = new Map();
    for (const x of targets) if (!x.c.deleted && !x.outsiderReads) memberSees.set(x, (await readBack(x, bTok))?.length > 0);

    if (roleCol && roles.admin.length) {
      // the role B really got (the column default when we left it out)
      added.role ??= rows(await client.select(M.name, { token: A.token, filter: memberFilter(bMemberVal) }))?.[0]?.[roleCol] ?? null;
      const up = roles.admin.find((v) => v !== added.role) ?? roles.admin[0];
      const r = await client.update(M.name, memberFilter(bMemberVal), { [roleCol]: up }, { token: bTok });
      const now = rows(await client.select(M.name, { token: A.token, filter: memberFilter(bMemberVal) }))?.[0];
      if (rows(r)?.length && now && now[roleCol] === up) {
        findings.push({
          table: M.name,
          id: 'tenant-role-escalation',
          severity: 'critical',
          title: `Members can make themselves ${up} of their organization ("${M.name}.${roleCol}")`,
          detail: `Proven: A added B as '${added.role}'; B changed its own ${roleCol} to '${up}'. A policy like "users update their own membership" also lets them change their role.`,
          evidence: `as user B (member): ${r.evidence} → ${roleCol} is now '${up}'`,
          fix: { sql: roleFix(ten) },
        });
        if (added.role !== null) await client.update(M.name, memberFilter(bMemberVal), { [roleCol]: added.role }, { token: A.token });
      } else if (now && now[roleCol] === added.role) passed.push(`${M.name}: members cannot raise their own ${roleCol}`);
    }

    // --- 3. A removes B; B keeps its session
    const rm = await client.remove(M.name, memberFilter(bMemberVal), { token: A.token });
    if (!rows(rm)?.length) {
      skipped.push(`Organizations (${label}): A could not remove B from the organization (${rm.status} ${msg(rm.data)}), so the removed-member test was not run`);
      return ten;
    }
    bMembership.deleted = true;
    for (const [x, saw] of memberSees) {
      if (!saw) {
        skipped.push(`${x.t.name}: B could not read the organization's row even as a member, so the removed-member test proves nothing`);
        continue;
      }
      const r = await client.select(x.t.name, { token: bTok, filter: filterFor(x.c) });
      if (rows(r)?.length) {
        findings.push({
          table: x.t.name,
          id: 'removed-member-access',
          severity: 'critical',
          title: `Removed members keep access to the organization's rows in "${x.t.name}"`,
          detail:
            "Proven: B was a member and could read the row; A removed B from the organization; B, with the same session, can still read it. " +
            'Policies that read the membership from the JWT (custom claims, app_metadata) only change when the token is refreshed, up to an hour later. Check the membership table in the policy instead.',
          evidence: `as user B after removal: ${r.evidence} → still returned the row`,
          fix: { sql: scopedFix(ten, x.t) },
        });
      } else passed.push(`${x.t.name}: removed members lose access right away`);
    }
    return ten;
  } finally {
    // newest first: tenant rows, B's membership, then the org, then A's membership
    let left = [];
    let orgGone = false;
    const orgRow = mine.find((c) => c.table === T);
    const ordered = [...mine.filter((c) => c.table !== T && c.table !== M), ...mine.filter((c) => c.table === M && c.row[userCol] !== ownerValue(M, A)), ...(orgRow ? [orgRow] : []), ...mine.filter((c) => c.table === M && c.row[userCol] === ownerValue(M, A))];
    for (const c of ordered) {
      if (c.deleted) continue;
      const filter = c.filter || filterFor(c);
      if (!filter) continue;
      let gone = false;
      for (const token of [A.token, B.token]) {
        const r = await client.remove(c.table.name, filter, { token });
        if (rows(r)?.length) {
          gone = true;
          break;
        }
      }
      if (gone && c === orgRow) orgGone = true;
      // the org delete may have cascaded to the memberships: only report what is really still there
      if (!gone && rows(await client.select(c.table.name, { token: A.token, filter }))?.length) left.push(c);
    }
    // rows that can't be deleted on their own (ratings with no DELETE policy) went with the
    // organization: a NOT NULL foreign key to it either cascades or blocks the org delete
    if (orgGone) left = left.filter((c) => c.table.columns.find((x) => x.name === col)?.fk?.table !== T.name);
    if (left.length) skipped.push(`Could not delete some organization test rows, remove them manually: ${left.map((c) => `${c.table.name} ${c.filter || filterFor(c)}`).join('; ')}`);
  }
}
