// Two leaks the row-ownership tests cannot see:
//
//  1. Privilege escalation: "users may update their own row" also lets a user change
//     role / is_admin / plan / credits on that row. A (the row's owner) tries exactly that
//     on its own test row, then puts the old value back.
//  2. Views that skip RLS: a view runs with its owner's rights unless it was created with
//     security_invoker, so it can show rows the table's policy hides. B queries every view
//     and looks for A's test rows from tables where B was refused.
//
// Same rules as everywhere else: a finding is a request that worked; a PASS needs an
// explicit refusal (401/403/42501) and a control read showing nothing changed.

import { privilegeFix, viewInvoker } from './fixes.js';

const ROLE = /^(user_?)?roles?$|^(access|permission)_?(level|role)s?$|^account_?type$|^user_?type$/i;
const ADMIN = /^(is_?)?(admin|super_?admin|superuser|staff|moderator)$/i;
const PLAN = /^(subscription_?)?(plan|tier)$|^subscription_?status$|^is_?(pro|premium|paid|vip)$/i;
const VERIFIED = /^is_?(verified|approved)$/i;
const BALANCE = /^(credits?|balance|coins|points)$/i;

export function isPrivileged(name) {
  return ROLE.test(name) || ADMIN.test(name) || PLAN.test(name) || VERIFIED.test(name) || BALANCE.test(name);
}

const HIGH = /admin|owner|super|staff|moderator|enterprise|premium|pro|vip|business|unlimited/i;
const TEXT = /^(text|character varying|character|citext|string)$/;
const NUMBER = /^(integer|bigint|smallint|numeric|real|double precision)$/;

// Values to try, most telling first. [] = nothing sensible to write.
export function escalationValues(c, current) {
  if (c.enum?.length) return c.enum.filter((v) => v !== current && HIGH.test(v)).slice(0, 3);
  if (c.format === 'boolean' || c.type === 'boolean') return current === true ? [] : [true];
  if (NUMBER.test(c.format) || c.type === 'integer' || c.type === 'number') return [Number(current || 0) + 1000];
  if (TEXT.test(c.format) || (c.type === 'string' && !c.format)) {
    if (ROLE.test(c.name) || ADMIN.test(c.name)) return ['admin', 'owner'].filter((v) => v !== current);
    if (/status/i.test(c.name)) return ['active'].filter((v) => v !== current);
    if (PLAN.test(c.name)) return ['pro', 'premium', 'enterprise'].filter((v) => v !== current);
    return [];
  }
  return [];
}

// A changes privileged columns of its own test row (mine). Called right after the control read.
export async function probeEscalation(client, t, mine, A, h) {
  const { tf, passed, skipped, filterFor, policyDenied, msg } = h;
  const cols = t.columns.filter(
    (c) => isPrivileged(c.name) && !c.pk && c !== t.owner && c.name !== mine.markerCol && !c.fk && c.name in (mine.row || {}),
  );
  if (!cols.length) return;
  const filter = filterFor(mine);
  if (!filter) return;
  const reread = async () => {
    const r = await client.select(t.name, { token: A.token, filter });
    return r.ok && Array.isArray(r.data) && r.data.length === 1 ? r.data[0] : null;
  };
  const escalated = [];
  const restoreFailed = [];
  const evidence = [];
  for (const c of cols) {
    const before = mine.row[c.name];
    const values = escalationValues(c, before);
    if (!values.length) continue;
    let outcome = null;
    let last = null;
    for (const v of values) {
      const r = await client.update(t.name, filter, { [c.name]: v }, { token: A.token });
      last = r;
      const row = r.ok && Array.isArray(r.data) ? r.data[0] : null;
      if (row && String(row[c.name]) === String(v)) {
        outcome = 'changed';
        escalated.push(`${c.name}: ${JSON.stringify(before)} → ${JSON.stringify(v)}`);
        if (!evidence.length) evidence.push(`as user A on its own row: ${r.evidence}`);
        const back = await client.update(t.name, filter, { [c.name]: before }, { token: A.token });
        if (!(back.ok && Array.isArray(back.data) && back.data.length)) restoreFailed.push(c.name);
        break;
      }
      if (policyDenied(r)) {
        outcome = 'refused';
        break;
      }
      // 23514 check / 22P02 enum / P0001 trigger: try the next value
    }
    if (outcome === 'refused') {
      const now = await reread();
      if (now && String(now[c.name]) === String(before)) passed.push(`${t.name}: users cannot change their own ${c.name}`);
      else skipped.push(`${t.name}: ${c.name} change test inconclusive (refused, but the row could not be re-read)`);
    } else if (!outcome && last) {
      skipped.push(`${t.name}: users could not change their own ${c.name}, but not because of a policy (${last.status} ${msg(last.data)}) — a trigger or constraint may protect it; not proven`);
    }
  }
  if (!escalated.length) return;
  const restoreNote = restoreFailed.length
    ? ` accessprobe could not put back ${restoreFailed.join(', ')}; the test row is deleted during cleanup.`
    : ' The old value was put back right away.';
  tf({
    id: 'self-escalation',
    severity: 'critical',
    title: `Users can change their own ${escalated.map((e) => e.split(':')[0]).join(', ')} in "${t.name}"`,
    detail:
      `Proven: user A updated its own row and set ${escalated.join('; ')}. ` +
      '"Users may update their own row" also covers these columns, so anyone can make themselves admin, upgrade their plan or add credits — unless your app never trusts these columns.' +
      restoreNote,
    evidence: evidence.join(''),
    fix: { sql: privilegeFix(t, escalated.map((e) => e.split(':')[0])) },
  });
}

// Views (and relations known only by name) that might expose rows B was refused.
// protectedRows: A's test rows that B could NOT read directly. Run before cleanup.
export async function probeViews(client, relations, protectedRows, [A, B], h) {
  const { findings, passed, skipped, policyDenied, msg } = h;
  const views = relations.filter((r) => r.isView);
  const live = protectedRows.filter((m) => !m.deleted && m.markerCol && m.marker);
  if (!relations.length) return;
  if (!live.length) {
    if (views.length) skipped.push(`views not tested (${views.map((v) => v.name).join(', ')}): no private test rows to look for`);
    return;
  }
  const look = async (name, token) => {
    const r = await client.select(name, { token, limit: 1000 });
    if (!r.ok || !Array.isArray(r.data)) return { r, hits: null };
    const text = JSON.stringify(r.data);
    return { r, hits: live.filter((m) => text.includes(m.marker)) };
  };
  for (const v of relations) {
    const a = await look(v.name, A.token);
    if (!a.hits?.length) {
      if (v.isView) skipped.push(`${v.name}: view shows none of A's test rows, so it could not be tested`);
      continue;
    }
    const tables = [...new Set(a.hits.map((m) => m.table.name))];
    const what = `${v.isView ? 'view' : 'relation'} "${v.name}"`;
    for (const [who, token, id] of [
      ['user B', B.token, 'view-bypass'],
      ['anonymous', undefined, 'view-bypass-anon'],
    ]) {
      const b = await look(v.name, token);
      if (b.hits?.length) {
        findings.push({
          table: v.name,
          id,
          severity: 'critical',
          title: `${who === 'user B' ? 'User B' : 'Anyone (not logged in)'} can read user A's private rows through ${what}`,
          detail:
            `Proven: "${tables.join('", "')}" hides A's test row from ${who}, but ${what} returns it. ` +
            'A view runs with the rights of its owner (usually postgres), so it skips Row Level Security unless it was created with security_invoker = true.',
          evidence: `as ${who}: ${b.r.evidence} → contained A's test row from "${tables[0]}"`,
          fix: { sql: viewInvoker(v.name) },
        });
        break; // the anonymous result adds nothing once B already sees it
      } else if (b.hits && b.r.data.length >= 1000) {
        skipped.push(`${v.name}: ${who} got a full page of 1000 rows without A's, so A's row may be further down; not proven`);
      } else if (b.hits || policyDenied(b.r)) {
        passed.push(`${v.name}: ${who === 'user B' ? "B" : 'anonymous visitors'} cannot read A's private rows through it`);
      } else {
        skipped.push(`${v.name}: ${who} check inconclusive (${b.r.status} ${msg(b.r.data)})`);
      }
    }
  }
}
