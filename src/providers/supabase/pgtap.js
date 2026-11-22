// Turns one accessprobe run into a pgTAP file for `supabase test db`, so every check it made
// keeps running in CI without a live API. Each test states the SECURE behaviour: checks that
// passed stay green, and checks behind a proven leak fail until the fix is applied.
//
// Recipes come from probes.js: the row user A inserted, and which checks gave a clear verdict.
// The SQL plays both users by switching to the authenticated / anon roles and setting
// request.jwt.claims, the way PostgREST does. Everything runs in one transaction and is rolled back.

import { writeFile, mkdir } from 'node:fs/promises';
import { dirname } from 'node:path';
import { readFileSync } from 'node:fs';

const A_ID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const B_ID = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const ident = (s) => `"${String(s).replace(/"/g, '""')}"`;
const rel = (name) => `public.${ident(name)}`;
const str = (s) => `'${String(s).replace(/'/g, "''")}'`;
// dollar quoting for nested SQL; the tag can't appear in our own values
const q = (sql) => `$ap$${sql}$ap$`;

function pgArray(a) {
  return `{${a.map((x) => (x === null ? 'NULL' : `"${String(typeof x === 'object' ? JSON.stringify(x) : x).replace(/["\\]/g, '\\$&')}"`)).join(',')}}`;
}

// a literal Postgres coerces to the column's type (unknown-typed string), or NULL
function lit(v) {
  if (v === null || v === undefined) return 'NULL';
  if (Array.isArray(v)) return str(pgArray(v));
  if (typeof v === 'object') return str(JSON.stringify(v));
  return str(v);
}

const claims = (id, email) => JSON.stringify({ sub: id, role: 'authenticated', aud: 'authenticated', email });
const AS = {
  A: `reset role;\nset local role authenticated;\nset local request.jwt.claims to ${str(claims(A_ID, 'accessprobe-a@example.test'))};`,
  B: `reset role;\nset local role authenticated;\nset local request.jwt.claims to ${str(claims(B_ID, 'accessprobe-b@example.test'))};`,
  anon: `reset role;\nset local role anon;\nset local request.jwt.claims to ${str(JSON.stringify({ role: 'anon' }))};`,
};

// same-length variant, like the live test (varchar limits must not fake a pass)
const tamper = (m) => `${m.slice(0, -1)}${m.endsWith('x') ? 'y' : 'x'}`;

export function pgtapTests(recipes, { version = '', target = '', date = new Date().toISOString() } = {}) {
  const usable = (recipes || []).filter((r) => r.checks.length || r.escalations.length || r.views.length);
  if (!usable.length) return null;
  let n = 0;
  const marker = () => `accessprobe-${(n++).toString(36).padStart(6, '0')}`;
  const body = [];
  let count = 0;
  const note = (ok) => (ok ? '' : '  -- FAILS until the fix from the accessprobe report is applied');
  const visible = (sql) => `accessprobe_t.visible(${q(sql)})`;
  const test = (expr, desc, ok) => {
    count++;
    body.push(`select ok(${expr}, ${str(desc)});${note(ok)}`);
  };
  const attempt = (sql) => body.push(`call accessprobe_t.attempt(${q(sql)});`);

  for (const r of usable) {
    const t = rel(r.table);
    const m = ident(r.markerCol);
    const has = (check) => r.checks.find((c) => c.check === check);
    const rowFor = (mk, ownerId = A_ID) => {
      const cols = Object.keys(r.sent);
      const vals = cols.map((c) => {
        const v = r.sent[c];
        if (r.owner && c === r.owner) return str(ownerId);
        if (v === r.marker) return str(mk);
        if (typeof v === 'string' && UUID.test(v)) return 'gen_random_uuid()';
        return lit(v);
      });
      return { cols: cols.map(ident).join(', '), vals: `(${vals.join(', ')})` };
    };
    const where = (mk, extra = '') => `select 1 from ${t} where ${m} = ${str(mk)}${extra}`;
    const ownedByA = r.owner ? ` and ${ident(r.owner)} = ${str(A_ID)}` : '';

    const rows = { base: marker() };
    if (has('update')) rows.update = marker();
    if (has('takeover')) rows.takeover = marker();
    if (has('delete')) rows.delete = marker();
    r.escalations.forEach((e, i) => (rows[`esc${i}`] = marker()));
    const forged = has('forge') ? marker() : null;

    body.push('', `-- ${r.table}`);
    const ins = Object.values(rows).map((mk) => rowFor(mk));
    body.push(AS.A);
    count++;
    body.push(
      `select lives_ok(${q(`insert into ${t} (${ins[0].cols}) values ${ins.map((x) => x.vals).join(', ')}`)}, ${str(`${r.table}: user A can create its own rows (setup)`)});`,
    );

    const read = has('read');
    if (read) {
      body.push(AS.B);
      test(`not ${visible(where(rows.base))}`, `${r.table}: B cannot read A's rows`, read.ok);
    }
    const anon = has('anon-read');
    if (anon) {
      body.push(AS.anon);
      test(`not ${visible(where(rows.base))}`, `${r.table}: anonymous visitors cannot read A's rows`, anon.ok);
    }
    for (const v of r.views) {
      body.push(v.actor === 'B' ? AS.B : AS.anon);
      test(
        `not ${visible(`select 1 from ${rel(v.view)} x where row_to_json(x)::text like ${str(`%${rows.base}%`)}`)}`,
        `${v.view}: ${v.actor === 'B' ? 'B' : 'anonymous visitors'} cannot read A's private rows through it`,
        v.ok,
      );
    }
    const upd = has('update');
    if (upd) {
      body.push(AS.B);
      attempt(`update ${t} set ${m} = ${str(tamper(rows.update))} where ${m} = ${str(rows.update)}`);
      body.push(AS.A);
      test(visible(where(rows.update)), `${r.table}: B cannot modify A's rows`, upd.ok);
    }
    const take = has('takeover');
    if (take) {
      body.push(AS.B);
      attempt(`update ${t} set ${ident(r.owner)} = ${str(B_ID)} where ${m} = ${str(rows.takeover)}`);
      body.push(AS.A);
      test(visible(where(rows.takeover, ownedByA)), `${r.table}: B cannot reassign A's rows to itself`, take.ok);
    }
    const forge = has('forge');
    if (forge) {
      const row = rowFor(forged);
      body.push(AS.B);
      attempt(`insert into ${t} (${row.cols}) values ${row.vals}`);
      body.push('reset role;');
      test(`not exists (${where(forged)})`, `${r.table}: B cannot insert rows as A`, forge.ok);
    }
    const del = has('delete');
    if (del) {
      body.push(AS.B);
      attempt(`delete from ${t} where ${m} = ${str(rows.delete)}`);
      body.push(AS.A);
      test(visible(where(rows.delete)), `${r.table}: B cannot delete A's rows`, del.ok);
    }
    r.escalations.forEach((e, i) => {
      const mk = rows[`esc${i}`];
      body.push(AS.A);
      attempt(`update ${t} set ${ident(e.column)} = ${lit(e.value)} where ${m} = ${str(mk)}`);
      body.push('reset role;');
      const same = e.before === null || e.before === undefined ? `${ident(e.column)} is null` : `${ident(e.column)} = ${lit(e.before)}`;
      test(`exists (${where(mk, ` and ${same}`)})`, `${r.table}: users cannot change their own ${e.column}`, e.ok);
    });
  }

  return [
    `-- accessprobe RLS regression tests${version ? ` (accessprobe ${version})` : ''}`,
    `-- Generated ${date.slice(0, 10)} from a run against ${target || 'a Supabase project'}.`,
    '--',
    '-- Run them with: supabase test db',
    '-- Every test states the secure behaviour. Tests marked "FAILS until the fix" belong to leaks',
    '-- accessprobe proved; they turn green once the fix from its report is applied, and then keep',
    '-- the leak from coming back. Everything runs in one transaction and is rolled back.',
    '-- Re-generate after schema changes: npx accessprobe --source . --pgtap <this file>',
    '',
    'begin;',
    'create extension if not exists pgtap with schema extensions;',
    `select plan(${count});`,
    '',
    '-- two test users, and helpers that run SQL as the current role',
    `insert into auth.users (id, email, aud, role, raw_app_meta_data, raw_user_meta_data) values`,
    `  (${str(A_ID)}, 'accessprobe-a@example.test', 'authenticated', 'authenticated', '{}', '{}'),`,
    `  (${str(B_ID)}, 'accessprobe-b@example.test', 'authenticated', 'authenticated', '{}', '{}');`,
    'create schema accessprobe_t;',
    'create procedure accessprobe_t.attempt(sql text) language plpgsql as $$',
    'begin execute sql; exception when others then null; end $$;',
    'create function accessprobe_t.visible(sql text) returns boolean language plpgsql as $$',
    'declare found boolean;',
    "begin execute format('select exists (%s)', sql) into found; return found;",
    'exception when insufficient_privilege then return false; end $$;',
    'grant usage on schema accessprobe_t to anon, authenticated;',
    'grant execute on procedure accessprobe_t.attempt(text) to anon, authenticated;',
    'grant execute on function accessprobe_t.visible(text) to anon, authenticated;',
    ...body,
    '',
    'reset role;',
    'select * from finish();',
    'rollback;',
    '',
  ].join('\n');
}

const VERSION = JSON.parse(readFileSync(new URL('../../../package.json', import.meta.url), 'utf8')).version;

// writes the file and returns a one-line message for the user
export async function writePgtap(file, result) {
  const sql = pgtapTests(result.recipes, { version: VERSION, target: result.target, date: result.date });
  if (!sql) return `No pgTAP tests written to ${file}: no Supabase table could be replayed (needs a table where user A created a row with a text column).`;
  await mkdir(dirname(file), { recursive: true });
  await writeFile(file, sql, 'utf8');
  const tests = Number(/select plan\((\d+)\)/.exec(sql)[1]);
  const failing = (sql.match(/FAILS until the fix/g) || []).length;
  return `pgTAP tests written to ${file}: ${tests} tests${failing ? `, ${failing} of them fail until the leaks are fixed` : ''}. Run them with: supabase test db`;
}
