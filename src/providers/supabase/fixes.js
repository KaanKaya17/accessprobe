// Fix SQL + copy-paste prompts for AI builders (Lovable, Bolt, Cursor, Claude Code).

const q = (ident) => `"${ident.replace(/"/g, '""')}"`;

// me: SQL expression for "the signed-in user's id as stored in ownerCol"
export function ownerPolicies(table, ownerCol, ops = ['select', 'insert', 'update', 'delete'], me = '(select auth.uid())') {
  const t = `public.${q(table)}`;
  const o = q(ownerCol);
  const lines = [
    `-- ${table}: only the owner (${ownerCol} = ${me}) may access a row`,
    `alter table ${t} enable row level security;`,
    '',
    '-- remove permissive policies first (check their names in Dashboard → Authentication → Policies)',
    `-- drop policy if exists "<old policy name>" on ${t};`,
    '',
  ];
  if (ops.includes('select'))
    lines.push(
      `create policy "${table}_select_own" on ${t}`,
      `  for select to authenticated using (${me} = ${o});`,
    );
  if (ops.includes('insert'))
    lines.push(
      `create policy "${table}_insert_own" on ${t}`,
      `  for insert to authenticated with check (${me} = ${o});`,
    );
  if (ops.includes('update'))
    lines.push(
      `create policy "${table}_update_own" on ${t}`,
      `  for update to authenticated using (${me} = ${o}) with check (${me} = ${o});`,
    );
  if (ops.includes('delete'))
    lines.push(
      `create policy "${table}_delete_own" on ${t}`,
      `  for delete to authenticated using (${me} = ${o});`,
    );
  return lines.join('\n');
}

export function enableRls(table) {
  return [
    `-- ${table}: RLS is off, so the public anon key can read/write everything`,
    `alter table public.${q(table)} enable row level security;`,
    '-- With RLS on and no policies, nobody (except service_role) can access the table.',
    '-- Then add only the policies you need, e.g. public read for a catalog:',
    `-- create policy "${table}_public_read" on public.${q(table)} for select to anon, authenticated using (true);`,
  ].join('\n');
}

export function noOwnerColumn(table) {
  return [
    `-- ${table}: no owner column found, so rows cannot be tied to a user.`,
    `alter table public.${q(table)} add column user_id uuid references auth.users(id) default auth.uid();`,
    '-- then apply owner-only policies (re-run accessprobe to get them)',
  ].join('\n');
}

// Users may update their row, but not these columns. Postgres column privileges do that:
// a column REVOKE is ignored while a table-wide UPDATE grant exists, so re-grant the rest.
export function privilegeFix(t, locked) {
  const tbl = `public.${q(t.name)}`;
  const rest = t.columns.filter((c) => !locked.includes(c.name) && !c.pk).map((c) => q(c.name));
  return [
    `-- ${t.name}: users may still edit their row, but not ${locked.join(', ')}`,
    `revoke update on ${tbl} from anon, authenticated;`,
    rest.length
      ? `grant update (${rest.join(', ')}) on ${tbl} to authenticated;`
      : `-- no other columns to allow: users can no longer update this table directly`,
    `-- Change ${locked.join(', ')} only from trusted code: an Edge Function / server route with the`,
    '-- service_role key, a payment webhook, or a SECURITY DEFINER function that checks the caller.',
    '-- Columns added later are not updatable until you add them to the grant above.',
  ].join('\n');
}

export function viewInvoker(view) {
  return [
    `-- ${view}: make the view respect the RLS policies of the tables it reads (Postgres 15+)`,
    `alter view public.${q(view)} set (security_invoker = true);`,
    '-- If the view must show data the tables hide (e.g. public profile fields), keep only those',
    '-- columns in it, or replace it with a SECURITY DEFINER function that checks auth.uid().',
  ].join('\n');
}

export function storagePolicies(bucket) {
  return [
    `-- bucket "${bucket}": each user may only touch files under "<their user id>/..."`,
    `create policy "${bucket}_own_files_select" on storage.objects for select to authenticated`,
    `  using (bucket_id = '${bucket}' and (storage.foldername(name))[1] = (select auth.uid())::text);`,
    `create policy "${bucket}_own_files_insert" on storage.objects for insert to authenticated`,
    `  with check (bucket_id = '${bucket}' and (storage.foldername(name))[1] = (select auth.uid())::text);`,
    `create policy "${bucket}_own_files_delete" on storage.objects for delete to authenticated`,
    `  using (bucket_id = '${bucket}' and (storage.foldername(name))[1] = (select auth.uid())::text);`,
    '-- and drop any policy that allows "select" on storage.objects for anon / all users.',
  ].join('\n');
}

// How fixes are presented in reports and AI prompts (used by core/report.js)
export const fixStyle = {
  lang: 'sql',
  codeLabel: 'Fix (SQL — run in the Supabase SQL editor or as a migration)',
  fixWhere: 'Please fix this at the database level (Row Level Security), not in the frontend.',
  codeIntro: 'Apply this SQL as a new migration (adjust names if needed):',
  dont: 'Do not disable RLS and do not use the service_role key in client code. Afterwards list every policy on this table so I can review it.',
  secretMove: 'Move every call that needs this secret into a Supabase Edge Function or server route.',
};
