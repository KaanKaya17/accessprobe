-- A small app for accessprobe's real-Postgres test (supabase start in CI).
-- Every table/view is either deliberately broken or deliberately correct.

-- CORRECT: owner-only for everything.
create table public.notes (
  id bigint generated always as identity primary key,
  user_id uuid not null default auth.uid() references auth.users(id) on delete cascade,
  body text
);
alter table public.notes enable row level security;
create policy notes_own on public.notes for all to authenticated
  using ((select auth.uid()) = user_id) with check ((select auth.uid()) = user_id);

-- BROKEN: every signed-in user reads all orders and may create one in anyone's name.
create table public.orders (
  id bigint generated always as identity primary key,
  user_id uuid not null references auth.users(id) on delete cascade,
  note text
);
alter table public.orders enable row level security;
create policy orders_read_all on public.orders for select to authenticated using (true);
create policy orders_insert_any on public.orders for insert to authenticated with check (true);
create policy orders_update_own on public.orders for update to authenticated
  using ((select auth.uid()) = user_id) with check ((select auth.uid()) = user_id);
create policy orders_delete_own on public.orders for delete to authenticated using ((select auth.uid()) = user_id);

-- BROKEN: owner-only, but "update own row" also covers plan and is_admin.
create table public.memberships (
  id bigint generated always as identity primary key,
  user_id uuid not null references auth.users(id) on delete cascade,
  nickname text,
  plan text not null default 'free',
  is_admin boolean not null default false
);
alter table public.memberships enable row level security;
create policy memberships_own on public.memberships for all to authenticated
  using ((select auth.uid()) = user_id) with check ((select auth.uid()) = user_id);

-- CORRECT: owner-only, and users may only update the label column.
create table public.subscriptions (
  id bigint generated always as identity primary key,
  user_id uuid not null references auth.users(id) on delete cascade,
  label text,
  plan text not null default 'free'
);
alter table public.subscriptions enable row level security;
create policy subscriptions_own on public.subscriptions for all to authenticated
  using ((select auth.uid()) = user_id) with check ((select auth.uid()) = user_id);
revoke update on public.subscriptions from anon, authenticated;
grant update (label) on public.subscriptions to authenticated;

-- BROKEN: a plain view runs as its owner (postgres) and skips the RLS of notes.
create view public.notes_feed as select id, user_id, body from public.notes;

-- CORRECT: security_invoker makes the view apply the caller's RLS.
create view public.my_notes with (security_invoker = true) as select id, user_id, body from public.notes;

grant select on public.notes_feed, public.my_notes to anon, authenticated;
