-- The fixes accessprobe's report suggests for the fixture, as a user would apply them
-- (including dropping the permissive policies by name). After this, every generated pgTAP test passes.

-- orders: owner-only reads and inserts
drop policy orders_read_all on public.orders;
drop policy orders_insert_any on public.orders;
create policy orders_select_own on public.orders for select to authenticated using ((select auth.uid()) = user_id);
create policy orders_insert_own on public.orders for insert to authenticated with check ((select auth.uid()) = user_id);

-- memberships: users may edit their nickname, not plan / is_admin
revoke update on public.memberships from anon, authenticated;
grant update (user_id, nickname) on public.memberships to authenticated;

-- notes_feed: apply the caller's RLS
alter view public.notes_feed set (security_invoker = true);
