-- Organizations for accessprobe's real-Postgres test: orgs, org_members (org_id, user_id, role),
-- and tables scoped by org_id. Each part is deliberately broken or deliberately correct.

create table public.orgs (
  id bigint generated always as identity primary key,
  name text not null,
  created_by uuid not null default auth.uid() references auth.users(id) on delete cascade
);

create table public.org_members (
  org_id bigint not null references public.orgs(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  role text not null default 'member' check (role in ('owner', 'admin', 'member')),
  primary key (org_id, user_id)
);

-- membership helpers (SECURITY DEFINER so policies on org_members don't recurse; they check auth.uid())
create function public.is_member_of(_org bigint) returns boolean
  language sql stable security definer set search_path = ''
  as $$ select exists (select 1 from public.org_members where org_id = _org and user_id = (select auth.uid())) $$;
create function public.is_admin_of(_org bigint) returns boolean
  language sql stable security definer set search_path = ''
  as $$ select exists (select 1 from public.org_members where org_id = _org and user_id = (select auth.uid()) and role in ('owner', 'admin')) $$;

alter table public.orgs enable row level security;
create policy orgs_read on public.orgs for select to authenticated using ((select public.is_member_of(id)) or created_by = (select auth.uid()));
create policy orgs_create on public.orgs for insert to authenticated with check (created_by = (select auth.uid()));
create policy orgs_update on public.orgs for update to authenticated using ((select public.is_admin_of(id)));
create policy orgs_delete on public.orgs for delete to authenticated using (created_by = (select auth.uid()));

alter table public.org_members enable row level security;
-- CORRECT: members see the member list of their own organizations only
create policy members_read on public.org_members for select to authenticated using ((select public.is_member_of(org_id)));
-- CORRECT: admins add members; the creator of an org may add itself
create policy members_add on public.org_members for insert to authenticated with check (
  (select public.is_admin_of(org_id))
  or (user_id = (select auth.uid()) and exists (select 1 from public.orgs o where o.id = org_id and o.created_by = (select auth.uid())))
);
-- BROKEN: "users update their own membership" also lets a member change its own role
create policy members_update_own on public.org_members for update to authenticated using (user_id = (select auth.uid()));
create policy members_remove on public.org_members for delete to authenticated using ((select public.is_admin_of(org_id)) or user_id = (select auth.uid()));

-- custom claims: org ids in app_metadata.orgs, refreshed into the JWT at the next sign-in
create function public.sync_org_claims() returns trigger
  language plpgsql security definer set search_path = ''
  as $$
declare uid uuid := coalesce(new.user_id, old.user_id);
begin
  update auth.users
     set raw_app_meta_data = coalesce(raw_app_meta_data, '{}'::jsonb)
       || jsonb_build_object('orgs', coalesce((select jsonb_agg(m.org_id) from public.org_members m where m.user_id = uid), '[]'::jsonb))
   where id = uid;
  return null;
end $$;
create trigger org_claims after insert or delete on public.org_members for each row execute function public.sync_org_claims();

-- CORRECT: members only, read from the membership table
create table public.projects (
  id bigint generated always as identity primary key,
  org_id bigint not null references public.orgs(id) on delete cascade,
  name text not null
);
alter table public.projects enable row level security;
create policy projects_read on public.projects for select to authenticated using ((select public.is_member_of(org_id)));
create policy projects_add on public.projects for insert to authenticated with check ((select public.is_member_of(org_id)));
create policy projects_change on public.projects for update to authenticated using ((select public.is_member_of(org_id)));
create policy projects_delete on public.projects for delete to authenticated using ((select public.is_admin_of(org_id)));

-- BROKEN: every signed-in user reads every organization's invoices
create table public.invoices (
  id bigint generated always as identity primary key,
  org_id bigint not null references public.orgs(id) on delete cascade,
  label text not null
);
alter table public.invoices enable row level security;
create policy invoices_read on public.invoices for select to authenticated using (true);
create policy invoices_add on public.invoices for insert to authenticated with check ((select public.is_member_of(org_id)));
create policy invoices_change on public.invoices for update to authenticated using ((select public.is_member_of(org_id)));
create policy invoices_delete on public.invoices for delete to authenticated using ((select public.is_admin_of(org_id)));

-- BROKEN: also trusts the JWT claim, so a removed member keeps access until the token is refreshed
create table public.org_files (
  id bigint generated always as identity primary key,
  org_id bigint not null references public.orgs(id) on delete cascade,
  path text not null
);
alter table public.org_files enable row level security;
create policy org_files_read on public.org_files for select to authenticated using (
  org_id in (select (jsonb_array_elements_text(coalesce(auth.jwt() -> 'app_metadata' -> 'orgs', '[]'::jsonb)))::bigint)
  or (select public.is_member_of(org_id))
);
create policy org_files_add on public.org_files for insert to authenticated with check ((select public.is_member_of(org_id)));
create policy org_files_change on public.org_files for update to authenticated using ((select public.is_member_of(org_id)));
create policy org_files_delete on public.org_files for delete to authenticated using ((select public.is_admin_of(org_id)));
