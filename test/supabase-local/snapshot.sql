-- Fingerprint of everything a --read-only run must leave untouched: the content of every
-- public table, storage objects and auth users. Used by the real-supabase CI job.
select string_agg(t.table_name || '=' || t.h, ' ' order by t.table_name)
from (
  select table_name,
         (xpath('/row/h/text()', query_to_xml(format(
           'select md5(coalesce(string_agg(x::text, %L order by x::text), %L)) as h from public.%I x', ',', '', table_name),
           false, true, '')))[1]::text as h
  from information_schema.tables
  where table_schema = 'public' and table_type = 'BASE TABLE'
  union all
  select 'storage.objects', (select md5(coalesce(string_agg(id::text || name, ',' order by id::text), '')) from storage.objects)
  union all
  select 'auth.users', (select md5(coalesce(string_agg(id::text || coalesce(email, ''), ',' order by id::text), '')) from auth.users)
) t;
