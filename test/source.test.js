import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { scanSource, sourceToDefinitions } from '../src/source.js';
import { parseSchema } from '../src/schema.js';

test('reads tables, columns, keys and RPCs from migrations + app code', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'rlsprobe-'));
  try {
    await mkdir(join(dir, 'supabase', 'migrations'), { recursive: true });
    await mkdir(join(dir, 'app'));
    await writeFile(
      join(dir, 'supabase', 'migrations', '001.sql'),
      `-- comment, with (parens), and commas
create table if not exists public.users (
    user_id bigint generated always as identity primary key,
    email   varchar(255) not null,
    created_at timestamptz default current_timestamp
);
alter table public.users add column if not exists auth_id uuid unique references auth.users(id) on delete cascade;
create table public.meal_log (
    log_id   bigint generated always as identity primary key,
    user_id  bigint not null,
    calories integer not null check (calories between 0 and 10000),
    numbers  numeric(10, 2),
    constraint fk_user foreign key (user_id) references public.users(user_id) on delete cascade
);
create or replace function public.delete_my_account() returns void language sql as $$ select 1 $$;
grant execute on function public.delete_my_account() to authenticated;
create or replace function public.internal_only() returns void language sql as $$ select 1 $$;
`,
    );
    await writeFile(join(dir, 'app', 'Api.kt'), '@GET("rest/v1/meal_log") @POST("rest/v1/rpc/delete_my_account") supabase.from("notes")');

    const src = await scanSource(dir);
    const schema = parseSchema(sourceToDefinitions(src));
    const by = Object.fromEntries(schema.tables.map((t) => [t.name, t]));

    assert.deepEqual(Object.keys(by).sort(), ['meal_log', 'notes', 'users']);
    assert.equal(by.users.pk.name, 'user_id');
    assert.equal(by.users.owner.name, 'auth_id', 'column referencing auth.users is the owner');
    assert.deepEqual(by.meal_log.owner.fk, { table: 'users', column: 'user_id' });
    assert.equal(by.meal_log.pk.name, 'log_id');
    const cal = by.meal_log.columns.find((c) => c.name === 'calories');
    assert.equal(cal.format, 'integer');
    assert.equal(cal.required, true);
    assert.equal(by.meal_log.columns.find((c) => c.name === 'numbers').format, 'numeric');
    assert.equal(by.notes.nameOnly, true);
    assert.deepEqual(schema.rpcs, ['delete_my_account'], 'only functions granted to API roles');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
