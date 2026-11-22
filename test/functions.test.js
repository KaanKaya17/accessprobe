import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, ANON_KEY } from './mock-supabase.js';
import { scan } from '../src/core/scan.js';
import { parseFunctions, definerFindings } from '../src/providers/supabase/functions.js';
import { sensitiveColumns } from '../src/providers/supabase/columns.js';

const SQL = [
  {
    file: 'supabase/migrations/001_init.sql',
    text: `
create function public.get_everything() returns setof notes
language sql security definer as $$ select * from notes $$;

create or replace function list_mine() returns setof notes
language sql stable security definer set search_path = ''
as $fn$ select * from public.notes where user_id = (select auth.uid()) $fn$;

create function public.admin_only() returns void language plpgsql security definer as $$
begin delete from notes; end $$;
revoke execute on function public.admin_only() from public;

create function public.internal_job() returns void language sql security definer as $$ delete from notes $$;
revoke all on function public.internal_job() from anon, authenticated, public;

create function public.on_signup() returns trigger language plpgsql security definer as $$ begin return new; end $$;

create function public.safe_invoker() returns setof notes language sql as $$ select * from notes $$;
create function private.hidden() returns void language sql security definer as $$ select 1 $$;
`,
  },
  {
    file: 'supabase/migrations/002_more.sql',
    // replacing a function keeps its grants
    text: `create or replace function public.internal_job() returns void language sql security definer as $$ delete from notes $$;`,
  },
];

test('parseFunctions: definer, volatility, search_path, auth checks, grants, triggers, schemas', () => {
  const d = parseFunctions(SQL);
  assert.deepEqual([...d.keys()].sort(), ['admin_only', 'get_everything', 'internal_job', 'list_mine', 'on_signup', 'safe_invoker']);
  assert.equal(d.get('get_everything').securityDefiner, true);
  assert.equal(d.get('get_everything').checksAuth, false);
  assert.equal(d.get('get_everything').searchPath, false);
  assert.equal(d.get('list_mine').checksAuth, true);
  assert.equal(d.get('list_mine').volatility, 'stable');
  assert.equal(d.get('list_mine').searchPath, true);
  assert.equal(d.get('admin_only').anon, true, 'REVOKE … FROM public leaves the anon grant');
  assert.equal(d.get('admin_only').revokedFromPublicOnly, true);
  assert.equal(d.get('internal_job').anon, false, 'CREATE OR REPLACE keeps the revoke');
  assert.equal(d.get('internal_job').authenticated, false);
  assert.equal(d.get('on_signup').trigger, true);
  assert.equal(d.get('safe_invoker').securityDefiner, false);
});

test('parseFunctions: ALTER DEFAULT PRIVILEGES revoking execute from anon applies to later functions', () => {
  const d = parseFunctions([
    { file: 'a.sql', text: "alter default privileges in schema public revoke execute on functions from anon, public;\ncreate function f() returns int language sql security definer as $$ select 1 $$;" },
  ]);
  assert.equal(d.get('f').anon, false);
  assert.equal(d.get('f').authenticated, true);
});

test('definerFindings: only callable SECURITY DEFINER functions that never check the caller', () => {
  const f = definerFindings(parseFunctions(SQL));
  const warned = f.filter((x) => x.id === 'definer-no-auth-check').map((x) => x.resource).sort();
  assert.deepEqual(warned, ['admin_only', 'get_everything']);
  assert.match(f.find((x) => x.resource === 'admin_only').detail, /does not remove the anon/);
  assert.match(f.find((x) => x.resource === 'get_everything').fix.sql, /alter function public\.get_everything\(\) security invoker/);
  const sp = f.find((x) => x.id === 'definer-search-path');
  assert.equal(sp.severity, 'info');
  assert.ok(!sp.title.includes('list_mine') && !sp.title.includes('on_signup'));
  // not exposed by the live API, or already proven live: no static warning
  assert.equal(definerFindings(parseFunctions(SQL), { exposed: new Set(['list_mine']) }).filter((x) => x.id === 'definer-no-auth-check').length, 0);
  assert.ok(!definerFindings(parseFunctions(SQL), { proven: new Set(['get_everything']) }).some((x) => x.resource === 'get_everything' && x.id === 'definer-no-auth-check'));
});

test('sensitiveColumns: secrets vs personal data, by name', () => {
  assert.deepEqual(sensitiveColumns(['id', 'email', 'password_hash', 'stripe_customer_id', 'title', 'api_key', 'token_count', 'emailed_at']), {
    secret: ['password_hash', 'api_key'],
    personal: ['email', 'stripe_customer_id'],
  });
});

let server;
let result;
before(async () => {
  server = createServer();
  await new Promise((r) => server.listen(0, r));
  result = await scan({ url: `http://localhost:${server.address().port}`, anonKey: ANON_KEY, quiet: true, freshUsers: true });
});
after(() => server.close());

test('functions: a GET-readable RPC that returns A\'s private rows is a proven leak; an invoker one passes', () => {
  const b = result.findings.find((f) => f.id === 'rpc-cross-user-read' && f.resource === 'all_notes');
  const anon = result.findings.find((f) => f.id === 'rpc-anon-read' && f.resource === 'all_notes');
  assert.equal(b?.severity, 'critical');
  assert.equal(anon?.severity, 'critical');
  assert.match(b.evidence, /^as user B: GET \/rest\/v1\/rpc\/all_notes/);
  assert.ok(!result.findings.some((f) => f.resource === 'notes_of_mine'));
  assert.ok(result.passed.includes("notes_of_mine(): B gets none of A's private rows"));
  assert.ok(result.passed.includes("notes_of_mine(): anonymous visitors get none of A's private rows"));
});

test('graphql: anon introspection that lists tables is a warning with names only', () => {
  const g = result.findings.find((f) => f.id === 'graphql-anon-schema');
  assert.equal(g?.severity, 'warning');
  assert.match(g.title, /notes/);
  assert.match(g.fix.sql, /drop extension if exists pg_graphql/);
  assert.match(g.evidence, /^anonymous: POST \/graphql\/v1/);
});

test('parseFunctions: calling a helper that checks auth.uid() counts as checking the caller', () => {
  const d = parseFunctions([
    {
      file: 'x.sql',
      text: `create function public.current_user_id() returns bigint language sql stable security definer set search_path = '' as $$ select user_id from public.users where auth_id = auth.uid() $$;
create function public.consume_quota(n int default 60) returns boolean language plpgsql security definer set search_path = '' as $$ declare uid bigint := public.current_user_id(); begin return uid is not null; end $$;
create function public.wrapper() returns boolean language sql security definer set search_path = '' as $$ select public.consume_quota() $$;
create function public.my_current_user_id_copy() returns int language sql security definer set search_path = '' as $$ select 1 $$;`,
    },
  ]);
  assert.equal(d.get('consume_quota').checksAuth, true);
  assert.equal(d.get('consume_quota').authVia, 'current_user_id');
  assert.equal(d.get('wrapper').checksAuth, true, 'transitive');
  assert.equal(d.get('my_current_user_id_copy').checksAuth, false, 'a name containing the helper is not a call');
  assert.ok(!definerFindings(d).some((f) => f.id === 'definer-no-auth-check' && f.resource !== 'my_current_user_id_copy'));
});

test('rpcReview: functions the migrations show to be safe are a passed check, the rest are listed', async () => {
  const { rpcReview } = await import('../src/providers/supabase/probes.js');
  const functions = parseFunctions([
    {
      file: 'x.sql',
      text: `create function public.me() returns uuid language sql stable security definer set search_path = '' as $$ select auth.uid() $$;
create function public.quota(n int default 1) returns boolean language sql security definer set search_path = '' as $$ select public.me() is not null $$;
create function public.internal() returns void language sql security definer set search_path = '' as $$ select 1 $$;
revoke all on function public.internal() from public, anon;
create function public.open_one() returns int language sql security definer set search_path = '' as $$ select 1 $$;`,
    },
  ]);
  const passed = [];
  const f = rpcReview({ rpcs: ['me', 'quota', 'internal', 'open_one', 'unknown_fn'], functions }, passed);
  assert.equal(f.length, 1);
  assert.match(f[0].evidence, /open_one/);
  assert.match(f[0].evidence, /unknown_fn/);
  assert.doesNotMatch(f[0].evidence, /\bme\b|quota|internal/);
  assert.match(passed[0], /quota\(\) checks the caller via me\(\)/);
  assert.match(passed[0], /internal\(\) is not executable by anonymous visitors/);
  // no migrations: everything is listed, as before
  assert.match(rpcReview({ rpcs: ['me'] })[0].detail, /pass --source/);
});
