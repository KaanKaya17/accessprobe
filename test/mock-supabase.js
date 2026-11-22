// A deliberately VULNERABLE fake Supabase (PostgREST + Auth + Storage subset)
// with the mistakes AI app builders make most often. Used by tests and `npm run demo`.
//
//   profiles   — policy "authenticated can read all"        → cross-user read
//   orders     — read all + insert without owner check      → cross-user read + impersonation
//   notes      — correct owner-only policies                → should PASS
//   products   — public catalog, anon read                  → warning only
//   api_logs   — RLS disabled                               → anon read/write
//   avatars    — bucket: anon can list, anyone can download → storage leaks
//   documents  — bucket: owner folder only                  → should PASS
//   site JS    — ships the service_role key                 → leaked key
//   memberships   — "update own row" also covers plan/is_admin → self-escalation
//   subscriptions — plan column not updatable (column grant)    → should PASS
//   notes_feed    — view without security_invoker over notes    → view bypasses RLS
//   my_notes      — view with security_invoker over notes       → should PASS

import { randomUUID } from 'node:crypto';
import http from 'node:http';
import { pathToFileURL } from 'node:url';

const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
const jwt = (payload) => `${b64({ alg: 'HS256', typ: 'JWT' })}.${b64(payload)}.${'s'.repeat(43)}`;
const parse = (t) => {
  try {
    return JSON.parse(Buffer.from(t.split('.')[1], 'base64url').toString());
  } catch {
    return null;
  }
};

export const ANON_KEY = jwt({ iss: 'supabase', ref: 'mockmockmockmockmock', role: 'anon' });
export const SERVICE_KEY = jwt({ iss: 'supabase', ref: 'mockmockmockmockmock', role: 'service_role' });

const own = (ctx, row, col = 'user_id') => ctx.uid && row[col] === ctx.uid;
const authed = (ctx) => ctx.role === 'authenticated';

function makeState() {
  const u1 = randomUUID();
  const u2 = randomUUID();
  // like a real app's current_user_id(): auth.uid() → app_users.user_id
  const appId = (c) => c.uid && S.tables.app_users.rows.find((r) => r.auth_id === c.uid)?.user_id;
  const mineApp = (c, r) => appId(c) !== undefined && String(r.user_id) === String(appId(c));
  const ownApp = () => ({ select: mineApp, insert: mineApp, update: mineApp, delete: mineApp });
  const membership = (c, org) => c.uid && S.tables.org_members.rows.find((m) => m.org_id === org && m.user_id === c.uid);
  const member = (c, org) => Boolean(membership(c, org));
  const admin = (c, org) => ['owner', 'admin'].includes(membership(c, org)?.role);
  const S = {
    users: new Map(), // email -> {id, password}
    tables: {
      profiles: {
        columns: { id: ['uuid', { pk: true, required: true, fk: 'users' }], email: ['text'], full_name: ['text'] },
        rls: {
          select: (c) => authed(c), // BUG: auth.role() = 'authenticated'
          insert: (c, r) => own(c, r, 'id'),
          update: (c, r) => own(c, r, 'id'),
          delete: (c, r) => own(c, r, 'id'),
        },
        rows: [
          { id: u1, email: 'alice@real-customer.com', full_name: 'Alice' },
          { id: u2, email: 'bob@real-customer.com', full_name: 'Bob' },
        ],
      },
      orders: {
        columns: {
          id: ['uuid', { pk: true, default: true }],
          user_id: ['uuid', { required: true }],
          total: ['numeric', { required: true }],
          note: ['text'],
        },
        rls: {
          select: (c) => authed(c), // BUG
          insert: (c) => authed(c), // BUG: no "with check (user_id = auth.uid())"
          update: (c, r) => own(c, r),
          delete: (c, r) => own(c, r),
        },
        rows: [{ id: randomUUID(), user_id: u1, total: 120, note: 'real order' }],
      },
      notes: {
        columns: {
          id: ['bigint', { pk: true, default: true }],
          user_id: ['uuid', { required: true }],
          body: ['text', { required: true }],
        },
        rls: {
          select: (c, r) => own(c, r),
          insert: (c, r) => own(c, r),
          update: (c, r) => own(c, r),
          delete: (c, r) => own(c, r),
        },
        rows: [{ id: 1, user_id: u1, body: 'private note' }],
      },
      products: {
        columns: { id: ['bigint', { pk: true, default: true }], name: ['text', { required: true }], price: ['numeric'] },
        rls: { select: () => true, insert: () => false, update: () => false, delete: () => false },
        rows: [{ id: 1, name: 'T-shirt', price: 20 }],
      },
      // real-app style: own users table with bigint ids, other tables point at it
      app_users: {
        columns: { user_id: ['bigint', { pk: true, default: true }], auth_id: ['uuid'], email: ['text'] },
        rls: {
          select: (c, r) => c.uid && r.auth_id === c.uid,
          insert: () => false,
          update: () => false,
          delete: () => false,
        },
        rows: [{ user_id: 1, auth_id: u1, email: 'alice@real-customer.com' }],
      },
      workouts: {
        columns: {
          id: ['bigint', { pk: true, default: true }],
          user_id: ['bigint', { required: true, fk: 'app_users', fkCol: 'user_id' }],
          name: ['text', { required: true }],
        },
        rls: ownApp(),
        rows: [{ id: 1, user_id: 1, name: 'leg day' }],
      },
      messages: {
        columns: {
          id: ['bigint', { pk: true, default: true }],
          user_id: ['bigint', { required: true, fk: 'app_users', fkCol: 'user_id' }],
          body: ['text', { required: true }],
        },
        rls: { ...ownApp(), select: (c) => authed(c) }, // BUG: read-all
        rows: [{ id: 1, user_id: 1, body: 'hi' }],
      },
      api_logs: {
        columns: { id: ['bigint', { pk: true, default: true }], message: ['text'], ip: ['text'] },
        rls: null, // RLS DISABLED
        rows: [{ id: 1, message: 'login', ip: '1.2.3.4' }],
      },
      // intended: strangers may sign the guestbook and read it, but not delete entries
      guestbook: {
        columns: { id: ['bigint', { pk: true, default: true }], message: ['text', { required: true }] },
        rls: { select: () => true, insert: () => true, update: () => false, delete: () => false },
        rows: [],
      },
      // ---- organizations: orgs, org_members (org_id, user_id, role), tables scoped by org_id
      orgs: {
        columns: { id: ['bigint', { pk: true, default: true }], name: ['text', { required: true }], created_by: ['uuid', { required: true }] },
        rls: { select: (c, r) => member(c, r.id) || own(c, r, 'created_by'), insert: (c, r) => own(c, r, 'created_by'), update: (c, r) => admin(c, r.id), delete: (c, r) => own(c, r, 'created_by') },
        rows: [],
      },
      org_members: {
        returningSnapshot: true,
        columns: { org_id: ['bigint', { pk: true, required: true, fk: 'orgs' }], user_id: ['uuid', { pk: true, required: true }], role: ['text'] },
        rls: {
          select: (c, r) => member(c, r.org_id),
          // BUG: "users insert their own membership" lets anyone join any org (as owner, even)
          insert: (c, r) => own(c, r) || admin(c, r.org_id),
          // BUG: "users update their own membership" lets members change their role
          update: (c, r) => own(c, r) || admin(c, r.org_id),
          delete: (c, r) => own(c, r) || admin(c, r.org_id),
        },
        rows: [],
      },
      // CORRECT: members only, read from the membership table
      projects: {
        columns: { id: ['bigint', { pk: true, default: true }], org_id: ['bigint', { required: true, fk: 'orgs' }], name: ['text', { required: true }] },
        rls: { select: (c, r) => member(c, r.org_id), insert: (c, r) => member(c, r.org_id), update: (c, r) => member(c, r.org_id), delete: (c, r) => admin(c, r.org_id) },
        rows: [],
      },
      // BUG: readable by every signed-in user
      invoices: {
        columns: { id: ['bigint', { pk: true, default: true }], org_id: ['bigint', { required: true, fk: 'orgs' }], label: ['text', { required: true }] },
        rls: { select: (c) => authed(c), insert: (c, r) => member(c, r.org_id), update: (c, r) => member(c, r.org_id), delete: (c, r) => admin(c, r.org_id) },
        rows: [],
      },
      // CORRECT, and nested: points at an invoice, no text column (recognized by its primary key)
      invoice_lines: {
        columns: {
          id: ['bigint', { pk: true, default: true }],
          org_id: ['bigint', { required: true, fk: 'orgs' }],
          invoice_id: ['bigint', { required: true, fk: 'invoices' }],
          amount: ['numeric', { required: true }],
        },
        rls: { select: (c, r) => member(c, r.org_id), insert: (c, r) => member(c, r.org_id), update: (c, r) => member(c, r.org_id), delete: (c, r) => admin(c, r.org_id) },
        rows: [],
      },
      // BUG: membership from the JWT (app_metadata.orgs): a removed member keeps access until the token is refreshed
      org_files: {
        columns: { id: ['bigint', { pk: true, default: true }], org_id: ['bigint', { required: true, fk: 'orgs' }], path: ['text', { required: true }] },
        rls: { select: (c, r) => c.orgs?.includes(r.org_id) || member(c, r.org_id), insert: (c, r) => member(c, r.org_id), update: (c, r) => member(c, r.org_id), delete: (c, r) => admin(c, r.org_id) },
        rows: [],
      },
      // composite primary key: a filter on team_id alone would hit OTHER members of team 1
      team_members: {
        columns: { team_id: ['bigint', { pk: true, required: true }], user_id: ['uuid', { pk: true, required: true }], role: ['text'] },
        // BUG: every member list is visible to all, and anyone may delete
        rls: { select: (c) => authed(c), insert: (c, r) => own(c, r), update: (c, r) => own(c, r), delete: () => true },
        rows: [
          { team_id: 1, user_id: u1, role: 'owner' },
          { team_id: 1, user_id: u2, role: 'member' },
        ],
      },
      // BUG: USING (true) lets B reach A's rows; WITH CHECK only checks the NEW owner → takeover
      docs: {
        columns: { id: ['bigint', { pk: true, default: true }], user_id: ['uuid', { required: true }], title: ['text'] },
        // shared reading (USING true for select + update) — Postgres needs the row to be SELECT-visible
        rls: { select: (c) => authed(c), insert: (c, r) => own(c, r), update: (c) => authed(c), delete: (c, r) => own(c, r), updateCheck: (c, r) => own(c, r) },
        rows: [],
      },
      // RLS would allow B's update, but a trigger rejects every update → must be inconclusive, not PASS
      audit_notes: {
        columns: { id: ['bigint', { pk: true, default: true }], user_id: ['uuid', { required: true }], note: ['text'] },
        rls: { select: (c) => authed(c), insert: (c, r) => own(c, r), update: (c) => authed(c), delete: (c, r) => own(c, r) },
        updateTriggerError: true,
        rows: [],
      },
      // correct policies + varchar(18), exactly the marker length: a longer tampered marker must not fake a PASS
      short_codes: {
        columns: { id: ['bigint', { pk: true, default: true }], user_id: ['uuid', { required: true }], code: ['character varying', { maxLen: 18 }] },
        rls: { select: (c, r) => own(c, r), insert: (c, r) => own(c, r), update: (c, r) => own(c, r), delete: (c, r) => own(c, r) },
        rows: [],
      },
      // BUG: users may update their own row, including plan and is_admin
      memberships: {
        columns: {
          id: ['bigint', { pk: true, default: true }],
          user_id: ['uuid', { required: true }],
          nickname: ['text'],
          plan: ['text', { defVal: 'free' }],
          is_admin: ['boolean', { defVal: false }],
        },
        rls: { select: (c, r) => own(c, r), insert: (c, r) => own(c, r), update: (c, r) => own(c, r), delete: (c, r) => own(c, r) },
        rows: [],
      },
      // correct: own-row policies, and plan is left out of the UPDATE grant
      subscriptions: {
        columns: {
          id: ['bigint', { pk: true, default: true }],
          user_id: ['uuid', { required: true }],
          label: ['text'],
          plan: ['text', { defVal: 'free' }],
        },
        rls: { select: (c, r) => own(c, r), insert: (c, r) => own(c, r), update: (c, r) => own(c, r), delete: (c, r) => own(c, r) },
        lockedCols: ['plan'],
        rows: [],
      },
      // no primary key and no text column: accessprobe must not guess a filter
      counters: {
        columns: { user_id: ['uuid', { required: true }], value: ['integer'] },
        rls: {
          select: (c, r) => own(c, r),
          insert: (c, r) => own(c, r),
          update: (c, r) => own(c, r),
          delete: (c, r) => own(c, r),
        },
        rows: [],
      },
    },
    // views: security definer (the default) skips the base table's RLS; security_invoker applies it
    views: {
      notes_feed: { base: 'notes', invoker: false },
      my_notes: { base: 'notes', invoker: true },
    },
    // RPCs readable with GET: a SECURITY DEFINER one skips the table's RLS, an invoker one applies it
    functions: {
      all_notes: { base: 'notes', definer: true }, // BUG: returns every user's notes
      notes_of_mine: { base: 'notes', definer: false },
    },
    seq: 100,
    buckets: {
      avatars: {
        list: () => true, // BUG: anon can list
        read: () => true, // BUG: anyone can read
        insert: (c, p) => c.uid && p.startsWith(`${c.uid}/`),
        delete: (c, p) => c.uid && p.startsWith(`${c.uid}/`),
        objects: new Map([[`${u1}/face.png`, 'png']]),
      },
      documents: {
        list: (c, prefix) => c.uid && prefix.startsWith(c.uid),
        read: (c, p) => c.uid && p.startsWith(`${c.uid}/`),
        insert: (c, p) => c.uid && p.startsWith(`${c.uid}/`),
        delete: (c, p) => c.uid && p.startsWith(`${c.uid}/`),
        objects: new Map([[`${u1}/contract.pdf`, 'pdf']]),
      },
      'public-assets': {
        public: true, // reading by URL is the point
        list: () => false,
        read: () => true,
        insert: (c, p) => c.uid && p.startsWith(`${c.uid}/`),
        delete: (c, p) => c.uid && p.startsWith(`${c.uid}/`),
        objects: new Map(),
      },
    },
  };
  return S;
}

function openapi(S) {
  const definitions = {};
  const paths = { '/': {}, '/rpc/delete_everything': { post: {} } };
  for (const name of Object.keys(S.functions)) paths[`/rpc/${name}`] = { get: {}, post: {} };
  for (const [name, t] of Object.entries(S.tables)) {
    const properties = {};
    const required = [];
    for (const [col, [format, o = {}]] of Object.entries(t.columns)) {
      let description = '';
      if (o.pk) description += 'Note:\nThis is a Primary Key.<pk/>';
      if (o.fk) description += `\nThis is a Foreign Key to \`${o.fk}.id\`.<fk table='${o.fk}' column='${o.fkCol || 'id'}'/>`;
      properties[col] = { format, type: /uuid|text/.test(format) ? 'string' : format === 'bigint' ? 'integer' : 'number', ...(description && { description }) };
      if (o.default) properties[col].default = 'gen';
      if (o.required) required.push(col);
    }
    definitions[name] = { type: 'object', properties, required };
    paths[`/${name}`] = { get: {}, post: {}, patch: {}, delete: {} };
  }
  for (const [name, v] of Object.entries(S.views)) {
    definitions[name] = { ...definitions[v.base] };
    paths[`/${name}`] = { get: {} };
  }
  return { swagger: '2.0', info: { title: 'mock' }, paths, definitions };
}

function ctxFrom(req) {
  const auth = (req.headers.authorization || '').replace(/^Bearer /, '');
  const p = parse(auth);
  if (!p) return { role: 'anon' };
  if (p.role === 'service_role') return { role: 'service_role', bypass: true };
  return { role: p.role, uid: p.sub, orgs: p.app_metadata?.orgs || [] };
}

const allow = (t, op, ctx, row) => ctx.bypass || !t.rls || t.rls[op](ctx, row);

function filters(sp) {
  const fs = [];
  for (const [k, v] of sp) {
    if (['select', 'limit', 'offset', 'order'].includes(k)) continue;
    const m = v.match(/^(eq|neq)\.(.*)$/);
    if (m) fs.push((row) => (m[1] === 'eq' ? String(row[k]) === m[2] : String(row[k]) !== m[2]));
  }
  return (row) => fs.every((f) => f(row));
}

async function body(req) {
  let s = '';
  for await (const ch of req) s += ch;
  return s;
}

export function createServer({ autoconfirm = true } = {}) {
  const S = makeState();
  S.signups = 0;
  const site = `<!doctype html><html><head><script type="module" src="/assets/index-abc123.js"></script></head><body><div id="root"></div></body></html>`;

  const server = http.createServer(async (req, res) => {
    const port = req.socket.localPort;
    const send = (status, data, headers = {}) => {
      res.writeHead(status, { 'Content-Type': 'application/json', ...headers });
      res.end(data === undefined ? '' : typeof data === 'string' ? data : JSON.stringify(data));
    };
    const u = new URL(req.url, `http://localhost:${port}`);
    const ctx = ctxFrom(req);

    // ---------- the "deployed app" ----------
    if (u.pathname === '/') return send(200, site, { 'Content-Type': 'text/html' });
    if (u.pathname.startsWith('/assets/')) {
      const js = `import{createClient as c}from"./vendor.js";const sb=c("http://localhost:${port}","${ANON_KEY}");const admin=c("http://localhost:${port}","${SERVICE_KEY}");export{sb,admin};`;
      return send(200, js, { 'Content-Type': 'application/javascript' });
    }

    // ---------- auth ----------
    if (u.pathname === '/auth/v1/settings' && req.method === 'GET') {
      return send(200, { disable_signup: false, mailer_autoconfirm: autoconfirm, phone_autoconfirm: false, external: { email: true } });
    }
    if (u.pathname === '/auth/v1/signup' && req.method === 'POST') {
      S.signups++;
      const { email, password } = JSON.parse(await body(req));
      if (S.users.has(email)) return send(422, { msg: 'User already registered' });
      const id = randomUUID();
      S.users.set(email, { id, password });
      S.tables.app_users.rows.push({ user_id: ++S.seq, auth_id: id, email }); // signup trigger
      return send(200, { id, email });
    }
    if (u.pathname === '/auth/v1/token' && req.method === 'POST') {
      const { email, password } = JSON.parse(await body(req));
      const user = S.users.get(email);
      if (!user || user.password !== password) return send(400, { error: 'invalid_grant', error_description: 'Invalid login credentials' });
      return send(200, { access_token: jwt({ sub: user.id, role: 'authenticated', email, app_metadata: { orgs: S.tables.org_members.rows.filter((m) => m.user_id === user.id).map((m) => m.org_id) } }), user: { id: user.id, email } });
    }

    // ---------- PostgREST ----------
    if (u.pathname === '/rest/v1/' && req.method === 'GET') return send(200, openapi(S));
    // pg_graphql: introspection lists every table the role may select (rows would still be RLS-filtered)
    if (u.pathname === '/graphql/v1' && req.method === 'POST') {
      const { query } = JSON.parse((await body(req)) || '{}');
      if (!/__schema/.test(query || '')) return send(200, { errors: [{ message: 'mock: introspection only' }] });
      const fields = [{ name: 'node' }, ...Object.keys(S.tables).filter((n) => n !== 'counters').map((n) => ({ name: `${n}Collection` }))];
      return send(200, { data: { __schema: { queryType: { fields } } } });
    }
    const fm = u.pathname.match(/^\/rest\/v1\/rpc\/([a-z_]+)$/);
    if (fm) {
      const fn = S.functions[fm[1]];
      if (!fn) return send(404, { code: 'PGRST202', message: `Could not find the function public.${fm[1]} without parameters` });
      if (req.method !== 'GET') return send(405, { message: 'mock: functions are read-only' });
      const b = S.tables[fn.base];
      return send(200, b.rows.filter((r) => fn.definer || allow(b, 'select', ctx, r)));
    }
    const tm = u.pathname.match(/^\/rest\/v1\/([a-z_]+)$/);
    if (tm) {
      const view = S.views[tm[1]];
      if (view) {
        if (req.method !== 'GET') return send(405, { code: '42809', message: 'cannot change a view' });
        const b = S.tables[view.base];
        const match = filters(u.searchParams);
        const rows = b.rows.filter((r) => (!view.invoker || allow(b, 'select', ctx, r)) && match(r));
        return send(200, rows, { 'Content-Range': `${rows.length ? `0-${rows.length - 1}` : '*'}/${rows.length}` });
      }
      const t = S.tables[tm[1]];
      if (!t) return send(404, { code: '42P01', message: `relation "public.${tm[1]}" does not exist` });
      const match = filters(u.searchParams);
      const ret = (req.headers.prefer || '').includes('return=representation');

      if (req.method === 'GET') {
        const visible = t.rows.filter((r) => allow(t, 'select', ctx, r) && match(r));
        const limit = Number(u.searchParams.get('limit') || 1000);
        const page = visible.slice(0, limit);
        return send(200, page, { 'Content-Range': `${page.length ? `0-${page.length - 1}` : '*'}/${visible.length}` });
      }
      const tooLong = (row) =>
        Object.entries(t.columns).find(([col, [, o = {}]]) => o.maxLen && typeof row[col] === 'string' && row[col].length > o.maxLen);
      const pkOf = Object.entries(t.columns).filter(([, [, o = {}]]) => o.pk).map(([c]) => c);
      if (req.method === 'POST') {
        const row = JSON.parse(await body(req));
        for (const [col, [format, o = {}]] of Object.entries(t.columns)) {
          if (row[col] === undefined && o.default) row[col] = format === 'uuid' ? randomUUID() : ++S.seq;
          if (row[col] === undefined && o.required) return send(400, { code: '23502', message: `null value in column "${col}"` });
          if (row[col] === undefined) row[col] = o.defVal ?? null; // PostgREST returns every column
        }
        const long = tooLong(row);
        if (long) return send(400, { code: '22001', message: `value too long for type character varying(${long[1][1].maxLen})` });
        if (pkOf.length && t.rows.some((r) => pkOf.every((c) => String(r[c]) === String(row[c]))))
          return send(409, { code: '23505', message: 'duplicate key value violates unique constraint' });
        if (!allow(t, 'insert', ctx, row))
          return send(403, { code: '42501', message: `new row violates row-level security policy for table "${tm[1]}"` });
        // like Postgres: RETURNING must pass the SELECT policy, and a STABLE helper such as
        // is_member_of() sees the table as it was before this statement
        if (ret && t.returningSnapshot && !allow(t, 'select', ctx, row))
          return send(403, { code: '42501', message: `new row violates row-level security policy for table "${tm[1]}"` });
        t.rows.push(row);
        return send(201, ret ? [row] : undefined);
      }
      if (req.method === 'PATCH') {
        const patch = JSON.parse(await body(req));
        const locked = (t.lockedCols || []).find((c) => c in patch);
        if (locked && !ctx.bypass) return send(403, { code: '42501', message: `permission denied for table ${tm[1]}` });
        // USING (old row) decides which rows are reachable; WITH CHECK (new row) must hold afterwards
        const hit = t.rows.filter((r) => allow(t, 'select', ctx, r) && allow(t, 'update', ctx, r) && match(r));
        for (const r of hit) {
          const next = { ...r, ...patch };
          if (t.rls?.updateCheck && !ctx.bypass && !t.rls.updateCheck(ctx, next))
            return send(403, { code: '42501', message: `new row violates row-level security policy for table "${tm[1]}"` });
          const long = tooLong(next);
          if (long) return send(400, { code: '22001', message: `value too long for type character varying(${long[1][1].maxLen})` });
          if (t.updateTriggerError && hit.length) return send(400, { code: 'P0001', message: 'audit trigger: updates are not allowed' });
        }
        hit.forEach((r) => Object.assign(r, patch));
        return send(200, ret ? hit : undefined);
      }
      if (req.method === 'DELETE') {
        const hit = t.rows.filter((r) => allow(t, 'select', ctx, r) && allow(t, 'delete', ctx, r) && match(r));
        t.rows = t.rows.filter((r) => !hit.includes(r));
        return send(200, ret ? hit : undefined);
      }
    }

    // ---------- Storage ----------
    if (u.pathname === '/storage/v1/bucket' && req.method === 'GET') {
      return send(200, ctx.uid ? Object.entries(S.buckets).map(([n, b]) => ({ id: n, name: n, public: Boolean(b.public) })) : []);
    }
    let m = u.pathname.match(/^\/storage\/v1\/object\/list\/([^/]+)$/);
    if (m && req.method === 'POST') {
      const b = S.buckets[m[1]];
      if (!b) return send(404, { error: 'Bucket not found' });
      const { prefix = '' } = JSON.parse(await body(req));
      if (!b.list(ctx, prefix)) return send(200, []);
      const names = [...b.objects.keys()].filter((p) => p.startsWith(prefix)).map((p) => ({ name: p.slice(prefix.length).replace(/^\//, '') }));
      return send(200, names);
    }
    m = u.pathname.match(/^\/storage\/v1\/object\/public\/([^/]+)\/(.+)$/);
    if (m && req.method === 'GET') {
      const b = S.buckets[m[1]];
      const p = decodeURIComponent(m[2]);
      if (!b || !b.public || !b.objects.has(p)) return send(400, { error: 'not_found', message: 'Object not found' });
      return send(200, b.objects.get(p), { 'Content-Type': 'text/plain' });
    }
    m = u.pathname.match(/^\/storage\/v1\/object\/authenticated\/([^/]+)\/(.+)$/);
    if (m && req.method === 'GET') {
      const b = S.buckets[m[1]];
      const p = decodeURIComponent(m[2]);
      if (!b || !b.objects.has(p) || !b.read(ctx, p)) return send(400, { error: 'not_found', message: 'Object not found' });
      return send(200, b.objects.get(p), { 'Content-Type': 'text/plain' });
    }
    m = u.pathname.match(/^\/storage\/v1\/object\/([^/]+)\/(.+)$/);
    if (m && req.method === 'POST') {
      const b = S.buckets[m[1]];
      const p = decodeURIComponent(m[2]);
      const content = await body(req);
      if (!b || !b.insert(ctx, p)) return send(400, { statusCode: '403', error: 'Unauthorized', message: 'new row violates row-level security policy' });
      b.objects.set(p, content);
      return send(200, { Key: `${m[1]}/${p}` });
    }
    m = u.pathname.match(/^\/storage\/v1\/object\/([^/]+)$/);
    if (m && req.method === 'DELETE') {
      const b = S.buckets[m[1]];
      const { prefixes = [] } = JSON.parse(await body(req));
      const done = prefixes.filter((p) => b && b.objects.has(p) && b.delete(ctx, p));
      done.forEach((p) => b.objects.delete(p));
      return send(200, done.map((name) => ({ name })));
    }

    send(404, { message: 'not found' });
  });
  server.stats = () => ({ signups: S.signups });
  return server;
}

// `node test/mock-supabase.js` → starts the demo on :54399
if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  const port = Number(process.env.PORT || 54399);
  createServer().listen(port, () => {
    console.log(`Vulnerable demo app + fake Supabase on http://localhost:${port}`);
    console.log('Now run:  npm run demo');
  });
}
