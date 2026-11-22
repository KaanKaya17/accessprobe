// Database functions exposed as RPC (POST /rest/v1/rpc/<fn>).
//
// 1) Live: every exposed function is called with GET and no arguments, as A (control), B and an
//    anonymous visitor. PostgREST runs GET in a READ ONLY transaction, so nothing can be written,
//    and a function that needs arguments is not called at all. If B or the visitor gets back one of
//    A's private test rows (a row B was refused through the table), the function leaks it: proven.
// 2) From the migrations: a SECURITY DEFINER function runs with its owner's rights and skips RLS.
//    One that never looks at the caller (auth.uid(), auth.jwt(), …) and that anon or authenticated
//    may execute is reported as a warning: accessprobe does not POST to it (it may change data).

const AUTH_CHECK = /auth\s*\.\s*(uid|jwt|role|email)\s*\(|current_setting\s*\(\s*'request\.jwt|request\.jwt\.claim|\bcurrent_user\b|\bsession_user\b|\bhas_(table|schema|function)_privilege\b/i;

const unq = (s) => s.replace(/"/g, '');

// one CREATE FUNCTION statement starting at `at`: { attrs (text outside the body), body, end }
function statementAt(text, at) {
  const dollar = /\$([A-Za-z_]\w*)?\$/g;
  dollar.lastIndex = at;
  const semi = text.indexOf(';', at);
  const open = dollar.exec(text);
  if (open && (semi === -1 || open.index < semi)) {
    const close = text.indexOf(open[0], open.index + open[0].length);
    if (close !== -1) {
      const after = text.indexOf(';', close + open[0].length);
      const end = after === -1 ? text.length : after;
      return {
        attrs: text.slice(at, open.index) + text.slice(close + open[0].length, end),
        body: text.slice(open.index + open[0].length, close),
        end,
      };
    }
  }
  const end = semi === -1 ? text.length : semi;
  return { attrs: text.slice(at, end), body: text.slice(at, end), end };
}

// [{ file, text }] in migration order → Map name → definition (the last CREATE OR REPLACE wins)
export function parseFunctions(sqlFiles = []) {
  const defs = new Map();
  let defaultAnon = true; // Supabase grants EXECUTE on new public functions to anon + authenticated
  let defaultAuth = true;
  const events = []; // creates and grant changes, in order
  for (const { file, text } of sqlFiles) {
    const mine = [];
    const header = /create\s+(?:or\s+replace\s+)?function\s+((?:"?\w+"?\s*\.\s*)?)"?(\w+)"?\s*\(([^)]*)\)/gi;
    for (const m of text.matchAll(header)) {
      const schema = m[1] ? unq(m[1]).replace(/\s*\.\s*$/, '') : 'public';
      if (schema !== 'public') continue;
      const st = statementAt(text, m.index);
      mine.push({ i: m.index, file, kind: 'create', name: m[2], args: m[3].trim(), st, line: text.slice(0, m.index).split('\n').length });
    }
    const revoke = /\b(revoke|grant)\s+(?:all(?:\s+privileges)?|execute)\s+on\s+(?:function\s+((?:"?\w+"?\s*\.\s*)?)"?(\w+)"?(?:\s*\([^)]*\))?|all\s+functions\s+in\s+schema\s+"?public"?)\s+(from|to)\s+([^;]+)/gi;
    for (const m of text.matchAll(revoke)) {
      mine.push({ i: m.index, file, kind: m[1].toLowerCase(), name: m[3] || '*', roles: m[5].toLowerCase() });
    }
    for (const m of text.matchAll(/alter\s+default\s+privileges[^;]*?\b(revoke|grant)\s+(?:all(?:\s+privileges)?|execute)\s+on\s+functions\s+(from|to)\s+([^;]+)/gi)) {
      mine.push({ i: m.index, file, kind: `default-${m[1].toLowerCase()}`, roles: m[3].toLowerCase() });
    }
    events.push(...mine.sort((a, b) => a.i - b.i));
  }
  for (const e of events) {
    const has = (r) => new RegExp(`\\b${r}\\b`).test(e.roles || '');
    if (e.kind === 'create') {
      const { attrs, body } = e.st;
      const prev = defs.get(e.name);
      defs.set(e.name, {
        name: e.name,
        args: e.args,
        file: e.file,
        line: e.line,
        securityDefiner: /\bsecurity\s+definer\b/i.test(attrs),
        volatility: (attrs.match(/\b(immutable|stable|volatile)\b/i)?.[1] || 'volatile').toLowerCase(),
        searchPath: /\bset\s+search_path\b/i.test(attrs),
        trigger: /\breturns\s+(event_)?trigger\b/i.test(attrs),
        checksAuth: AUTH_CHECK.test(body),
        body,
        // CREATE OR REPLACE keeps the grants of the function it replaces
        anon: prev ? prev.anon : defaultAnon,
        authenticated: prev ? prev.authenticated : defaultAuth,
      });
    } else if (e.kind === 'default-revoke' || e.kind === 'default-grant') {
      const v = e.kind === 'default-grant';
      if (has('anon')) defaultAnon = v;
      if (has('authenticated')) defaultAuth = v;
    } else {
      const v = e.kind === 'grant';
      const targets = e.name === '*' ? [...defs.values()] : [defs.get(e.name)].filter(Boolean);
      for (const d of targets) {
        if (has('anon')) d.anon = v;
        if (has('authenticated')) d.authenticated = v;
        if (!v && has('public')) d.revokedFromPublicOnly = !has('anon');
      }
    }
  }
  // a helper that reads auth.uid() counts for its callers: current_user_id(), is_member_of(org) …
  for (let changed = true; changed; ) {
    changed = false;
    const checkers = [...defs.values()].filter((d) => d.checksAuth).map((d) => d.name);
    for (const d of defs.values()) {
      if (d.checksAuth || !checkers.length) continue;
      const calls = (n) => new RegExp(`(^|[^\\w.]|public\\s*\\.\\s*)"?${n}"?\\s*\\(`, 'i').test(d.body);
      const via = checkers.find(calls);
      if (via) {
        d.checksAuth = true;
        d.authVia = via;
        changed = true;
      }
    }
  }
  for (const d of defs.values()) delete d.body;
  return defs;
}

const sig = (d) => `public.${d.name}(${d.args.replace(/\s+default\s+[^,]+/gi, '').replace(/\s+/g, ' ')})`;

// static: SECURITY DEFINER functions that never look at the caller
export function definerFindings(defs, { exposed = null, proven = new Set() } = {}) {
  const findings = [];
  const noPath = [];
  for (const d of defs.values()) {
    if (!d.securityDefiner || d.trigger) continue;
    if (exposed && exposed.size && !exposed.has(d.name)) continue; // the live API does not list it
    if (!d.searchPath) noPath.push(d);
    if (d.checksAuth || proven.has(d.name) || !(d.anon || d.authenticated)) continue;
    const who = d.anon ? 'Anyone with the anon key (not logged in)' : 'Any signed-in user';
    findings.push({
      resource: d.name,
      id: 'definer-no-auth-check',
      severity: 'warning',
      title: `"${d.name}()" runs with its owner's rights (SECURITY DEFINER) and never checks who calls it`,
      detail:
        `${who} can call POST /rest/v1/rpc/${d.name}, and inside it Row Level Security does not apply. ` +
        "Its body never reads auth.uid() or auth.jwt(), so it can't limit callers to their own data. " +
        `accessprobe did not POST to it (it may change data).${d.revokedFromPublicOnly ? ' Note: REVOKE … FROM public does not remove the anon / authenticated grants Supabase adds to new functions.' : ''}`,
      evidence: `${d.file.replace(/\\/g, '/').split('/').slice(-3).join('/')}:${d.line}: create function ${d.name}(…) security definer — no auth.uid() / auth.jwt() in the body`,
      fix: {
        sql:
          `-- if it should only touch the caller's own data, run it with the caller's rights (RLS applies):\n` +
          `alter function ${sig(d)} security invoker;\n\n` +
          `-- or keep SECURITY DEFINER and check the caller first, inside the function:\n` +
          `--   if (select auth.uid()) is null then raise exception 'not allowed'; end if;\n\n` +
          `-- and if the app never calls it over the API:\n` +
          `revoke execute on function ${sig(d)} from anon, authenticated, public;`,
      },
    });
  }
  if (noPath.length) {
    findings.push({
      resource: noPath[0].name,
      id: 'definer-search-path',
      severity: 'info',
      title: `${noPath.length} SECURITY DEFINER function(s) without a fixed search_path: ${noPath.map((d) => d.name).join(', ')}`,
      detail: 'A function that runs with its owner\'s rights should pin search_path, so a caller can\'t make it resolve tables or functions to objects they created.',
      evidence: noPath.map((d) => `${d.name}(): no "set search_path"`).join(', '),
      fix: { sql: noPath.map((d) => `alter function ${sig(d)} set search_path = '';`).join('\n') },
    });
  }
  return findings;
}

// live: GET /rest/v1/rpc/<fn> (read-only transaction, no arguments) as A, B and anon
export async function probeFunctions(client, rpcs, protectedRows, [A, B], { findings, passed, skipped, defs = new Map() }) {
  const live = protectedRows.filter((m) => !m.deleted && m.markerCol && m.marker);
  const proven = new Set();
  if (!rpcs.length) return proven;
  if (!live.length) {
    skipped.push(`functions not called (${rpcs.join(', ')}): no private test rows to look for`);
    return proven;
  }
  const call = async (fn, token) => {
    const r = await client.request('GET', `/rest/v1/rpc/${encodeURIComponent(fn)}`, { token });
    if (!r.ok || r.data === null || r.data === undefined) return { r, hits: null };
    const text = JSON.stringify(r.data);
    return { r, hits: live.filter((m) => text.includes(m.marker)) };
  };
  for (const fn of rpcs) {
    const def = defs.get(fn);
    if (def?.trigger) continue;
    const a = await call(fn, A.token);
    if (!a.hits?.length) continue; // needs arguments, not readable with GET, or shows none of A's rows
    const tables = [...new Set(a.hits.map((m) => m.table.name))];
    for (const [who, token, id] of [
      ['user B', B.token, 'rpc-cross-user-read'],
      ['anonymous', undefined, 'rpc-anon-read'],
    ]) {
      const b = await call(fn, token);
      if (b.hits?.length) {
        proven.add(fn);
        const definer = def?.securityDefiner;
        findings.push({
          resource: fn,
          id,
          severity: 'critical',
          title: `${who === 'user B' ? 'User B' : 'Anyone (not logged in)'} can read user A's private rows through the function "${fn}()"`,
          detail:
            `Proven: A's test row in ${tables.map((t) => `"${t}"`).join(', ')} is hidden from ${who === 'user B' ? 'B' : 'anonymous visitors'} by the table's policies, but ${fn}() returns it. ` +
            (definer === false
              ? 'The function is SECURITY INVOKER, so it reads the rows some other way (a view, or a SECURITY DEFINER function it calls).'
              : 'Most likely it is SECURITY DEFINER: it runs with its owner\'s rights and skips Row Level Security.'),
          evidence: `${who === 'user B' ? 'as user B' : 'anonymous'}: ${b.r.evidence} → returned A's private row(s)`,
          fix: {
            sql:
              `-- run it with the caller's rights, so the table policies apply:\n` +
              `alter function ${def ? sig(def) : `public.${fn}()`} security invoker;\n` +
              `-- or filter inside it: … where user_id = (select auth.uid())` +
              (who === 'anonymous' ? `\n-- and if visitors should not call it at all:\nrevoke execute on function ${def ? sig(def) : `public.${fn}()`} from anon, public;` : ''),
          },
        });
      } else if (b.r.ok || [401, 403, 404].includes(b.r.status) || b.r.data?.code === '42501') {
        passed.push(`${fn}(): ${who === 'user B' ? 'B gets' : 'anonymous visitors get'} none of A's private rows`);
      } else {
        skipped.push(`${fn}(): ${who} call inconclusive (${b.r.status})`);
      }
    }
  }
  return proven;
}
