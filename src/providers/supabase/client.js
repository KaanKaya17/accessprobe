// Minimal Supabase HTTP client (PostgREST, GoTrue, Storage). Zero dependencies.

export class SupabaseClient {
  constructor({ url, anonKey, timeoutMs = 15000 }) {
    this.url = url.replace(/\/+$/, '');
    this.anonKey = anonKey;
    this.timeoutMs = timeoutMs;
  }

  headers(token, extra = {}) {
    return {
      apikey: this.anonKey,
      Authorization: `Bearer ${token || this.anonKey}`,
      ...extra,
    };
  }

  async request(method, path, { token, body, headers = {}, raw = false } = {}) {
    const h = this.headers(token, headers);
    let payload;
    if (body !== undefined) {
      if (raw) {
        payload = body;
      } else {
        h['Content-Type'] = 'application/json';
        payload = JSON.stringify(body);
      }
    }
    let res;
    let text;
    try {
      res = await fetch(this.url + path, {
        method,
        headers: h,
        body: payload,
        signal: AbortSignal.timeout(this.timeoutMs),
      });
      text = await res.text();
    } catch (e) {
      // network error / timeout: an inconclusive result (status 0), never a crash and never a PASS
      return {
        ok: false,
        status: 0,
        data: { message: `network error: ${e.cause?.code || e.name || e.message}` },
        headers: new Headers(),
        evidence: `${method} ${path} → network error`,
      };
    }
    let data = text;
    try {
      data = text ? JSON.parse(text) : null;
    } catch {
      /* keep as text */
    }
    return {
      ok: res.ok,
      status: res.status,
      data,
      headers: res.headers,
      // what we show in the report as evidence (no secrets)
      evidence: `${method} ${path}${body !== undefined && !raw ? ` ${JSON.stringify(body)}` : ''} → ${res.status}`,
    };
  }

  // ---------- PostgREST ----------
  openapi({ token } = {}) {
    return this.request('GET', '/rest/v1/', { token, headers: { Accept: 'application/openapi+json' } });
  }

  select(table, { token, filter = '', limit = 5 } = {}) {
    const q = `select=*${filter ? `&${filter}` : ''}&limit=${limit}`;
    return this.request('GET', `/rest/v1/${encodeURIComponent(table)}?${q}`, {
      token,
      headers: { Prefer: 'count=exact' },
    }).then((r) => ({ ...r, total: parseTotal(r.headers.get('content-range')) }));
  }

  insert(table, row, { token } = {}) {
    return this.request('POST', `/rest/v1/${encodeURIComponent(table)}`, {
      token,
      body: row,
      headers: { Prefer: 'return=representation' },
    });
  }

  // Last line of defence: PostgREST applies an UPDATE/DELETE without a filter to EVERY row.
  // Writes are only ever sent with equality filters that pin down a test row.
  static safeFilter(filter) {
    return typeof filter === 'string' && filter.length > 0 && filter.split('&').every((p) => /^[A-Za-z_]\w*=eq\..+/.test(p));
  }

  refused(method, table) {
    return Promise.resolve({ ok: false, status: 0, data: { message: 'refused by rlsprobe: no safe row filter' }, headers: new Headers(), evidence: `${method} /rest/v1/${table} → not sent (no safe filter)` });
  }

  update(table, filter, patch, { token } = {}) {
    if (!SupabaseClient.safeFilter(filter)) return this.refused('PATCH', table);
    return this.request('PATCH', `/rest/v1/${encodeURIComponent(table)}?${filter}`, {
      token,
      body: patch,
      headers: { Prefer: 'return=representation' },
    });
  }

  remove(table, filter, { token } = {}) {
    if (!SupabaseClient.safeFilter(filter)) return this.refused('DELETE', table);
    return this.request('DELETE', `/rest/v1/${encodeURIComponent(table)}?${filter}`, {
      token,
      headers: { Prefer: 'return=representation' },
    });
  }

  // ---------- Auth ----------
  // public GoTrue settings: { disable_signup, mailer_autoconfirm, … } — no secrets involved
  authSettings() {
    return this.request('GET', '/auth/v1/settings');
  }

  signUp(email, password) {
    return this.request('POST', '/auth/v1/signup', { body: { email, password } });
  }

  signIn(email, password) {
    return this.request('POST', '/auth/v1/token?grant_type=password', { body: { email, password } });
  }

  // ---------- Storage ----------
  listBuckets({ token } = {}) {
    return this.request('GET', '/storage/v1/bucket', { token });
  }

  listObjects(bucket, { token, prefix = '' } = {}) {
    return this.request('POST', `/storage/v1/object/list/${encodeURIComponent(bucket)}`, {
      token,
      body: { prefix, limit: 100, offset: 0 },
    });
  }

  upload(bucket, path, content, { token } = {}) {
    return this.request('POST', `/storage/v1/object/${encodeURIComponent(bucket)}/${path}`, {
      token,
      body: content,
      raw: true,
      headers: { 'Content-Type': 'text/plain', 'x-upsert': 'false' },
    });
  }

  download(bucket, path, { token } = {}) {
    return this.request('GET', `/storage/v1/object/authenticated/${encodeURIComponent(bucket)}/${path}`, { token });
  }

  // public buckets: what any visitor can fetch, no Authorization beyond the anon key
  downloadPublic(bucket, path) {
    return this.request('GET', `/storage/v1/object/public/${encodeURIComponent(bucket)}/${path}`);
  }

  deleteObjects(bucket, paths, { token } = {}) {
    return this.request('DELETE', `/storage/v1/object/${encodeURIComponent(bucket)}`, {
      token,
      body: { prefixes: paths },
    });
  }
}

function parseTotal(contentRange) {
  // "0-4/123" or "*/0"
  if (!contentRange) return null;
  const m = contentRange.match(/\/(\d+|\*)$/);
  if (!m || m[1] === '*') return null;
  return Number(m[1]);
}

export function decodeJwt(token) {
  try {
    const part = token.split('.')[1];
    return JSON.parse(Buffer.from(part.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8'));
  } catch {
    return null;
  }
}
