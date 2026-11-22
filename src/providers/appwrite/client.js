// Minimal Appwrite REST client. Talks exactly like the Web SDK in a browser: the project id
// (X-Appwrite-Project) and, for a signed-in user, that user's session — so the collection,
// document and bucket permissions apply. accessprobe never asks for, accepts or uses API keys
// (X-Appwrite-Key) or console credentials.
//
// The data API exists under two names. Every path is built in `api()` below, so the probes
// never care which one a target uses:
//   documents  /v1/databases/{db}/collections/{coll}/documents   (Appwrite 1.5+)
//   rows       /v1/tablesdb/{db}/tables/{table}/rows             (TablesDB, Appwrite 1.8+)

export const API = {
  documents: {
    base: (db, coll) => `/v1/databases/${encodeURIComponent(db)}/collections/${encodeURIComponent(coll)}/documents`,
    idKey: 'documentId',
    listKey: 'documents',
    noun: 'document',
    container: 'collection',
  },
  rows: {
    base: (db, coll) => `/v1/tablesdb/${encodeURIComponent(db)}/tables/${encodeURIComponent(coll)}/rows`,
    idKey: 'rowId',
    listKey: 'rows',
    noun: 'row',
    container: 'table',
  },
};

// Appwrite 1.5+ queries are JSON; 1.4 and older used method("attr", [values]) strings
const QUERY = {
  json: {
    equal: (attr, value) => JSON.stringify({ method: 'equal', attribute: attr, values: [value] }),
    limit: (n) => JSON.stringify({ method: 'limit', values: [n] }),
  },
  legacy: {
    equal: (attr, value) => `equal("${attr}", ${JSON.stringify([value])})`,
    limit: (n) => `limit(${n})`,
  },
};

export class AppwriteClient {
  constructor({ url, projectId, timeoutMs = 15000 }) {
    this.url = normalizeEndpoint(url);
    this.projectId = projectId;
    this.timeoutMs = timeoutMs;
    this.queryStyle = 'json';
  }

  // auth: { cookie, fallback } | { session } | { jwt } | undefined (anonymous: only the project header)
  async request(method, path, { auth, body, form } = {}) {
    const headers = { 'X-Appwrite-Project': this.projectId };
    if (auth?.jwt) headers['X-Appwrite-JWT'] = auth.jwt;
    else if (auth?.session) headers['X-Appwrite-Session'] = auth.session;
    else if (auth?.cookie) {
      headers.Cookie = auth.cookie;
      headers['X-Fallback-Cookies'] = auth.fallback;
    }
    let payload;
    if (form) payload = form;
    else if (body !== undefined) {
      headers['Content-Type'] = 'application/json';
      payload = JSON.stringify(body);
    }
    const shown = decodeURIComponent(path.split('?')[0]) + (path.includes('?') ? '?…' : '');
    let res;
    let text;
    try {
      res = await fetch(this.url + path, { method, headers, body: payload, signal: AbortSignal.timeout(this.timeoutMs) });
      text = await res.text();
    } catch (e) {
      // network error / timeout: inconclusive (status 0), never a crash and never a PASS
      return { ok: false, status: 0, data: { message: `network error: ${e.cause?.code || e.name || e.message}` }, evidence: `${method} ${shown} → network error` };
    }
    let data = text;
    try {
      data = text ? JSON.parse(text) : null;
    } catch {
      /* keep text */
    }
    return { ok: res.ok, status: res.status, data, headers: res.headers, evidence: `${method} ${shown} → ${res.status}` };
  }

  // ------------------------------------------------------------ account (test users)

  signUp(email, password) {
    return this.request('POST', '/v1/account', { body: { userId: 'unique()', email, password, name: 'accessprobe test user' } });
  }

  // POST /v1/account/sessions/email → { auth, session } (the session cookie, as a browser keeps it)
  async signIn(email, password) {
    const r = await this.request('POST', '/v1/account/sessions/email', { body: { email, password } });
    if (!r.ok) return { r, auth: null };
    const cookies = {};
    for (const c of r.headers.getSetCookie?.() || []) {
      const m = /^\s*(a_session_[^=;]+)=([^;]*)/.exec(c);
      if (m && m[2]) cookies[m[1]] = m[2];
    }
    try {
      Object.assign(cookies, JSON.parse(r.headers.get('x-fallback-cookies') || '{}'));
    } catch {
      /* ignore */
    }
    const names = Object.keys(cookies).filter((k) => cookies[k]);
    let auth = null;
    if (names.length) auth = { cookie: names.map((k) => `${k}=${cookies[k]}`).join('; '), fallback: JSON.stringify(Object.fromEntries(names.map((k) => [k, cookies[k]]))) };
    else if (r.data?.secret) auth = { session: r.data.secret };
    // the session cookie, not a JWT: a JWT expires after 15 minutes, and an expired one answers
    // 401 like a refusal would
    return { r, auth };
  }

  account(auth) {
    return this.request('GET', '/v1/account', { auth });
  }
  // the closest a client gets to deleting itself: block the account (ends every session)
  blockSelf(auth) {
    return this.request('PATCH', '/v1/account/status', { auth });
  }
  signOut(auth) {
    return this.request('DELETE', '/v1/account/sessions/current', { auth });
  }

  // ------------------------------------------------------------ documents / rows

  // t: { db, id, mode }
  async list(t, { auth, equalId, limit = 1 } = {}) {
    const run = async (style) => {
      const q = [];
      if (equalId) q.push(QUERY[style].equal('$id', equalId));
      q.push(QUERY[style].limit(limit));
      return this.request('GET', `${API[t.mode].base(t.db, t.id)}?${q.map((x) => `queries[]=${encodeURIComponent(x)}`).join('&')}`, { auth });
    };
    let r = await run(this.queryStyle);
    if (r.status === 400 && /query/i.test(r.data?.type || r.data?.message || '') && this.queryStyle === 'json') {
      const legacy = await run('legacy');
      if (legacy.ok) {
        this.queryStyle = 'legacy';
        r = legacy;
      }
    }
    const arr = r.ok && r.data && Array.isArray(r.data[API[t.mode].listKey]) ? r.data[API[t.mode].listKey] : null;
    return { ...r, items: arr, total: arr ? r.data.total ?? null : null };
  }
  view(t, id, { auth } = {}) {
    return this.request('GET', `${API[t.mode].base(t.db, t.id)}/${encodeURIComponent(id)}`, { auth });
  }
  create(t, data, { auth, permissions } = {}) {
    const body = { [API[t.mode].idKey]: 'unique()', data };
    if (permissions) body.permissions = permissions;
    return this.request('POST', API[t.mode].base(t.db, t.id), { auth, body });
  }
  update(t, id, { data, permissions } = {}, { auth } = {}) {
    const body = {};
    if (data) body.data = data;
    if (permissions) body.permissions = permissions;
    return this.request('PATCH', `${API[t.mode].base(t.db, t.id)}/${encodeURIComponent(id)}`, { auth, body });
  }
  remove(t, id, { auth } = {}) {
    return this.request('DELETE', `${API[t.mode].base(t.db, t.id)}/${encodeURIComponent(id)}`, { auth });
  }

  // ------------------------------------------------------------ storage

  files(bucket) {
    return `/v1/storage/buckets/${encodeURIComponent(bucket)}/files`;
  }
  async listFiles(bucket, { auth, equalId } = {}) {
    const q = [];
    if (equalId) q.push(QUERY[this.queryStyle].equal('$id', equalId));
    q.push(QUERY[this.queryStyle].limit(equalId ? 1 : 25));
    const r = await this.request('GET', `${this.files(bucket)}?${q.map((x) => `queries[]=${encodeURIComponent(x)}`).join('&')}`, { auth });
    const items = r.ok && Array.isArray(r.data?.files) ? r.data.files : null;
    return { ...r, items, total: items ? r.data.total ?? null : null };
  }
  upload(bucket, name, content, { auth, permissions } = {}) {
    const form = new FormData();
    form.append('fileId', 'unique()');
    form.append('file', new Blob([content], { type: 'text/plain' }), name);
    for (const p of permissions || []) form.append('permissions[]', p);
    return this.request('POST', this.files(bucket), { auth, form });
  }
  fileMeta(bucket, id, { auth } = {}) {
    return this.request('GET', `${this.files(bucket)}/${encodeURIComponent(id)}`, { auth });
  }
  download(bucket, id, { auth } = {}) {
    return this.request('GET', `${this.files(bucket)}/${encodeURIComponent(id)}/download`, { auth });
  }
  updateFile(bucket, id, body, { auth } = {}) {
    return this.request('PUT', `${this.files(bucket)}/${encodeURIComponent(id)}`, { auth, body });
  }
  removeFile(bucket, id, { auth } = {}) {
    return this.request('DELETE', `${this.files(bucket)}/${encodeURIComponent(id)}`, { auth });
  }
}

// "https://cloud.appwrite.io/v1" (what setEndpoint() takes) → "https://cloud.appwrite.io"
export function normalizeEndpoint(url) {
  return String(url || '').replace(/\/+$/, '').replace(/\/v1$/, '').replace(/\/console$/, '');
}

// GET /v1/health/version is public on every Appwrite server and answers {"version":"1.x.y"}.
const healthCache = new Map();
export function looksLikeAppwrite(url) {
  const base = normalizeEndpoint(url);
  if (!/^https?:\/\//i.test(base)) return Promise.resolve(false);
  if (!healthCache.has(base)) {
    healthCache.set(
      base,
      (async () => {
        try {
          const r = await fetch(`${base}/v1/health/version`, { signal: AbortSignal.timeout(4000) });
          const j = await r.json().catch(() => null);
          return Boolean(r.ok && j && typeof j.version === 'string' && /^\d+\.\d+/.test(j.version));
        } catch {
          return false;
        }
      })(),
    );
  }
  return healthCache.get(base);
}
