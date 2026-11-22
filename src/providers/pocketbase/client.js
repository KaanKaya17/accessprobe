// Minimal PocketBase REST client. Talks exactly like the JS SDK in a browser: no token
// (anonymous) or a regular user's auth token, so the collection API rules apply.
// accessprobe never asks for, accepts or uses superuser (admin) credentials.

import { readOnlyBlock } from '../../core/read-only.js';

export class PocketBaseClient {
  constructor({ url, timeoutMs = 15000, readOnly = false }) {
    this.readOnly = readOnly;
    this.url = url.replace(/\/+$/, '');
    this.timeoutMs = timeoutMs;
  }

  async request(method, path, { token, body } = {}) {
    const blocked = this.readOnly && readOnlyBlock(method, path);
    if (blocked) return { ok: false, status: 0, data: { message: blocked }, evidence: `${method} ${path} → ${blocked}` };
    const headers = {};
    if (token) headers.Authorization = token;
    let payload;
    if (body !== undefined) {
      headers['Content-Type'] = 'application/json';
      payload = JSON.stringify(body);
    }
    const shown = decodeURIComponent(path).replace(/\s+/g, ' ');
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
    return { ok: res.ok, status: res.status, data, evidence: `${method} ${shown} → ${res.status}` };
  }

  records(coll) {
    return `/api/collections/${encodeURIComponent(coll)}/records`;
  }

  signUp(coll, email, password) {
    return this.request('POST', this.records(coll), { body: { email, password, passwordConfirm: password } });
  }
  authWithPassword(coll, identity, password) {
    return this.request('POST', `/api/collections/${encodeURIComponent(coll)}/auth-with-password`, { body: { identity, password } });
  }

  // GET …/records?filter=…  → r.items (array or null), r.total
  async list(coll, { token, filter, perPage = 30 } = {}) {
    const q = [`perPage=${perPage}`];
    if (filter) q.push(`filter=${encodeURIComponent(filter)}`);
    const r = await this.request('GET', `${this.records(coll)}?${q.join('&')}`, { token });
    const items = r.ok && r.data && Array.isArray(r.data.items) ? r.data.items : null;
    return { ...r, items, total: items ? r.data.totalItems ?? null : null };
  }
  view(coll, id, { token } = {}) {
    return this.request('GET', `${this.records(coll)}/${encodeURIComponent(id)}`, { token });
  }
  create(coll, body, { token } = {}) {
    return this.request('POST', this.records(coll), { token, body });
  }
  update(coll, id, body, { token } = {}) {
    return this.request('PATCH', `${this.records(coll)}/${encodeURIComponent(id)}`, { token, body });
  }
  remove(coll, id, { token } = {}) {
    return this.request('DELETE', `${this.records(coll)}/${encodeURIComponent(id)}`, { token });
  }
}

// GET /api/health answers {"message":"API is healthy.", ...} on every PocketBase server.
const healthCache = new Map();
export function looksLikePocketBase(url) {
  const base = String(url || '').replace(/\/+$/, '');
  if (!/^https?:\/\//i.test(base)) return Promise.resolve(false);
  if (!healthCache.has(base)) {
    healthCache.set(
      base,
      (async () => {
        try {
          const r = await fetch(`${base}/api/health`, { signal: AbortSignal.timeout(4000) });
          const j = await r.json().catch(() => null);
          return Boolean(j && typeof j.message === 'string' && /api is healthy/i.test(j.message));
        } catch {
          return false;
        }
      })(),
    );
  }
  return healthCache.get(base);
}
