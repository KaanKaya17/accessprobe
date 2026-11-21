// Minimal Firebase REST client: Identity Toolkit (auth), Firestore, Realtime Database, Storage.
// Talks exactly like a browser client with a user's ID token, so Security Rules apply.

// emulator: { auth, firestore, database, storage } base URLs, e.g. "http://127.0.0.1:9099"
export const DEFAULT_EMULATOR = {
  auth: 'http://127.0.0.1:9099',
  firestore: 'http://127.0.0.1:8080',
  database: 'http://127.0.0.1:9000',
  storage: 'http://127.0.0.1:9199',
};

export function endpoints(cfg, emulator) {
  if (emulator) {
    const e = { ...DEFAULT_EMULATOR, ...emulator };
    const ns = cfg.databaseURL ? new URL(cfg.databaseURL).hostname.split('.')[0] : `${cfg.projectId}-default-rtdb`;
    return {
      auth: `${e.auth}/identitytoolkit.googleapis.com`,
      firestore: `${e.firestore}/v1/projects/${cfg.projectId}/databases/(default)/documents`,
      database: e.database,
      databaseNs: ns,
      storage: `${e.storage}/v0/b/${cfg.storageBucket || `${cfg.projectId}.appspot.com`}`,
    };
  }
  return {
    auth: 'https://identitytoolkit.googleapis.com',
    firestore: `https://firestore.googleapis.com/v1/projects/${cfg.projectId}/databases/(default)/documents`,
    database: cfg.databaseURL || null,
    databaseNs: null,
    storage: cfg.storageBucket ? `https://firebasestorage.googleapis.com/v0/b/${cfg.storageBucket}` : null,
  };
}

export class FirebaseClient {
  constructor(cfg, { emulator, timeoutMs = 15000 } = {}) {
    this.cfg = cfg;
    this.ep = endpoints(cfg, emulator);
    this.timeoutMs = timeoutMs;
  }

  async request(method, url, { token, body, headers = {}, raw = false, authScheme = 'Bearer' } = {}) {
    const h = { ...headers };
    if (token) h.Authorization = `${authScheme} ${token}`;
    let payload;
    if (body !== undefined) {
      if (raw) payload = body;
      else {
        h['Content-Type'] = 'application/json';
        payload = JSON.stringify(body);
      }
    }
    const res = await fetch(url, { method, headers: h, body: payload, signal: AbortSignal.timeout(this.timeoutMs) });
    const text = await res.text();
    let data = text;
    try {
      data = text ? JSON.parse(text) : null;
    } catch {
      /* keep text */
    }
    const shown = url
      .replace(/([?&])key=[^&]+/, '$1key=<apiKey>')
      .replace(/([?&])auth=[^&]+/, '$1auth=<token>')
      .replace(this.ep.firestore, '…/documents')
      .replace(this.ep.storage || '\u0000', '…')
      .replace(/^https?:\/\/[^/]+(?=\/[^?]*\.json)/, '');
    return { ok: res.ok, status: res.status, data, evidence: `${method} ${shown} → ${res.status}` };
  }

  // ---------- Auth ----------
  signUp(email, password) {
    const body = email ? { email, password, returnSecureToken: true } : { returnSecureToken: true };
    return this.request('POST', `${this.ep.auth}/v1/accounts:signUp?key=${this.cfg.apiKey}`, { body });
  }
  signIn(email, password) {
    return this.request('POST', `${this.ep.auth}/v1/accounts:signInWithPassword?key=${this.cfg.apiKey}`, {
      body: { email, password, returnSecureToken: true },
    });
  }
  deleteAccount(idToken) {
    return this.request('POST', `${this.ep.auth}/v1/accounts:delete?key=${this.cfg.apiKey}`, { body: { idToken } });
  }

  // ---------- Firestore ----------
  createDoc(collectionPath, docId, data, { token } = {}) {
    return this.request('POST', `${this.ep.firestore}/${collectionPath}?documentId=${encodeURIComponent(docId)}`, {
      token,
      body: { fields: encodeFields(data) },
    });
  }
  getDoc(docPath, { token } = {}) {
    return this.request('GET', `${this.ep.firestore}/${docPath}`, { token });
  }
  // exists=true precondition: a PATCH must never create a document by accident
  updateDoc(docPath, data, { token } = {}) {
    const mask = Object.keys(data)
      .map((f) => `updateMask.fieldPaths=${encodeURIComponent(f)}`)
      .join('&');
    return this.request('PATCH', `${this.ep.firestore}/${docPath}?${mask}&currentDocument.exists=true`, {
      token,
      body: { fields: encodeFields(data) },
    });
  }
  // exists=true precondition: deleting a missing doc must not look like a successful delete
  deleteDoc(docPath, { token } = {}) {
    return this.request('DELETE', `${this.ep.firestore}/${docPath}?currentDocument.exists=true`, { token });
  }
  // list a collection: what "allow list" really permits
  listDocs(collectionPath, { token, limit = 20 } = {}) {
    const { parent, id } = splitCollection(collectionPath);
    return this.request('POST', `${this.ep.firestore}${parent ? `/${parent}` : ''}:runQuery`, {
      token,
      body: { structuredQuery: { from: [{ collectionId: id }], limit } },
    }).then((r) => ({ ...r, docs: Array.isArray(r.data) ? r.data.filter((x) => x.document).map((x) => x.document) : [] }));
  }
  countDocs(collectionPath, { token } = {}) {
    const { parent, id } = splitCollection(collectionPath);
    return this.request('POST', `${this.ep.firestore}${parent ? `/${parent}` : ''}:runAggregationQuery`, {
      token,
      body: {
        structuredAggregationQuery: { structuredQuery: { from: [{ collectionId: id }] }, aggregations: [{ alias: 'n', count: {} }] },
      },
    }).then((r) => {
      const v = Array.isArray(r.data) ? r.data.find((x) => x.result)?.result?.aggregateFields?.n : null;
      return { ...r, count: v ? Number(v.integerValue) : null };
    });
  }

  // ---------- Realtime Database ----------
  rtdbUrl(path, token, extra = '') {
    const base = this.ep.database.replace(/\/+$/, '');
    const qs = [this.ep.databaseNs ? `ns=${this.ep.databaseNs}` : '', token ? `auth=${token}` : '', extra].filter(Boolean).join('&');
    return `${base}/${path.replace(/^\/+/, '')}.json${qs ? `?${qs}` : ''}`;
  }
  rtdbGet(path, { token, shallow = false } = {}) {
    return this.request('GET', this.rtdbUrl(path, token, shallow ? 'shallow=true' : ''));
  }
  rtdbPut(path, value, { token } = {}) {
    return this.request('PUT', this.rtdbUrl(path, token), { body: value });
  }
  rtdbDelete(path, { token } = {}) {
    return this.request('DELETE', this.rtdbUrl(path, token));
  }

  // ---------- Storage ----------
  upload(path, content, { token } = {}) {
    return this.request('POST', `${this.ep.storage}/o?name=${encodeURIComponent(path)}`, {
      token,
      authScheme: 'Firebase',
      body: content,
      raw: true,
      headers: { 'Content-Type': 'text/plain' },
    });
  }
  download(path, { token } = {}) {
    return this.request('GET', `${this.ep.storage}/o/${encodeURIComponent(path)}?alt=media`, { token, authScheme: 'Firebase' });
  }
  removeFile(path, { token } = {}) {
    return this.request('DELETE', `${this.ep.storage}/o/${encodeURIComponent(path)}`, { token, authScheme: 'Firebase' });
  }
  // delimiter=/ like the SDK's listAll(): without it the emulator denies a list the app can do (API-NOTES trap 6)
  listFiles(prefix, { token } = {}) {
    return this.request('GET', `${this.ep.storage}/o?prefix=${encodeURIComponent(prefix)}&delimiter=%2F`, { token, authScheme: 'Firebase' });
  }
}

// "users/U1/private" -> { parent: "users/U1", id: "private" }
function splitCollection(path) {
  const parts = path.split('/').filter(Boolean);
  return { parent: parts.slice(0, -1).join('/'), id: parts[parts.length - 1] };
}

export function encodeFields(obj) {
  const out = {};
  for (const [k, v] of Object.entries(obj)) out[k] = encodeValue(v);
  return out;
}

function encodeValue(v) {
  if (v === null) return { nullValue: null };
  if (typeof v === 'boolean') return { booleanValue: v };
  if (typeof v === 'number') return Number.isInteger(v) ? { integerValue: String(v) } : { doubleValue: v };
  if (v instanceof Date) return { timestampValue: v.toISOString() };
  if (Array.isArray(v)) return { arrayValue: { values: v.map(encodeValue) } };
  if (typeof v === 'object') return { mapValue: { fields: encodeFields(v) } };
  return { stringValue: String(v) };
}

export function decodeFields(fields = {}) {
  const out = {};
  for (const [k, v] of Object.entries(fields)) out[k] = decodeValue(v);
  return out;
}

function decodeValue(v) {
  if ('stringValue' in v) return v.stringValue;
  if ('integerValue' in v) return Number(v.integerValue);
  if ('doubleValue' in v) return v.doubleValue;
  if ('booleanValue' in v) return v.booleanValue;
  if ('nullValue' in v) return null;
  if ('timestampValue' in v) return v.timestampValue;
  if ('arrayValue' in v) return (v.arrayValue.values || []).map(decodeValue);
  if ('mapValue' in v) return decodeFields(v.mapValue.fields);
  return v;
}
