// Reads appwrite.json / appwrite.config.json (what `appwrite init` / `appwrite pull` write) —
// statically, it is plain JSON. It is the only schema a client can get: Appwrite lists
// databases, collections and buckets only to API keys and the console, which accessprobe never uses.
//
//   { projectId, endpoint,
//     databases:   [{ $id, name }],
//     collections: [{ $id, databaseId, name, documentSecurity, $permissions, attributes: [...] }],  (1.5+)
//     tablesDB:    [{ $id, name }],
//     tables:      [{ $id, databaseId, name, rowSecurity, $permissions, columns: [...] }],         (1.8+)
//     buckets:     [{ $id, name, fileSecurity, $permissions, enabled }] }

export const CONFIG_FILES = ['appwrite.json', 'appwrite.config.json'];

// tolerate comments and trailing commas (hand-edited files)
function parseLoose(text) {
  try {
    return JSON.parse(text);
  } catch {
    let out = '';
    for (let i = 0; i < text.length; i++) {
      const c = text[i];
      if (c === '"') {
        let j = i + 1;
        while (j < text.length && text[j] !== '"') j += text[j] === '\\' ? 2 : 1;
        out += text.slice(i, j + 1);
        i = j;
      } else if (c === '/' && text[i + 1] === '/') {
        while (i < text.length && text[i] !== '\n') i++;
        out += '\n';
      } else if (c === '/' && text[i + 1] === '*') {
        i = text.indexOf('*/', i + 2);
        if (i < 0) break;
        i++;
      } else out += c;
    }
    return JSON.parse(out.replace(/,(\s*[}\]])/g, '$1'));
  }
}

// "read(\"users\")" → { action: 'read', role: 'users' }
export function parsePermission(p) {
  const m = /^\s*(read|create|update|delete|write)\s*\(\s*"([^"]+)"\s*\)\s*$/.exec(String(p));
  return m ? { action: m[1], role: m[2] } : null;
}

// which roles a permission list grants for one action (write = create + update + delete)
export function rolesFor(perms, action) {
  return (perms || [])
    .map(parsePermission)
    .filter((p) => p && (p.action === action || (p.action === 'write' && action !== 'read')))
    .map((p) => p.role);
}

function attribute(a) {
  return {
    key: a.key,
    type: a.type, // string, integer, double/float, boolean, datetime, relationship, … (tables: varchar, text, …)
    format: a.format || null, // email, url, ip, enum
    elements: Array.isArray(a.elements) ? a.elements : null,
    size: a.size ?? null,
    min: a.min ?? null,
    max: a.max ?? null,
    required: Boolean(a.required),
    array: Boolean(a.array),
    default: a.default ?? a.xdefault ?? null,
    status: a.status || 'available',
  };
}

// text of one config file → { projectId, endpoint, databases, collections, buckets }
export function readConfig(text, file = 'appwrite.json') {
  const j = parseLoose(text);
  if (!j || typeof j !== 'object') throw new Error(`${file} is not a JSON object`);
  const databases = [...(j.databases || []), ...(j.tablesDB || j.tablesdb || [])].map((d) => ({ id: d.$id, name: d.name || d.$id })).filter((d) => d.id);
  const collections = [];
  for (const c of j.collections || []) {
    if (!c.$id || !c.databaseId) continue;
    collections.push({
      db: c.databaseId,
      id: c.$id,
      name: c.name || c.$id,
      mode: 'documents',
      enabled: c.enabled !== false,
      security: c.documentSecurity === true,
      permissions: Array.isArray(c.$permissions) ? c.$permissions : [],
      attributes: Array.isArray(c.attributes) ? c.attributes.map(attribute) : [],
    });
  }
  for (const t of j.tables || []) {
    if (!t.$id || !t.databaseId) continue;
    collections.push({
      db: t.databaseId,
      id: t.$id,
      name: t.name || t.$id,
      mode: 'rows',
      enabled: t.enabled !== false,
      security: t.rowSecurity === true,
      permissions: Array.isArray(t.$permissions) ? t.$permissions : [],
      attributes: Array.isArray(t.columns) ? t.columns.map(attribute) : [],
    });
  }
  const buckets = (j.buckets || [])
    .filter((b) => b.$id)
    .map((b) => ({ id: b.$id, name: b.name || b.$id, enabled: b.enabled !== false, security: b.fileSecurity === true, permissions: Array.isArray(b.$permissions) ? b.$permissions : [] }));
  return {
    file,
    projectId: typeof j.projectId === 'string' ? j.projectId : null,
    endpoint: typeof j.endpoint === 'string' && /^https?:\/\//.test(j.endpoint) ? j.endpoint : null,
    databases,
    collections,
    buckets,
  };
}
