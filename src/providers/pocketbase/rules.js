// What the API rules from pb_migrations tell us: which collection is the users (auth)
// collection, which field holds a record's owner, which fields of a user's OWN record
// grant extra rights (`@request.auth.role = "admin"`).

import { USERS_ID, RULES } from './migrations.js';
import { isPrivileged, escalationValues } from '../supabase/privilege.js';

export const COMMON_OWNER_FIELDS = ['user', 'owner', 'author', 'createdBy', 'created_by', 'userId', 'user_id', 'owner_id', 'ownerId'];

export function authCollection(collections) {
  const auth = (collections || []).filter((c) => c.type === 'auth');
  return auth.find((c) => c.name === 'users' || c.id === USERS_ID) || auth[0] || { id: USERS_ID, name: 'users', type: 'auth', fields: [] };
}

export function pointsToUsers(f, auth) {
  return f.type === 'relation' && [auth.id, auth.name, USERS_ID, 'users'].includes(f.collectionId);
}

const esc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
function compares(rule, field) {
  if (!rule) return false;
  const f = esc(field);
  return new RegExp(`(^|[^\\w.@])${f}(\\.id)?\\s*\\??=\\s*@request\\.auth\\.id\\b|@request\\.auth\\.id\\s*\\??=\\s*${f}(\\.id)?\\b`).test(rule);
}

// The field that ties a record to its owner: a relation to users that the rules compare with
// @request.auth.id, else the only relation to users, else a common owner name.
export function ownerFieldOf(c, auth) {
  if (!c) return null;
  if (c.type === 'auth') return 'id';
  const rules = RULES.map((r) => c[r]).filter(Boolean);
  const rel = (c.fields || []).filter((f) => pointsToUsers(f, auth));
  const used = rel.find((f) => rules.some((r) => compares(r, f.name)));
  if (used) return used.name;
  if (rel.length) return rel[0].name;
  const any = (c.fields || []).find((f) => rules.some((r) => compares(r, f.name)));
  if (any) return any.name;
  return (c.fields || []).find((f) => COMMON_OWNER_FIELDS.includes(f.name))?.name || null;
}

const SKIP_AUTH_FIELDS = new Set(['id', 'email', 'collectionId', 'collectionName', 'created', 'updated', 'tokenKey', 'password']);
const VALUE = String.raw`("([^"]*)"|'([^']*)'|true|false|-?\d+(?:\.\d+)?)`;

function literal(m) {
  if (m[2] !== undefined) return m[2];
  if (m[3] !== undefined) return m[3];
  if (m[1] === 'true') return true;
  if (m[1] === 'false') return false;
  return Number(m[1]);
}

// collection name → [{ field, value, rules: ["admin_reports.listRule", …] }]
// `@request.auth.role = "admin"` → the auth collection; `@collection.members.role = "admin"` → members
export function privilegeRefs(collections, auth) {
  const out = new Map();
  const add = (coll, field, value, where) => {
    if (!out.has(coll)) out.set(coll, []);
    const list = out.get(coll);
    let e = list.find((x) => x.field === field);
    if (!e) list.push((e = { field, value, rules: [] }));
    if (!e.rules.includes(where)) e.rules.push(where);
  };
  for (const c of collections || []) {
    for (const r of RULES) {
      const rule = c[r];
      if (!rule) continue;
      for (const m of rule.matchAll(new RegExp(String.raw`@request\.auth\.(\w+)\s*\??=\s*` + VALUE, 'g'))) {
        if (SKIP_AUTH_FIELDS.has(m[1])) continue;
        add(auth.name, m[1], literal(m.slice(1)), `${c.name}.${r}`);
      }
      for (const m of rule.matchAll(new RegExp(String.raw`@collection\.(\w+)\.(\w+)\s*\??=\s*` + VALUE, 'g'))) {
        if (m[2] === 'id' || m[1] === auth.name) continue;
        add(m[1], m[2], literal(m.slice(2)), `${c.name}.${r}`);
      }
    }
  }
  return out;
}

// Fields NOT referenced by any rule we could read, but named like a privilege (role, isAdmin,
// plan, credits…): the app code may still trust them. `fields` from migrations, or the keys of
// the user's own record when there are no migrations.
export function privilegedByName(fields, record, known) {
  const out = [];
  const seen = new Set(known.map((k) => k.field));
  const candidates = fields?.length
    ? fields.filter((f) => !f.system && !f.hidden && !['relation', 'file', 'json', 'autodate', 'password'].includes(f.type))
    : Object.keys(record || {}).map((name) => ({ name, type: typeof record[name] === 'boolean' ? 'bool' : typeof record[name] === 'number' ? 'number' : 'text' }));
  for (const f of candidates) {
    if (seen.has(f.name) || SKIP_AUTH_FIELDS.has(f.name) || f.name === 'verified' || !isPrivileged(f.name)) continue;
    if (f.type === 'select' && f.maxSelect > 1) continue;
    const col = { name: f.name, enum: f.type === 'select' ? f.values : null, type: f.type === 'bool' ? 'boolean' : f.type === 'number' ? 'number' : 'string' };
    const values = escalationValues(col, record?.[f.name]);
    if (values.length) out.push({ field: f.name, value: values[0], rules: [] });
  }
  return out;
}
