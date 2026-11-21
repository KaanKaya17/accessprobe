// Turns PostgREST's OpenAPI document into a list of tables / RPCs we can probe.

import { randomUUID } from 'node:crypto';

const OWNER_NAMES = [
  'user_id',
  'owner_id',
  'owner',
  'created_by',
  'author_id',
  'profile_id',
  'account_id',
  'uid',
  'userid',
  'creator_id',
  'member_id',
];

export function parseSchema(openapi) {
  if (!openapi || typeof openapi !== 'object' || !openapi.definitions) {
    return { tables: [], rpcs: [] };
  }
  const paths = openapi.paths || {};
  const tables = [];
  for (const [name, def] of Object.entries(openapi.definitions)) {
    const p = paths[`/${name}`] || {};
    const props = def.properties || {};
    const required = new Set(def.required || []);
    const columns = Object.entries(props).map(([col, spec]) => {
      const desc = spec.description || '';
      const fk = desc.match(/<fk table='([^']+)' column='([^']+)'\/>/);
      return {
        name: col,
        format: spec.format || spec.type || 'text',
        type: spec.type,
        required: required.has(col),
        hasDefault: spec.default !== undefined,
        pk: desc.includes('<pk/>'),
        fk: fk ? { table: fk[1], column: fk[2] } : null,
        enum: spec.enum || null,
      };
    });
    tables.push({
      name,
      columns,
      pk: columns.find((c) => c.pk) || columns.find((c) => c.name === 'id') || null,
      // ALL primary-key columns: a filter on just the first one of a composite key
      // (team_members: team_id=eq.1) would hit other people's rows
      pkCols: columns.some((c) => c.pk) ? columns.filter((c) => c.pk) : columns.filter((c) => c.name === 'id'),
      owner: guessOwner(name, columns),
      writable: Boolean(p.post || p.patch || p.delete),
      isView: !p.post && !p.patch && !p.delete,
      nameOnly: Boolean(def['x-name-only']),
    });
  }
  const rpcs = Object.keys(paths)
    .filter((k) => k.startsWith('/rpc/'))
    .map((k) => k.slice(5));
  return { tables, rpcs };
}

function guessOwner(table, columns) {
  // strongest signal: the column references auth.users (it holds auth.uid())
  const authRef = columns.find((c) => c.fk && c.fk.table === 'auth.users');
  if (authRef) return authRef;
  for (const n of OWNER_NAMES) {
    const c = columns.find((col) => col.name.toLowerCase() === n);
    if (c) return c;
  }
  // FK to a users/profiles table
  const fk = columns.find((c) => c.fk && /^(users|profiles)$/i.test(c.fk.table) && !c.pk);
  if (fk) return fk;
  // profiles.id / users.id usually = auth.uid()
  if (/^(profiles?|users?|accounts?)$/i.test(table)) {
    const id = columns.find((c) => c.name === 'id' && /uuid/.test(c.format));
    if (id) return id;
  }
  return null;
}

// Builds a plausible row for an INSERT probe. Returns null if we can't satisfy a required column.
export function buildRow(table, { ownerId, marker }) {
  const row = {};
  for (const c of table.columns) {
    if (table.owner && c.name === table.owner.name) {
      row[c.name] = ownerId;
      continue;
    }
    if (c.pk && (c.hasDefault || !c.required)) continue;
    if (!c.required || c.hasDefault) {
      // fill one text column with our marker so the row is recognizable
      if (!row.__markerSet && isText(c) && !c.fk && !c.enum) {
        row[c.name] = marker;
        row.__markerSet = c.name;
      }
      continue;
    }
    if (c.fk) return null; // can't invent a valid foreign key
    const v = sampleValue(c, marker);
    if (v === undefined) return null;
    row[c.name] = v;
    // never use a primary-key column as the marker: changing it would move the row out of our filter
    if (!row.__markerSet && isText(c) && !c.pk) row.__markerSet = c.name;
  }
  const markerCol = row.__markerSet || null;
  delete row.__markerSet;
  return { row, markerCol };
}

function isText(c) {
  return /^(text|character varying|character|citext|string)$/.test(c.format) || c.type === 'string' && !c.format;
}

function sampleValue(c, marker) {
  if (c.enum?.length) return c.enum[0];
  const f = c.format;
  if (/uuid/.test(f)) return randomUUID();
  if (/^(text|character varying|character|citext)$/.test(f)) return marker;
  if (/^(integer|bigint|smallint)$/.test(f)) return 1;
  if (/^(numeric|real|double precision)$/.test(f)) return 1;
  if (f === 'boolean') return false;
  if (/timestamp/.test(f)) return new Date().toISOString();
  if (f === 'date') return new Date().toISOString().slice(0, 10);
  if (/^jsonb?$/.test(f)) return {};
  if (/\[\]$/.test(f)) return [];
  if (c.type === 'string') return marker;
  if (c.type === 'integer' || c.type === 'number') return 1;
  if (c.type === 'boolean') return false;
  return undefined;
}
