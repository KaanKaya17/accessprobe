// pg_graphql (/graphql/v1) builds its schema from what the calling role may SELECT. Rows stay
// behind RLS, but an anonymous visitor can list every such table, its columns and relations
// through introspection (Supabase's own advisor: pg_graphql_anon_table_exposed).
// Only an introspection query is sent; it reads the schema, never data.

const INTROSPECT = '{ __schema { queryType { fields { name } } } }';

export async function probeGraphql(client, { findings, passed, skipped, only = null }) {
  const r = await client.graphql(INTROSPECT);
  const fields = r.ok ? r.data?.data?.__schema?.queryType?.fields : null;
  if (!Array.isArray(fields)) {
    if (r.status === 404 || /graphql|extension|function .*resolve/i.test(JSON.stringify(r.data ?? ''))) passed.push('GraphQL (pg_graphql) is not enabled for anonymous visitors');
    else if (r.status !== 0 || r.rateLimited) skipped.push(`GraphQL introspection inconclusive (${r.status})`);
    return;
  }
  let tables = fields.map((f) => f.name).filter((n) => /Collection$/.test(n)).map((n) => n.replace(/Collection$/, ''));
  if (only?.length) tables = tables.filter((t) => only.includes(t));
  if (!tables.length) {
    passed.push('GraphQL: anonymous visitors see no tables');
    return;
  }
  const shown = tables.slice(0, 12).join(', ') + (tables.length > 12 ? `, … (${tables.length} in total)` : '');
  findings.push({
    resource: 'graphql',
    id: 'graphql-anon-schema',
    severity: 'warning',
    title: `The GraphQL endpoint lists ${tables.length} table(s) to anyone with the anon key: ${shown}`,
    detail:
      'pg_graphql is enabled and the anon role may SELECT these tables, so introspection hands out their names, columns and relations. ' +
      'Rows are still filtered by RLS; the schema is not. If the app does not use GraphQL, turn it off. Otherwise revoke SELECT from anon on tables visitors never read.',
    evidence: `anonymous: POST /graphql/v1 ${INTROSPECT} → ${tables.length} collection(s)`,
    fix: {
      sql:
        '-- the app does not use GraphQL:\ndrop extension if exists pg_graphql;\n\n' +
        '-- or keep it, and hide tables that visitors never read:\n' +
        tables
          .slice(0, 12)
          .map((t) => `revoke select on public.${/^[a-z_][a-z0-9_]*$/.test(t) ? t : `"${t}"`} from anon;`)
          .join('\n'),
    },
  });
}
