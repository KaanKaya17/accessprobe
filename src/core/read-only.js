// --read-only: no request that could change anything in the project is sent. Inserts, updates,
// deletes, uploads, RPC calls and sign-ups are stopped in the client, before fetch, and come
// back like a network error (status 0). Every probe already treats status 0 as inconclusive —
// never as "refused" — so a write that was not sent can't turn into a PASS.
//
// What still runs: plain reads, plus the few POSTs that only read or sign in. Sign-ups are writes
// too, so --read-only needs two existing accounts (--user-a, --user-b).

const READ_POSTS = [
  /^\/auth\/v1\/token\?grant_type=password$/, // Supabase sign-in
  /^\/storage\/v1\/object\/list\//, // Supabase storage listing
  /accounts:signInWithPassword\?/, // Firebase sign-in
  /:runQuery(\?|$)/, // Firestore query
  /:runAggregationQuery(\?|$)/, // Firestore count
  /^\/api\/collections\/[^/]+\/auth-with-password$/, // PocketBase sign-in
  /^\/v1\/account\/sessions\/email$/, // Appwrite sign-in
];

// → null when the request may go out, otherwise the reason it was not sent
export function readOnlyBlock(method, url) {
  const m = method.toUpperCase();
  if (m === 'GET' || m === 'HEAD') return null;
  if (m === 'POST' && READ_POSTS.some((re) => re.test(url))) return null;
  if (m === 'DELETE' && /^\/v1\/account\/sessions\/current$/.test(url)) return null; // Appwrite sign-out
  return 'not sent (--read-only)';
}
