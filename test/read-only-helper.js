// Shared checks for --read-only runs: records every request that leaves the process (fetch),
// independently of the guard under test.
import assert from 'node:assert/strict';

// the only non-GET requests a read-only run may send: sign-ins and read-only queries
const READ_LIKE = /token\?grant_type=password|\/storage\/v1\/object\/list\/|accounts:signInWithPassword|:runQuery|:runAggregationQuery|\/auth-with-password|\/v1\/account\/sessions\/(email|current)/;

export async function recordRequests(fn) {
  const orig = globalThis.fetch;
  const seen = [];
  globalThis.fetch = (url, opts = {}) => {
    seen.push({ method: String(opts.method || 'GET').toUpperCase(), url: String(url) });
    return orig(url, opts);
  };
  try {
    return { result: await fn(), seen };
  } finally {
    globalThis.fetch = orig;
  }
}

export function assertReadOnly({ result, seen }) {
  assert.ok(seen.length > 3, 'requests were made');
  const writes = seen.filter((r) => r.method !== 'GET' && r.method !== 'HEAD' && !READ_LIKE.test(r.url)).map((r) => `${r.method} ${r.url}`);
  assert.deepEqual(writes, [], 'no write request may leave the process');
  const claims = result.passed.filter((p) => /cannot (insert|update|modify|change|delete|create|upload|take|forge|write|overwrite)|can't (insert|create|write)/i.test(p));
  assert.deepEqual(claims, [], 'skipped writes must never be reported as passed');
  assert.match(result.notes[0], /^Read-only run: nothing was written/);
}
