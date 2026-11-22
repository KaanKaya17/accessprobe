import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, ANON_KEY } from './mock-supabase.js';
import { scan } from '../src/core/scan.js';
import { fetchRetry, throttled } from '../src/core/http.js';

let server;
let base;
const realFetch = globalThis.fetch;
after(() => {
  globalThis.fetch = realFetch;
  server?.close();
});

// answer 429 (Retry-After: 0) for matching requests, pass the rest through
function throttle(match, { times = Infinity } = {}) {
  let n = 0;
  globalThis.fetch = (url, opts = {}) => {
    if (match(String(opts.method || 'GET').toUpperCase(), String(url)) && n++ < times) {
      return Promise.resolve(new Response('{"message":"Too Many Requests"}', { status: 429, headers: { 'Retry-After': '0' } }));
    }
    return realFetch(url, opts);
  };
  return () => n;
}

before(async () => {
  server = createServer();
  await new Promise((r) => server.listen(0, r));
  base = `http://localhost:${server.address().port}`;
});

test('fetchRetry: a 429 is retried and the next answer is used', async () => {
  const count = throttle((m, u) => u.endsWith('/rest/v1/'), { times: 2 });
  const res = await fetchRetry(`${base}/rest/v1/`, { headers: { apikey: ANON_KEY } }, { timeoutMs: 5000 });
  globalThis.fetch = realFetch;
  assert.equal(count(), 3);
  assert.ok(!throttled(res));
  assert.equal(res.status, 200);
});

test('scan: checks that stay rate limited are inconclusive, never passed, and get one clear note', async () => {
  // every change / delete and every authenticated download is throttled for good
  throttle((m, u) => ((m === 'PATCH' || m === 'DELETE') && u.includes('/rest/v1/')) || u.includes('/storage/v1/object/authenticated/'));
  const r = await scan({ url: base, anonKey: ANON_KEY, quiet: true, freshUsers: true });
  globalThis.fetch = realFetch;
  const claims = r.passed.filter((p) => /cannot (change|modify|update|delete|download)/i.test(p));
  assert.deepEqual(claims, []);
  assert.ok(!r.findings.some((f) => /update|delete|takeover/.test(f.id) && !f.id.startsWith('storage-')), 'nothing proven by a throttled request');
  const note = r.notes.find((n) => n.startsWith('Rate limited:'));
  assert.ok(note, r.notes.join('\n'));
  assert.match(note, /not counted as passed/);
  assert.equal(r.notes.filter((n) => n.includes('rate limited (HTTP 429')).length, 0, 'per-check notes are folded into one');
});
