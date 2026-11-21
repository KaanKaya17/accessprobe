import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, ANON_KEY } from './mock-supabase.js';
import { scan } from '../src/core/scan.js';

test('"Confirm email" on: stop before any sign-up (no bouncing emails), explain what to do', async () => {
  const server = createServer({ autoconfirm: false });
  await new Promise((r) => server.listen(0, r));
  try {
    await assert.rejects(
      scan({ url: `http://localhost:${server.address().port}`, anonKey: ANON_KEY, quiet: true }),
      /"Confirm email" is enabled[\s\S]*Nothing was created[\s\S]*--user-a/,
    );
    assert.equal(server.stats().signups, 0, 'not a single sign-up request was sent');
  } finally {
    server.close();
  }
});
