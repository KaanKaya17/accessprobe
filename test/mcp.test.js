import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { createInterface } from 'node:readline';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createServer, ANON_KEY } from './mock-supabase.js';
import { toOptions } from '../src/mcp/server.js';

const BIN = fileURLToPath(new URL('../bin/accessprobe.js', import.meta.url));
let server;
let base;
let mcp;
let nextId = 1;
const waiting = new Map();
const stray = [];

before(async () => {
  server = createServer();
  await new Promise((r) => server.listen(0, r));
  base = `http://localhost:${server.address().port}`;
  mcp = spawn(process.execPath, [BIN, 'mcp'], { env: { ...process.env, NO_COLOR: '1' }, cwd: tmpdir() });
  createInterface({ input: mcp.stdout }).on('line', (line) => {
    const msg = JSON.parse(line); // every stdout line must be a protocol message
    const w = waiting.get(msg.id);
    if (w) {
      waiting.delete(msg.id);
      w(msg);
    } else stray.push(msg);
  });
});
after(() => {
  mcp.stdin.end();
  server.close();
});

function rpc(method, params) {
  const id = nextId++;
  return new Promise((resolve) => {
    waiting.set(id, resolve);
    mcp.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id, method, params })}\n`);
  });
}
const call = (name, args) => rpc('tools/call', { name, arguments: args });

test('MCP: initialize, tools/list, ping', async () => {
  const init = await rpc('initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 't', version: '0' } });
  assert.equal(init.result.protocolVersion, '2025-06-18');
  assert.equal(init.result.serverInfo.name, 'accessprobe');
  assert.ok(init.result.capabilities.tools);
  mcp.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' })}\n`);

  const unknownVersion = await rpc('initialize', { protocolVersion: '1999-01-01' });
  assert.match(unknownVersion.result.protocolVersion, /^\d{4}-\d{2}-\d{2}$/);
  assert.notEqual(unknownVersion.result.protocolVersion, '1999-01-01');

  const list = await rpc('tools/list', {});
  assert.deepEqual(list.result.tools.map((t) => t.name), ['accessprobe_plan', 'accessprobe_scan']);
  assert.equal(list.result.tools[0].annotations.readOnlyHint, true);
  assert.deepEqual(list.result.tools[1].inputSchema.required, ['owner_confirmed']);

  assert.deepEqual((await rpc('ping')).result, {});
  assert.equal((await rpc('nope/nope')).error.code, -32601);
  assert.equal((await call('nope', {})).error.code, -32602);
});

test('MCP: plan shows the targets and writes nothing', async () => {
  const before = server.requests?.length;
  const r = await call('accessprobe_plan', { url: base, anon_key: ANON_KEY });
  assert.ok(!r.result.isError, r.result.content?.[0]?.text);
  assert.equal(r.result.structuredContent.targets[0].platform, 'supabase');
  assert.match(r.result.content[0].text, /Ask the user/);
  if (before !== undefined) assert.ok(!server.requests.slice(before).some((q) => q.method !== 'GET'));
});

test('MCP: scan refuses without owner_confirmed', async () => {
  const r = await call('accessprobe_scan', { url: base, anon_key: ANON_KEY });
  assert.equal(r.result.isError, true);
  assert.match(r.result.content[0].text, /owner_confirmed/);
});

test('MCP: scan proves leaks, returns fixes, writes the report file, never echoes the key', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'ap-mcp-'));
  try {
    const r = await call('accessprobe_scan', { owner_confirmed: true, url: base, anon_key: ANON_KEY, directory: dir, report_file: 'report.md' });
    assert.ok(!r.result.isError, r.result.content?.[0]?.text);
    const s = r.result.structuredContent;
    assert.equal(s.exitCode, 1);
    assert.ok(s.critical > 0);
    assert.ok(s.findings.some((f) => f.severity === 'critical' && f.evidence && f.fix));
    assert.match(r.result.content[0].text, /proven critical/);
    assert.match(readFileSync(join(dir, 'report.md'), 'utf8'), /# accessprobe report/);
    assert.ok(!JSON.stringify(r).includes(ANON_KEY));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('MCP: errors come back as tool errors, and stdout stays clean', async () => {
  const r = await call('accessprobe_plan', { directory: join(tmpdir(), 'ap-missing-dir-xyz') });
  assert.equal(r.result.isError, true);
  assert.match(r.result.content[0].text, /does not look like a project/);
  assert.deepEqual(stray, []);
});

test('toOptions resolves paths against directory and defaults source to it', () => {
  const { opts } = toOptions({ project_id: 'p', directory: 'app', firestore_rules: 'rules/f.rules', tables: ['a'] }, process.cwd().replace(/[\\/]$/, '') + '/..');
  assert.ok(opts.firestoreRules.endsWith(join('app', 'rules', 'f.rules')));
  const withUrl = toOptions({ url: 'http://x', directory: '.' });
  assert.equal(withUrl.opts.source, undefined);
  assert.equal(toOptions({}, process.cwd()).opts.source, process.cwd());
});
