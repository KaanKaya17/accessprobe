// Test-only helper: downloads a PINNED PocketBase release binary for this OS/arch (checked
// against the release's SHA-256), starts it on a free port with a fresh temp data dir and
// the fixture migrations, and creates a superuser for TEST SETUP ONLY (verifying cleanup).
// accessprobe itself never sees or uses the superuser credentials.
//
//   import { available, startPocketBase } from './pocketbase/server.js';
//   const pb = await startPocketBase();   // rejects with a clear Error if it cannot start
//   ... pb.url, await pb.superuserToken() ...
//   await pb.stop();
//
// Run directly:  node test/pocketbase/server.js   (Ctrl+C to stop)
//
// The binary is cached in ~/.cache/accessprobe/pocketbase-<version>-<os>_<arch>/
// (override with ACCESSPROBE_CACHE_DIR). Set ACCESSPROBE_SKIP_POCKETBASE=1 to skip.

import { spawn, spawnSync } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync, renameSync, chmodSync } from 'node:fs';
import { tmpdir, homedir } from 'node:os';
import { inflateRawSync } from 'node:zlib';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import net from 'node:net';

// pinned in test/versions.json (with the SHA-256 sums from the release's checksums.txt)
const PINNED = JSON.parse(readFileSync(new URL('../versions.json', import.meta.url), 'utf8')).pocketbase;
export const POCKETBASE_VERSION = PINNED.version;
const SHA256 = PINNED.sha256;

const here = path.dirname(fileURLToPath(import.meta.url));
export const APP_DIR = path.join(here, 'app'); // the fixture app (what --source points at)
export const MIGRATIONS_DIR = path.join(APP_DIR, 'pb_migrations');
const isWin = process.platform === 'win32';

export function platformKey() {
  const os = { win32: 'windows', linux: 'linux', darwin: 'darwin' }[process.platform];
  const arch = { x64: 'amd64', arm64: 'arm64', arm: 'armv7' }[process.arch];
  return os && arch && SHA256[`${os}_${arch}`] ? `${os}_${arch}` : null;
}

export function available() {
  if (process.env.ACCESSPROBE_SKIP_POCKETBASE === '1') return false;
  return Boolean(platformKey());
}

function cacheDir() {
  return path.join(process.env.ACCESSPROBE_CACHE_DIR || path.join(homedir(), '.cache', 'accessprobe'), `pocketbase-${POCKETBASE_VERSION}-${platformKey()}`);
}

// Minimal zip reader (central directory + deflate/store) — enough for one file from a release zip.
function unzipEntry(buf, wanted) {
  let eocd = -1;
  for (let i = buf.length - 22; i >= Math.max(0, buf.length - 65557); i--) {
    if (buf.readUInt32LE(i) === 0x06054b50) {
      eocd = i;
      break;
    }
  }
  if (eocd < 0) throw new Error('not a zip file');
  const count = buf.readUInt16LE(eocd + 10);
  let p = buf.readUInt32LE(eocd + 16);
  for (let n = 0; n < count; n++) {
    if (buf.readUInt32LE(p) !== 0x02014b50) throw new Error('bad zip central directory');
    const method = buf.readUInt16LE(p + 10);
    const csize = buf.readUInt32LE(p + 20);
    const nameLen = buf.readUInt16LE(p + 28);
    const extraLen = buf.readUInt16LE(p + 30);
    const commentLen = buf.readUInt16LE(p + 32);
    const local = buf.readUInt32LE(p + 42);
    const name = buf.toString('utf8', p + 46, p + 46 + nameLen);
    if (name === wanted) {
      const start = local + 30 + buf.readUInt16LE(local + 26) + buf.readUInt16LE(local + 28);
      const data = buf.subarray(start, start + csize);
      if (method === 0) return Buffer.from(data);
      if (method === 8) return inflateRawSync(data);
      throw new Error(`unsupported zip method ${method}`);
    }
    p += 46 + nameLen + extraLen + commentLen;
  }
  throw new Error(`${wanted} not found in the zip`);
}

export async function ensureBinary({ log = () => {} } = {}) {
  const key = platformKey();
  if (!key) throw new Error(`no PocketBase release for ${process.platform}/${process.arch}`);
  const dir = cacheDir();
  const exe = path.join(dir, isWin ? 'pocketbase.exe' : 'pocketbase');
  if (existsSync(exe)) return exe;
  const url = `https://github.com/pocketbase/pocketbase/releases/download/v${POCKETBASE_VERSION}/pocketbase_${POCKETBASE_VERSION}_${key}.zip`;
  log(`downloading ${url}`);
  const res = await fetch(url, { signal: AbortSignal.timeout(180000) });
  if (!res.ok) throw new Error(`download failed: ${res.status} ${url}`);
  const zip = Buffer.from(await res.arrayBuffer());
  const sum = createHash('sha256').update(zip).digest('hex');
  if (sum !== SHA256[key]) throw new Error(`checksum mismatch for ${url}: ${sum}`);
  const bin = unzipEntry(zip, path.basename(exe));
  mkdirSync(dir, { recursive: true });
  const tmp = `${exe}.${process.pid}.tmp`;
  writeFileSync(tmp, bin);
  if (!isWin) chmodSync(tmp, 0o755);
  renameSync(tmp, exe);
  return exe;
}

function freePort() {
  return new Promise((resolve, reject) => {
    const s = net.createServer();
    s.once('error', reject);
    s.listen(0, '127.0.0.1', () => {
      const { port } = s.address();
      s.close(() => resolve(port));
    });
  });
}

async function healthy(url) {
  try {
    const r = await fetch(`${url}/api/health`, { signal: AbortSignal.timeout(2000) });
    await r.arrayBuffer();
    return r.ok;
  } catch {
    return false;
  }
}

/**
 * Start PocketBase with the fixture migrations. Resolves
 * { url, stop(), superuserToken(), admin(method, path, body) }.
 */
export async function startPocketBase({ timeoutMs = 60000, log = false, migrationsDir = MIGRATIONS_DIR } = {}) {
  const exe = await ensureBinary({ log: log ? (m) => process.stderr.write(`${m}\n`) : () => {} });
  const dataDir = mkdtempSync(path.join(tmpdir(), 'accessprobe-pb-'));
  const email = `setup-${randomUUID().slice(0, 8)}@example.com`;
  const password = `Setup-${randomUUID()}`;

  // superuser for test setup/verification only — never passed to accessprobe
  const su = spawnSync(exe, ['superuser', 'upsert', email, password, '--dir', dataDir, '--migrationsDir', migrationsDir], {
    encoding: 'utf8',
    timeout: 60000,
    windowsHide: true,
  });
  if (su.status !== 0) {
    rmSync(dataDir, { recursive: true, force: true });
    throw new Error(`pocketbase superuser upsert failed: ${(su.stderr || su.stdout || su.error?.message || '').trim().slice(0, 400)}`);
  }

  const port = await freePort();
  const url = `http://127.0.0.1:${port}`;
  const child = spawn(
    exe,
    ['serve', '--http', `127.0.0.1:${port}`, '--dir', dataDir, '--migrationsDir', migrationsDir, '--hooksDir', path.join(dataDir, 'no_hooks')],
    { cwd: dataDir, stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true },
  );
  let output = '';
  const onData = (d) => {
    output = (output + d).slice(-20000);
    if (log) process.stderr.write(d);
  };
  child.stdout.on('data', onData);
  child.stderr.on('data', onData);
  let exited = false;
  child.once('exit', () => (exited = true));

  const stop = async () => {
    if (!exited) {
      child.kill();
      for (let i = 0; i < 50 && !exited; i++) await new Promise((r) => setTimeout(r, 100));
      if (!exited) child.kill('SIGKILL');
    }
    for (let i = 0; i < 20; i++) {
      try {
        rmSync(dataDir, { recursive: true, force: true });
        return;
      } catch {
        await new Promise((r) => setTimeout(r, 200)); // Windows: file handles linger briefly
      }
    }
  };

  let token = null;
  const superuserToken = async () => {
    if (token) return token;
    const r = await fetch(`${url}/api/collections/_superusers/auth-with-password`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ identity: email, password }),
    });
    const j = await r.json();
    if (!r.ok) throw new Error(`superuser auth failed: ${r.status} ${JSON.stringify(j)}`);
    token = j.token;
    return token;
  };
  const admin = async (method, p, body) => {
    const r = await fetch(url + p, {
      method,
      headers: { Authorization: await superuserToken(), ...(body !== undefined && { 'Content-Type': 'application/json' }) },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const text = await r.text();
    let data = text;
    try {
      data = text ? JSON.parse(text) : null;
    } catch {
      /* keep text */
    }
    return { ok: r.ok, status: r.status, data };
  };

  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    if (exited) {
      await stop();
      throw new Error(`PocketBase exited before becoming ready:\n${output.slice(-3000)}`);
    }
    if (await healthy(url)) return { url, stop, superuserToken, admin, output: () => output, version: POCKETBASE_VERSION };
    await new Promise((r) => setTimeout(r, 200));
  }
  await stop();
  throw new Error(`PocketBase not ready after ${timeoutMs} ms:\n${output.slice(-3000)}`);
}

// Direct run: start, print the URL, stop on Ctrl+C.
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const pb = await startPocketBase({ log: process.argv.includes('--verbose') });
    console.log(`PocketBase ${POCKETBASE_VERSION} ready at ${pb.url}`);
    console.log('Press Ctrl+C to stop.');
    const shutdown = async () => {
      await pb.stop();
      process.exit(0);
    };
    process.on('SIGINT', shutdown);
    process.on('SIGTERM', shutdown);
  } catch (e) {
    console.error(e.message);
    process.exit(1);
  }
}
