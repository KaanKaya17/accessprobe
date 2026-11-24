// Test-only helper: starts the Firebase emulators (auth, firestore, database,
// storage) for the fake `demo-accessprobe` project via a PINNED firebase-tools
// version run through npx. accessprobe itself never depends on firebase-tools.
//
//   import { available, startEmulators } from './firebase/emulator.js';
//   if (!available()) skip();
//   const emu = await startEmulators();   // rejects with a clear Error if it cannot start
//   ... emu.hosts.firestore ...
//   await emu.stop();
//
// Run directly:  node test/firebase/emulator.js   (Ctrl+C to stop)
//
// Note: the first run downloads the emulator jars from Google into
// ~/.cache/firebase/emulators; that can take a minute.

import { spawn, spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import net from 'node:net';

// pinned in test/versions.json
export const FIREBASE_TOOLS_VERSION = JSON.parse(readFileSync(new URL('../versions.json', import.meta.url), 'utf8'))['firebase-tools'];
export const PROJECT_ID = 'demo-accessprobe';

const here = path.dirname(fileURLToPath(import.meta.url));
export const CONFIG_PATH = path.join(here, 'firebase.json');
const isWin = process.platform === 'win32';

const PORTS = { auth: 9099, firestore: 8080, database: 9000, storage: 9199 };
export const hosts = Object.freeze({
  auth: `http://127.0.0.1:${PORTS.auth}`,
  firestore: `http://127.0.0.1:${PORTS.firestore}`,
  database: `http://127.0.0.1:${PORTS.database}`,
  storage: `http://127.0.0.1:${PORTS.storage}`,
  projectId: PROJECT_ID,
  rtdbNamespace: `${PROJECT_ID}-default-rtdb`,
  storageBucket: `${PROJECT_ID}.appspot.com`,
});

let lastStartFailed = false;

function hasCommand(cmd, args) {
  try {
    const r = spawnSync(cmd, args, { shell: isWin, stdio: 'ignore', timeout: 20000 });
    return r.status === 0;
  } catch {
    return false;
  }
}

/**
 * Synchronous best-effort check: Java and npx are on PATH and no previous
 * startEmulators() call in this process failed. startEmulators() can still
 * reject (e.g. ports busy, no network for the first jar download); callers
 * should treat a rejection as "skip".
 */
export function available() {
  if (lastStartFailed) return false;
  if (process.env.ACCESSPROBE_SKIP_FIREBASE === '1') return false;
  return hasCommand('java', ['-version']) && hasCommand('npx', ['--version']);
}

function portInUse(port) {
  return new Promise((resolve) => {
    const s = net.connect({ host: '127.0.0.1', port });
    s.once('connect', () => { s.destroy(); resolve(true); });
    s.once('error', () => resolve(false));
    s.setTimeout(1000, () => { s.destroy(); resolve(false); });
  });
}

async function respondsHttp(url) {
  try {
    const res = await fetch(url, { signal: AbortSignal.timeout(2000) });
    await res.arrayBuffer();
    return true;
  } catch {
    return false;
  }
}

function killTree(child) {
  if (!child || child.pid === undefined) return;
  try {
    if (isWin) {
      spawnSync('taskkill', ['/pid', String(child.pid), '/T', '/F'], { stdio: 'ignore' });
    } else {
      process.kill(-child.pid, 'SIGKILL');
    }
  } catch { /* already gone */ }
}

/**
 * Start all four emulators. Resolves { stop(), hosts, pid, startupMs } once
 * every emulator answers HTTP. Rejects (after cleaning up) on failure/timeout.
 */
export async function startEmulators({ timeoutMs = 180000, log = false } = {}) {
  const busy = [];
  for (const [name, port] of Object.entries(PORTS)) {
    if (await portInUse(port)) busy.push(`${name}:${port}`);
  }
  if (busy.length) {
    lastStartFailed = true;
    throw new Error(`Firebase emulator ports already in use: ${busy.join(', ')}`);
  }

  const args = [
    '--yes', `firebase-tools@${FIREBASE_TOOLS_VERSION}`,
    'emulators:start',
    '--only', 'auth,firestore,database,storage',
    '--project', PROJECT_ID,
    '--config', CONFIG_PATH,
  ];
  const started = Date.now();
  // Node >= 20 refuses to spawn .cmd files without a shell on Windows.
  const child = isWin
    ? spawn(['npx', ...args.map((a) => (/[\s()]/.test(a) ? `"${a}"` : a))].join(' '), {
        shell: true, cwd: here, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'],
        env: { ...process.env, CI: 'true' },
      })
    : spawn('npx', args, {
        cwd: here, detached: true, stdio: ['ignore', 'pipe', 'pipe'],
        env: { ...process.env, CI: 'true' },
      });

  let output = '';
  const onData = (d) => {
    const s = d.toString();
    output = (output + s).slice(-20000);
    if (log) process.stderr.write(s);
  };
  child.stdout.on('data', onData);
  child.stderr.on('data', onData);

  let exited = false;
  child.once('exit', () => { exited = true; });

  const stop = async () => {
    killTree(child);
    // wait briefly for ports to be released
    for (let i = 0; i < 50; i++) {
      const anyUp = (await Promise.all(Object.values(PORTS).map(portInUse))).some(Boolean);
      if (!anyUp) return;
      await new Promise((r) => setTimeout(r, 200));
    }
  };

  const probes = [
    `${hosts.auth}/`,
    `${hosts.firestore}/`,
    `${hosts.database}/.json?ns=${hosts.rtdbNamespace}`,
    `${hosts.storage}/`,
  ];
  while (Date.now() - started < timeoutMs) {
    if (exited) {
      lastStartFailed = true;
      throw new Error(`Firebase emulators exited before becoming ready:\n${output.slice(-4000)}`);
    }
    const ok = await Promise.all(probes.map(respondsHttp));
    if (ok.every(Boolean)) {
      return { stop, hosts, pid: child.pid, startupMs: Date.now() - started, output: () => output };
    }
    await new Promise((r) => setTimeout(r, 500));
  }
  await stop();
  lastStartFailed = true;
  throw new Error(`Firebase emulators not ready after ${timeoutMs} ms:\n${output.slice(-4000)}`);
}

// Direct run: start, print hosts, stop on Ctrl+C.
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (!available()) {
    console.error('Firebase emulators unavailable (need java and npx on PATH).');
    process.exit(1);
  }
  try {
    const emu = await startEmulators({ log: process.argv.includes('--verbose') });
    console.log(`Emulators ready in ${emu.startupMs} ms (pid ${emu.pid}):`);
    console.log(JSON.stringify(emu.hosts, null, 2));
    console.log('Press Ctrl+C to stop.');
    const shutdown = async () => { await emu.stop(); process.exit(0); };
    process.on('SIGINT', shutdown);
    process.on('SIGTERM', shutdown);
  } catch (e) {
    console.error(e.message);
    process.exit(1);
  }
}
