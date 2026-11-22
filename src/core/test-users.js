// Test users are kept for the next run when a platform does not let them delete themselves
// (Supabase without a delete-account RPC, Appwrite). Otherwise every run would leave two more
// accounts in the project's user list.
//
// Stored outside the project folder, so they are never committed:
//   $ACCESSPROBE_CACHE_DIR, else $XDG_CACHE_HOME/accessprobe, else ~/.cache/accessprobe
// One entry per platform + target. The passwords are random and belong to throwaway test accounts.

import { readFileSync, writeFileSync, mkdirSync, chmodSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';

export function cacheDir() {
  return process.env.ACCESSPROBE_CACHE_DIR || join(process.env.XDG_CACHE_HOME || join(homedir(), '.cache'), 'accessprobe');
}

export function usersFile() {
  return join(cacheDir(), 'test-users.json');
}

function readAll() {
  try {
    const j = JSON.parse(readFileSync(usersFile(), 'utf8'));
    return j && typeof j === 'object' ? j : {};
  } catch {
    return {};
  }
}

function writeAll(all) {
  mkdirSync(cacheDir(), { recursive: true });
  writeFileSync(usersFile(), `${JSON.stringify(all, null, 2)}\n`, { mode: 0o600 });
  try {
    chmodSync(usersFile(), 0o600);
  } catch {
    // Windows: permissions come from the user profile folder
  }
}

const keyOf = (platform, target) => `${platform} ${String(target).replace(/\/+$/, '')}`;

// → { A: 'email:password', B: 'email:password' } or null
export function loadUsers(platform, target) {
  const e = readAll()[keyOf(platform, target)];
  if (!e?.A?.email || !e?.B?.email) return null;
  return { A: `${e.A.email}:${e.A.password}`, B: `${e.B.email}:${e.B.password}` };
}

export function saveUsers(platform, target, users) {
  const [A, B] = ['A', 'B'].map((l) => users.find((u) => u.label === l));
  if (!A?.password || !B?.password) return false;
  try {
    const all = readAll();
    all[keyOf(platform, target)] = { A: { email: A.email, password: A.password }, B: { email: B.email, password: B.password }, saved: new Date().toISOString() };
    writeAll(all);
    return true;
  } catch {
    return false;
  }
}

export function forgetUsers(platform, target) {
  const all = readAll();
  if (!(keyOf(platform, target) in all)) return;
  delete all[keyOf(platform, target)];
  try {
    writeAll(all);
  } catch {
    // nothing to do: a stale entry only costs one failed sign-in next time
  }
}

// Runs setup with the cached users when there are any; falls back to fresh sign-ups when they
// no longer sign in (deleted in the dashboard, password changed, …).
export async function withReusableUsers({ platform, target, opts, log }, setup) {
  const reuse = !opts.freshUsers && !opts.userA && !opts.userB;
  const cached = reuse ? loadUsers(platform, target) : null;
  if (cached) {
    try {
      const users = await setup(cached.A, cached.B);
      for (const u of users) u.reused = true;
      log('  reusing the test users from an earlier run');
      return { users, reuse };
    } catch {
      forgetUsers(platform, target);
      log('  the saved test users no longer sign in; creating new ones');
    }
  }
  return { users: await setup(opts.userA, opts.userB), reuse };
}
