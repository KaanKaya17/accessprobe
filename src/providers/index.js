// Platform adapters. Each exports:
//   id, label, fixStyle
//   detect(opts, { site })            → is this app on my platform?
//   scan(opts, { site, log })         → { target, findings, passed, notes, stats }
import * as supabase from './supabase/index.js';
import * as firebase from './firebase/index.js';
import * as pocketbase from './pocketbase/index.js';
import * as appwrite from './appwrite/index.js';

export const providers = [supabase, firebase, pocketbase, appwrite];

export function byId(id) {
  return providers.find((p) => p.id === id);
}
