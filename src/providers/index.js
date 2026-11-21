// Platform adapters. Each exports:
//   id, label, fixStyle
//   detect(opts, { site })            → is this app on my platform?
//   scan(opts, { site, log })         → { target, findings, passed, notes, stats }
import * as supabase from './supabase/index.js';

export const providers = [supabase];

export function byId(id) {
  return providers.find((p) => p.id === id);
}
