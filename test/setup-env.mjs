// Loaded by `npm test` (node --import): saved test users go to a throwaway folder,
// never into the developer's real ~/.cache/accessprobe.
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

if (!process.env.ACCESSPROBE_CACHE_DIR) process.env.ACCESSPROBE_CACHE_DIR = mkdtempSync(join(tmpdir(), 'accessprobe-cache-'));
