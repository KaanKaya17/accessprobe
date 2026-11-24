// Prints the pinned backend versions from test/versions.json as KEY=value lines, for
//   node test/versions.mjs >> "$GITHUB_ENV"
import { readFileSync } from 'node:fs';

const v = JSON.parse(readFileSync(new URL('./versions.json', import.meta.url), 'utf8'));
console.log(`SUPABASE_CLI_VERSION=${v['supabase-cli']}`);
console.log(`FIREBASE_TOOLS_VERSION=${v['firebase-tools']}`);
console.log(`APPWRITE_VERSION=${v.appwrite}`);
console.log(`POCKETBASE_VERSION=${v.pocketbase.version}`);
