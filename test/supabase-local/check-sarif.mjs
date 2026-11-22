// CI check: the --sarif file from the real-Postgres run has one located result per finding,
// and every location is a migration of the fixture project.
import { readFileSync } from 'node:fs';

const [sarifFile, resultFile] = process.argv.slice(2);
const sarif = JSON.parse(readFileSync(sarifFile, 'utf8'));
const result = JSON.parse(readFileSync(resultFile, 'utf8'));
const res = sarif.runs[0].results;

if (res.length !== result.findings.length) throw new Error(`SARIF has ${res.length} results, the run had ${result.findings.length} findings`);
const off = res.filter((x) => !/^test\/supabase-local\/supabase\/migrations\/[^/]+\.sql$/.test(x.locations?.[0]?.physicalLocation?.artifactLocation?.uri ?? ''));
if (off.length) throw new Error(`not located in a migration: ${off.map((x) => `${x.ruleId} ${x.properties.resource ?? ''} → ${x.locations?.[0]?.physicalLocation?.artifactLocation?.uri}`).join(', ')}`);
const atTop = res.filter((x) => x.properties.resource && x.locations[0].physicalLocation.region.startLine === 1);
for (const x of res) console.log(`${x.level.padEnd(7)} ${x.ruleId} ${x.properties.resource ?? ''} → ${x.locations[0].physicalLocation.artifactLocation.uri}:${x.locations[0].physicalLocation.region.startLine}`);
if (atTop.length > res.length / 2) throw new Error('most results fell back to line 1: the locator did not find the tables');
console.log(`${res.length} results, all located in migrations`);
