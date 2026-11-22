# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- **Test users are reused** (Supabase, Appwrite). With only the public key, accessprobe cannot delete the accounts it signs up, so every run used to leave two more in the project. They are now saved outside the project (`~/.cache/accessprobe/test-users.json`, or `$ACCESSPROBE_CACHE_DIR`) and later runs sign in with them; if they no longer sign in, new ones are created. `--fresh-users` (MCP: `fresh_users`) restores the old behaviour. Appwrite test users are no longer blocked when they are kept.
- **`--schema <file.sql>`** (Supabase; MCP: `schema_files`): read the live database schema from `supabase db dump`, for when migrations don't match production.
- **Schema drift notes** (Supabase): tables that exist only in the migrations or only in the live API are listed. A table named in migrations or code that the live database doesn't have is reported as not in the live database instead of being tested.

### Fixed
- `supabase db dump` / pg_dump schema files were not understood: quoted `"public"."table"` names, primary and foreign keys added with `ALTER TABLE … ADD CONSTRAINT`, identity columns added later, and schema-qualified enum types.

## [0.8.0] - 2026-11-22

### Added
- **Appwrite adapter** (`--platform appwrite`, or `--url <endpoint> --project-id <id>`; an endpoint is detected through the public `/v1/health/version`). Also detected from `--source`: `appwrite.json` / `appwrite.config.json`, or the Appwrite SDK with `setProject("…")`. It never asks for or uses API keys or console credentials: only `X-Appwrite-Project` and the test users' own sessions.
  - Collections (attributes, `$permissions`, `documentSecurity`), TablesDB tables and buckets are read from `appwrite.json`. Without it, ids come from `databases.createDocument("db", "…")` / `tablesDB.createRow({ databaseId, tableId })` calls, env vars or `--table <database>/<collection>`, and attributes are guessed from Appwrite's answers.
  - Two test users sign up through the Account API. A creates a document without explicit permissions (so the defaults apply), then B and an anonymous visitor try to read, list, modify, delete and create; B also tries to rewrite a document's `$permissions` to itself. Catches `read("any")` / `read("users")` on private data, collection-level `update("users")` / `delete("users")`, document security turned off and `create("any")`. Storage buckets get the same tests.
  - A 404 or an empty list only counts as a pass when A's control read through the same endpoint shows the document unchanged.
  - Test documents and files are deleted. Appwrite clients cannot delete their own account, so test users block themselves and the report lists them for deletion in the console.
  - Fixes are Appwrite permission strings, the `appwrite.json` snippet when the project has one, and a `Permission` / `Role` SDK snippet.
  - An Appwrite API key in a browser-exposed env var or in the site bundle is reported.
- Unit tests against a mock Appwrite server, and a `real-appwrite` e2e job against a pinned self-hosted Appwrite 2.7.4 (schema created from the fixture appwrite.json; a server key is used for that setup and the cleanup check only). The job also records the real answers the adapter relies on (status codes, error types, default permissions, session cookies), and the mock follows them.

### Changed
- `--project-id` with `--url` (and without `--api-key`), or with `--platform appwrite`, now means the Appwrite project; Firebase is no longer started for it. `--url` pointing at an Appwrite server is no longer assumed to be Supabase.

## [0.7.0] - 2026-11-22

### Added
- **pgTAP regression tests** (`--pgtap supabase/tests/accessprobe.test.sql`, or `pgtap_file` in the MCP tool). Supabase checks from the run are written as tests for `supabase test db`, so they keep running in CI without a live API.
  - Each test states the secure behaviour: B cannot read, modify, take over or delete A's rows, B cannot insert rows as A, anonymous visitors cannot read them, users cannot change their own role / plan / credits, and views do not show A's private rows.
  - Checks that passed are passing tests. Checks behind a proven leak fail until the fix from the report is applied, then guard against the leak coming back.
  - The tests play both users the way PostgREST does (the `authenticated` / `anon` roles and `request.jwt.claims`), use two fixed test users, and run in one rolled-back transaction.
- The real-Postgres e2e job runs the generated tests twice. Before the fixes, exactly the leak tests must fail. After applying the fixes, every test must pass.

## [0.6.0] - 2026-11-22

### Added
- **MCP server** (`npx accessprobe mcp`, stdio, no dependencies). Coding agents such as Claude Code, Cursor and Codex can call accessprobe as a tool after they change tables, policies or rules.
  - `accessprobe_plan` (read-only) shows which backend and exactly which project or URL would be tested.
  - `accessprobe_scan` returns the Markdown report with evidence and fixes, plus a structured summary (`grade`, `exitCode`, `findings` with `fix`, `passed`, `notes`). It refuses to run unless `owner_confirmed` is true, which agents are told to set only after the user confirms the targets from the plan. Scans run one at a time.
  - Setup for Claude Code: `claude mcp add accessprobe -- npx -y accessprobe mcp`.

## [0.5.0] - 2026-11-21

### Added
- **PocketBase adapter** (`--platform pocketbase`, or `--url <pocketbase url>`, detected through `/api/health`). Also detected from `--source`: a `pb_migrations/` folder or the `pocketbase` JS SDK (`new PocketBase("…")`). It never asks for or uses admin / superuser credentials.
  - Collections, fields and the five API rules are read from `pb_migrations/*.js` without running them (v0.23+ `fields` and v0.22 `schema` formats, `unmarshal`, snapshots). Without migrations, names come from `pb.collection("…")` in code or `--table`.
  - Two test users sign up through the `users` collection, A creates a record (marker text, owner = A), then B and an anonymous visitor try to view, list, modify, take over, forge and delete it. A 404 or an empty list only counts as a pass when A's control read through the same endpoint shows the record unchanged. Test records are always cleaned up; test users delete themselves, or the report lists them.
  - **Users making themselves admin:** when a rule trusts a field of the caller's own record (`@request.auth.role = "admin"`), A tries to set it. The fix is an update rule with `@request.body.role:isset = false`.
  - Fixes are PocketBase API rule strings, plus the same change as a `pb_migrations` file.
- End-to-end tests against a real PocketBase binary (v0.40.6, downloaded once into `~/.cache/accessprobe` and checked against the release's SHA-256). Set `ACCESSPROBE_SKIP_POCKETBASE=1` to skip them.
- **GitHub Action** (`uses: KaanKaya17/accessprobe@v0.5.0`): runs accessprobe on every pull request against a local Supabase (`supabase start`) or the Firebase Emulator Suite. It fails only on proven critical leaks and puts the report into the job summary.
- **A real-Postgres end-to-end test** in CI: a local Supabase with migrations that mix broken and correct rules.

### Changed
- `--url` without `--anon-key` is no longer assumed to be Supabase when the server answers like PocketBase.

- The Claude Code skill and the `AGENTS.md` section now cover PocketBase.

### Fixed
- **Writable views** (found by the real-Postgres test): a simple view without `security_invoker` is auto-updatable, so anonymous users could write to the base table through it. Such views are recognised from the migrations. Their findings now get the `security_invoker` fix instead of table policies, and they are not reported twice.

## [0.4.0] - 2026-11-21

### Added
- **Users making themselves admin (Supabase).** "Users may update their own row" usually also lets them change `role`, `is_admin`, `plan`, `credits` and similar columns on that row. User A now tries this on its own test row and puts the old value back right away. A finding includes column-grant SQL that keeps the row editable but locks these columns. A refusal (for example, a missing column grant) is recorded as a pass.
- **Users making themselves admin (Firestore).** When rules grant rights based on the caller's own document (`get(/…/users/$(request.auth.uid)).data.role == 'admin'`), user A tries to set that field itself. The fix uses `affectedKeys().hasAny([...])` to block it.
- **Views that skip RLS (Supabase).** A view runs with its owner's rights unless it has `security_invoker = true`, so it can show rows that the table's policy hides. B and an anonymous visitor now look through every view for A's test rows from protected tables. A finding includes the `alter view … set (security_invoker = true)` fix. Views are also found in `supabase/migrations`.

### Fixed
- An anonymous read of a view no longer suggests `create policy` SQL, which is invalid on a view. It suggests `security_invoker` instead.

## [0.3.1] - 2026-11-21

### Changed
- Releases are now staged on npm by the release workflow (trusted publishing, no token) and go live only after a maintainer approves them with 2FA. This is the first version shipped that way. No changes to the CLI itself.

## [0.3.0] - 2026-11-21

### Changed
- **Renamed to accessprobe** (was rlsprobe): npm refused the old name as too similar to an existing package, and it covers Firebase rules too, not just RLS. Command: `npx accessprobe`.

### Added
- **Supabase "Confirm email" check:** before signing up test users, accessprobe reads the project's public auth settings. If confirmation emails would be sent, it stops and nothing is created. Bouncing emails to made-up addresses can get a project's email sending restricted.
- npm releases use Trusted Publishing (OIDC) in **stage-only** mode: no npm token is stored, and the workflow only stages a version. A maintainer makes it live with 2FA, so a compromised workflow cannot publish.
- **Zero-config:** `npx accessprobe` in a project folder finds everything by itself.
  - **Supabase:** the URL and the public anon key come from `.env*`, `local.properties`, `app.json` or client code.
  - **Firebase:** the web config comes from `initializeApp({...})`.
  - Secret keys are never used. A secret key in a browser-exposed variable (`VITE_`, `NEXT_PUBLIC_`, `EXPO_PUBLIC_`, …) or in client code is reported as critical.
- **The target is named before anything is written.** The confirmation (and the `Target:` line, shown with `--yes` too) names the exact Supabase URL or Firebase project. If one folder configures several projects (`.env` vs `.env.local`, dev vs prod `google-services.json`), accessprobe stops and asks for `--url` / `--project-id`.
- **`accessprobe setup-agent`** installs a Claude Code skill and an `AGENTS.md` section (Codex, Cursor and others). Coding agents then confirm ownership, report only proven findings, read every data access in the app before changing a rule, test locally and ask before deploying. It never overwrites existing files.
- **New takeover test (Supabase and Firestore):** can user B set the owner of A's record to itself? This happens with `USING (true) … WITH CHECK (owner = me)`, or with an update rule that only checks `request.resource.data`.
- **Firebase Realtime Database:**
  - Paths come from the app code (`getReference()`/`.child()` chains) when there is no `database.rules.json`, and are combined with the rules when there is one.
  - Rules exported from the console are accepted (`--database-rules`, `--firestore-rules`, `--storage-rules`).
  - `.validate` shapes are used for the test record.
  - Inboxes are detected from code that writes through a recipient id.
  - New test: can anyone list every entry under a node? It is critical when the entries are keyed by user id or by a secret such as a backup code.
- `--version`.
- **CI:** the packed package is installed and run on Ubuntu, Windows and macOS. A release workflow stages a version on `v*` tags.

### Fixed
Most of these came from the first real-project runs and from an independent code review. The first two groups are the most important.

**No PASS without proof**
- A check passes only on an explicit refusal, or on an empty answer while A still sees its own row unchanged through the same filter. A control request runs first.
- 400, 404, network errors, trigger errors and length errors are now *inconclusive*. Before, they could be reported as passed.
- "Saw nothing" without a test row is reported as unproven.

**Never touch real data**
- Supabase filters pin the test row with every primary-key column plus the marker. Before, composite keys produced filters like `team_id=eq.1`.
- The client refuses to send PATCH or DELETE without a safe equality filter.
- The marker is never placed in a key column, and tampered values keep their length.
- RTDB test entries are only written under the test user's own key. A child is never added under a node holding a plain value, and the whole node of a real (`--user-a`) account is never overwritten.

**Public data**
- Public Supabase buckets are tested through the public URL and never reported as "B cannot download".
- `allow read: if true` is *public by design*.
- Content-like tables (posts, comments, products…) and leaderboard or presence nodes only lower the severity of *read* findings.

**Firebase**
- Firestore PASSes that rest only on a 403 wait until some Firestore request has succeeded. This rules out the API being off or App Check.
- Storage is skipped, instead of crashing, when there is no bucket.
- If `--project-id` doesn't match a config file, that file's database URL and bucket are ignored.
- If the given rules lock the root but the root is readable, accessprobe is talking to the wrong database, and its Realtime Database results are discarded.

**Robustness**
- Network errors are inconclusive instead of fatal.
- Cleanup of test data always runs, in `finally`.
- If one backend fails, the other's results and its "delete these test users" note are kept.
- A `google-services.json` used only for push no longer triggers Firebase tests.
- Anthropic keys are no longer also reported as OpenAI keys.
- Text files use LF line endings (`.gitattributes`), which fixes Windows checkouts.
- Each "passed" line and note is reported only once.

## [0.2.0] - 2026-11-21

### Added
- **Firebase support:** Firestore, Realtime Database and Storage, using the same two-user engine.
  - Reads the config from the site bundle, `google-services.json` or `GoogleService-Info.plist`.
  - Reads `firestore.rules`, `storage.rules` and `database.rules.json` to find owner fields, `{uid}`
    path ownership and validator schemas.
  - Reports `allow read: if true` as *public by design*.
  - Test users delete themselves at the end.
- `--platform`, `--project-id`, `--api-key` and `--emulator` flags.
- End-to-end tests against the Firebase Emulator Suite, plus verified REST notes in `test/firebase/API-NOTES.md`.

### Changed
- Split the core from the platform adapters (`src/core`, `src/providers/<platform>`). Supabase
  behaviour is unchanged.
- Node 20 or newer is now required.

## [0.1.0] - 2026-11-20

### Added
- Supabase: two real test users. User A creates rows and files; user B and anonymous visitors try to
  read, modify, forge and delete them.
- Discovers the Supabase URL and anon key from a site bundle, and flags leaked `service_role`,
  `sb_secret_`, Stripe, OpenAI and AWS keys.
- `--source`: reads the schema from `supabase/migrations` and app code, since the API schema is
  hidden on new projects.
- Fix SQL (including for apps with their own users table) and copy-paste AI prompts.
- `--cleanup-rpc` to delete test users, coverage-aware grading (`N/A` when nothing could be tested),
  and CI-friendly exit codes.

[Unreleased]: https://github.com/KaanKaya17/accessprobe/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/KaanKaya17/accessprobe/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/KaanKaya17/accessprobe/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/KaanKaya17/accessprobe/releases/tag/v0.1.0
