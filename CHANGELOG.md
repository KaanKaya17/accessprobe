# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.14.1] - 2026-11-22

### Changed
- Supabase `rpc-review` (info) only lists functions the migrations do not show to be safe. A function that checks the caller (`auth.uid()`, directly or through a helper) or that anonymous visitors cannot execute becomes a passed check that says why. On a real app this turned its only remaining note into a pass. Without migrations every function is listed, as before.
- "No supported backend found" names the folder it looked in. A run from the wrong folder (PowerShell 5 has no `&&`, so `cd x && npx accessprobe` stays in the old folder) now says so.

## [0.14.0] - 2026-11-22

Found by preparing a run on a real Supabase fitness app (its migrations), running 0.13.0 on a real Firebase game, and on a new multi-tenant app built from scratch (a five-a-side squad app: groups, matches, line-ups, anonymous ratings).

### Added
- **Organizations: nested tables.** A table scoped by the organization that points at another scoped table (`match_players.match_id → matches`) is filled with the row A just created there, and a second user column (`ratings.ratee_id`) gets user B. Rows without a text column are recognized by their primary key (the change test needs a text column; read and delete are still tested).
- **Organizations: roles from the migrations.** Allowed values of `CHECK (role in (…))` become the column's values (like an enum), so roles named `organizer` / `player` (or `kaptan` / `oyuncu`) are understood. A member insert can leave the role to its default.
- **Sensitive columns** are also checked when B reads other users' existing rows (a profile table filled by a trigger, where accessprobe can't insert its own row).

### Fixed
- `definer-no-auth-check` no longer flags a SECURITY DEFINER function that checks the caller through a helper (`public.current_user_id()`, `is_member_of(org)` …) defined in the migrations: a function that calls a function that reads `auth.uid()` / `auth.jwt()` counts as checking, transitively. Found on a real app before it could cause a false alarm.
- Firebase: a project that only uses the Realtime Database no longer gets "No firestore.rules … pass --source" when `--source` was passed; the note now says Firestore is not used.
- Organizations: rows that can't be deleted on their own (no DELETE policy, e.g. ratings) but went with the organization through its foreign key are no longer reported as left behind.
- e2e: Supabase CLI pinned to 3.2.0; resolving "latest" hit the GitHub API rate limit.

## [0.13.0] - 2026-11-22

### Added (Supabase)
- **Organizations / teams.** Multi-tenant rules are tested automatically when the schema has a tenant table (`orgs`, `organizations`, `teams`, `workspaces`, `tenants`, `companies` …), a membership table with a user column and the tenant column (`org_members (org_id, user_id, role)`, found by foreign key or name) and tables scoped by the same column. A creates a test organization, makes itself owner (unless a trigger already did) and writes a row into every scoped table. Then:
  - **outsider** (B, not a member): `cross-tenant-read` / `-update` / `-delete` on the scoped rows, `cross-tenant-members-read` (warning) on the member list, and `tenant-self-join`: B inserts a membership for itself into A's organization, as owner or admin first, then as a plain member;
  - **member** (A adds B with a member role, B signs in again so JWT claims are current): `tenant-role-escalation` when B can set its own role to owner / admin (the old role is put back);
  - **removed member** (A removes B; B keeps that session): `removed-member-access` when B can still read the organization's rows. That is what policies built on JWT claims (`app_metadata`) do until the token is refreshed. Tables already open to outsiders are not reported twice.
  - Fixes are policies built on `is_member_of()` / `is_admin_of()` SECURITY DEFINER helpers (no policy recursion on the members table), an admin-only insert policy for memberships, and no self-service role updates.
  - Test organizations, memberships and rows are deleted at the end (children first). The per-user notes that could not fill `org_id` for those tables are replaced by one "Organizations: tested …" note. Skipped under `--read-only`.
- e2e (real Postgres): a second fixture migration with `orgs`, `org_members` (self-service role update bug), `projects` (correct), `invoices` (readable by everyone) and `org_files` (trusts a JWT claim kept in sync by a trigger). CI checks every verdict.

## [0.12.0] - 2026-11-22

### Added (Supabase)
- **Sensitive columns.** When anonymous visitors or user B can read someone else's row, its columns are checked by name for personal data (`email`, `phone`, addresses, date of birth, national ids, IBAN / card, IP, `stripe_customer_id`, location) and secrets (`password_hash`, `api_key`, `*_token`, `*_secret`, private keys, recovery codes). Findings `sensitive-columns-anon` / `sensitive-columns`: critical for secrets, a warning for personal data. They have their own ids, so a table accepted as public in `.accessprobeignore` (`profiles cross-user-read`) still reports the email in it. The fix is a column-level grant (or a private side table). Values are never shown.
- **Functions, proven.** Every RPC the API exposes is called with GET and no arguments as A (control), B and an anonymous visitor. PostgREST runs GET in a read-only transaction, so nothing can be written, and a function that needs arguments is not called. If B or the visitor gets back one of A's private test rows (one B was refused through the table), that is `rpc-cross-user-read` / `rpc-anon-read` (critical). A function that applies RLS is a passed check. Runs under `--read-only` too.
- **`SECURITY DEFINER` functions, from the migrations.** A definer function that never reads `auth.uid()` / `auth.jwt()` (or the request JWT) and that `anon` or `authenticated` may execute is `definer-no-auth-check` (warning; accessprobe never POSTs to it). Grants are followed in migration order: `REVOKE … FROM anon`, `ALTER DEFAULT PRIVILEGES`, `CREATE OR REPLACE` keeping the old grants. `REVOKE … FROM public` alone is called out: Supabase grants anon and authenticated directly. Trigger functions are skipped. Definer functions without `set search_path` are one `definer-search-path` info finding.
- **GraphQL.** An introspection query to `/graphql/v1` as an anonymous visitor; tables it lists are `graphql-anon-schema` (warning, like Supabase's `pg_graphql_anon_table_exposed` advisor). Only a schema query is sent; the client refuses mutations, and `--read-only` allows this one POST.
- e2e (real Postgres): the fixture has a leaking definer function, an invoker function and a data-changing definer function guarding a canary row. CI checks the leak is proven, the invoker passes, the static warning is there, and the canary row survives.

## [0.11.0] - 2026-11-22

### Added
- **`--sarif <file>`** writes the findings as SARIF 2.1.0 for GitHub code scanning (`github/codeql-action/upload-sarif`) and other SARIF viewers. Each result is placed on the line that leaks: the newest policy for that table and command in the migrations or `--schema` files (a read leak points at the SELECT policy, an update leak at the UPDATE policy), the `CREATE TABLE` when there is no policy, `bucket_id = '…'` for storage, the `match /…` block in `firestore.rules` / `storage.rules`, the node in `database.rules.json`, the collection in `pb_migrations` or `appwrite.json`. Paths are relative to the repository root, so they resolve when the Action runs in a subfolder. Rules carry `security-severity` (critical 9.1, warning 5.3, info 2.0) and results a stable fingerprint, so an alert stays the same alert across runs. Accepted findings are left out.
- GitHub Action: `sarif` input and output.
- e2e: the real-Postgres run writes SARIF; it must validate against the SARIF 2.1.0 schema and every result must point into the fixture's migrations.

### Fixed
- **A rate limit could pass a check.** A Supabase Storage download or delete by user B that got HTTP 429 counted as "B cannot download / delete A's files", because any 4xx counted as refused. All four clients now retry a 429 (and a 503 with `Retry-After`) up to 3 times, following `Retry-After` (at most 8 s per wait). A request that is still throttled comes back as inconclusive, like a network error, so it can never pass.
- The report folds all throttled checks into one "Rate limited" note that names the tables and checks. A throttled Supabase sign-up says that sign-ups are limited per hour and suggests `--user-a` / `--user-b`.

## [0.10.0] - 2026-11-22

### Added
- **`--read-only`** (MCP: `read_only`), for production and for tables with triggers, database webhooks or Cloud Functions you don't want to fire. No request that could change anything is sent: inserts, updates, deletes, uploads, RPC calls and sign-ups are stopped in the client before they leave the process, on all four platforms. It needs two existing accounts (`--user-a`, `--user-b`). Anonymous reads and B's reads of other users' existing rows are still tested; write checks are listed as not run and never reported as passed. A blocked write looks like a network error to the probes, which already count that as inconclusive.
- **`.accessprobeignore`** (or `--ignore-file`; MCP: `ignore_file`) for findings that are open on purpose. One `<resource> [finding id]  # reason` per line. Accepted findings are shown in their own section with the reason, don't count for the grade or the exit code, and their failing checks are left out of the `--pgtap` / `--rules-tests` files. Entries that matched nothing are listed in the notes.
- The ownership prompt says that inserts fire triggers and webhooks, and points to `--read-only`.
- `real-supabase` e2e: a `--read-only` run against real Postgres must leave every public table, storage object and auth user exactly as it was (content fingerprint before and after).

## [0.9.0] - 2026-11-22

### Added
- **Test users are reused** (Supabase, Appwrite). With only the public key, accessprobe cannot delete the accounts it signs up, so every run used to leave two more in the project. They are now saved outside the project (`~/.cache/accessprobe/test-users.json`, or `$ACCESSPROBE_CACHE_DIR`) and later runs sign in with them; if they no longer sign in, new ones are created. `--fresh-users` (MCP: `fresh_users`) restores the old behaviour. Appwrite test users are no longer blocked when they are kept.
- **`--schema <file.sql>`** (Supabase; MCP: `schema_files`): read the live database schema from `supabase db dump`, for when migrations don't match production.
- **Schema drift notes** (Supabase): tables that exist only in the migrations or only in the live API are listed. A table named in migrations or code that the live database doesn't have is reported as not in the live database instead of being tested.
- **Anonymous-auth attacker** (Firebase). If the project has Anonymous sign-in enabled (`accounts:signUp` with only `returnSecureToken` returns a token), a third test user signs in anonymously and repeats every Firestore, Realtime Database and Storage read, list and write the unauthenticated visitor was refused. Rules like `allow read: if request.auth != null` are effectively public then. Findings: `anon-auth-read`, `anon-auth-create` / `anon-auth-write`, `rtdb-anon-auth-root` / `-list` / `-read` / `-write`, `storage-anon-auth-read`; critical when they reach user A's private data. The fix adds `request.auth.token.firebase.sign_in_provider != 'anonymous'`, or says to disable Anonymous sign-in. A refused anonymous sign-up is a passed check ("Anonymous sign-in is disabled"). The anonymous user is deleted at the end.
- **Security Rules regression tests** (`--rules-tests test/accessprobe.rules.test.mjs`, or `rules_tests_file` in the MCP tool), the Firebase counterpart of `--pgtap`. Each Firestore / Realtime Database / Storage check with a clear verdict becomes a `node:test` test for `@firebase/rules-unit-testing` (installed by your project): A's data is seeded with rules disabled, A's own read is the control, then B, an unauthenticated visitor and an anonymous-auth user try the attack. Tests behind a proven leak are marked `FAILS until the fix` and fail until it is deployed. Run with `firebase emulators:exec --only firestore,database,storage "node --test <file>"`.
- `firebase-rules-tests` e2e job: generates the file against the emulators, runs it with a pinned `@firebase/rules-unit-testing` under `firebase emulators:exec`, and checks that exactly the tests for proven leaks fail.

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
