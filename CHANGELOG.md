# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.3.0] - 2026-11-21

### Added
- **Supabase "Confirm email" check:** before signing up test users, rlsprobe reads the project's public auth settings. If confirmation emails would be sent, it stops and nothing is created. Bouncing emails to made-up addresses can get a project's email sending restricted.
- npm releases use Trusted Publishing (OIDC), so no npm token needs to be stored. Private repositories skip npm.
- **Zero-config:** `npx rlsprobe` in a project folder finds everything by itself.
  - **Supabase:** the URL and the public anon key come from `.env*`, `local.properties`, `app.json` or client code.
  - **Firebase:** the web config comes from `initializeApp({...})`.
  - Secret keys are never used. A secret key in a browser-exposed variable (`VITE_`, `NEXT_PUBLIC_`, `EXPO_PUBLIC_`, …) or in client code is reported as critical.
- **The target is named before anything is written.** The confirmation (and the `Target:` line, shown with `--yes` too) names the exact Supabase URL or Firebase project. If one folder configures several projects (`.env` vs `.env.local`, dev vs prod `google-services.json`), rlsprobe stops and asks for `--url` / `--project-id`.
- **`rlsprobe setup-agent`** installs a Claude Code skill and an `AGENTS.md` section (Codex, Cursor and others). Coding agents then confirm ownership, report only proven findings, read every data access in the app before changing a rule, test locally and ask before deploying. It never overwrites existing files.
- **New takeover test (Supabase and Firestore):** can user B set the owner of A's record to itself? This happens with `USING (true) … WITH CHECK (owner = me)`, or with an update rule that only checks `request.resource.data`.
- **Firebase Realtime Database:**
  - Paths come from the app code (`getReference()`/`.child()` chains) when there is no `database.rules.json`, and are combined with the rules when there is one.
  - Rules exported from the console are accepted (`--database-rules`, `--firestore-rules`, `--storage-rules`).
  - `.validate` shapes are used for the test record.
  - Inboxes are detected from code that writes through a recipient id.
  - New test: can anyone list every entry under a node? It is critical when the entries are keyed by user id or by a secret such as a backup code.
- `--version`.
- **CI:** the packed package is installed and run on Ubuntu, Windows and macOS. A release workflow publishes on `v*` tags; npm needs the `NPM_TOKEN` secret.

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
- If the given rules lock the root but the root is readable, rlsprobe is talking to the wrong database, and its Realtime Database results are discarded.

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

[Unreleased]: https://github.com/KaanKaya17/rlsprobe/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/KaanKaya17/rlsprobe/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/KaanKaya17/rlsprobe/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/KaanKaya17/rlsprobe/releases/tag/v0.1.0
