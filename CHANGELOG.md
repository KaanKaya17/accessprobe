# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Firebase Realtime Database: paths are taken from the app code (`getReference()`/`.child()` chains) when there is no `database.rules.json`.
- New test: can anyone list every entry under a node? It is critical when the entries are keyed by user id or by a secret such as a backup code.
- `--database-rules`, `--firestore-rules` and `--storage-rules` take rules exported from the console, e.g. `firebase database:get /.settings/rules`.
- Rules and code are combined. Code adds the keyed structure that rules often leave out, so `"duel_invites": {".write": "auth != null"}` is tested as `duel_invites/$targetUserId`.
- RTDB `.validate` shapes (`hasChildren`, `isNumber`) are used for the test record, so schema-checked user nodes are fully tested.
- Inboxes are detected from code that writes through a recipient id. Ids that are only read are no longer treated as inboxes.

### Fixed
- rlsprobe no longer writes test entries into shared nodes, where create-only rules could make them impossible to remove. This was found on the first real project.
- Listing counts no longer include rlsprobe's own test entries.
- Recipient-keyed nodes (invite inboxes) report overwrites as a warning with create-only advice.
- A record read back from RTDB is compared regardless of key order. RTDB sorts keys, which used to make A's own write look failed.
- Public-looking node names (presence, leaderboard) now lower the severity of read findings only. Another user overwriting your data is always critical.

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

[Unreleased]: https://github.com/KaanKaya17/rlsprobe/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/KaanKaya17/rlsprobe/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/KaanKaya17/rlsprobe/releases/tag/v0.1.0
