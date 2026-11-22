# accessprobe

[![CI](https://github.com/KaanKaya17/accessprobe/actions/workflows/ci.yml/badge.svg)](https://github.com/KaanKaya17/accessprobe/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![Node 20+](https://img.shields.io/badge/node-%3E%3D20-brightgreen)
![Zero dependencies](https://img.shields.io/badge/dependencies-0-brightgreen)
[![Sponsor](https://img.shields.io/badge/sponsor-%E2%9D%A4-ea4aaa)](https://github.com/sponsors/KaanKaya17)

**Prove your Supabase RLS and Firebase Security Rules actually work.**

Most scanners check whether a policy *exists*. A policy like `using (auth.role() = 'authenticated')`
(Supabase) or `allow read: if request.auth != null` (Firebase) exists and passes every checklist,
yet it lets every logged-in user read everyone else's data.

accessprobe doesn't guess. It signs up **two real test users** in your app, has user A create rows and
files, then checks whether user B (or an anonymous visitor) can **read, change or delete** them.

```bash
cd your-app
npx accessprobe
```

Works on Linux, macOS and Windows with Node.js 20 or newer, with no other dependencies. Every pull request runs the full test suite on all three.

<details><summary>Windows PowerShell</summary>

- Run the two lines one by one. Windows PowerShell 5 has no `&&`, so `cd your-app && npx accessprobe` stays in the old folder.
- You can also skip `cd` and pass the folder: `npx accessprobe --source C:\path\to\your-app`.
- Multi-line examples below end lines with `\`. In PowerShell, use a backtick `` ` `` instead, or put everything on one line.
- Put `email:password` in single quotes (`--user-a 'a@test.dev:p@ss!'`) so PowerShell leaves `@`, `$` and `!` alone.

</details>

That's it. accessprobe finds your Supabase, Firebase, PocketBase or Appwrite config in `.env`, `local.properties`,
`google-services.json`, `pb_migrations/`, `appwrite.json` or your code, using only the public key an attacker would also see. Then it
reads your migrations or rules and runs the tests. Add `--site https://your-app.com` to also check
the deployed JavaScript bundle for leaked secret keys.

```
✖ CRITICAL  User B can read user A's rows in "orders"
   Proven: A created a row, B fetched it. In total B can see 1,240 row(s) that belong to other users.
   proof: as user B: GET /rest/v1/orders?select=*&id=eq.f78f… → 200 → returned A's row

✖ CRITICAL  User B can create rows in "orders" in user A's name
   proof: as user B: POST /rest/v1/orders {"user_id":"<user A id>",...} → 201

  ✔ notes: B cannot read A's rows
  ✔ notes: B cannot modify A's rows
```

- **Evidence, not warnings.** Every critical finding is a request that actually succeeded against test data, so the findings are not false alarms.
- **Fixes included.** `--out report.md` gives the exact policy SQL or Security Rules for every finding, plus a prompt you can paste into Lovable, Bolt, Cursor or Claude Code.
- **Local and open source.** It runs on your machine and needs only the public keys an attacker can also see. Nothing is sent anywhere else.
- **Zero dependencies.** Node 20+ is all you need.

## Using it with Claude Code, Codex or Cursor

Run this once in your project:

```bash
npx accessprobe setup-agent
```

It adds a Claude Code skill (`.claude/skills/accessprobe/SKILL.md`) and a short section to `AGENTS.md`,
which Codex, Cursor and other agents read. Then just ask your agent: *"check my database rules with
accessprobe"*.

The skill tells the agent to:

- confirm you own the app before testing;
- report only proven findings and say clearly what wasn't tested;
- before tightening a rule, read every place in your code that uses that data. A rule that blocks a
  read your app depends on breaks the app for every user;
- test the fix locally (Firebase Emulator Suite or a Supabase branch), and **ask you before deploying**.

### As an MCP server

accessprobe also runs as an [MCP](https://modelcontextprotocol.io) server, so an agent can call it as a
tool after it changes tables, policies or rules:

```bash
# Claude Code
claude mcp add accessprobe -- npx -y accessprobe mcp
```

Cursor (`.cursor/mcp.json`), Windsurf, VS Code and other clients take the same command:

```json
{ "mcpServers": { "accessprobe": { "command": "npx", "args": ["-y", "accessprobe", "mcp"] } } }
```

Codex (`~/.codex/config.toml`):

```toml
[mcp_servers.accessprobe]
command = "npx"
args = ["-y", "accessprobe", "mcp"]
```

It has two tools:

- `accessprobe_plan` is read-only. It shows which backend and exactly which project or URL would be tested.
- `accessprobe_scan` runs the test and returns the report with evidence and fixes, plus a structured
  summary (`grade`, `exitCode`, `findings`, `notes`). It only runs with `owner_confirmed: true`, which
  the agent is told to set only after you confirm you own the targets shown by the plan.

The server runs in your project folder by default; pass `directory` to test another one.

## What it tests

**Supabase**

| Area | Check |
|---|---|
| Site bundle | Supabase URL + anon key discovery; leaked `service_role` / `sb_secret_` / Stripe / OpenAI / AWS keys |
| Tables | anonymous read, anonymous write (RLS off), **B reads A's row**, **B updates A's row**, **B takes A's row over** (sets the owner to itself), **B deletes A's row**, **B inserts a row as A**, **users make themselves admin** (change `role`, `is_admin`, `plan`, `credits`… on their own row; the old value is put back) |
| Organizations / teams | found from the schema: the tenant table (`orgs`, `teams`, `workspaces` …), the membership table (`org_members (org_id, user_id, role)`) and every table scoped by the same `org_id`. A creates a test organization, becomes its owner and writes a row into each scoped table. **B as an outsider** reads, changes and deletes those rows, lists the members and **adds itself to A's organization** (as owner, then as member). **B as a plain member** tries to **raise its own role** to admin / owner. **B after being removed** reads the rows again with its member session: policies that trust JWT claims (`app_metadata`) keep removed members in until the token refreshes. Fixes use `is_member_of()` / `is_admin_of()` helpers |
| Views | **views that skip RLS**: B (and anonymous visitors) look for A's private test rows in every view. Views without `security_invoker` run with the owner's rights |
| Storage | anonymous listing, **B downloads A's file**, **B deletes A's file**, public buckets via their public URL |
| Project config | secret keys in browser-exposed env vars (`VITE_`, `NEXT_PUBLIC_`, `EXPO_PUBLIC_` …) or in client code |
| Sensitive columns | rows that anonymous visitors or other users can read are checked for **personal data and secrets by column name** (`email`, `phone`, `address`, `stripe_customer_id`, `password_hash`, `api_key`, `*_token` …). RLS works on rows, not columns: a public profile can still hand out the email. Values are never shown |
| Functions | every exposed RPC is called with **GET and no arguments** as A, B and an anonymous visitor (PostgREST runs GET in a read-only transaction, so nothing is written, and functions that need arguments are not called). **B or a visitor getting A's private rows back through a function** is a proven leak. From the migrations: **`SECURITY DEFINER` functions that never check the caller** (no `auth.uid()` / `auth.jwt()`) and that `anon` / `authenticated` may execute, `REVOKE … FROM public` that leaves Supabase's anon grant in place, and definer functions without a fixed `search_path`. Data-changing functions are never POSTed to |
| GraphQL | `pg_graphql` introspection as an anonymous visitor: the tables, columns and relations it lists (rows stay behind RLS, the schema does not) |

**Firebase**

| Area | Check |
|---|---|
| Config | `firebaseConfig` in the site bundle, `google-services.json`, `GoogleService-Info.plist`; leaked service-account keys and FCM server keys |
| Firestore | **B reads / lists / modifies / takes over / deletes A's documents**, **B creates a document in A's name**, anonymous read and write. Owner fields, `{uid}` path ownership and validator schemas (`hasOnly`, `is string`) are read from `firestore.rules`. **Users make themselves admin**: when your rules grant rights from the caller's own document (`get(/…/users/$(request.auth.uid)).data.role == 'admin'`), A tries to set that field itself |
| Realtime Database | anonymous read of the root, **B reads / overwrites A's node** (`users/$uid`), **anyone lists every entry** of a node (user ids, backup codes…), open nodes. Paths come from the rules, or from your code when the rules only live in the console |
| Storage | **B downloads / lists / deletes A's files**, anonymous download |
| Anonymous sign-in | if the project has the Anonymous provider enabled, **an anonymous-auth user** (a free ID token, no account needed) repeats every read, list and write the unauthenticated visitor was refused. `request.auth != null` is true for it, so such rules are effectively public |
| Rules file | test-mode time limits (`request.time < timestamp.date(…)`), `{document=**}` catch-alls |

`allow read: if true` is reported as *public by design*, not as a leak.

**PocketBase**

| Area | Check |
|---|---|
| Config | server URL from `new PocketBase("…")` in the site bundle or code, `POCKETBASE_URL` / `PB_URL` env vars, or `--url`. Collections, fields and the five API rules are read from `pb_migrations/*.js` (read, never executed) |
| Collections | **B views / lists / modifies / takes over / deletes A's records**, **B creates a record in A's name**, anonymous view, list and create. The owner field is the relation to `users` that your rules compare with `@request.auth.id` |
| Users | B reads, lists, changes or deletes A's account; anonymous listing of users |
| Privilege escalation | **users make themselves admin**: when a rule trusts a field of the caller's own record (`@request.auth.role = "admin"`, `@collection.members.role = …`), A tries to set it on its own record and puts the old value back |

PocketBase hides records instead of refusing: a list that doesn't match returns no items, and view,
update and delete return 404. accessprobe only counts that as a pass when A's own read through the same
endpoint shows the record still exists and is unchanged. A `""` (public) list or view rule is reported
as *public by design*. Fixes are API rule strings, plus the same rules as a `pb_migrations` file.

**Appwrite**

| Area | Check |
|---|---|
| Config | endpoint + project id from `new Client().setEndpoint("…").setProject("…")`, `APPWRITE_ENDPOINT` / `APPWRITE_PROJECT_ID` env vars, `appwrite.json`, or `--url` + `--project-id`. Collections (attributes, `$permissions`, `documentSecurity`), TablesDB tables and buckets are read from `appwrite.json` / `appwrite.config.json`; ids also come from `databases.createDocument("db", "…")` calls. An API key in a browser-exposed env var or the site bundle is reported |
| Collections / tables | A creates a document **without explicit permissions** (what most apps do), then **B reads, lists, modifies and deletes it**, **B rewrites a document's `$permissions` to itself** (takeover), anonymous read, list and create. Catches `read("any")` / `read("users")` on private data, `update("users")` / `delete("users")` at collection level, document security turned off, and `create("any")` |
| Storage | **B downloads / lists / renames / takes over / deletes A's files**, anonymous download and upload (`--bucket` or buckets from `appwrite.json` and code) |

Appwrite hides documents instead of refusing when document security is on (404 or an empty list).
accessprobe only counts that as a pass when A's own read through the same endpoint shows the document
unchanged; a `401 user_unauthorized` is an explicit refusal. Both the `databases/…/documents` API and the
TablesDB `tablesdb/…/rows` API are supported. Fixes are Appwrite permission strings
(document security on, `create("users")` at collection level, `Permission.read(Role.user(id))` per
document), plus the `appwrite.json` snippet when the project has one.

Test rows, documents, records and files are deleted at the end. Firebase and PocketBase test users
delete themselves (where the users delete rule allows it; otherwise the report lists them). Appwrite
clients cannot delete their own account, so Appwrite test users block themselves and the report lists
them for deletion in the console. Supabase
test users can't be deleted with the anon key, so the report tells you which ones to remove, unless
you pass `--cleanup-rpc`.

## Usage

```bash
# recommended: deployed site + your project folder
npx accessprobe --site https://your-app.com --source . --out report.md

# mobile app / no website: point it at the project directly
npx accessprobe --url https://xyz.supabase.co --anon-key eyJ... --source .

# "Confirm email" enabled? accessprobe notices and stops BEFORE signing anyone up (bouncing
# confirmation emails can get a project's email sending restricted). Create two users in the
# dashboard with "Auto Confirm User" and pass them. If your API has a "delete my account"
# function, accessprobe can remove them afterwards.
npx accessprobe --url ... --anon-key ... --source . \
  --user-a a@test.dev:pass1 --user-b b@test.dev:pass2 --cleanup-rpc delete_my_account
```

**Why `--source`?** New Supabase projects only show the API schema (`/rest/v1/`) to the
`service_role` key, so an outside tool can't list your tables. accessprobe reads them from
`supabase/migrations/*.sql` (columns, types, keys, `NOT NULL`, foreign keys) and from your app code
(`.from("table")`, `rest/v1/table`, `.rpc("fn")`). Your code stays on your machine.

**Migrations don't match production?** When the API schema is readable, the live schema wins and
accessprobe tells you which tables exist only in your migrations or only in the live database. A table
named in your migrations or code that the live database doesn't have is reported as drift, not
tested. When only the `service_role` key can read the schema, give it a dump of the live database:

```bash
supabase db dump -f live-schema.sql          # the linked project's live schema
npx accessprobe --url ... --anon-key ... --schema live-schema.sql
```

It also understands apps that keep their own `users`/`profiles` table, where `user_id` points at
that table's id instead of `auth.uid()`. Fix SQL is generated with that mapping too.

**Test users.** With only the anon key, accessprobe can't delete the two test users it signs up. It
keeps them for the next run instead of piling up accounts: they are saved outside your project
(`~/.cache/accessprobe/test-users.json`), and later runs sign in with them. The report names them, so
you can delete them in the dashboard when you're done. Other options: `--user-a`/`--user-b` with two
accounts you made yourself, `--cleanup-rpc <fn>` if your API has a "delete my account" function, or
`--fresh-users` for new accounts every run. Appwrite works the same way. Firebase and PocketBase test
users delete themselves.

**Firebase:**

```bash
# web app: config comes from the bundle, rules and collection names from your project
npx accessprobe --site https://your-app.web.app --source .

# Android / iOS: config from google-services.json / GoogleService-Info.plist
npx accessprobe --source .

# rules only live in the console? export them first (read-only, needs `firebase login`)
firebase database:get /.settings/rules --project my-app > database.rules.json
npx accessprobe --source . --database-rules database.rules.json

# against the local Emulator Suite (firebase emulators:start)
npx accessprobe --project-id demo-my-app --api-key any --source . --emulator
```

Email/password sign-up must be enabled. If it isn't, accessprobe falls back to anonymous accounts, which
still pass a rule like `request.auth != null`.

**Anonymous sign-in.** When the Anonymous provider is enabled, anyone can get a Firebase ID token with one
request (`accounts:signUp` with no email), and that token passes `request.auth != null`. accessprobe
signs up a third, anonymous test user and repeats each attack the unauthenticated visitor was refused.
Where it gets through, the finding (`anon-auth-read`, `anon-auth-write`, `rtdb-anon-auth-read`,
`storage-anon-auth-read`, …) explains this, and the fix adds
`request.auth.token.firebase.sign_in_provider != 'anonymous'` to the rule, or tells you to disable
Anonymous sign-in in the console if the app doesn't use it. A refused anonymous sign-up is recorded as
"Anonymous sign-in is disabled". The anonymous user is deleted at the end like the others.

Without a `database.rules.json`, Realtime Database paths are taken from your code
(`getReference("rooms").child(roomCode)` → `rooms/$roomCode`). An attacker can read the same paths
out of your app, so this is a fair test. accessprobe only writes test entries under its own test user's
key, never into shared nodes.

**PocketBase:**

```bash
# server URL + your project folder (pb_migrations/ holds the collections and API rules)
npx accessprobe --url https://pb.your-app.com --source .

# the URL is also found in your code: new PocketBase("https://pb.your-app.com")
npx accessprobe --source .

# sign-up closed (users create rule is superusers-only)? create two users in the dashboard
npx accessprobe --url https://pb.your-app.com --source . \
  --user-a a@test.dev:pass1 --user-b b@test.dev:pass2
```

accessprobe never asks for admin / superuser credentials: it sees exactly what your app's users see.
Test users sign up through the `users` collection and delete themselves at the end. PocketBase only
lists collections to superusers, so without `pb_migrations` the collection names come from your code
(`pb.collection("posts")`) or `--table`, and fields are worked out from the API's answers.

**Appwrite:**

```bash
# endpoint + project id (both public) + your project folder with appwrite.json
npx accessprobe --url https://cloud.appwrite.io/v1 --project-id 6650abc --source .

# found in your code too: new Client().setEndpoint("…").setProject("…")
npx accessprobe --source .

# no appwrite.json? name the collections as database/collection (run `appwrite pull collections` for exact results)
npx accessprobe --url https://cloud.appwrite.io/v1 --project-id 6650abc --table main/orders --bucket receipts
```

accessprobe never asks for an API key or console login: it sends only `X-Appwrite-Project` and the test
users' own session, exactly like the Web SDK. Test users sign up through the Account API
(email/password must be enabled). Appwrite lists collections only to API keys, so without `appwrite.json`
the ids come from your code or `--table`, and attributes are worked out from the API's answers; a
collection whose required attributes can't be guessed is listed in the notes as not tested.
`--project-id` with `--url` (or `--platform appwrite`) means the Appwrite project, not Firebase.

**Exit codes:** `0` ok, `1` critical issue found, `2` usage error, `3` nothing could be tested.
accessprobe never reports a clean grade for an app it couldn't test.

## Keep the checks as pgTAP tests (Supabase)

Write every check from a run into a test file for `supabase test db`:

```bash
npx accessprobe --source . --pgtap supabase/tests/accessprobe.test.sql
supabase test db
```

Each test states the secure behaviour: B cannot read, modify, take over or delete A's rows, cannot
insert rows as A, anonymous visitors cannot read them, users cannot change their own role or plan,
and views do not show A's private rows. Checks that passed are passing tests. Checks behind a leak
accessprobe proved are marked `FAILS until the fix` and turn green once you apply the fix from the
report. After that they keep the leak from coming back, in CI and without a running API.

The tests act as two fixed test users the way PostgREST does (the `authenticated` and `anon` roles
plus `request.jwt.claims`) and run in one transaction that is rolled back. Re-generate the file after
schema changes.

## Keep the checks as rules tests (Firebase)

Write every Firestore, Realtime Database and Storage check from a run into a test file for the
Emulator Suite:

```bash
npx accessprobe --source . --emulator --project-id demo-my-app --api-key any   --rules-tests test/accessprobe.rules.test.mjs
npm i -D @firebase/rules-unit-testing
firebase emulators:exec --only firestore,database,storage "node --test test/accessprobe.rules.test.mjs"
```

The file uses [`@firebase/rules-unit-testing`](https://www.npmjs.com/package/@firebase/rules-unit-testing)
with `node:test`; your project installs it as a dev dependency (accessprobe itself has no dependencies).
Each test seeds A's document, value or file with security rules disabled, checks that A can still read
it, and then states the secure behaviour as user B, as an unauthenticated visitor or as an
anonymous-auth user: B cannot read, list, modify, take over or delete A's data, cannot create
documents as A, and users cannot set the fields your rules use for admin rights. Checks that passed
are passing tests. Checks behind a leak accessprobe proved are marked
`// FAILS until the fix from the accessprobe report is applied` and turn green once you deploy the fix.
After that they keep the leak from coming back, in CI and without a live project.

The rules are read from your project files (paths from `firebase.json` when present). Under
`firebase emulators:exec` the emulator hosts and project id come from its environment; otherwise the
ports in `firebase.json` (or the defaults) are used. Re-generate the file after rules changes.

## Production: `--read-only`

Every insert accessprobe makes is a real insert: your triggers, database webhooks and Cloud
Functions fire as they would for a user (a "new order" email, a Slack message, a Stripe call).
Against production, or tables where that matters, use `--read-only`:

```bash
npx accessprobe --source . --read-only --user-a a@your-app.com:pw --user-b b@your-app.com:pw
```

No request that could change anything is sent: no sign-ups (so it needs two existing accounts), rows,
files or RPC calls. Writes are stopped before they leave the process. What still runs is everything
that only reads: whether anonymous visitors can read your data, and whether user B can read rows that
belong to other users. Write checks (change, delete, forge, upload) are listed as not run, never as
passed, so a clean read-only report is not a clean bill of health. Run the full test against a local or
staging copy.

## Things that are open on purpose: `.accessprobeignore`

A public `profiles` table or a product catalog is reported every run, and a CI job that fails on it
stays red. List those in `.accessprobeignore` in your project folder (or pass `--ignore-file`):

```text
# <table / collection / bucket>  [finding id]   # why
profiles   cross-user-read   # profiles are public in this app
products                     # the whole catalog is public
```

They move to an "Accepted" section with your reason, stop counting for the grade and the exit code,
and their failing checks are left out of `--pgtap` / `--rules-tests` files. Without a finding id every
finding on that resource is accepted, so prefer naming the id: a new kind of leak on the same table
still fails. Lines that no longer match anything are pointed out in the notes.

## Run it on every pull request (GitHub Action)

Test your rules in CI against a **local** backend started from your repository, so every policy or rules change is attacked before it ships. Production is never touched.

**Supabase** (your `supabase/migrations` running in a local Supabase):

```yaml
# .github/workflows/accessprobe.yml
name: accessprobe
on: pull_request
jobs:
  rls:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: 22 }
      - uses: supabase/setup-cli@v1
      - run: |
          supabase start
          eval "$(supabase status -o env)"
          echo "SB_URL=$API_URL" >> "$GITHUB_ENV"
          echo "SB_ANON=${ANON_KEY:-$PUBLISHABLE_KEY}" >> "$GITHUB_ENV"
      - uses: KaanKaya17/accessprobe@v0.14.1
        with:
          args: --url ${{ env.SB_URL }} --anon-key ${{ env.SB_ANON }} --source .
```

**Firebase** (your rules files in the Emulator Suite):

```yaml
      - uses: actions/setup-java@v4
        with: { distribution: temurin, java-version: '21' }
      - run: npx firebase-tools emulators:start --only auth,firestore,database,storage --project demo-ci &
      - run: npx wait-on tcp:127.0.0.1:8080 tcp:127.0.0.1:9099
      - uses: KaanKaya17/accessprobe@v0.14.1
        with:
          args: --project-id demo-ci --api-key fake --source . --emulator
```

The step fails when a critical leak is **proven** (`fail-on: never` only warns), and the report with fix SQL or rules goes into the job summary. Inputs: `args`, `working-directory`, `report`, `fail-on`, `summary`, `sarif`. Outputs: `exit-code`, `report`, `sarif`. On public repositories the job summary is public too; set `summary: false` if that matters.

### Findings in the Security tab and on the pull request (SARIF)

Set `sarif:` and upload the file. Each finding then shows up under **Security → Code scanning**, and on the pull request it is placed on the line that leaks: the policy for that table and command in `supabase/migrations` (the SELECT policy for a read leak), the `match` block in `firestore.rules` / `storage.rules`, the node in `database.rules.json`, the collection in `pb_migrations` or `appwrite.json`. Accepted findings (`.accessprobeignore`) are left out.

```yaml
    permissions:
      contents: read
      security-events: write
    steps:
      # … start the backend as above …
      - uses: KaanKaya17/accessprobe@v0.14.1
        with:
          args: --url ${{ env.SB_URL }} --anon-key ${{ env.SB_ANON }} --source .
          sarif: accessprobe.sarif
          fail-on: never   # let the upload run; code scanning blocks the merge instead
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: accessprobe.sarif
          category: accessprobe
```

Without the Action: `npx accessprobe --source . --sarif accessprobe.sarif`. Code scanning is free on public repositories; private ones need GitHub Advanced Security.

### Rate limits

Backends throttle bursts of requests, sign-ups especially. accessprobe waits and retries a throttled request (it follows `Retry-After`, up to 3 tries). A check that is still throttled after that is listed under one "Rate limited" note and is **never counted as passed**. Run again later, use `--only <table>`, or pass existing users with `--user-a` / `--user-b` (Supabase limits sign-ups per hour).

accessprobe tests itself this way: [`e2e.yml`](.github/workflows/e2e.yml) runs it against real Postgres, PostgREST and GoTrue, and against the Firebase emulators, on every pull request.

## Tested on real apps

- **Supabase:** a production Android fitness app with 8 tables, `bigint` user ids mapped through
  `current_user_id()`, and strict GRANTs.
  - Result: 5 tables fully attacked, 3 read-only for users, **0 false positives**.
  - All test users and rows were removed afterwards.
- **Firebase Realtime Database:** a multiplayer Android game whose rules lived only in the console.
  - Result: 3 critical leaks proven. Any player could overwrite another player's online status, and
    could read and overwrite other players' duel invites.
  - The rules fix was tested in the Emulator Suite: all 25 of the game's own read/write flows still
    worked and all 8 attacks were blocked. It was then deployed and re-verified live.
  - One read stays open: the app itself reads other players' inboxes to count pending invites, so
    closing it needs an app update, not a rules change.

Each run also turned up bugs in accessprobe itself, all fixed and covered by tests:

- the hidden API schema and id mapping;
- CHECK constraints and `.validate` shapes;
- test entries in create-only nodes;
- a guard against testing the wrong database.

## Try it on a deliberately vulnerable app

```bash
npm run demo:server   # fake Supabase with the most common AI-builder mistakes
npm run demo          # in a second terminal
```

## Rules

**Only test apps you own or are authorized to test.** accessprobe creates users and data in the target
project (unless you pass `--read-only`). It asks you to confirm ownership before every run unless you pass `--yes`.

## Roadmap

- [x] Claude Code skill + `AGENTS.md` for Codex / Cursor (`accessprobe setup-agent`)
- [x] Zero-config runs (`npx accessprobe` in a project folder)
- [x] GitHub Action: attack your rules on every pull request (local Supabase / Firebase emulators)
- [x] Turn findings into permanent pgTAP regression tests (`--pgtap`)
- [x] Firebase: anonymous-auth attacker, and findings as Security Rules regression tests (`--rules-tests`)
- [x] MCP server: agents run it after every schema change (`npx accessprobe mcp`)
- [x] `--read-only` for production, and `.accessprobeignore` for things that are open on purpose
- [x] SARIF output for GitHub code scanning (`--sarif`), findings placed on the leaking policy / rule
- [x] Team / organization roles: outsider, self-join, member raising its role, removed member (Supabase)
- [ ] Organization roles for Firebase, PocketBase and Appwrite (Teams)
- [x] Sensitive columns in readable rows, `SECURITY DEFINER` functions (proven through GET, plus a static check), `pg_graphql` schema exposure
- [ ] Edge Function checks (auth required? cross-user IDs?)
- [x] Firebase: Firestore, Realtime Database, Storage (tested against the Emulator Suite)
- [x] Privilege escalation (users editing their own `role` / `plan`) and views that skip RLS
- [x] PocketBase: collection API rules, users and privilege escalation (tested against a real PocketBase binary)
- [x] Appwrite: collection, document and bucket permissions, documents and TablesDB APIs (tested against a real self-hosted Appwrite)

## Contributing

Bug reports are very welcome, especially **wrong results**: a false alarm, or a leak that accessprobe
passed. Use the *Wrong result* issue template. If real data is exposed, report it privately through
[Security → Report a vulnerability](SECURITY.md). See [CONTRIBUTING.md](CONTRIBUTING.md) to set up
the tests or add a platform.

## Sponsor

accessprobe is free and MIT-licensed. If it caught something before your users did, consider
[sponsoring the project](https://github.com/sponsors/KaanKaya17). Sponsorship pays for new platform
adapters and keeps them tested against real backends.

## License

[MIT](LICENSE) © Kaan Kaya
