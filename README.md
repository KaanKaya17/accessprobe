# rlsprobe

**Prove your Supabase Row Level Security actually works.**

Most scanners check whether a policy *exists*. A policy like `using (auth.role() = 'authenticated')`
exists, passes every checklist, and lets every logged-in user read everyone else's data.

rlsprobe doesn't guess. It signs up **two real test users** in your app, has user A create rows and
files, then checks whether user B (or an anonymous visitor) can **read, change or delete** them.

```bash
npx rlsprobe --site https://your-app.lovable.app
```

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
- **Fixes included.** `--out report.md` gives the exact policy SQL for every finding, plus a prompt you can paste into Lovable, Bolt, Cursor or Claude Code.
- **Local and open source.** It runs on your machine and needs only the public anon key, the same key an attacker sees. Nothing is sent anywhere else.
- **Zero dependencies.** Node 20+ is all you need.

## What it tests

| Area | Check |
|---|---|
| Site bundle | Supabase URL + anon key discovery; leaked `service_role` / `sb_secret_` / Stripe / OpenAI / AWS keys |
| Tables | anonymous read, anonymous write (RLS off), **B reads A's row**, **B updates A's row**, **B deletes A's row**, **B inserts a row as A** |
| Storage | anonymous listing, **B downloads A's file**, **B deletes A's file** |
| Functions | lists RPCs exposed over the API for review (never calls them) |

Test rows and files are deleted at the end. Test users can't be deleted with the anon key, so the
report tells you which ones to remove.

## Usage

```bash
# recommended: deployed site + your project folder
npx rlsprobe --site https://your-app.com --source . --out report.md

# mobile app / no website: point it at the project directly
npx rlsprobe --url https://xyz.supabase.co --anon-key eyJ... --source .

# "Confirm email" enabled? create two users in the dashboard (auto-confirm) and pass them.
# If your API has a "delete my account" function, rlsprobe can remove them afterwards.
npx rlsprobe --url ... --anon-key ... --source . \
  --user-a a@test.dev:pass1 --user-b b@test.dev:pass2 --cleanup-rpc delete_my_account
```

**Why `--source`?** New Supabase projects only show the API schema (`/rest/v1/`) to the
`service_role` key, so an outside tool can't list your tables. rlsprobe reads them from
`supabase/migrations/*.sql` (columns, types, keys, `NOT NULL`, foreign keys) and from your app code
(`.from("table")`, `rest/v1/table`, `.rpc("fn")`). Your code stays on your machine.

It also understands apps that keep their own `users`/`profiles` table, where `user_id` points at
that table's id instead of `auth.uid()`. Fix SQL is generated with that mapping too.

**Exit codes:** `0` ok, `1` critical issue found, `2` usage error, `3` nothing could be tested.
rlsprobe never reports a clean grade for an app it couldn't test.

## Tested on a real app

The first real-world run was against FitLog, an Android app with 8 tables, `bigint` user ids mapped
through `current_user_id()`, and strict GRANTs. The result: 5 tables fully attacked, 3 read-only for
users, **0 false positives**, and all test users and rows removed afterwards. The run turned up
three bugs in rlsprobe itself: the hidden API schema, the id mapping, and CHECK constraints. All three
are now fixed and covered by tests.

## Try it on a deliberately vulnerable app

```bash
npm run demo:server   # fake Supabase with the most common AI-builder mistakes
npm run demo          # in a second terminal
```

## Rules

**Only test apps you own or are authorized to test.** rlsprobe creates users and data in the target
project. It asks you to confirm ownership before every run unless you pass `--yes`.

## Roadmap

- [ ] GitHub Action + turn findings into permanent pgTAP regression tests
- [ ] MCP server / Claude Code skill: agents run it after every schema change
- [ ] Edge Function checks (auth required? cross-user IDs?)
- [ ] Firebase (Firestore, Realtime Database, Storage), then PocketBase and Appwrite. Same two-user engine, a platform adapter for each.

## License

MIT
