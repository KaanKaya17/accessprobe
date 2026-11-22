---
name: accessprobe
description: Prove that a Supabase, Firebase, PocketBase or Appwrite app's access rules actually protect user data, by running accessprobe with two real test users, then fix what it finds without breaking the app. Use when the user asks to check security, RLS, Row Level Security, Firestore/Realtime Database/Storage rules, PocketBase API rules, Appwrite collection/document/bucket permissions, "can users see each other's data", or before shipping an app built on Supabase, Firebase, PocketBase or Appwrite.
---

# accessprobe: prove access rules work, then fix them safely

accessprobe signs up two throwaway test users. User A creates rows, documents or files, and then user B
and an anonymous visitor try to read, list, change, forge and delete them. Every critical finding is
a request that actually succeeded. A PASS is only recorded when the backend explicitly refused.

## 1. Ask before running (always)

accessprobe creates test users and test data in the target project and removes them afterwards. Before
the first run, ask the user:

- "Is this your app, or are you authorized to test it?" Never run it against an app the user doesn't
  own.
- Supabase: "Is 'Confirm email' enabled?" If it is, ask them to create two test users in the
  dashboard and pass them with `--user-a` and `--user-b`.

Only pass `--yes` after the user has confirmed. accessprobe prints a `Target:` line naming the exact
Supabase URL or Firebase project; show it to the user. If accessprobe stops because several projects
are configured (for example `.env` and `.env.local`, or dev and prod), **ask the user which one to
test** and pass `--url` / `--project-id`. Never pick production yourself.

If the user does want to check production, use `--read-only` with two accounts they give you
(`--user-a`, `--user-b`): normal runs insert real rows, which fire triggers, webhooks and Cloud
Functions. A read-only report skips every write check, so never call it a clean bill of health.

Only add a line to `.accessprobeignore` (findings that are open on purpose) after the user confirms
that resource is meant to be shared, and write their reason after `#`. Never add one to make a run
pass.

## 2. Run it

From the app's project folder (where `supabase/`, `firestore.rules`, `google-services.json`, `pb_migrations/` or `appwrite.json` live):

```bash
# Supabase
npx accessprobe --url https://<ref>.supabase.co --anon-key <public anon key> --source . --yes --json > accessprobe.json

# Firebase (web or mobile; config is read from the bundle or google-services.json)
npx accessprobe --source . --yes --json > accessprobe.json

# PocketBase (collections and rules are read from pb_migrations/; never pass superuser credentials)
npx accessprobe --url https://pb.example.com --source . --yes --json > accessprobe.json

# Appwrite (endpoint + project id only, both public; collections and permissions come from appwrite.json)
npx accessprobe --url https://cloud.appwrite.io/v1 --project-id <project id> --source . --yes --json > accessprobe.json

# deployed web app (also checks the JS bundle for leaked secret keys)
npx accessprobe --site https://the-app.com --source . --yes --json > accessprobe.json
```

- Only the **public** anon / publishable / web API key is needed. Never pass a service_role or secret
  key; accessprobe refuses them. Appwrite needs no key at all: never pass an Appwrite API key.
- Appwrite collection ids need their database: `--table <database>/<collection>`.
- If the Firebase rules live only in the console and the user is logged in with the Firebase CLI,
  export them first (this reads the rules, not data):
  `firebase database:get /.settings/rules --project <id> > database.rules.json`, then add
  `--database-rules database.rules.json`.
- Exit codes: `0` no critical findings, `1` critical findings, `2` usage error, `3` nothing could be
  tested. Treat `3` as "unknown", never as "safe".

## 3. Read the result

`accessprobe.json` has `findings[]` (`severity`, `title`, `detail`, `evidence`, `fix.code` or
`fix.sql`), `passed[]`, `notes[]` and `stats`. When reporting to the user:

- Lead with the **critical** findings and quote each one's `evidence` line. That line is the proof.
- Read `notes[]`. Skipped or inconclusive tests are **not** passes, so say what wasn't covered.
- `warning` and `info` items are often intentional (a public catalog, a leaderboard,
  `allow read: if true`). Ask before "fixing" them.
- Never paste other users' data. accessprobe only reports counts and field names, and you should do the
  same.

## 4. Fix it without breaking the app

The rules or policies are the backend's contract with the app's code. A tighter rule that the app
relies on breaks the app for every user. Before proposing or applying a fix:

1. **Read the app code** for every access to the affected table, collection or path, including reads
   done for validation. One real case: the app read another user's whole invite inbox to count pending
   invites before sending one, so an "owner-only read" rule would have made invites impossible. List
   who reads and writes what.
2. Write the fix so that each of those accesses is still allowed and the attacks are denied. Start from
   `fix.code` / `fix.sql`, but adapt it to the access list.
3. **Test before deploying:**
   - Firebase: run the app's flows and the attacks in the Emulator Suite
     (`firebase emulators:exec --only auth,database "node flows.mjs"`), then
     `firebase deploy --only database --dry-run` to validate the syntax on the server.
   - Supabase: apply the migration to a branch or local database (`supabase db reset`) and re-run
     accessprobe against it.
   - PocketBase: run a local `pocketbase serve` with the new `pb_migrations` file and re-run accessprobe
     against it.
   - Appwrite: change the permissions in appwrite.json, `appwrite push collections` to a local or
     staging Appwrite, and re-run accessprobe against it.
4. **Ask the user before deploying to production**, and back up the current rules or policies first.
   After deploying, re-run accessprobe and confirm the critical findings are gone and nothing new appeared.
5. Some leaks can't be fixed by rules alone, because the app itself needs the access. Tell the user
   which ones, and what app change would close them.

## 5. Clean up

accessprobe deletes its test data. Firebase and PocketBase test users delete themselves. Appwrite test
users can only block themselves, so they are listed in `notes[]` for removal in the console. Supabase test users need
`--cleanup-rpc <fn>` (if the app has a delete-my-account function) or manual removal, and
accessprobe lists them in `notes[]`. Relay any "Could not delete" note to the user.
