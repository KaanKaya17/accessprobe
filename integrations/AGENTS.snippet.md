## Security checks (rlsprobe)

This project's data is protected by backend access rules (Supabase RLS / Firebase Security Rules).
Before shipping changes to tables, policies, rules or data access code:

1. Ask the user to confirm they own the app, then run
   `npx rlsprobe --source . --yes --json > rlsprobe.json` (add `--url`/`--anon-key` for Supabase).
2. Report critical findings with their `evidence` line. Items in `notes[]` were **not** tested, so
   never call them safe. Exit code `3` means nothing could be tested.
3. Before changing a rule or policy, read every place in the code that touches that data, including
   reads done for validation. Make sure the new rule still allows all of them.
4. Test rule changes locally first (Firebase Emulator Suite or a Supabase branch/local DB). Ask the
   user before deploying to production, and re-run rlsprobe afterwards.
