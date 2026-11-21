# Contributing

Thanks for helping. A few rules keep rlsprobe trustworthy.

## The three rules

1. **Never report a PASS that wasn't proven.** A check passes only when the backend explicitly
   refused the request (Supabase/PostgREST `42501`, Firestore `403 PERMISSION_DENIED`, RTDB
   `401 Permission denied`, Storage `403 No … permission`). A 404, a 400, a timeout or a `200` with
   an empty result is *inconclusive* and goes into the notes.
2. **Every critical finding is a request that succeeded** against data the test users created
   themselves. Never print other people's data, only counts and column or field names.
3. **Zero runtime dependencies.** Node 20+ built-ins only. Dev tooling, such as the Firebase emulator
   through a pinned `npx`, is fine in tests.

## Setup

```bash
git clone https://github.com/KaanKaya17/rlsprobe && cd rlsprobe
npm test
```

`npm test` runs everything:

- **Supabase** tests run against a deliberately vulnerable fake Supabase in `test/mock-supabase.js`.
- **Firebase** tests run against the real Firebase Emulator Suite (`test/firebase/`). They need Java
  11+. The first run downloads the emulator jars, which takes about a minute. Set
  `RLSPROBE_SKIP_FIREBASE=1` to skip them.

Try the CLI against the vulnerable demo:

```bash
npm run demo:server   # terminal 1
npm run demo          # terminal 2
```

## Layout

```
bin/rlsprobe.js            CLI
src/core/                  site fetching, orchestration, report, AI prompt
src/providers/<platform>/  one adapter per backend: detect(), scan(), fixStyle
test/                      unit + end-to-end tests
```

## Adding a platform

Create `src/providers/<name>/index.js` that exports `id`, `label`, `fixStyle`, `detect(opts, { site })`
and `scan(opts, { site, log })`. `scan()` returns `{ target, findings, passed, notes, stats }`. See the
Supabase and Firebase adapters for the shape. Register the adapter in `src/providers/index.js`.

An adapter is done when:

- it has an end-to-end test against something real (an emulator, a container or a binary), with both
  broken and correct rules;
- the correct rules produce **zero findings**, and every attack on them shows up under "Passed";
- it cleans up its test data, and its test users too where the platform allows it.

## Pull requests

- Add a test for every bug fix, especially false PASS or false alarm fixes.
- Keep PRs focused. Update `CHANGELOG.md` under "Unreleased".
- Never commit real keys, tokens or report files from real projects. `*-report.md` is git-ignored.
