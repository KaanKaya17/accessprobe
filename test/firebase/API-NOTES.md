# Firebase REST behaviour (verified against the local emulators)

Verified 2026-11-21 with `firebase-tools@15.35.0` (Firestore emulator v1.22.0, Database emulator v4.11.2,
Storage rules runtime v1.1.3) on Java 26.0.2 and Node 22, Windows 10. Re-run with
`node test/firebase/verify-api.js` (add `--attach` to use emulators that are already running and
`--json out.json` to dump the raw results). Rules under test: `firestore.rules`, `database.rules.json`
and `storage.rules` in this folder. Line numbers in the error messages below are from `firestore.rules`.

"A" = owner, "B" = second signed-in user, "anon" = no credentials at all.
Production behaviour not tested here is marked **(unverified)**.

## Hosts and identifiers

| Service | Emulator base URL | Production equivalent |
|---|---|---|
| Auth | `http://127.0.0.1:9099/identitytoolkit.googleapis.com/v1/...?key=any` | `https://identitytoolkit.googleapis.com/v1/...?key=<apiKey>` |
| Firestore | `http://127.0.0.1:8080/v1/projects/demo-accessprobe/databases/(default)/documents` | `https://firestore.googleapis.com/v1/projects/<id>/databases/(default)/documents` |
| RTDB | `http://127.0.0.1:9000/<path>.json?ns=demo-accessprobe-default-rtdb` | `https://<ns>.firebaseio.com/<path>.json` or `https://<ns>.<region>.firebasedatabase.app/<path>.json` (the namespace comes from the host, with no `ns=`) |
| Storage | `http://127.0.0.1:9199/v0/b/demo-accessprobe.appspot.com/o` | `https://firebasestorage.googleapis.com/v0/b/<bucket>/o` |

* The emulator's default bucket is **`demo-accessprobe.appspot.com`**, and its upload responses echo that bucket name. The
  Storage emulator auto-creates **any** bucket name on first upload (`some-other-bucket` worked). It treats
  `demo-accessprobe.firebasestorage.app` as a separate, empty bucket. Projects created after Oct 2024 default to
  `<id>.firebasestorage.app` in production **(unverified here)**, so take the bucket from the app's config.
* `?key=` is required by the Auth emulator (it returns 403 `"The request is missing a valid API key."` without it), but
  the emulator accepts any value.

## Auth (Identity Toolkit REST)

All requests are `POST` with a JSON body. Errors look like `{"error":{"code":400,"message":"<CODE>","errors":[...]}}`.

| Call | Body | Result |
|---|---|---|
| `accounts:signUp` | `{email,password,returnSecureToken:true}` | 200 `{localId,email,idToken,refreshToken,expiresIn}` |
| `accounts:signUp` (anonymous) | `{returnSecureToken:true}` | 200 `{localId,idToken,...}` with no email; the token has `provider_id: "anonymous"` |
| `accounts:signUp` duplicate | | 400 `EMAIL_EXISTS` |
| `accounts:signUp` short password | | 400 `WEAK_PASSWORD : Password should be at least 6 characters` |
| `accounts:signInWithPassword` | `{email,password,returnSecureToken:true}` | 200; wrong password gives 400 `INVALID_PASSWORD`, unknown email gives 400 `EMAIL_NOT_FOUND` |
| `accounts:delete` | `{idToken}` (the user's **own** token, no admin needed) | 200 `{"kind":"identitytoolkit#DeleteAccountResponse"}`; a second call gives 400 `USER_NOT_FOUND`; a garbage token gives 400 `INVALID_ID_TOKEN`. This works for both email and anonymous users. |

* Emulator ID tokens are **unsigned** (`{"alg":"none","typ":"JWT"}`). The claims are `sub`/`user_id` = uid,
  `aud` = project id, `iss` = `https://securetoken.google.com/demo-accessprobe`, `firebase.sign_in_provider`, and 1 h expiry.
* Production differences **(unverified)**: email-enumeration protection (the default on newer projects) collapses the
  sign-in errors into `INVALID_LOGIN_CREDENTIALS`. Email/password and anonymous sign-in must be enabled in the console,
  otherwise you get `OPERATION_NOT_ALLOWED` / `ADMIN_ONLY_OPERATION`. `accounts:delete` can return
  `CREDENTIAL_TOO_OLD_LOGIN_AGAIN` for old sessions. App Check, if enforced, can block REST calls.

## Firestore REST

Auth header: `Authorization: Bearer <idToken>` (no header = unauthenticated). Values are typed:
`{"fields":{"ownerId":{"stringValue":"uid"},"total":{"integerValue":"42"},"ok":{"booleanValue":true}}}`
(`integerValue` is a **string**).

| Operation | Request | Allowed | Denied |
|---|---|---|---|
| create | `POST .../documents/<coll>?documentId=<id>` + fields body | 200, the document `{name,fields,createTime,updateTime}` | 403 |
| create existing id | same | 409 `ALREADY_EXISTS` (only reached if the rules allow) | 403 |
| get | `GET .../documents/<coll>/<id>` | 200 document | 403 |
| patch | `PATCH .../<coll>/<id>?updateMask.fieldPaths=title` | 200, the merged document | 403 (message lists both `create` and `update`) |
| delete | `DELETE .../<coll>/<id>` | 200 `{}` | 403 |
| list | `POST .../documents:runQuery` `{"structuredQuery":{"from":[{"collectionId":"orders"}]}}` | 200, a JSON **array** `[{document,readTime},...]`; an empty result is `[{"readTime":...,"done":true}]` | 403 |
| list (GET) | `GET .../documents/<coll>?pageSize=5` | 200 `{"documents":[...]}` | 403 |
| count | `POST .../documents:runAggregationQuery` `{"structuredAggregationQuery":{"structuredQuery":{...},"aggregations":[{"alias":"n","count":{}}]}}` | 200 `[{"result":{"aggregateFields":{"n":{"integerValue":"2"}}},...}]` | 403 (evaluated as `list`) |

The denied shape is always `{"error":{"code":403,"message":"\n<detail>","status":"PERMISSION_DENIED"}}`. In the
emulator, `<detail>` is a rule trace such as `false for 'get' @ L22`, `evaluation error at L22:38 ...`, or
`No matching allow statements` when no `match` block applies. Production returns
`"Missing or insufficient permissions."` with no trace **(unverified here; documented behaviour)**.

Verified rule outcomes for the sample app:

| Collection | B read A's doc | B list | B update/delete A's | B create in A's name | anon read |
|---|---|---|---|---|---|
| `profiles` | **200 (leak)**, and an anonymous-auth user also gets 200 | n/a | 403 | n/a | 403 |
| `orders` | **200 (leak)** | **200 runQuery returns all docs, count = all** | 403 | **200 (forgery)** | 403 |
| `notes` (correct) | 403 | 403 unfiltered / `ownerId==A`; 200 for `ownerId==B` | 403 | 403 | 403 |
| `public_posts` | 200 (intended) | n/a | 403 | n/a | 200 (intended) |
| `logs` | 200 | 200 | 200 | 200 | **200 create/delete** |
| `users/{A}/private` | 403 | collection group: 403 | n/a | 403 | n/a |
| `strict` | n/a | n/a | 403 | 403 | n/a |

* A query must be *provably* within the rules. `notes` with `resource.data.ownerId == request.auth.uid` denies an
  unfiltered list (`Property ownerId is undefined on object. for 'list'`), but allows a query filtered by
  `ownerId == <own uid>`. A rule like `request.auth != null` lets B list **everything**.
* Emulator-only: `Authorization: Bearer owner` bypasses all rules (admin). A garbage bearer gives 400 `invalid jwt`.
  A **hand-forged unsigned JWT** with any `sub` is accepted, so the emulator cannot test token verification.
* Firestore keeps accepting a deleted user's ID token until it expires (verified in the emulator; in production the
  same is expected, because rules do not check revocation **(unverified)**).

## Realtime Database REST

Use `?auth=<idToken>` for the token (verified). `Authorization: Bearer <idToken>` is also accepted by the emulator.

| Operation | Request | Allowed | Denied |
|---|---|---|---|
| read | `GET /<path>.json?ns=...` | 200, the JSON value (`null` if missing) | **401** `{"error":"Permission denied"}` |
| write | `PUT` / `PATCH` / `POST` (push) `/<path>.json` | 200, echoes the value | 401 same body |
| delete | `DELETE /<path>.json` | 200 `null` | 401 same body |
| shallow | `GET /<path>.json?shallow=true` | 200 `{"key":true,...}` | 401 |

* In the sample rules, `users/$uid` is readable by any signed-in user, so **B reads A's node (200, leak)**. `users`
  itself has no `.read`, so `GET /users.json` and `shallow=true` on it give 401 (rules cascade down, not up). The root
  is denied, and `open` allows everything to anyone.
* Emulator-only: `Authorization: Bearer owner` bypasses the rules. `?auth=owner` does **not** bypass them (401).

## Cloud Storage (Firebase REST, v0)

Auth header: `Authorization: Firebase <idToken>` (verified). `Bearer <idToken>` also works in the emulator.
Paths in `/o/<path>` must be URL-encoded (`avatars%2F<uid>%2Fpic.png`).

| Operation | Request | Allowed | Denied |
|---|---|---|---|
| upload | `POST /v0/b/<bucket>/o?name=<path>` with raw body + `Content-Type` (`uploadType=media` optional) | 200, metadata JSON `{name,bucket,generation,size,contentType,md5Hash,...}` | 403 `{"error":{"code":403,"message":"Permission denied. No WRITE permission."}}` |
| metadata | `GET /o/<enc path>` | 200 metadata JSON | 403 `No READ permission.` |
| download | `GET /o/<enc path>?alt=media` | 200, raw bytes | 403 `No READ permission.` |
| delete | `DELETE /o/<enc path>` | **204**, empty body | 403 `No WRITE permission.` |
| list | `GET /o?prefix=<dir/>&delimiter=/` | 200 `{"prefixes":[...],"items":[{name,bucket}]}` | 403 `No LIST permission.` |

* Verified: **B downloads, reads metadata for, and lists A's avatars (leak)**. B cannot write, overwrite, delete or forge
  into `avatars/A/`, and cannot read or list `private/A/`. Anon gets 403 everywhere.
* A missing object returns 404 `Not Found` (plain text) **only when the rules allow** the operation. A denied operation on
  a missing object returns 403.
* Emulator-only: `Authorization: Bearer owner` bypasses the rules.

## Traps for a tool that must never report a false PASS

1. **Deleting a missing Firestore doc returns 200 `{}`** when the rules allow it (verified on `logs`). A 200 from
   DELETE proves nothing unless the doc existed. Use `?currentDocument.exists=true`: a missing doc then returns
   **404 `NOT_FOUND`**. Better still, re-read the doc as the owner afterwards to confirm it is gone, or still there for
   a "denied" result. RTDB `DELETE` of a missing path also returns 200 `null`.
2. **PATCH is an upsert.** `PATCH` on a missing doc *creates* it (200), and the rules evaluate it as `create`. Use
   `currentDocument.exists=true` for "modify existing" tests (missing doc → 404).
3. **Denied and not-found are indistinguishable when the rules use `resource.data`.** A get or delete of a
   *non-existent* doc in `notes` / `orders` returns **403** (`Null value error`), not 404. In Storage, a denied request
   on a missing object is also 403. A 403 therefore does not prove the target exists: always create the target as A
   first, confirm A can read it, and only then probe as B and anon.
4. **Validator failures look exactly like permission denials.** `strict` with an extra field or a non-string title
   returns the same `403 PERMISSION_DENIED`, with the same `false for 'create' @ L46`, as B forging `ownerId=A`. A
   forgery attempt with an invalid body would "pass" for the wrong reason, so send a payload that is valid for the owner
   (prove it by creating the same shape as A first), then change **only** the owner field. Production cannot tell the
   two apart at all (same generic message).
5. **An empty list is not "protected".** `runQuery` returning `[{"readTime":...}]` with no `document` is a *success* (200).
   Treat list as PASS only on 403. Treat it as a leak only if the result includes A's doc, so create A's doc first.
   The same applies to RTDB `null` reads (200) and to an empty Storage `items` list.
6. **A Storage list without `delimiter=/` is denied** with rules like `match /avatars/{uid}/{file}` (403), even though
   `listAll()` (which sends `delimiter=/`) is **allowed** and leaks. Probe with `delimiter=/` as the SDK does, or a real
   leak is reported as PASS. A `prefix` must end in `/` or be empty (otherwise 400).
7. **Wrong RTDB namespace or bucket = a different, unprotected store.** Without `?ns=` or with a wrong `ns`, the
   emulator serves a separate database with **no rules** (no-auth PUT to `users/x` gives 200). A wrong bucket name is
   auto-created. In tests this produces false *criticals*, and against production a wrong host or bucket produces
   404s that could be misread as "protected". Always derive `ns` and the bucket from the app's config, and require A's
   own write and read to succeed before trusting any B or anon result.
8. **Status codes differ by service.** Firestore and Storage deny with 403, RTDB with **401**, and Auth errors are 400.
   Firestore denial is also returned for unknown collections (`No matching allow statements`). A garbage Firestore token
   gives **400** `invalid jwt`, not 403, so do not treat any non-2xx as "denied". Match the specific
   denial (`PERMISSION_DENIED` / `Permission denied`) and treat everything else as an error or inconclusive result.
9. **Success codes differ too.** Storage DELETE returns 204 with an empty body, Firestore DELETE returns 200 `{}`,
   and RTDB DELETE returns 200 `null`. Do not require a JSON body.
10. **Emulator laxness.** The emulator accepts unsigned or forged tokens and `Bearer owner`, accepts any `?key=`, and
    auto-creates buckets and namespaces. Never use `owner` in probes. Tests built on the emulator cannot cover token
    validation, API-key restrictions, App Check, or which providers are enabled.
11. **Deleted users keep access** until their ID token expires (verified in the emulator). Sign B out by discarding
    its token, not by deleting the account, if a test depends on B losing access.

## Not verified

Everything about production (messages, hosts, the default bucket for new projects, email-enumeration protection,
App Check, `CREDENTIAL_TOO_OLD_LOGIN_AGAIN`), plus: refresh-token exchange (`securetoken.googleapis.com/v1/token`),
multipart or resumable Storage uploads, Storage `PATCH` metadata, Firestore `:commit`/`:batchWrite` (only checked that
a `:commit` delete with `currentDocument.exists=true` on a missing doc returns 404), and RTDB `orderBy`/`equalTo` queries.
