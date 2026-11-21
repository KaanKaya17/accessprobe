# Security policy

accessprobe is a security tool, so bugs in it matter twice. The worst bug is a **false PASS**: accessprobe
says a check passed when the data is actually exposed. Please report those the same way as
vulnerabilities.

## Reporting

Please **do not open a public issue** for:

- a vulnerability in accessprobe itself, for example leaking a key or token into a report or log, or
  touching data that does not belong to its test users;
- a false PASS that would leave real users' data exposed.

Report it privately instead: **Security → Report a vulnerability** on this repository
(GitHub private vulnerability reporting). Include the accessprobe version, the platform (Supabase or
Firebase), and a minimal setup that reproduces it: the policy or rules plus the command you ran.
Leave out real keys and other people's data.

You will get an answer within 7 days. Fixes for false PASS bugs are released as soon as they are
verified.

## Supported versions

Only the latest release gets fixes.

## Scope

accessprobe is meant for apps you own or are authorized to test. Reports about using it against
third-party apps are out of scope.
