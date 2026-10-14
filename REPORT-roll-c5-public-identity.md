# REPORT-roll-c5-public-identity.md

Packet `roll-c5-public-identity`: gateway refused identity's public routes, so
nobody could sign up. Status: **done, green, committed on branch
`roll/c5-public-identity`** (this report describes the work; the manager merges).

Worktrees used: this packet's gateway worktree only
(`moon/wt/roll-c5-public-identity`). No second worktree was created: identity
was **read, never written** (its `openapi/v1.yaml` at commit `9dc80c9`,
extracted mechanically — command in the fixture header). The main identity
checkout was left on `master`, untouched; `git status` there is clean.

Quarters: Q1 — fixtures + failing tests, committed red (`f733e4c`). Q2 gate:
commit existed, continued. Q3 — implementation, README, CHANGELOG, full
`bin/prime` green. Q4 — docker test-stage build, this report, final commit,
self-exit.

## The live evidence (from the brief, quoted as the red control)

A fresh box, substrate installed, gateway Ready
(`{"deps":{"identity":"ok","redis":"ok"}}`), probed in-cluster:

| request | direct to identity | through gateway |
|---|---|---|
| `POST /v1/signup-timestamp` | **200** | **401** |
| `POST /v1/users` (the signup itself) | **422** (validation — reachable) | **401** |
| `GET /v1/me` (private, for contrast) | — | 401 (correct) |

Gateway's refusal was its own:

```json
{"type":"https://docs.cafaye.com/errors/unauthorized","title":"Unauthorized","status":401,
 "detail":"a bearer token is required","instance":"/v1/signup-timestamp","code":"unauthorized"}
```

And identity's own spec says the opposite (`openapi/v1.yaml`,
`/v1/signup-timestamp`): **"The endpoint is public and unauthenticated,
exactly as `POST /v1/users` is: a browser arriving at the form holds nothing
but the address it was sent to."**

## A count correction, measured not argued: fifteen, not seventeen

The brief says seventeen and pastes a list of fifteen paths. Mechanical
extraction from identity `9dc80c9` (every operation under `/v1/*` with
`security: []`) yields **15 operations on 15 unique paths** — exactly the
fifteen pasted. The only other `security: []` hits in identity's file are its
own `/healthz` and `/readyz`, which are not under `/v1/*`. So "seventeen" is
overcounted by two; the packet floor (signup-timestamp + users) and the full
surface are the fifteen below. Nothing was dropped to reach this number — the
extraction command and its output are in
`internal/httpapi/testdata/identity-public.txt`.

## The mechanism chosen, and why not the other shape

**Shape 2: the gate consults identity's declaration for `/v1` paths the table
does not own.** `credentialGate` lets an identity-public operation through
with no credential; the pass-through forwards it to `IDENTITY_URL` with the
caller's path intact.

The table did NOT gain fifteen entries, for a structural reason the proxy
makes: a table entry **strips** its prefix before forwarding
(`UpstreamPath`), so `/v1/users` aimed at identity would arrive as `/`, which
identity does not serve. Table prefixes rename a foreign namespace into
gateway's (`/v1/pantry-writes/projects` → `/projects`); identity's surface
needs no renaming — gateway and identity share `/v1`, so the caller's path IS
the upstream path. The one prefix that would preserve it (`/v1`) claims the
private routes too. The fallback therefore rebuilds with an **empty** prefix:
same segment decode/refuse/re-encode traversal defense, no stripping.

Two precedence rules, one in each place, so gate and relay cannot disagree: a
table entry wins wherever both claim a path (an operator's explicit routing is
never second-guessed), and the fallback only fires when configured
(`IdentityBaseURL == ""` preserves master's exact answers).

The list is derived from identity's spec, not hand-written twice: the
extraction lives in `testdata/identity-public.txt` (source commit + command),
the enforcement in `identitypublic.go`, and `compareIdentityPublicRoutes`
holds them equal in **both** directions. Refresh = re-run the command,
replace the fixture body, update the compiled list, commit all three.

No new environment variable: `RuntimeOptions` sets `IdentityBaseURL` from the
already-read `IDENTITY_URL` (the exact-variables test is untouched), with or
without `REDIS_URL` — a relayed public operation holds no session state, so
the browser surface's shared-store rule does not apply. Validation is in
`New()`, never in `RuntimeOptions`, per the house rule. Neither shipped
`ROUTE_TABLE` changed — **that is the packet's answer to "fix both or say why
one is exempt"**: both stacks already set `IDENTITY_URL`, so the fix is in the
binary both run, not in either table. Pantry's entries are byte-identical.

## What each of the fifteen is for

- `POST /v1/users` — the signup itself. The packet's floor with the next line.
- `POST /v1/signup-timestamp` — the anti-forgery anchor the signup form
  fetches first. The packet's floor.
- `POST /v1/session` — the login. Presenting a credential IS the operation,
  so none is required. (`DELETE /v1/session`, logout, stays gated.)
- `POST /v1/session/mfa` — the second step of a `202` login challenge.
- `POST /v1/password-resets`, `POST /v1/password-resets/confirm` — ask for a
  reset mail, then spend the token. No session, or nothing would need reset.
- `POST /v1/email-verifications`,
  `POST /v1/email-verifications/confirm` — same shape for verification mail.
- `POST /v1/email-changes/current-address`,
  `POST /v1/email-changes/new-address` — the two confirmations of an address
  change, each arriving by mail link.
- `POST /v1/agents`, `GET /v1/agents/claim/{token}` — an agent registers,
  then the claim link (opened by a human, in a browser) binds it. The link
  carries the token, so nothing else is presented.
- `POST /v1/session-links/redeem` — magic-link redemption: the link IS the
  credential. (Minting, `POST /v1/session-links`, stays gated.)
- `GET /v1/auth/oauth/{provider}`, `GET /v1/auth/oauth/{provider}/callback`
  — OAuth start and the provider's return. The state cookie authenticates the
  round trip, not a bearer token.

## The controls' verdicts

- **Green, real tree:** all 15 operations forwarded with no credential
  (`TestIdentityPublicOperationsAreForwardedWithoutACredential`), identity
  saw all 15 with full path and verbatim query; `bin/prime` → `== prime ok`
  (Go build/vet/lint/tests, codegen currency, bun suite 276 passed).
- **Green, real tree:** `GET /v1/me`, `GET /v1/accounts`, `GET /v1/introspections`
  still `401` without a token, plus 10 near-miss negatives (wrong method on a
  public path, missing/extra template segment, authenticated identity ops) —
  and identity saw 0 requests from any of them.
- **Green, real tree:** compiled list == fixture in both directions
  (`TestIdentityPublicMatchesIdentityDeclaration`).
- **RED control 1 (master fails):** the brief's live table above, quoted; plus
  on this tree, Q1 commit `f733e4c` (fixtures + tests, no implementation)
  fails `go vet` on undefined symbols — the tests cannot pass on master — and
  a scratch test replaying master's shape (pantry-only table, refusing gate,
  no fallback) reproduces `401` on both signup paths (passed as a refusal
  demonstration, then deleted).
- **RED control 2 (drift fixture goes red):** a scratch assertion of the extra
  fixture as a passing state fails with exactly
  `missing=["POST /v1/password-resets/expired-purge"]` (deleted after
  demonstration); the committed `TestIdentityPublicDriftFixtureIsDetected`
  pins that detection permanently.
- **Independent verification (not mine to write):** the in-cluster probe —
  the two tables above, before and after — on a box.

## Known follow-up, deliberately unchanged

The relay translates upstream redirects, so the OAuth start's `302` becomes
the same `503` any upstream redirect does. After this packet OAuth is no
longer *refused* (no 401) but the start still does not *work* through gateway.
Relaxing `IsRelayableStatus` for identity's 302s is a real decision with
`Location`-header consequences and is a separate packet; it is recorded in the
README and CHANGELOG entries, not smuggled into this one.

## Files

- `internal/httpapi/identitypublic.go` — compiled list, method-aware matcher,
  both-directions comparator, `checkIdentityBaseURL` (new).
- `internal/httpapi/testdata/identity-public.txt` — the extraction (new).
- `internal/httpapi/testdata/identity-public.extra.txt` — drift fixture (new).
- `internal/httpapi/identitypublic_test.go` — drift check + behavior (new).
- `internal/httpapi/gate.go` — gate consults the declaration (table wins ties).
- `internal/httpapi/proxy.go` — path-intact fallback relay, public entry.
- `internal/httpapi/httpapi.go` — `Options.IdentityBaseURL`, validation, wiring.
- `internal/httpapi/runtime.go` — `IDENTITY_URL` feeds the fallback (no new var).
- `README.md`, `CHANGELOG.md` — routing section + entry.
