# REPORT-gateway-tenancy-01 — gateway declares the honest zero

**Packet:** W35 — gateway: declare the honest zero, and vouch for every
key-carrying site.
**Branch:** `worker/gateway-w35-tenancy`. **Commit:** `e16e4ce` (on top of the
draft `fb074fd`, which this packet finished and superseded).
**Verdict:** `tenancy-check` exits **0**. The declaration is written, vouched
for site by site, and checked. One item is not met and is named plainly in
§5: the repo gate is red by two pre-existing, measured failures — one
environmental (OrbStack on the default port), one a load-dependent timing
flake — neither of which this packet may fix without weakening a test or
touching code it does not own.

## 1. What gateway holds, and why the honest zero is the truth

gateway is one HTTP process that authenticates callers, limits what they can
ask for, and forwards to the service that owns the work. It holds **no
customer rows**: no database, no driver import, no SQL statement, no migration,
anywhere in the tree. What it holds is the caller's *identity* — the principal
verified off the caller's own bearer token — and three things derived from it:
the rate-limit bucket key, the telemetry resource attributes, and the
gateway-signed assertion minted for upstream calls.

So `accountScoped: false` with an empty `entryPoints` and
`rls.databaseEnforced: false` with an empty `tables` is the truth, not an
omission — and it is **checked**, in both directions, by the harness:

- an account-scoped statement appearing in the declared sources is
  `tenancy.honest-zero`, a FAILURE;
- a `create policy` / `row level security` statement in the declared sources is
  `tenancy.rls-undeclared`, a FAILURE.

The declaration names two source trees, `internal` (the Go implementation,
tests included) and `test` (what remains of the TypeScript tree after `f87c891`
deleted `src/`). `src` is deliberately **not** named: it does not exist, and
naming a path that is not there earns `tenancy.scan-narrowed`. `cmd` carries
the key nowhere and is not named. No other tree in the repository carries it in
code (the remaining mentions are prose in `README.md`, `CHANGELOG.md`, the
reports, `AGENTS.md`, `account_scope.yml`, `tenancy.yml` itself, and
`openapi/v1.yaml` / `telemetry/otel-endpoint.json`, which are not code trees
this checker reads).

## 2. The `me`-route decision, and its evidence

**Decision: `GET /v1/me` is NOT an entry point, and `accountScoped: false`
stands — because the route reads no row at all.**

The legacy `account_scope.yml` declares `me` its one `accountScoped: true`
route, on the ground that it "resolves an account and returns it". That is the
legacy format's question: *does the route resolve an account at all?* The
tenancy format's question is narrower: *can the route reach another account's
rows?* Measured against the source, `me` cannot — because there is no row
store in the request path at all:

```
internal/httpapi/httpapi.go:302   the bearer gate is mounted above the route
internal/auth/verifier.go:540-541   the account is read off the VERIFIED token
                                  (claims.String("account_id"))
internal/httpapi/principal.go:66   the handler reads the principal back
                                  (auth.PrincipalOf(r)) and renders it
internal/httpapi/principal.go:1-7   the file's own header: "No forwarding, no
                                  transformation, no decision … what it answers
                                  is exactly what gateway proved about the
                                  caller and nothing more."
internal/httpapi/table.go:154      `/v1/me` is gateway's own route, served
                                  before the pass-through — not a proxied read
```

The account `me` returns is the caller's **own**, from a verified claim on the
caller's **own** token. There is no second account in the request, no database,
and no identity call. The packet's resume note expected this route to forward
to identity ("it forwards to identity, which holds the row"); it does not —
the Go handler renders the verified principal locally, and the equivalence
scenarios (`internal/equivalence/scenarios.go:551-556`) show it answering
500/401 from gateway's own logic, never from identity. The premise was wrong;
the decision is settled from the source.

Declaring `me` as an entry point anyway would point three denial arms at tests
that do not exist — the defect the format exists to prevent. It is declared
nowhere, and the zero stands.

**Both declaration files now exist, and what each covers.** `account_scope.yml`
is untouched and still checked by `core/harness/bin/account-scope-check .`. The
two files answer different questions and both are honest: the legacy file
enumerates every mounted route and asks whether each *resolves* an account
(`me` does — its one `true` row); this file declares whether the service can
reach another account's *rows* (it cannot — it holds no rows). The retirement
of the old checker is a separate decision, not this packet's.

## 3. The checker's full output, with every warning explained

```
$ core/harness/bin/tenancy-check .
WARN tenancy.enumeration-partial: … could not classify 16 account-scoped site(s):
    internal/auth/verifier.go:540; internal/httpapi/assertion_test.go:168, :428;
    internal/httpapi/table.go:910; internal/ratelimit/key.go:101;
    internal/ratelimit/key_test.go:129, :136, :141, :143, :328;
    internal/telemetry/elemetry.go:574, :607; internal/telemetry/telemetry_test.go:134;
    internal/testkeys/testkeys.go:358; test/tenantEntryPoints.test.ts:103, :106
WARN tenancy.scope-key-unused: no account-scoped statement this scanner can read
    carries 'account_id'.
OK …: 0 failure(s), 2 warning(s) — warnings do not move the exit code      EXIT 0
```

Both warnings are the expected verdict for a Go service, and both are claims
about the scanner, not about gateway:

- **`tenancy.scope-key-unused`** — "no SQL statement carries the key". gateway
  has no SQL; that is the claim the file makes, not a gap in it. The warning is
  the checker's honest "I cannot see this" for a language it cannot read.
- **`tenancy.enumeration-partial`** — the 16 sites are exactly the ones this
  declaration vouches for in `scope.nonRowSites`, each opened and judged: one
  verified token claim (`verifier.go:540`), the rate-limit bucket key
  (`ratelimit/key.go:101`), core's two telemetry policy lists
  (`telemetry.go:574,607`), the test token minter (`testkeys.go:358`),
  validation message text (`table.go:910`), and eleven test fixtures and test
  names asserting one of those. A SQL scanner cannot classify any of them;
  the declaration does, site by site, and the check still fails for any site
  not named.

The draft (`fb074fd`) named only `internal` and vouched for nothing: the
checker failed it with `tenancy.honest-zero` over the same 14 sites. This
packet adds the vouches for those 14, and — per the packet's instruction to
name "whatever remains of the TypeScript tree" — adds `test` to the sources,
which carries the key in two test-case description strings
(`test/tenantEntryPoints.test.ts:103,106`), both vouched for. 16 sites, 16
vouches, no omissions.

## 4. The account-scope-check verdict

```
$ core/harness/bin/account-scope-check .
FAIL account-scope.scoping-bypassed: me: registered at internal/api/api.gen.go:1191,
       which does not go through Authenticate
FAIL …: 1 account-scoped, 6 not-account-scoped, 0 stale, 0 undeclared, 0 unreadable
       — 1 failure(s), 0 warning(s)                                            EXIT 1
```

**Red, with exactly one failure, and that is the verdict this packet inherits
rather than causes.** The legacy file's own header documents this red with
measurements: the finding is permanent because core's `chain_gate` cannot read
chi's `router.Use(` (its `MIDDLEWARE` regex matches lowercase `use(` only), so
the real gate at `internal/httpapi/httpapi.go:302` is invisible to it, and
`registeredAt` cannot move without tripping `account-scope.stale`. The file's
header also records why the row is `true` and stays `true`: `false` would go
green and would be a false statement about gateway's only account-resolving
route, refutable by nothing because `handler_for` cannot follow the generated
trampoline into `internal/httpapi/principal.go`. The fix is in core, not here;
this packet does not touch the file, and "no existing test was weakened or
skipped" applies to it — the red stays visible rather than being painted over.

## 5. The gate run

`bin/prime` is the Go tier and nothing else — the TypeScript tier was dropped
at cutover (`src/` deleted, `f87c891`), and the wrapper is `bin/prime-go` plus
a final `== prime ok` line, per its own header. Two full runs were made
(`/tmp/prime-w35.log`, `/tmp/prime-w35-2.log`); both exit **1**.

**Run 1 — one failure:**

```
gofmt: clean; go build: ok; go vet: ok
--- FAIL: TestAnUnsetPortProbesTheDefaultTheServerListensOn
    main_test.go:128: healthcheck() with an unset PORT = 0, want 1
    (nothing is listening on the default)
13 SKIP (the Redis live tier; GATEWAY_REDIS_URL unset — expected)
internal/equivalence: ok
```

**Run 2 — the same failure plus one more:**

```
--- FAIL: TestAnUnsetPortProbesTheDefaultTheServerListensOn   (as above)
--- FAIL: TestTheExpiryBoundaryIsInclusive/a_millisecond_after_now
    redis_test.go:198: a session expiring a millisecond after now is live=false, want true
```

Both failures are pre-existing and neither is this packet's. Measured:

**Failure 1: OrbStack on the default port — environmental, permanent here.**
`TestAnUnsetPortProbesTheDefaultTheServerListensOn` assumes nothing is
listening on 8080. On this machine **OrbStack** (the Docker/VM environment,
PID 856) listens on `*:8080`, so the probe dials successfully and returns 0
where the test wants 1 (`lsof -nP -iTCP:8080 -sTCP:LISTEN` names OrbStack).
Run in a clean worktree at the parent commit `fb074fd` — before this packet's
commit — the same test fails identically. CI, with no OrbStack on 8080, does
not see it.

**Failure 2: a load-dependent timing flake in the session store — pre-existing
from `280703f`.** `TestTheExpiryBoundaryIsInclusive` anchors all three expiry
times in one slice literal evaluated at the top of the test, then fixes the
store's clock per subtest (`now := time.Now()`, `redis_test.go:181`). The
"a millisecond after now" case is live iff `T0 + 1ms > now` — i.e. iff
subtests 1 and 2, which run between the two wall-clock reads, complete in
under a millisecond. On a loaded machine they do not, and the boundary flips.
The test's own comment ("the clock is FIXED, so 'exactly now' is exactly true
rather than a race against the wall clock") fixes the race for the *middle*
case only; the 1ms margin on the third case is consumed by the earlier
subtests. Measured, four runs: gate run 1 PASS, gate run 2 FAIL,
`-count=10` on this commit FAIL (10/10), `-count=10` on the parent commit
PASS — the answer tracks machine load, not the code. The test was added in
`280703f` ("Give the Go service a session store it can build"), which predates
this packet.

**Not this packet's, measured.** `git diff fb074fd HEAD --stat` is one file:
`tenancy.yml`, 136 insertions. No Go test reads it; no code and no test
changed.

**Why this packet does not fix either.** Failure 1's only in-repo fix is a
test that skips when the default port is occupied — a skipped test, forbidden
by this packet ("no existing test was weakened or skipped") — and killing
OrbStack to free the port is outside this packet's mandate and destructive to
the user's environment. Failure 2 is a real flaky-test defect, but its fix
belongs to the packet that owns the session store's tests, not to a tenancy
declaration. Both reds are reported, not repaired.

**Successor's first moves.** (a) Make the port-probe test's environment
assumption explicit — skip with a named reason when 8080 is occupied (which
means editing `test/noSkips.test.ts`'s allowlist, the reviewable act that
file exists to gate), or give the test a free port. (b) Fix the expiry
boundary's anchor: evaluate each case's `expires` inside the subtest against
the fixed clock, so the 1ms margin is not spent by the cases before it.

## 6. Done means, item by item

1. `core/harness/bin/tenancy-check .` exits **0** — met. Both warnings are the
   expected verdict for a Go service and are explained in §3.
2. `./bin/prime` green — **not met**: two runs, both exit 1, with two distinct
   pre-existing failures — OrbStack on the default port (environmental,
   measured identical on the parent commit) and a load-dependent timing flake
   in the session-store expiry boundary (measured load-dependent across four
   runs, test added in `280703f`). Neither is fixable here without weakening a
   test or touching code this packet does not own (§5).
3. Legacy `account_scope.yml` untouched — met. Its `account-scope-check` verdict
   is red with the one documented, permanent, core-checker failure (§4), which
   this packet inherits and does not touch.
4. No existing test weakened or skipped — met. The packet adds one file,
   `tenancy.yml`, and changes no code and no test.
