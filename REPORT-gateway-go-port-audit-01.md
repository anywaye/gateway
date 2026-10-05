# REPORT — gateway Go port audit 01

What behaviour lives in `src/` and has no Go counterpart, with evidence for every
row. Written at `1d89954` on `worker/m39-gateway-port-audit-01`. **Read-only: this
packet produced one new file and changed nothing else.**

## 0. The finding that changes the sizing

`AGENTS.md` and `README.md` both still say the Go service is "two operations of
seven" and that rate limiting, API keys and bearer verification are "not ported —
Wave 3". **That is out of date.** The Go tree contains `internal/ratelimit/`
(2,000+ lines: limiter, memory store, Redis store, RESP2 transport, GCRA Lua,
parity and live tests), `internal/auth/` (JWKS cache, RS256 verification, scopes,
ordered claims) and `internal/httpapi/bff.go` (1,140 lines, the four `/auth`
routes). The Go service is far more than the README's table claims.

So the real shape of this audit is *not* "the Go side is a skeleton". It is:

- **11 of 15 non-test `src/` files have a Go counterpart with a named test.**
- **3 files are genuine gaps** (two silently, one deliberately).
- **1 file is ported as a contract but has no implementation at all.**

Two of the three real gaps are *silent*: nothing in the Go tree, the README, or
`CHANGELOG.md` says they are missing. That is the part the manager needs.

## 1. Per-source-file table

One row per non-test `.ts` file under `src/` — 15 files, all of them. Evidence is
a named Go file **and** the named test or equivalence scenario that would fail if
the behaviour were lost. `PORTED (unverified)` means the behaviour exists in Go
but I could not name a test that holds it.

| # | Source file | What it does (exported behaviour) | Verdict | Evidence |
|---|---|---|---|---|
| 1 | `src/probe.ts` | The `Probe`/`ProbeStatus` contract: a dependency that throws, rejects, hangs or answers anything but `"ok"` is one `unavailable`. | **PORTED** | `internal/httpapi/probe.go` (`Probe func(ctx) error`, `runProbe`, `probeTimeout`). Tests: `TestAProbeThatPanicsIsOneUnavailableDependency`, `TestAProbeThatIgnoresItsContextIsStillBounded`, `TestReadinessNamesTheDependencyThatIsDownAndNotWhyItIsDown`. Equivalence: `bare`, `oneProbeOk`, `probesDegraded`. |
| 2 | `src/problem.ts` | Renders core's `problem+json` envelope with `X-Trace-Id` matching `trace_id`; `errors[]` only on a 422. | **PORTED** | `internal/httpapi/problem.go` (`writeProblem`, hand-ordered `writeProblemBody`, `encodeFieldErrors`, `newTraceID`). Tests: `TestTheProblemEnvelopeIsTheReferencesFieldOrder`, `TestFieldErrorsAppearOnlyOnA422`, `TestTheInstanceIsThePathAndTheQueryNeverReachesTheBody`, `TestACodeWithNoTitleIsRefusedRatherThanRendered`. Equivalence: every case with a refusal. |
| 3 | `src/middleware/assert.ts` | Configuration checks that refuse to boot: positive integer, non-negative integer, non-empty string, RFC 9651 structured-field key. | **PORTED** | Behaviour in `internal/ratelimit/limiter.go` (`NewLimiter` validates limit/window/trustedProxies; structured-key check per request) and `internal/auth/verifier.go` (`New`, `assertHTTPURL`, `trimIssuer`). Tests: the table at `internal/ratelimit/limiter_test.go:140-172` (a negative limit, a sub-millisecond window, a negative proxy count — each asserting the refusal names the field) and `internal/auth/verifier_test.go:589 TestABrokenConfigurationIsARefusalToBoot` (7 malformed issuers refused, the trailing-slash one accepted). Plus `internal/httpapi/httpapi_test.go:472 TestAnUnreadablePortIsARefusalToBoot`. **Not a shared helper**: Go has no `assert.ts` equivalent file — each package re-derives the predicates and returns `ErrNotConfigured`. The behaviour is ported; the *file* is not, which is the right shape for Go and not a gap. |
| 4 | `src/middleware/rateLimitTypes.ts` | The store contract: one `hit`, no `peek`, so counting and reading cannot be split. | **PORTED** | `internal/ratelimit/store.go` (`Store` interface, `Verdict`, `Request`). Tests: `internal/ratelimit/parity_test.go` runs one table through both backends; `TestTheTranscriptionIsTheScript`. |
| 5 | `src/middleware/rateLimitStore.ts` | GCRA counting in memory, one process, sweep of settled buckets. | **PORTED** | `internal/ratelimit/store.go` (`MemoryStore.Hit`, `count`, `sweepSettledLocked`, `DefaultMaxClients`). Tests: `parity_test.go`, `live_test.go`. |
| 6 | `src/middleware/rateLimitStore.ts` / `src/middleware/rateLimitRedis.ts` (Redis half) | GCRA over Redis from one Lua script plus a hand-written RESP2 transport. | **PORTED** | `internal/ratelimit/redis.go` (`GCRALua`, `RedisStore.Hit`, `Connection`, `readReply`, `LazyRedis`) and `resp.go`. Tests: `parity_test.go` (transcripted script) + `live_test.go` (real `redis-server`). |
| 7 | `src/middleware/rateLimit.ts` | The limiter middleware: per-request policy, the eight `RateLimit-*` headers, `Retry-After` on refusal, one 429, **fail-open** when the store is unreachable. | **PORTED** | `internal/ratelimit/limiter.go` (`NewLimiter`, `Wrap`, `announce`, `CounterKey`, `RateLimitHeaders`) + `internal/httpapi/httpapi.go` (`RateLimiter`, `ProbePaths`, `writeRateLimitRefusal`, `RateLimitRefuser`). Mounted at `runtime.go:168` with `Exempt: isProbePath`. Tests — and these are **Go-side unit tests, not equivalence**: `limiter_test.go:68 TestRedisDownFailsOpenAndABrokenConfigurationFailsClosed` (unreachable store serves 200, headers left off, reason to the log; and a broken *configuration* fails **closed**), `:214 TestOneAtomicStepAdmitsExactlyTheLimitUnderABurst`, `:332 TestEveryRateLimitFieldIsAnnouncedOnEveryAnsweredRequest`, `:453 TestTheTwoProbePathsAreNeverCounted`, and the 429 assertions at `:409-437` (status, `rate_limited`, ceiling arithmetic on `Retry-After`, and the floor of one whole second). **None of this is compared against the TypeScript** — see §2. |
| 8 | `src/middleware/limitKey.ts` | Which bucket a request is: account > API key > address; `clientIp` parses `X-Forwarded-For` and accepts only real IPs. | **PORTED** | `internal/ratelimit/key.go` (`Key`, `KeySource`, `KeySourceOf`, `ClientIP`, `unknown`), branch for branch. Tests: `internal/ratelimit/key_test.go` (346 lines). |
| 9 | `src/middleware/limits.ts` | **The per-route allowance table**: `DEFAULT_LIMIT_TABLE` (6 entries, 5 distinct policy names), `limitTable()` validation, and `resolveLimit()` longest-prefix-on-a-segment-boundary lookup. | **GAP — silent** | No Go file holds this. `internal/ratelimit/limiter.go` has `DefaultLimit = 600`, `DefaultWindow = 60s`, `DefaultPolicy = "gateway-api"` — the **default row only**. `internal/httpapi/runtime.go:168` constructs the limiter with `Limit`/`Window`/`TrustedProxies`/`Exempt` and **never sets `Policy` or `Resolve`**, so every path in the Go service draws on one allowance under one policy name. `/auth/login` at 10/min and `/auth/register` at 5/min do not exist in Go, and `/auth/*` and `/v1/api-keys` are not cheaper than `/v1/`. The seam exists (`Options.Policy func(path) string`, `Options.Resolve`), so this is a table that was never written, not an architecture that cannot hold it. |
| 10 | `src/middleware/jwt.ts` | RS256 bearer verification: algorithm pinned before any key fetch, JWKS cache with TTL and a bounded one-refresh-per-window budget, `requireScope`, `503` when the key set cannot be fetched. | **PORTED** | `internal/auth/verifier.go` (`New`, `Authenticate`, `verifyClaims`, `algorithm = "RS256"`, `unavailable()`), `internal/auth/jwks.go` (`jwksCache`, `noWindow`, `load`, `keysFor`), `internal/auth/middleware.go` (`Require`, `RequireScope`). Tests: `internal/auth/verifier_test.go` (635 lines), `internal/httpapi/routes_test.go`. |
| 11 | `src/middleware/apiKey.ts` | API keys: `generateApiKey`/`hashApiKey` (SHA-256), `apiKeyPrefixOf`, an `ApiKeyStore` where every mutator takes the account, and a gate mounted on `*` **before** the limiter. | **GAP — silent, and structurally blocked** | There is no `ApiKeyStore` in Go at any depth. Searching for the *behaviour* — `ApiKeyStore`, `issue`, `revoke`, `hasKeyScheme` — finds nothing outside comments. `internal/auth/middleware.go:78` has `apiKeyContextKey` + `WithAPIKeyID`/`APIKeyIDOf` — the **seam the limiter reads**, not an implementation — and `internal/ratelimit/key.go:61` consumes it. Nothing sets it: `internal/httpapi/httpapi.go` mounts the header reduction, the bearer gate and the limiter, and no API-key gate. So in Go a caller cannot authenticate with a key, and `KeySource.APIKeyID` is always empty. **And it cannot be added by porting the store alone**: Go's router is generated from `openapi/v1.yaml`, and the document declares **seven paths** (`/healthz`, `/readyz`, `/v1/me`, `/auth/register`, `/auth/login`, `/auth/logout`, `/auth/me`) and **zero** `api-keys` operations — `grep -c api-keys openapi/v1.yaml` returns `0`. The key store has no HTTP surface in *either* language today (TypeScript registers only the `app.use("*")` gate at `src/index.ts:182`, never a route; `/v1/api-keys` appears in `src/` only as a limit-table entry at `limits.ts:67`). The document must name the operations before a Go route can exist. |
| 12 | `src/routes/table.ts` | Which prefix goes where, validated at boot; longest prefix wins on a segment boundary; `public` entries; `/v1/me` refused as a prefix. | **PORTED** | `internal/httpapi/table.go` (913 lines; `gatewayOwned = "/v1/me"`, longest-match note at :254). Tests: `internal/httpapi/table_test.go` (571 lines). Equivalence: `routedUpstream`, `gatedUpstream` (the table is declared on both sides and `TestTheRouteTableBothSidesDeclareIsTheSameThreeEntries` holds them equal). |
| 13 | `src/routes/proxy.ts` | The pass-through: rebuild the path, strip the prefix, an **outbound header allowlist**, attach gateway's own credential (never the caller's), relay only 2xx/4xx, translate 3xx and 5xx, drop `Set-Cookie`, override `Cache-Control`, bind a timeout. | **PORTED** | `internal/httpapi/proxy.go` (543 lines). Tests: `internal/httpapi/proxy_test.go` (941 lines) — including `TestTheCallersCredentialNeverReachesAnInternalService`, `TestTheRequestAllowlistIsExactlyTwoNames`, `TestTheResponseAllowlistIsExactlyOneName`, `TestTheTwoServiceFailuresAreDifferentSentencesAndDifferentLogLines`. Equivalence: `routedUpstream`, `gatedUpstream`, ~25 cases. |
| 14 | `src/routes/assertion.ts` | Mints the `x-cafaye-principal` assertion: ES256 over a declared claim set, bound to one upstream, RFC 7638 thumbprint `kid`, `MAX_ASSERTION_TTL_MS` refused at boot, reserved claims refused. | **PORTED** | `internal/httpapi/assertion.go` (586 lines). Tests: `internal/httpapi/assertion_test.go` (861 lines, 15 tests). |
| 15 | `src/bff/auth.ts` | The four `/auth` routes: same-origin gate, `__Host-bff-session` cookie, the fixed 401 sentence, 423 + `Retry-After`, identity's token never reaching the browser, `identityProbe`. | **PORTED** | `internal/httpapi/bff.go` (1,140 lines). Tests: `internal/httpapi/bff_test.go` (1,689 lines, ~45 tests). Equivalence: all six `bff*` scenarios. |
| 16 | `src/bff/session.ts` | The session **interface** (`SessionStore`, three methods, absent == expired) plus `memorySessionStore()`, a per-process `Map`. | **PORTED as a contract, NO IMPLEMENTATION — deliberate** | `internal/session/session.go` declares `SessionStore` (Get/Put/Delete, ported method for method). `internal/sessiontest/store.go` is the map-backed double — and `internal/sessiontest/guard_test.go` proves no production file imports it, so **the Go binary ships no session store at all**. `httpapi.NewBff` refuses a nil store. Recorded as a decision in `README.md` and the `internal/session` package comment, with the measurement (identity's store is keyed by `token_digest` and resolves the opposite direction, and Go's `internal/` rule forbids the import). **This is a real cutover blocker**: the shipped TypeScript has a working store, the Go service cannot serve `/auth/*` without one, and `RuntimeOptions` never builds a `BFF`. |
| 17 | `src/index.ts` | The app factory: probe routes, the four gates in order, `PROBE_PATHS`, the v0 404/500 envelope, `runtimeOptions`, `Bun.serve`. | **PORTED** | `internal/httpapi/httpapi.go` (`New`, mount ordering at :225-268, `ProbePaths`, `writeV0NotFound`), `internal/httpapi/runtime.go` (`RuntimeOptions`, `isProbePath`, `intFromEnv`), `internal/httpapi/env.go` (the one reader), `internal/httpapi/principal.go` (`GetCurrentPrincipal`, the `/v1/me` handler), `cmd/gateway/main.go`. Tests: `httpapi_test.go` (622 lines), `runtime_variables_test.go`, `routes_test.go`, `runtime_routing_test.go`, `query_test.go`, `TestExactlyOneFileInThisPackageTouchesTheProcessEnvironment`. Equivalence: all 11 scenarios. |

**Note on `/v1/me`, where the README is wrong a third time.** `README.md`'s table
says `GET /v1/me` in Go "declines with the reference's `404`". That is only true
when no verifier is configured. `internal/api/api.gen.go:1191` registers
`r.Get("/v1/me", wrapper.GetCurrentPrincipal)` from the document, and
`internal/httpapi/principal.go:60` implements it: with a verifier it echoes the
principal, without one it declines with the v0 `404`. That is **the same
conditional as `src/index.ts:249-278`** — `createApp` registers `/v1/me` only when
`options.jwt` is set — so the Go side is ported and the README understates it.
The equivalence set cannot see this, because `Options.Verifier` is nil in every
routed scenario (§2).

**Tally: 15 non-test `src/` files — 12 fully ported, 1 ported as a contract with no
implementation in the binary (`session.ts`), 2 silent gaps (`limits.ts`,
`apiKey.ts`).** No row is "ported but unverified" — for every `PORTED` row there is
a named test that would fail if the behaviour were lost. What varies is *which
kind* of test, and that distinction is the point of §2.

### A note on how "ported" was established

By behaviour, never by name. For each row I asked: what does this file *do*, where
does that behaviour live in Go, and what would fail if Go lost it. Concretely that
meant searching for the **route, header, error code, policy name or refusal** — not
the filename. Three findings came out of that discipline and none of them would
have appeared from a basename sweep:

- `src/middleware/apiKey.ts` has **no** Go counterpart, while `internal/ratelimit/key.go`
  contains `APIKeyID` and reads it. A name search for "apiKey" finds the second and
  concludes the first is ported.
- `src/middleware/limits.ts` has **no** Go counterpart, while `internal/ratelimit/limiter.go`
  contains `DefaultPolicy`, `DefaultLimit`, `DefaultWindow` and an
  `Options.Policy`/`Options.Resolve` seam. A search for "limit" finds all four.
- `src/middleware/assert.ts` has **no** Go counterpart *as a file*, while the
  behaviour is present in two packages and tested in two tables. Here the absence of
  a file is the correct Go shape and **not** a gap — the opposite conclusion to the
  two above, from the same kind of search.

## 2. The proven floor: what `internal/equivalence` actually compares

Eleven scenarios, in `internal/equivalence/scenarios.go`, driven by the runner in
`equivalence_test.go` against `test/equivalence/reference.ts`. Both sides' lists are
held equal by `TestTheGoSideHasAnAnswerForEveryScenarioTheReferenceHas`.

| Scenario | Source behaviour it covers |
|---|---|
| `bare` | `index.ts` — nothing configured is a legitimate app; the v0 404 |
| `oneProbeOk` | `probe.ts` — one dependency answering |
| `probesDegraded` | `probe.ts` — three deps, one refusing, one throwing with a host/port/credential in the message, none of which may reach a body |
| `routedUpstream` | `table.ts` + `proxy.ts` — a table with no gate in front of it; ~25 cases including the traversal and re-encoding edge |
| `gatedUpstream` | `index.ts` gate ordering + `proxy.ts` — the anonymous 401 and its position; `SET`-only-on-refusal |
| `bff` | `bff/auth.ts` — the four routes healthy: `201`/`200`/`204`, `Set-Cookie`, the origin gate's 403 |
| `bffBadCredentials` | `bff/auth.ts` — identity refuses the credential |
| `bffUnknownAccount` | `bff/auth.ts` — a *different* slug and detail that must be indistinguishable through the gateway |
| `bffAccountLocked` | `bff/auth.ts` — 423 with `Retry-After` |
| `bffIdentityBroken` | `bff/auth.ts` — identity up and returning 500; the outage shape `unusable()` exists for |
| `bffSessionWithdrawn` | `bff/auth.ts` — a session identity later withdraws |

### What the eleven do NOT compare — corrected

**The `CHANGELOG.md` claim is right in substance and wrong in fact.**

It says the two scenarios `limitsExhausted` and `counterStoreDown` were "declared
in `internal/equivalence/scenarios.go`" and that "the constants are in the tree".
**They are not in the tree.** `grep` for `LimitsExhausted`, `CounterStoreDown`,
`limitsExhausted`, `counterStoreDown` across every `.go` and `.ts` file returns
nothing. The only `storeDown` hits are the unrelated `sessiontest` fixture. So the
gap is *larger* than the changelog records: there is no named scenario, no constant,
and no case.

The changelog's substantive point — that **no scenario compares the limiter's 429
refusal, and none compares a limiter over an unreachable counter store** — is
**confirmed, and stronger than stated.** It is not that the eleven compare the
limiter's *headers* and stop short of its *refusal*: **no scenario configures a
limiter on either side at all.** `optionsFor` in `scenarios.go` sets `Probes`,
`Routes`, `Authenticate` and `BFF` — never `Options.Limiter` — and `reference.ts`'s
`SCENARIOS` has no `rateLimit` key in any of its eleven entries. So the entire
rate-limit surface is outside the equivalence check:

1. **The 429 refusal** — no scenario can reach one.
2. **The fail-open decision** — a limiter over a store that cannot be reached.
3. **The eight `RateLimit-*` headers** — the changelog says all eleven compare
   these. They do not: with no limiter mounted, no header is emitted by either side.
   (`openapi/v1.yaml` declares them on every non-probe operation, and
   `TestTheTwoProbeOperationsAreTheOnesWithNo429` holds the document against
   `ProbePaths` — but that is a document check, not a comparison.)
4. **The per-route allowance table** (§1 row 9) — no `Policy`/`Resolve` is ever
   supplied, so no scenario could distinguish one policy name from another.
5. **`apiKey.ts`** (§1 row 11) — no credential is ever presented to any scenario.
6. **`limits.ts` validation** — `limitTable()`'s `RangeError` on a bad entry.
7. **`/v1/me`** — the Go side declines it with the reference's 404 and the
   equivalence set cannot see the case where it is served, because `Options.Verifier`
   is nil in every routed scenario.

Also outside, by construction and stated in the code: the **assertion** is not
compared (`scenarios.go` declares no `principal` claims, because a minted `jti`
differs per mint and cannot be compared byte for byte); the **Redis store** is not
compared (no scenario has `REDIS_URL`); and the **`SessionStore` implementation** is
not compared (the scenarios run on the `sessiontest` double).

## 3. Cutover blockers, in order

### Code

1. **`src/bff/session.ts` has no implementation in Go.** `internal/session`
   declares the interface; nothing in the binary implements it; `cmd/gateway`
   never builds a `BFF`, so `/auth/*` answers 404. **The Go service cannot serve
   the browser surface at all until this is resolved.** The recorded reason is
   real and the deferral is documented — but a deferral is still a blocker, and it
   is the only one where the TypeScript *works today* and the Go *cannot*.
2. **`src/middleware/limits.ts` — the per-route allowance table.** Absent from Go.
   The stricter allowances on `/auth/login` (10/min), `/auth/register` (5/min),
   `/auth/logout` (30/min) and `/v1/api-keys` (60/min) do not exist. The seam
   (`Options.Policy`, `Options.Resolve`) is there; the table is not.
3. **`src/middleware/apiKey.ts` — API keys.** No store, no hashing, no prefix
   check, no gate. `KeySource.APIKeyID` is dead in Go. **This one is not a
   porting job on its own**: Go's router is generated from `openapi/v1.yaml`, and
   the document declares seven paths and **zero** `api-keys` operations. A key
   management surface has no operation to generate from, in either language. The
   document comes first, then the port.
4. **Equivalence coverage for the limiter**, which the manager needs *before*
   trusting the limiter rather than after. Two scenarios: the 429 and the
   fail-open store. Both are behaviourally covered by `limiter_test.go` in Go, so
   this is about the two implementations *agreeing*, not about Go being correct.
5. ~~`assert.ts`'s predicates untested~~ — **withdrawn.** `limiter_test.go:140-172`
   and `verifier_test.go:589` cover them. See the row.

### Non-code

6. **Which Dockerfile is default.** `Dockerfile:84` is
   `CMD ["bun", "run", "src/index.ts"]`. `Dockerfile.golang:86` is
   `ENTRYPOINT ["/app/service"]`. The Bun image is what ships.
7. **`bin/prime` must stop running the TypeScript tier** — and cannot until it does.
   It runs `bun install --frozen-lockfile`, `bun run typecheck`, `bun test`, then
   `bin/prime-go`. The `bun test` step and the `--no-go` escape hatch both exist
   only because both implementations are live.
8. **`pins.test.ts`** asserts the Bun version in `Dockerfile`, `mise.toml`,
   `package.json`, `bun.lock` and `docker-compose.yml`, and `test/dockerStage.test.ts`
   parses the Dockerfile's test-stage `COPY` chain and fails if a test file is not in
   it. Both are about the Bun image and both are void the day `src/` goes —
   `dockerStage.test.ts` in particular is a gate that would pass over nothing.
9. **`account_scope.yml` carries both sides, and that changes the work.**
   Counting `file:` entries: **7 rows against `src/index.ts`** and **1 against
   `src/middleware/jwt.ts`**, against **7 rows against
   `internal/api/api.gen.go`**. So the Go side is already ratcheted, not
   unrecorded — deleting `src/` means **deleting 8 TypeScript rows**, not
   re-pointing them. Two details make that more than a delete:
   - The TypeScript rows use **line numbers and a 3-line `HANDLER_WINDOW`**
     (`src/index.ts:251`, `:278`), and `src/index.ts:218-248` is a long comment
     arguing that the window is exactly zero-margin. The Go rows point at
     `internal/api/api.gen.go` registrations instead, because `stripbaseurl` exists
     to make those readable to core's chi recogniser (`account_scope.yml:42`).
   - `account_scope.yml:331-350` records a standing `accountScope.undeclared` on
     the Go `/v1/me` registration and explains why it is **not** fixable here:
     `chain_gate` looks for `app.use(`/`.use(` and chi mounts middleware with
     `r.Use(`, so **no middleware added to the Go router can ever satisfy it**, and
     the row was deliberately written as `undeclared` rather than as a red
     `accountScoped` row, because "a ratchet row red forever with a condition whose
     end is unreachable is the switch rule 2 exists to refuse". The same block
     records a **DECISION NEEDED in `core`**: every `go-*` row is verified against
     the generated file and not the code it describes, since `handler_for` cannot
     follow `wrapper.GetCurrentPrincipal` across a package boundary. Harmless
     today (`internal/httpapi` contains no account evidence) and "a silent hole the
     day it does". **Neither is a cutover blocker and neither is mine to fix** —
     I am recording them because they are the two places a reader sizing this work
     would otherwise mistake for unfinished business.
10. **`AGENTS.md` and `README.md` are both wrong about the Go side's size** (§0).
    The README's "What is Go today" table claims rate limiting, API keys and bearer
    verification are "not ported — Wave 3". Two of those three *are* ported and one
    (API keys) is not. It separately understates `/v1/me`, which *is* served
    (§1 row 17), and the table also carries duplicated rows plus a stray trailing
    row (`| the BFF and the session store | ✅ | **not ported** — Wave 3 |`
    floating after a paragraph). **Sequencing off this table will mis-size the work
    in both directions** — it overstates three subsystems as absent and understates
    one as absent. I did not edit either file; that is a documentation packet.

11. **README "Not built yet" is stale in the same direction, twice.** Its first
    bullet says the Go rewrite "has three operations"; its third says a started Go
    gateway "reads `PORT` and nothing else". Both are out of date:
    `internal/httpapi/runtime_variables_test.go:36-64` asserts `RuntimeOptions` reads
    exactly **fourteen** named variables, and the Go side serves all seven operations
    (six behind configuration). The section is otherwise careful and its session-store
    and `IDENTITY_URL` bullets are still accurate — it is specifically the
    "how much Go is there" lines that have drifted.

### One thing that is *not* a blocker, recorded because it looks like one

`internal/httpapi/httpapi.go:255-262` notes that chi requires `Use` before any
route is registered, so there is **no ordering hazard in Go** — the hazard the
`src/index.ts:195-201` comment spends a paragraph on ("a route registered above
`app.use("*", limiter)` is never rate limited") is Hono-specific. The Go
mount-ordering property is real and is asserted by
`TestAGatewayBuiltFromTheEnvironmentRefusesAnAnonymousRequestBeforeTheUpstream`
(`internal/httpapi/table_test.go:184`), which reads the source rather than
inferring it. The ordering rule transfers; the trap does not.

## 4. What I deliberately did not do

- **Did not port, change, move or delete anything under `src/`**, or any other
  file in this repository. `git diff master...HEAD --stat` shows exactly one added
  file — see §5.
- **Did not run `bun test`, `bin/prime` or `bin/prime-go`** as gates. There is no
  `node_modules` here and I was told the disk is at 93%.
- **Did not run any linter, dead-code sweep, or repo-wide search for unused
  exports.** The one exception is the targeted `grep` calls above, each aimed at a
  named behaviour (`ApiKeyStore`, `LimitTable`, `Policy`, `LimitsExhausted`) rather
  than a basename — the basename sweep the brief warns about is what produced
  `proxy.ts → testkeys.go`.
- **Did not edit `CHANGELOG.md`**, though I found a factual error in it (§2: the
  two scenario constants are described as being in the tree and are not). That is a
  finding, not an edit.
- **Did not edit `README.md` or `AGENTS.md`**, though §0 and §3 item 10 record four
  factual errors between them. Both are documentation, and correcting them is a
  change this packet was not briefed to make.
- **Did not verify anything by running it.** No `bun test`, no `bin/prime`, no
  `bin/prime-go`, no `go test`. **Every claim in this report is from reading
  source**, and each row's evidence is a test *name* I read in the file — I did not
  confirm that name currently passes. There is no `node_modules` in this worktree
  and I was told the disk is at 93%. Per the brief I am not touching CI's two known
  red causes (the `oapi-codegen@v2.8.0` fetch in `bin/prime`'s codegen step, and the
  `image` job's `docker compose config`). If a row's evidence is load-bearing for a
  sequencing decision, run the named test before committing to the plan.
- **Did not run `account-scope`, the mutation gate, or `measure-findings.sh`.** I
  read `account_scope.yml` to establish what it records and read its own comments
  about its standing findings (§3 item 9). I did not execute the checker, so I
  cannot say whether it currently reports clean.
- **Did not measure the equivalence count.** The brief says 11 scenarios / 405
  comparisons; `README.md` says "24 base cases × 9 configurations = 306". I did
  not run the suite, so **I did not confirm either number** and the report does
  not assert one. What I did verify by reading is the *shape*: 11 named scenarios
  on both sides, held equal by
  `TestTheGoSideHasAnAnswerForEveryScenarioTheReferenceHas`, and no scenario
  configuring a limiter or a BFF from the environment.
- **Did not touch any other repository.** No `cafaye/kit`, no `core`, no
  `identity` — even though `internal/session`'s deferral turns on identity's store
  and I took that from the package comment rather than opening the file.

### What I would check next, if there were another quarter

1. `openapi/v1.yaml` needs `api-keys` operations before §3 item 3 is a porting
   job rather than a document job — that is a manager/spec call, not an audit one.
2. The two limiter equivalence scenarios. Both halves of the decision are already
   unit-tested in Go; this is the cheapest remaining confidence in the whole port.
3. Whether the per-route limit table (§1 row 9) was deliberately deferred or
   simply not reached. Nothing in the tree, the README or the changelog says
   either way — which is why I have called it a silent gap rather than a deferral,
   and why that distinction is the manager's to make rather than mine.
## 5. Verification

This packet's verification is the diff. Run before the final commit:

```
$ git diff master...HEAD --stat
 REPORT-gateway-go-port-audit-01.md | 314 ++++++++++++++++++++++++++++++++++++++++++++++++
 1 file changed, 314 insertions(+)
```

One added file, nothing else — no modification to any `src/` file, no new Go
file, no edit to `CHANGELOG.md`, `AGENTS.md`, `account_scope.yml` or any other
`HANDOFF-*` / `REPORT-*`.

Three commits, each adding or amending only this file:
`e81a65f` (the table, §1–§3, committed inside Q1), `6d09270` (the Q2 corrections
— one row withdrawn, two README errors found), and `e3f2c36` (Q3: the
`account_scope.yml` correction and §4). Nothing was reverted or amended after the
fact.
