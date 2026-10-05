# AGENTS.md

Conventions for `gateway`, the cafaye public gateway. Read this before changing
anything; the house rules in `moon/PLAN.md` §1 and §3 apply on top of it.

## What this repository is

`gateway`, one HTTP process, **mid-rewrite into Go**. It is the only door into a
cafaye deployment: it authenticates callers, limits what they can ask for, and
(forwards requests) to the service that owns the work. The contracts are owned by
`cafaye/core`; the manifest in `cafaye.yml` is how the other tools find this
service.

**TWO IMPLEMENTATIONS ARE LIVE AND BOTH ARE CURRENT.** `src/` is TypeScript on
Bun >= 1.3 and is the **reference** — not legacy, not scheduled for deletion on
this packet's say-so. `cmd/gateway` and `internal/` are the Go rewrite, which
serves the same contract and **serves all seven operations**: the two probes, the
error envelope, the pass-through and the route table, `/v1/me`, the limiter with
its per-route allowance table, the RS256 verifier, and the four `/auth` routes on a
Redis session store. It used to be described here as "two operations of seven",
which understated it by five; **the honest measure of the Go side is not the size
of the tree, it is the "Not built yet" list**, and there are four things on it:
no API keys (blocked on the OpenAPI document), no scope check mounted on any
route, the limiter not counting forwarded traffic, and no per-service readiness
probes. `src/` is deleted in a later packet, once `internal/equivalence` has proven
equivalence rather than asserted it. The README's
[Go rewrite](README.md#the-go-rewrite) section is the table of which is which,
and its [Not built yet](README.md#not-built-yet) list is the source of truth for
what this repository does not claim.

**A Go gateway started by `cmd/gateway` is not `New(Options{})`.** This distinction
is the one that made every claim above go stale, so it is stated here rather than
left to the reader to infer from the table. `RuntimeOptions` builds a verifier, a
counter store, the limiter with the allowance table and an `identity` readiness
probe **unconditionally** (`internal/httpapi/runtime.go:97-104`), exactly as
`runtimeOptions` in `src/index.ts` passes `jwt:` with no unset-issuer state. The
nil-verifier shape — where `/v1/me` declines with the reference's `404` and the
limiter counts nothing but its own defaults — is a library constructor, and it is
what `internal/equivalence`'s `bare` scenario builds. **When you are about to write
that the Go side does not do something, check which of the two you are describing**;
a claim about `New(Options{})` is true and useless, and one about the shipped
binary is the one a reader will act on.

The rules below are written for the TypeScript implementation because it is the
one that has the security core. They bind the Go rewrite too — the security
properties are properties of *gateway*, not of a language — and the Go-specific
mechanisms they translate into are named where they differ.

## Layout

TWO TREES. Everything under `src/`, `test/` and `pins.test.ts` is TypeScript and
is the reference. Everything under `cmd/` and `internal/` is the Go rewrite.

```
cmd/gateway/main.go      the Go binary — reads the environment through httpapi.RuntimeOptions, hands the result to httpapi.New, listens
internal/api/            oapi-codegen output, the //go:generate lines, and stripbaseurl
internal/auth/           the bearer verifier: RS256, the JWKS cache and its refresh budget, scopes, ordered claims
internal/httpapi/        Options, New, probes, the problem envelope, the one env reader
internal/equivalence/    the Go side of the equivalence check, and the scenarios it compares
test/equivalence/reference.ts   the TypeScript side, stood up on a port by the same check
bin/prime-go             the Go tier of the gate
Dockerfile               the Go image: distroless/static, a `test` stage that runs `go vet` and `go test`, and `docker build .` as the runtime target

src/index.ts            the app factory (createApp), env parsing, Bun.serve bootstrap
src/problem.ts          core's error envelope — the one rejection path
src/probe.ts            what a readiness probe is, so a module can offer one
src/middleware/jwt.ts   createJwtVerifier — JWKS cache, RS256, requireScope
src/middleware/limitKey.ts  which bucket a request is: account > api key > address
src/middleware/limits.ts     the per-route allowance table
src/middleware/rateLimit.ts  the limiter — key, policy, headers, 429, fail-open
src/middleware/rateLimitTypes.ts   the RateLimitStore contract
src/edge.test.ts          the edge under attack: no SSRF, path traversal, header injection
src/middleware/rateLimitStore.ts   GCRA in memory, per process
src/middleware/rateLimitRedis.ts   GCRA in Redis, one Lua script, plus RESP2
src/middleware/apiKey.ts     API keys — issue, authenticate, revoke
src/middleware/assert.ts     configuration checks, one RangeError each
src/routes/table.ts         which prefix goes where — validated, and the resolver
src/routes/proxy.ts         the pass-through: rebuild the path, attach gateway's credential
src/bff/auth.ts         the /auth surface — identity calls, the cookie, the origin gate
src/bff/session.ts      SessionStore + the in-memory v0 implementation
test/fakeIdentity.ts    a stand-in for identity's auth API; the image never gets it
test/jwksServer.ts      a stand-in for identity's JWKS; the image never gets it
test/limitTable.ts      a one-number limit table, for tests
test/openapiPaths.ts    reads openapi/v1.yaml and Hono's app.routes, and raises
                        rather than under-reading either
test/openapiDocument.test.ts  openapi/v1.yaml held to the router, both directions
test/noSkips.test.ts     reads the suite's own source; fails on any skip outside one allowlist
pins.test.ts            the bun pin, asserted across every file that states it
openapi/v1.yaml         the HTTP contract, and the open decisions in its header
bin/prime               the gate: frozen install, typecheck, bun test, then bin/prime-go
.github/workflows/ci.yml   kit's reusable workflow, plus the four jobs it cannot own
```

`createApp` is the only thing the TypeScript tests import, and it must stay
importable without opening a socket — the `Bun.serve` call is behind
`import.meta.main`. Configuration arrives as an argument (`AppOptions`), never as
a module-level global read from the environment, so a test can build two
differently-configured apps in one process. `runtimeOptions` is the single place
the environment is read.

**The same property, in Go, and it needs a different mechanism to hold.**
`httpapi.New(Options)` takes its configuration and `httpapi.RuntimeOptions(Env)`
is the only function in the module that reads one. Go makes this *easier to lose*
than TypeScript did, because `os.Getenv` is a free function any package may call
at any time — so "there is no global" is not a property one can assert by
inspection. Two checks read `internal/httpapi`'s own sources instead: exactly one
file may call `os.Getenv` (it is `env.go`), and `RuntimeOptions` may read exactly
one variable. A new packet that adds a variable adds the assertion with it, and a
new file that reaches for `os.Getenv` fails the gate rather than passing review.

## Rules

**Tests first.** Write the case, watch it fail, then implement until green
(PLAN.md §3). Every handler change asserts the status code *and* the JSON body
*and* the `Content-Type` — `/readyz` returning 200 with the wrong shape is a
failure, not a pass.

**A test the image does not copy is not a passing test, it is a missing one.**
`docker build --target test` is a gate, and a gate is a claim about what ran. A
test file outside the test stage's `COPY` list is not executed and cannot fail, so
the build stays green having verified less than it appears to — the image once ran
392 tests across 15 files where a host ran 399 across 16, and the seven missing
were `pins.test.ts`, the check that the image and the repository agree on the pin.
Two things hold that down, and a new one needs both: `test/dockerStage.test.ts`
reads the Dockerfile and fails the local gate when a test file is not in the copy
chain, and the `image` CI job diffs the test files the *built image* discovered
against `find`, which is the half the Dockerfile reader cannot see because
`.dockerignore` can drop a directory out of a `COPY src ./src` and buildkit copies
the rest. Keep the copy list explicit — `COPY . .` is always a superset, so the
first check would pass without saying anything — and add a test file to that list
in the same commit that adds the file.

**Liveness never touches a dependency.** `/healthz` is unconditional and
`/readyz` is the only endpoint that may fail because something else is down. A
database or identity outage must not get the process restarted out from under
in-flight requests. Keep the split, and keep both endpoints exempt from rate
limiting: a throttled probe is an orchestrator that cannot see a healthy
process, and the restart that follows is worse than the traffic it was guarding.

**A probe that fails is `unavailable`, not an exception.** A dependency that
throws, rejects, hangs, or answers with anything but `"ok"` is one unavailable
dependency. None of them may take the process down. Readiness reports which
dependency failed by name; the underlying error goes to the log, never to an
unauthenticated caller — an error message can carry a host, a port or a query.

**The token never chooses how it is checked.** The algorithm is pinned in
`middleware/jwt.ts` and the protected header is read before any key is fetched,
so an `alg: none` or HS256 token costs no network call and never reaches a
verifier. The accepted algorithms are one constant, never something a token can
widen and never a per-request option.

**A dependency outage is `503`, not `401`.** If identity's key set cannot be
fetched, the caller's credential was not the problem, and a 401 would send them
to fix something that is fine. `401` means "this token is not acceptable";
`503` means "we cannot tell".

**Stubs stay honest, and say so in their own file.** A stub must never grow a
token parse that *looks* like verification: a half-check is worse than an
obvious stub, because a caller will believe a token was checked when nothing was.
Every stub carries a `TODO(gateway-0N)` naming the packet that replaces it, and the
README lists it as not built. A packet that is not written yet is absent, not a
fake that looks finished.

**A packet id that names a dispatched packet is history, and history keeps its
name.** `gateway-0N` above is a template for a packet that does not exist yet, so
it follows the service's name. A `TODO(guard-06)` in the source names
`logs/briefs/guard-06.txt`, which is on disk under that name and was dispatched
under it, so rewriting the id breaks the only link from the code to the brief
that produced it. The two forms differ because they mean different things, and a
sweep that cannot tell them apart either corrupts history or points the next
packet at the old name.

**A refresh on the hot path needs a reason and a budget.** The JWKS cache is the
only reason gateway talks to identity at all, and it is bounded twice: a cached set
is reused for its TTL, and a `kid` that is not in it buys **one** forced refresh
per cache window. A rule a caller can trigger per request is an amplifier aimed
at a dependency, not a fallback. Claim that budget **before** the fetch, not
after: a budget recorded when the work lands is a budget a burst walks straight
through, and a burst is the shape an edge actually receives. The budget is a
window number rather than a flag, because a flag cannot tell one TTL window from
the next, and a refresh that *fails* spends it too — otherwise an unreachable
identity is an unlimited fetch allowance for anyone naming a `kid`.

**An address filter is a parser, not a charset.** `X-Forwarded-For` entries end
up in a bucket name, so they are checked — and "contains no character unsafe for
a Redis key" is not the question. `[0-9a-f:.%]+` accepted `deadbeef`, `cafe` and
`999.1.1.1`, each of which became a bucket of its own, so a caller who could put
an entry in the trusted position minted an allowance per request with a string
that was never an address. `clientIp` uses `isIP` from `node:net` — a runtime
builtin, not a dependency — and a new filter there has to answer "is this an
address". Rejecting everything is the same defect pointing the other way: it
silently merges every client behind one proxy into one bucket.

**A dependency answering 5xx is not an outage gateway can be quiet about.**
`call()` logs when the *transport* fails, which is the rare half. An identity
that is up and returning 500 — a broken deploy, an OOM, a panic — reached
`unusable()` with no log line at all, so every login in a deployment failed with
one status and nothing was recorded for an operator to correlate. `unusable()`
takes the target URL and the status and writes them down. **Never the body**: a
dependency's error page is exactly where a credential turns up, so the line
records the *shape* of the answer and never its contents.

**The bucket is the strongest identity the request has, and no weaker.** The key
is derived in one order — verified account id, then API key id, then client
address — in `middleware/limitKey.ts`, and never from a header value or an
unverified token. The limiter is mounted *after* the auth gates for that reason,
so a token that does not verify is answered 401 and counted against nothing. Keep
the ordering, and keep the consequence visible: a credential-garbage flood is not
counted either, which is affordable only because a rejected token costs no key
fetch.

**A bucket name is not a place to put caller input.** The identity is digested
into the counter key before it reaches a store, because an `account_id` claim is
whatever identity chose to put there and a bucket name becomes a Redis key. A key
that trips a store's charset check is not a loud failure: the store throws, the
middleware fails open, and the limiter is silently off in the deployment that has
one.

**Cross-tenant is absence, and absence is not just a status code.** A resource the
caller cannot see does not exist, and gateway says the same thing it says when the
resource does not exist. A `403` is a confirmation: it tells the caller the thing
is real and belongs to somebody else, which is a smaller leak than the data and a
perfectly good way to walk the platform. This holds *below* the wire too, which is
the half that is easy to forget — `ApiKeyStore.revoke` on another account's key is
a no-op with no error and no return value, because a distinguishable failure is the
same oracle one layer down.

The two `403`s gateway writes are correct and are not tenancy: `requireScope` is a
capability failure (the token authenticated and lacks a scope — a fact about the
caller, which they already know) and `requireSameOrigin` is about the request.
Neither names a resource, so neither can confirm one exists. The line is drawn in
exactly that place and both directions are load-bearing: a `403` for *tenancy* is
a finding to fix, and a `404` for *capability* would throw away a distinction the
caller is entitled to.

**A key id is not a tenant.** Every `ApiKeyStore` operation that acts on a record
takes the account: `revoke(accountId, id)` and `list(accountId)`. Ids are shown
to a holder to tell two keys apart and given to an operator for revocation, so an
id that reached either method on its own would let any caller who learned it act on
somebody else's credential. `list` filters on the record's own `accountId` rather
than trusting an id set, because the store's id map is keyed by id and a
caller-chosen id is not a guarantee. `createApiKeyAuth.issue` mints a
`randomUUID`, which makes a collision improbable rather than impossible — and
`TODO(guard-07)` is about to write a shared store. The rule for the whole platform
is the same: an identifier a caller can hold is a handle, not a tenant.

**Count and read in one step, or it is not a limiter.** `RateLimitStore` has one
method and no `peek`, because a read-then-write counter admits N× the limit under
a burst. Any new implementation is proved by `rateLimitParity.test.ts`, which
runs one behaviour table through every implementation and requires identical
transcripts. `bin/prime` touches neither Redis nor the network: the Redis path is
driven by a transcription of its Lua and its transport is tested as pure
functions. The script *itself* is executed by `rateLimitRedisLive.test.ts`
against a real `redis-server`, in the `redis` CI job only — see below.

**In-memory is single-instance only, and is never called a platform limit.** A
caller gets `limit` per window from *each* replica, so N replicas is an N× limit,
and every bucket is lost on restart. `REDIS_URL` selects the shared store; the
truth is in the source, the README and the manifest's DECISION NEEDED, and it
stays in all three.

**The window slides; there is no aligned edge.** GCRA spends the allowance
continuously, because a fixed window hands out 2× the limit across its boundary in
two milliseconds. Do not reintroduce wall-clock-aligned buckets, and do not report
`remaining` as a countdown to a fixed edge: under a sliding window a caller
pacing itself at exactly its allowance holds a constant remaining, and a
countdown would promise burst room the limiter then refuses.

**A counter store that cannot answer fails OPEN.** The cost is named in the source
and the README: for as long as it is unreachable, gateway applies no limit. Failing
closed would hand a Redis outage to every caller as a 429. The `RateLimit-*`
headers are left off rather than guessed at, and the store is a readiness probe —
which is what makes the gap visible instead of silent.

**Invalid config is an error, not a fallback.** `rateLimit` validates `limit`,
`windowMs` and `trustedProxies` at construction and throws a `RangeError`; a limit
of `0` is a programming error, not "unlimited". `limitTable` validates every
entry, `createApiKeyAuth` validates the account and the scopes of every key it
issues, `createJwtVerifier` does the same for the issuer, the audience, the
key-set URL and both durations, and `runtimeOptions` does it for the environment.
The one exception is *absent*: an app built with no `rateLimit` option runs
unlimited, which is the honest v0 default, and an app built with no `jwt` option
serves probes only.

**A credential crossing to a service is gateway's to choose.** The caller's inbound
`Authorization` is never forwarded past the edge, and neither is their `Cookie`:
if a caller can set an arbitrary `Authorization` and have it reach pantry, gateway
is a confused deputy and the caller authenticates to the edge before choosing who
they are behind it. `src/routes/proxy.ts` enforces it as an outbound header
*allowlist*, so a header nobody thought of cannot become a smuggling channel,
and a table entry with no token sends no `Authorization` at all — which is a
different thing from one gateway invented. `GET /auth/me` holds the same line for
identity by taking the stored token from the session. A future route that
genuinely needs a caller's own bearer downstream has to say so, name its scope
check, and be argued for in review; it is not a default to be widened into.

**Deps are `hono`, `jose` and nothing else.** Reasoning in
[README.md](README.md#why-hono-and-bun). `jose` earns its place because signature
verification is not code to hand-write; there is still no Redis *client*
dependency — `rateLimitRedis.ts` is forty lines of RESP2 and a transport port, and
that is deliberate — no logger, no test framework beyond `bun test`, and no
dependency without a cause stated in review. `node:crypto` is a runtime builtin,
not a package: SHA-256 for an API key and for a bucket digest, and
`crypto.getRandomValues` for the key itself.

**Comments say why.** Explain the decision and the constraint, not the
mechanism. A comment restating the line below it is noise.

**`cafaye.yml` follows core's frozen schema.** It is `additionalProperties:
false`, so a field core does not define is a validation failure, not a comment.
`exposes` is missing on purpose and the reason is a `DECISION NEEDED` callout in
the file: filling it in needs an OpenAPI document, and specs are manager-owned.

## Gates

```sh
mise trust && mise install   # once per clone, if you use mise — see below
bin/prime                    # THE GATE: frozen install, typecheck, bun test, then bin/prime-go
bin/prime-go                 # the Go tier alone: gofmt, build, vet, test, codegen currency
bin/prime --no-go            # everything but the Go tier, and it prints that it skipped
bun run typecheck            # tsc --noEmit, must print nothing
docker build --target test . # the Go suite inside the image, the same tree CI builds
docker compose build         # the runtime image itself
docker build .               # the runtime image, same answer, no compose
```

All of them before a commit lands.

`mise trust` gates the typecheck rather than being housekeeping: mise refuses to
read an untrusted config, and `bun run typecheck` reaches `node` to launch
`tsc`, so an untrusted `mise.toml` fails the gate for a reason that has nothing
to do with the code. Run it once per clone before the first gate.

**`bin/prime` runs BOTH TIERS, and that is not optional.** `bin/prime-go` exists
so a developer working on the Go port does not have to install bun to find out
whether `go vet` is happy; `bin/prime` invokes it so the *declared gate* covers
both implementations. A gate a change to either language can pass without the
other running would be two gates wearing one name, and `gate.yml`'s proofs are
checked by RUNNING `gate.command` — so a Go change that broke `go vet` would
otherwise ship through a green `bin/prime`. When `src/` is deleted, this line goes
with it. `--no-go` is the one escape, it prints a loud skip, and `pins.test.ts`
asserts both that the banner appears and that an unknown argument is still
refused.

**The Go pin is stated in three files and enforced by none of them.**
`mise.toml`'s `go`, `go.mod`'s own `go` directive and `Dockerfile`'s
`ARG GO_VERSION` all say 1.26 — the ARG names the image tag, so it carries the
series and not the patch, which is what `pantry` does with its `RUST_VERSION` —
and the pin itself, 1.26.1, is what `pantry` and `identity` say.
`bin/prime-go` compares mise.toml against go.mod **before it runs anything**, and
compares both against the running toolchain, because the cafaye-rb lesson is that
a developer on a newer compiler silently produces a binary CI never built and
reads the difference as a defect in the code under test.

**The generated code is committed, and a gate proves it is current.**
`internal/api/api.gen.go` is `oapi-codegen` output and it is in the tree, because
`bin/prime-go` regenerates and diffs it — and a header grep is not a substitute,
since it is true of every file the generator has ever written. The Go router IS
that file, so a stale one does not fail to compile: it answers the old routes
with the new contract's promises. Regenerate and commit **in the same commit as
the document change**. The step runs offline from the module cache via a `file://`
GOPROXY and does not skip when it cannot run: no `|| true`, no conditional green.

**`internal/api/stripbaseurl` is part of generation, not a hand edit.** The second
`//go:generate` line removes the `options.BaseURL+` token from the route
registrations. Core's chi recogniser requires a `/`-prefixed literal as the first
term after `(`, so an untouched `oapi-codegen` registration is INVISIBLE to
`account-scope-check` — measured on this tree: 8 registrations readable, 6
unreadable, and `surface-thin` reporting that the floor "is not being violated, it
is unfalsifiable". With the token removed: 14 readable, 0 unreadable. A hand edit
would be a permanently red gate; `bin/prime-go` also fails on a committed file
that has regressed, matching the SHAPE rather than the token so it cannot fire on
the comment that explains the step.

**A generated file needs the same tripwire for its own step.** `stripbaseurl`
exits non-zero when it has nothing to rewrite, because exiting 0 there would be a
green saying "the registrations are readable" while the file still says
`options.BaseURL+`. A post-processing step that silently does nothing is worse
than no step.

**An environment-gated tier that skips is a green run that verified nothing.**
`rateLimitRedisLive.test.ts` needs a real `redis-server`, so it skips when
`GATEWAY_REDIS_URL` is unset — and `bun test` exits 0 on a fully skipped file. Two
mechanisms stop that from reading as a pass, and a new gated tier needs both:

- `GATEWAY_REDIS_REQUIRED=true` makes the tier throw at module load when the URL is
  unset, rather than skip.
- The `redis` job parses the summary and fails on `0 pass` or on any skip.

Those two protect **one file**. A second gated tier added tomorrow, or a
`test.skip` left behind after a flaky run, arrives with neither, so
`test/noSkips.test.ts` is the third: it reads the suite's own source and fails on
any `skip`, `skipIf`, `todo` or `only` outside a one-entry allowlist, and it names
the file in the failure. Adding a skip means editing that allowlist, which is a
reviewable act. Its detector is assembled from arrays at runtime rather than
written as a regex literal, because a literal `.\s*(skip|skipIf)` matches its own
source and the tripwire would then always fail for the wrong reason.

Set the environment and prove the count. A tier added without all three is a tier
nobody will notice is not running.

**THE EQUIVALENCE TIER IS THE FOURTH MECHANISM, AND IT IS GATED THE SAME WAY.**
`internal/equivalence` needs `bun` to stand the TypeScript reference up, so it
skips without it, and `go test` **discards a passing package's output entirely** —
so a package printing its own skip row prints it into a void on every green run.
That is not a theory: the Redis tier did exactly this in TypeScript here.
Therefore `bin/prime-go` runs `go test -v`, filters the output, and counts the
skip at the GATE; `GATEWAY_EQUIVALENCE_REQUIRED=1` turns it into a failure inside
the test; the CI `prime` job sets it and additionally reads the comparison count
and fails under 72. **That number is the gate's weakest number and it is not mine
to raise**: a run on this tree prints `51 cases across 13 scenarios = 912
comparisons`, so the floor is under 8% of what it is a floor on, and a hand-written
case list that lost nine tenths of itself would pass. Recorded in
`HANDOFF-docs-corrections-01.md` §1.3. The rule this paragraph exists to teach —
*a tier that can pass by not running is a green about nothing* — is why the skip is
caught; the floor is a second, weaker mechanism against a different failure, and it
is the one that drifted.

Three details that were measured rather than reasoned, and each was wrong first:

- the gate's `sed` needs `.*` before `equivalence:` and not `^`, because
  `go test -v` prefixes log lines with `    file.go:357: `. The anchored version
  matched nothing, which would have reported a green on a run that skipped
  everything.
- `gate.yml` carries **no floor** on the comparison count: the line only exists on
  a run that found `bun`, so a `minimum` on it would turn every developer's machine
  without bun into a red gate. A floor on something a legitimate environment
  cannot print is not a floor. The number is held in CI instead, where the flag
  guarantees it is printed.
- the degraded scenario's dependency names are deliberately **not alphabetical**
  (`redis, identity, aperture`). A planted mutation that swapped the hand-written
  `/readyz` ordering for `json.Marshal(api.Readiness{…})` PASSED while the names
  were `aperture, identity, redis`, because a sorted set renders identically
  whether the gateway preserves insertion order or sorts. Planting a mutation and
  finding it does not fail is the only way to find that one.

**An account-scoped entry point needs a negative test, and the count is asserted.**
`test/tenantEntryPoints.test.ts` derives the enumeration from the code — the
routes off Hono's own `app.routes`, the account-scoped store methods off the
interface declarations, and every `status: 403` in production source — and requires
each one to have a case named in `src/middleware/tenantIsolation.test.ts`. A new
route or a new store method that takes an account therefore fails the gate until
the negative case exists, and a case for something not in the table is decoration.

Three things make it a check rather than a list somebody maintains, and all three
are the ones that were wrong in its first draft:

- **The expectations are derived, not transcribed.** A row that repeats the digest
  from `bucket()` is a copy of the production logic, and it passed with the digest
  deleted. The key is read off the transport — what `eval` was actually handed —
  because `bucket()` is private and the observation point is the only honest one.
- **A fixture has to assert its own pre-condition.** The listing case built its
  colliding id through `createApiKeyAuth.issue`, which is idempotent on the
  *hash*: the second `issue` returned early, the collision never happened, and the
  test passed against the broken store. It now writes records straight to the
  store and asserts the collision exists.
- **The count is asserted against a literal, and the operation kinds are counted
  from the rows.** read 5, list 1, update 3, delete 2 — all four present, because
  a service that scopes reads and forgets deletes is the common shape and a table
  with no delete row cannot be showing it.

**A guard has to be shown to fail.** Five divergences were planted and reverted for
the isolation packet, each caught by the named test; the transcript is in
`REPORT-guard-11-isolation.md`. **Any new guard here gets a planted divergence
before it is believed**, and if it hangs or passes on a broken source that is a
finding about the gateway, not about the source.

**CI runs `bin/prime`, not a CI-only variant.** kit's `bun` job runs the same
*steps* from kit's copy of the conventions, and the `prime` job runs gateway's own
command, so the two cannot drift into disagreeing about what the gate is. The
`git diff --exit-code -- bun.lock` that follows it is the check that survives a
future edit dropping `--frozen-lockfile`: a plain `bun install` resolves a
different tree and the run stays green while doing it.

## Adding an endpoint

1. Decide whether it is liveness, readiness, or traffic. Only traffic is
   authenticated and rate limited.
2. Tests first: status code, JSON shape, `Content-Type`, the anonymous case, and
   the throttled case if it is traffic. A rejection asserts the whole envelope,
   not just the status.
3. Errors go through `problem()` — core's `problem+json` envelope — with a
   `detail` that is a fixed string per case. The v0 `{ "error": …, "message": … }`
   shape survives only on `404` and `500`, and moving those is a packet (see the
   DECISION NEEDED in the README). Do not add a third shape.
4. If it needs a dependency, add a `Probe` to the record `createApp` builds.
   Never a bespoke health path.
5. Under `/v1/*` the auth gate is already mounted; add `requireScope(...)` after
   it rather than re-checking the token, and mount it on the route, not the
   prefix, so one scoped route does not lock out the rest.
6. If it needs its own allowance, add a row to `DEFAULT_LIMIT_TABLE` and a test
   for that row. The policy name is the unit of accounting, so a new entry is a
   new budget and a new bucket, not a second number under an existing one.
7. **Register the route after the limiter.** Hono matches handlers in
   registration order and a route answers without calling `next`, so a route
   registered above `app.use("*", limiter)` is never rate limited — and the test
   that catches it is one that asserts a 429, not one that asserts a 200.
8. Add the row to the README endpoint table, add a `CHANGELOG.md` entry, and
   re-run the three gates.

## Adding a route the OpenAPI document does not know about yet

`test/openapiDocument.test.ts` will fail the moment step 1 adds a route, in one
direction or the other, and that failure is the gate working. Add the operation to
`openapi/v1.yaml` in the same commit.

**The document is a judgement call, so the judgement goes in the file.** Three
things are worth saying out loud in a new operation rather than leaving a reader
to infer them:

- **The `429`.** Every route except the two in `PROBE_PATHS` can be throttled, so
  it declares one, and the eight `RateLimit-*` fields go on the success response
  as well as on the refusal. The test reads the exemption from `PROBE_PATHS` and
  the header names from `RATE_LIMIT_HEADERS`, so neither is a list somebody
  typed — a header added to `announce` and not to the document fails the gate.
- **The error statuses.** Read them out of the handler, not out of habit. A `401`
  means "this token is not acceptable" and a `503` means "we cannot tell"; an
  operation that reaches a dependency declares the `503`.
- **Whether it is authenticated.** `security: []` is a statement, and a genuinely
  unauthenticated route needs one the way it needs a `summary`: `identity` and
  `courier` both carry theirs as recorded decisions, and the next reader needs to
  know it was a choice.

Where gateway and `core/docs/openapi-conventions.md` genuinely disagree, record it
as a `> DECISION NEEDED (gateway-NN)` in the **document's header** and keep going.
Do not pick a side silently, and do not describe the route gateway ought to have.
