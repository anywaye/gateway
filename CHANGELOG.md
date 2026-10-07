# Changelog

All notable changes to `gateway` are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). `core`'s
mini-semver grammar (`^`, `~`, `>=`, exact) is what `cafaye.yml` uses; npm
dependency versions follow npm's own rules.

## [Unreleased]

### Added

- **gateway has a deploy artifact: a hand-written Helm chart, and the Argo
  `Application` that pulls it.** `charts/gateway/` is what turns the image
  into a running service on the launch substrate — k3s + Traefik +
  cert-manager + ArgoCD + CloudNativePG + Redis (`DEPLOYMENT.md`) — with a
  hostname, a readiness gate and a rollback. Before this, gateway had a
  `Dockerfile` and nothing that deployed it: no `config/deploy.yml`, no
  chart, no `Application`. The chart renders a `Deployment`, a `Service`, a
  Traefik-class `Ingress`, a `ConfigMap` for the clear env, and a `Secret`
  **reference** for the secret env; `deploy/argocd/gateway-application.yaml`
  completes the pull-only loop — a commit changes the chart, Argo makes the
  box agree, hand edits self-heal, rollback is `git revert`.

  **What the chart is for:** the launch deploy artifact for the front
  door. **What it is not:** not a second deploy path. `DEPLOYMENT.md` is
  explicit that there is no helm-from-CI template in kit and one may never
  be added, because a second deploy path beside Argo is a split brain —
  the chart is pulled by Argo, or it does not run. It is also not Kamal,
  not compose, and not a hosted platform.

  **It is the reference `caf gen chart` (packet L10) must reproduce**, and
  is written generated-shaped: every value that belongs in a manifest is in
  `values.yaml`, and nothing in the templates is a hand-typed constant a
  generator could not emit. The manifest fields it reads, so L10 has a
  specification rather than a guess:

  | values.yaml | manifest field |
  |---|---|
  | `image.repository`, `image.tag`, `image.pullPolicy` | Deployment container image |
  | `replicaCount` | Deployment replicas |
  | `service.type`, `service.port` | Service type and port |
  | `ingress.enabled`, `.className`, `.host`, `.annotations`, `.tls.enabled`, `.tls.secretName` | Ingress (class `traefik`, TLS via cert-manager secret) |
  | `env` (every key) | ConfigMap `data`, read via `envFrom` |
  | `secrets.redisUrlSecretName`, `.redisUrlSecretKey` | Deployment `env` `secretKeyRef` for `REDIS_URL` |
  | `resources` | Deployment requests/limits |
  | `probes.liveness.*`, `probes.readiness.*` | Deployment probes |

  **The readiness probe is `/readyz`**, gateway's real, bounded,
  dependency-aware probe (`internal/httpapi/runtime.go`); liveness is
  `/healthz`. An Argo or rollout gate that reads `/healthz` accepts a
  container that cannot reach identity, which is the whole reason `/readyz`
  exists.

  **`REDIS_URL` is a required `secretKeyRef`, never a literal in
  `values.yaml`** — the secret lives on the box and the chart names it,
  because closed-source charts and their secrets ride a pull-based system.
  No secret, no pod: a deployment cannot forget Redis. The comment at that
  line states both consequences — no `REDIS_URL` means **no browser
  surface** (the four `/auth/*` routes decline, so no sign-in) *and* an N×
  rate limit whose counters reset on every deploy.

  **`TRUSTED_PROXIES` is a value with the reason**: behind the ingress the
  limiter must believe one hop of `X-Forwarded-For`; at `0` every caller
  shares the ingress's peer address and the launch rate-limits all users as
  one. Too high is the same defect pointing the other way — a caller who
  can write the trusted hop mints a bucket per request.

  **Also in this change:** `docker-compose.yml` sets `REDIS_URL` and
  `TRUSTED_PROXIES` explicitly (both were commented out), so the local
  stack brings gateway up with its browser surface. Locally
  `TRUSTED_PROXIES` is `"0"` — the kit stack runs no ingress in front of
  gateway, so the socket peer is the right key; the chart sets `"1"` for
  the box, where Traefik appends exactly one hop.

- **gateway emits real telemetry: one server span per request, and the fleet's
  collector can now see them.** `internal/telemetry/` is `caf gen telemetry`
  output — the per-signal attribute allowlists, the span-name grammar, the endpoint
  contract and the no-op path, all read out of core's vendored schemas — plus a
  hand-written SDK half (`sdk.go`) that consults that generated contract rather than
  copying it. `internal/httpapi/telemetry.go` mounts it, outermost, in exactly one
  of the two places `New` builds its chain, and `cmd/gateway` installs the exporter
  and flushes it on SIGTERM.

  A span carries three attributes — `http.request.method`, `http.route` (the matched
  TEMPLATE, never a caller's path) and `http.response.status_code` — plus
  `error.type` from core's closed vocabulary and a failed status on a 5xx and on
  nothing else. The process identity (`service.name`, `service.namespace`,
  `service.version`, `deployment.environment`, `tenant_id`) is on the RESOURCE, which
  is where core puts an identity and is exempt from the 2000-combination metric cap.
  An inbound W3C `traceparent` is continued; a missing or malformed one starts a new
  trace and never changes the answer.

  New variables: `GATEWAY_OTEL_ENDPOINT` (default `http://otel-collector:4317`, set
  in `docker-compose.yml`), `GATEWAY_TENANT_ID`, and the standard
  `OTEL_SDK_DISABLED` / `OTEL_TRACES_EXPORTER` switches. Unset endpoint is **not** a
  no-op: core's contract makes the shipped collector the default, so a developer with
  nothing configured gets traces.

  `cafaye.yml`'s `language` said `typescript`, an implementation deleted at cutover,
  and `caf gen telemetry` refuses any language it does not emit for — so the field
  had to agree with the tree before the fleet's own generator could be used. That
  does not resolve DECISION NEEDED item 7, which is about which implementation the
  manifest describes.

### Removed

- **gateway's own Argo `Application` is deleted; kit's substrate manifest is
  the one.** `deploy/argocd/gateway-application.yaml` is gone, with the empty
  `deploy/` tree around it. Measured across the fleet, gateway was the only
  service repository committing an `Application`, and its copy collided with
  kit's `templates/substrate/manifests/applications/gateway.yaml`: same
  `metadata.name: gateway`, same `namespace: argocd`, a **git** source
  (`https://github.com/cafaye/gateway.git`, `path: charts/gateway`,
  `targetRevision: master`) where the OCI design requires a chart repository
  with one read-only pull secret, and destination namespace `cafaye` — the
  compose project's development name, not a cluster one. Two `Application`s
  of one name in one namespace fight, and the later `kubectl apply` wins: a
  deploy whose target depends on apply order is not a deploy.

  `DEPLOYMENT.md`, "Who owns the `Application`": the substrate owns it, one
  per service, OCI-sourced, destination namespace = the service name, and a
  service repository commits none. The chart (`charts/gateway/`) is unchanged
  and still the deploy artifact — what changed is that the repository no
  longer competes with its own substrate for the right to apply it. Every
  reference to the deleted file (`README.md`, `charts/gateway/values.yaml`,
  `REPORT-gateway-chart-01.md`) now names kit's manifest instead.

### Changed

- **`/v1/api-keys`' 60/min allowance is a deliberate tightening, checked, and left
  alone — and the reference's own suite would not have noticed it changing.**
  `REPORT-gateway-api-keys-01.md` §1 settles the question the allowance-table packet
  flagged. The Go side already matched `src/middleware/limits.ts` and was verified
  byte for byte across eight paths rather than read off a table, so **no number
  moved on either side**; `internal/ratelimit/limits.go` gained the argument as a
  comment, because the row's existing comment states the intent and not the
  decision.

  The argument is the table's shape: **every entry that names a new bucket is
  strictly cheaper than the bucket it inherits**, and the one exception (`/v1/`) is
  not an exception because it reuses the default's own `gateway-api` name at the
  default's own 600. A dropped digit would not land on both "tighter than its
  parent" and "the number the table already spends on a named security surface".

  The finding worth acting on is an asymmetry, measured by planting `60`→`600` in
  both trees. **The reference does not notice** — `bun test src/middleware/limits.test.ts`
  reports 17 pass / 0 fail, because `limits.test.ts:74-78` pins the *policy name*
  for this row and no number while pinning 10, 5 and 600 for its neighbours.
  **Four Go assertions do**: two in `limits_test.go`, one through `PolicyResolver`,
  and one reading `q=` out of `RateLimit-Policy` through the whole HTTP stack. So
  the number is currently held by the Go suite alone — the safe direction to fail
  in, and the reason those four stay exactly as they are.
- **`RATE_LIMIT_TABLE` — the escape hatch the limit table's own header offers
  operators — does not exist.** `limits.ts:53` tells an operator with a real traffic
  shape to "replace this table with their own through `RATE_LIMIT_TABLE`". That
  variable appears exactly once in the repository: in that sentence.
  `runtimeOptions` reads `RATE_LIMIT_REQUESTS` and `RATE_LIMIT_WINDOW_MS`, and both
  write the **default row only** (`src/index.ts:409-410`), so no per-route entry is
  configurable from the environment on either side. The honest statement is the
  inverse of the header's: a shipped allowance is **not** operator-tunable in a
  deployment today. That raises the stakes on every number in the table slightly,
  and it is a packet rather than something to change here.
- **What porting API-key management to Go would take: a contract change, not a
  translation — and it obliges the TypeScript reference in the same commit.**
  `REPORT-gateway-api-keys-01.md` §2 enumerates it. `openapi/v1.yaml` declares
  seven operations and **zero** `api-keys` operations; the `apiKeyCredential`
  security scheme describes how a caller *presents* a key and is not coverage for
  managing one, and the document says so itself at lines 787-789. Three operations
  would have to be **added** — `POST /v1/api-keys`, `GET /v1/api-keys`,
  `DELETE /v1/api-keys/{id}` — with two new schemas and one new parameter.

  The consequence that makes this the wrong shape for a port: `openapi/v1.yaml`
  describes what **gateway** answers, and gateway answers it in TypeScript until
  `src/` is deleted. Adding the operations makes
  `test/openapiDocument.test.ts` demand matching routes in `src/`, so it is
  "add a feature to the reference, then add it to the port" — contract first, then
  reference, then Go.

  Three questions in that change belong to the manager and are named rather than
  answered:

  - **Does the listing response carry `hash`?** `ApiKeyRecord` has six fields and
    one is the digest. Rule 1 is about what is *stored* and rule 2 about what is
    *shown*, so a display projection is required and neither tree builds one.
  - **Is `DELETE` on a key that is not yours a `204` or a `404`?** `revoke` refuses
    by not acting, and cross-tenant is absence — but every other operation in the
    document 404s on a missing resource, so this needs the sentence saying why.
  - **Is there a scope requirement on any of the three?** `requireScope` exists and
    **no route in `createApp` uses it**, so today any valid credential could mint,
    list and revoke. Whether revocation needs a weaker scope than issuance — a
    compromised issuance-capable caller should not also be able to destroy the audit
    trail — is an authorization policy question.

  One reframe worth recording, because it is a third reason the Q1 number is
  deliberate and the strongest of the three: **`/v1/api-keys` is a route that does
  not exist yet.** `apiKey.ts`'s five exports are three helpers, a store, a
  middleware, and three management operations that no route calls in either
  language. So the row is an allowance declared for a surface that is not served
  yet, and a number chosen *before* the question of traffic existed is what a
  starting-point-not-a-measurement number looks like. It also means the row is
  currently inert on the wire — nothing ever draws `gateway-api-keys` — so the four
  Go assertions holding 60 are holding the resolution rule, not a live quota.

||||||| 3241c76
- **`docker build .` builds the Go gateway.** `Dockerfile` is now the Go image —
  `golang:${GO_VERSION}` for the build, `gcr.io/distroless/static-debian12:nonroot`
  for the runtime — and `Dockerfile.golang` is deleted rather than left beside it,
  so there is exactly one shipped Dockerfile and no reader has to guess which one
  `docker build .` uses. The test stage stays and is now Go: `go vet ./... && go
  test -count=1 -v ./...`, run with `docker build --target test .`.

  Two properties were moved rather than dropped, and where each went is written
  down at both ends:

  - **The image runs every test file the repository has.** The Bun test stage
    copied an explicit list, and `test/dockerStage.test.ts` held that list to the
    repository because a test file the image does not have does not fail, it is
    not run. The Go test stage copies the whole build context — `go test ./...`
    finds a package by walking the tree, and a named list would be a subset
    somebody maintains by hand — which makes two of that test's assertions
    impossible and its other two tautologies, so the file is retired. The
    property it held is now asserted where the image can be seen: the CI `image`
    job asks the built image which `*_test.go` files it holds and diffs that set
    against `find`, and a new step exports the shipped image's filesystem and
    fails if it carries any repository path. `gate.yml`'s exact test-file floor
    moves 25 -> 24 with the deletion named in place. A Go-side *local* half of the
    same check is not written yet; `HANDOFF-cutover-01.md` carries it.
  - **The toolchain pin the image is built on is still asserted.** `pins.test.ts`'s
    two Bun-image cases (`ARG BUN_VERSION`, compose's build arg) are false now that
    the image is not built on Bun, so they are retargeted at the Go toolchain
    rather than deleted: `ARG GO_VERSION` and compose's `GO_VERSION` must be the
    same tag, and that tag must be the pin in `mise.toml` at a component boundary.

- **`cmd/gateway` answers `-healthcheck`.** The compose healthcheck was
  `bun -e …`, and the runtime image is distroless: no shell, no `curl`, no `wget`.
  The binary now probes its own `/healthz` over the container loopback and exits 0
  or 1, which is `identity`'s arrangement for the same reason. It probes
  `/healthz` and **not** `/readyz` — where `identity`'s probes `/readyz` —
  because a dependency outage must not restart the gateway, so the probe composes
  `up --wait` waits on has to be liveness.

- **`docker-compose.yml` builds the Go image** (`GO_VERSION` rather than
  `BUN_VERSION`), drops `NODE_ENV`, which nothing reads any more, and carries the
  `-healthcheck` probe above.

### Added

- **The recorded reason for the missing Go session store was CHECKED, and it is
  CORRECT. The decision it implied is not.** `REPORT-gateway-session-store-01.md`
  verifies both halves against `cafaye/identity` at source rather than inheriting
  them, because a claim in a document is a reader's premise:

  - identity's `sessions` table **has no column for the presented value**. It is
    keyed on `token_digest` with a unique index, `migrations/00003_sessions.sql`
    stores "only its SHA-256", and the table's only read — `ByToken` —
    takes a *token* and hashes it. So the inverse lookup gateway needs
    (browser id → identity token) is not merely absent, it is unimplementable
    from that table: the value is not stored. `/v1/session` carries only `post`
    and `delete`, so there is no HTTP route either.
  - Go's `internal/` rule forbids the import, **answered by the compiler**: a
    scratch module with a `replace` onto the identity checkout fails with
    `use of internal package github.com/cafaye/identity/internal/sessions not
    allowed`. That line arrives *after* unrelated missing-go.sum errors rather
    than instead of them, so it is the kind of failure a skimmed log reads as
    something else.

  Both hold, so the justification in `README.md` and in `internal/session`'s
  package comment stays as written — it is accurate. What it wrongly implied is
  that nothing could be built. Gateway **owns** its sessions rather than reusing
  identity's, and the decision is to put them in Redis over the RESP2 transport
  `internal/ratelimit` already speaks, sharing **one** client and one socket with
  the limiter rather than forking `resp.go`.

### Added

- **The per-route allowance table, in Go.**
  `internal/ratelimit/limits.go` ports `src/middleware/limits.ts`: the six shipped
  entries, the policy names, the longest-prefix-on-a-segment-boundary resolution and
  the `limitTable()` validation. `internal/httpapi/runtime.go` now supplies the
  resolver, so the table is reachable from the shipped binary.
- **A session store the Go service can actually build, so `/auth/*` stops
  answering `404` on a configured deployment.** This was the code blocker from
  `REPORT-gateway-go-port-audit-01.md`: `internal/session` declared the interface,
  `internal/sessiontest` held a map-backed double whose guard proved no production
  file imports it, and `cmd/gateway` built no BFF at all — so the Go service could
  not serve the browser surface while the TypeScript reference serves it today.

  **`internal/sessionredis` is the store, and gateway owns it.** `gateway:sess:<id>`,
  one `SET` carrying the expiry in the payload with a `PX` backstop, absent and
  expired the same answer, `DELETE` of an absent id a success — reproduced from
  `src/bff/session.ts` rather than invented, including the `<=` expiry boundary and
  the already-expired-`put`-is-stored-and-reads-back-absent row that a stricter
  store would get wrong.

  It is built on `internal/ratelimit`'s client and **`RuntimeOptions` hands the
  limiter and the session store the same `*LazyRedis`**, so a deployment has one
  socket to Redis rather than two, one command-in-flight lock rather than two, and
  one implementation of RESP2 rather than two implementations that will disagree.
  `Commands` is the store's own one-method interface and `Connecter` takes the lazy
  client, so `internal/ratelimit` was not widened for a caller it does not have.

  Two properties the reference's `Map` does not need and a shared store does:

  - **A session id is CALLER INPUT on `Get` and `Delete`**, because it arrives in
    the `__Host-bff-session` cookie. An id that is not the canonical lowercase UUID
    `login` mints is *absent* and issues no Redis command at all — so caller bytes
    cannot reach a key, and a junk cookie is a stranger answering `401` rather than
    an outage answering `503`. On `Put` the asymmetry runs the other way: that id is
    gateway's, so a bad one is a defect and is refused.
  - **The token is stored in the clear**, because `Get` must return it for
    `/v1/me`'s `Bearer` header. That is the reference's posture and a *different*
    one from identity's, so it is named rather than glossed. Error messages report a
    Redis reply by shape and never by contents, so an error path cannot log a
    credential.

  `RuntimeOptions` reads `IDENTITY_URL` and builds the surface **only with
  `REDIS_URL` too** — a per-process store is the degraded shape this exists to stop,
  and `IDENTITY_URL` alone is the configuration that looks set and serves `404`. An
  unusable `IDENTITY_URL` is a refusal to boot.

  Proved against a **real `redis-server` started in-process** by
  `internal/httpapi/runtime_session_test.go`, with no `GATEWAY_REDIS_URL` and no
  skip: login, `/me` with the cookie, logout, the stale cookie refused, and **a
  second gateway built from the same environment reading a session the first one
  created** — the property a `Map` cannot have and the reason the whole packet
  exists. Three planted divergences were caught: dropping `Options.BFF` (the four
  routes answered `404`), disabling the expiry check (sessions outliving their
  token), and skipping the id assertion (caller bytes in keys).

  `bin/prime-go` green: **187 passed, 0 failed**.


  `REPORT-gateway-go-port-audit-01` found this gap and found it **silent**:
  `httpapi.Options.Policy` and `Options.Resolve` were already on the limiter and
  nothing ever set them, so every request drew the `gateway-api` default. `/auth/login`
  was answered at 600/min rather than the 10/min it is specified at, and a cutover
  shipping that would have quietly widened the most attacked surface on the edge.

  The policy names are part of the wire contract — they go into `RateLimit-Policy`
  and are half the counter key — so they are asserted directly, not only through the
  resolver. The allowances are asserted **by name** and by enforcement, not by
  announcing them: `TestTheLoginAllowanceIsEnforcedAndNotJustAnnounced` admits ten
  logins and refuses the eleventh, because a header assertion alone cannot tell a
  table that is wired from a table that is merely present.

  Two things are worth knowing about how it was ported:

  - **`/auth/login/extra` DOES draw the `/auth/login` allowance.** The packet asked
    for a test asserting the opposite. The reference's `claims` accepts
    `path === prefix || startsWith(prefix + "/")` and its own suite asserts the same
    shape, so inverting that here would have the Go gateway draw a different
    allowance from the service it replaces, on the surface this port tightens.
    `TestASubpathUnderAPrefixDrawsThatPrefix` pins the reference's behaviour and the
    non-match case is asserted with `/auth/loginfoo`.
  - **A policy name claimed by two entries with DIFFERENT numbers is refused at
    construction.** The reference's `byPolicy` map resolves that case by insertion
    order, which a Go map does not have — so which numbers a request drew would be
    per-iteration. Two entries sharing a name while disagreeing about the numbers is a
    table contradicting itself, and a startup failure is the only answer that does not
    depend on iteration order. Identical numbers under one name are accepted; the
    shipped `/v1/` row relies on that.

  Every shipped window is 60s, which was checked per entry rather than assumed. The
  window stays a per-ENTRY field regardless, because a table whose window lived
  elsewhere could not express an entry with a different one.

  Not changed: the default allowance, the default window, and the limiter's
  fail-open behaviour. `RATE_LIMIT_REQUESTS` and `RATE_LIMIT_WINDOW_MS` remain the
  allowance for a policy the table does not name, and
  `TestTheConstructorAllowanceDoesNotOverrideAnEntryTheTableNames` holds that setting
  them does not widen a route the table names.

  Still not configurable: the table is code and the prefixes are configuration, so
  [a per-prefix allowance](README.md#not-built-yet) is still a later packet.

- **The limiter's refusal and its store-down behaviour, compared: the two
  equivalence scenarios `worker/gateway-go-auth-01` declared and never built.**
  `ScenarioLimitsExhausted` and `ScenarioCounterStoreDown` were constants in
  `internal/equivalence/scenarios.go` with **no case anywhere building on either** —
  the same shape as a comment asserting a property the code does not have, which is
  why the previous entry recorded them as unbuilt rather than leaving them to look
  like coverage. That entry is now false and this one replaces it.

  The inventory is **thirteen** scenarios, and `internal/equivalence` reports that
  number from the list it drove rather than from a literal, with
  `TestTheInventoryIsEveryScenarioBothSidesDeclareAndNothingTwice` holding the two
  equal.

  - **`limitsExhausted`** — a limiter at three per minute, with the clock frozen on
    both sides at 2026-01-01T00:00:00Z so the crossing is a function of the request
    count and not of the wall clock. Compared: the `429`'s status, its problem body
    byte for byte, and the rate-limit headers **by value** rather than by presence
    (`headerValuesComparedByValue`, read from `ratelimit.RateLimitHeaders` so it
    cannot fall behind `announce`). The burst is compared at its first and its last
    answer, because GCRA spends the allowance continuously and a burst that
    overspends by two reaches an identical refusal — the difference would otherwise
    show only in the `RateLimit-Remaining` on the way there.
  - **`counterStoreDown`** — the same limiter over a store whose `Hit` fails. The
    fail-open decision is now a comparison: the request is **served**, no rate-limit
    headers are written, `/readyz` reports `redis` unavailable, and **no part of the
    failure reaches either response body** — checked against a host, a port, a
    hostname, a credential and the connection error, on both sides. The run asserts
    the two scenarios produced their own decisions in opposite directions:
    `limitsExhausted` must have refused something, and `counterStoreDown` must have
    refused **nothing**, because a run where the fail-open scenario starts refusing
    is fail-closed and would be green on the diff alone.

  Two scenarios rather than two modes of one, as planned: one answers 429 and the
  other answers 200, and a configuration where both did the same thing would be
  indistinguishable from a limiter that was never mounted.

  **The routed case, added since the finding above was written.** One of
  `limiterCases` is now on a path the route table **claims** — `GET
  /v1/pantry/items` — so the comparison covers forwarded traffic and not only the
  router's own routes. It is asked **last**, because the allowance is one bucket per
  identity rather than one per path: the two unrouted bursts spend it first, and the
  routed one then compares a `429` that the routed path spent. Asked first it would
  spend the allowance on the routed path and the two above would be comparing a 429
  against a path the limiter never saw.

  **The finding itself is FIXED** — see the entry below this section. The
  paragraphs above describe what was true when it was written; they are not edited,
  because a changelog that rewrites history is not a changelog.

### Fixed

- **The Go limiter now runs on the traffic the route table forwards.** This closes
  the divergence the previous entry recorded as reported-and-unfixed: under an
  exhausted bucket, `GET /v1/pantry/items` was a `429` with the whole `RateLimit-*`
  family on the reference and a `200` with **no** rate-limit headers at all on the Go
  side. An edge whose limiter does not run on forwarded traffic is not limiting the
  traffic that costs it money, and forwarded traffic is the expensive kind — it
  reaches an upstream that does work.

  The cause was the mount, and the reason it was wrong is worth recording: **chi's
  `Mux.Use` wraps the routes registered on the router it is called on.** The
  pass-through is mounted *on top of* that router and, for a path a table claims,
  never calls it, so the limiter counted gateway's own routes and forwarded nothing.
  The reference registers `app.use("*", limiter)` before `app.use("/v1/*", proxy)`
  and counts it. `httpapi.New` had carried a comment claiming chi had no ordering
  hazard where Hono had one — that belief is what produced this, and the comment is
  corrected.

  `everyRequest` now builds the request chain once, in the reference's order: the
  repeated-header reduction, then the credential gate, then the limiter. It is
  registered with `Use` when there is no pass-through and wrapped around the
  pass-through when there is, and the limiter goes to **exactly one** of the two —
  the pass-through calls the router for a path no table claims, so a limiter in both
  places counts those requests twice. That was measured during the fix: the Go side
  reported `RateLimit-Remaining: 1` where the reference reported `2` on the first
  request of a run, and the comparison stayed green on status alone while the two
  sides' arithmetic parted company by one request per case. `credentialGate` returns
  the middleware rather than a wrapped handler, so the gate and the limiter are
  ordered in the one list both are named in, and authentication still resolves
  **before** the limiter: a request refused by the gate is counted against nothing.

  `TestTheGoSideDoesNotCountRoutedTraffic` is **renamed and inverted** to
  `TestTheGoSideCountsRoutedTraffic` — it failed the moment the mount was fixed,
  which is the signal to replace a test rather than adjust one. It now asserts the
  refusal *and* the announced header values, because a limiter that counted a routed
  request twice refuses identically and differs only in `RateLimit-Remaining`, and
  it asserts the upstream was not contacted.

  No rate limit, window or policy name changed: this is **where** the limiter runs,
  not what it allows. `equivalence: 51 cases across 13 scenarios = 914 comparisons, 0
  differences` (912 before; the two are the routed burst's ends).

- **The equivalence comparison gained a `burst` field and a header-value
  comparison.** Both are additions: a case with no burst is asked once and compared
  exactly as before, so the eleven existing scenarios are unchanged.

- **The browser-facing surface, in Go: four `/auth` routes and the origin gate.**
  `internal/httpapi/bff.go` ports `src/bff/auth.ts` — `POST /auth/register`,
  `POST /auth/login`, `POST /auth/logout`, `GET /auth/me` — behind
  `Options.BFF`, which is **nil by default**: `cmd/gateway` therefore serves probes
  only and the four routes answer the reference's v0 `404`, which is what
  `createApp({})` gives. Set `Options.BFF` and they are served.

  The properties it holds, each with a test that is shown red by mutation:

  - **The origin gate is the CSRF defence, and there is no double-submit token.**
    `RequireSameOrigin` covers the three mutating routes and *not* `GET /auth/me`,
    and the coverage is read out of the generated document's registrations rather
    than from a hand-written list, so a route added next week is gated by default.
    A token is absent because the gate is the defence; the reasoning for not adding
    one — the second cookie would be readable by the very script the first hides
    from, so the "secret" is compared against a value the attacker supplied — is in
    the source.
  - **The session cookie is `__Host-bff-session`**: `Secure`, `Path=/`, `HttpOnly`,
    `SameSite=Lax`, no `Domain`, and it expires when *identity's* session does.
    The clearing cookie repeats every attribute, because a deletion missing one
    leaves the original in place.
  - **The browser never receives an identity token.** Asserted behaviourally (the
    login body is exactly `{"expires_at":…}`; `/auth/me` returns exactly
    `{"id":…,"email":…}`) *and* by reading `bff.go`'s own sources for any line that
    writes a token into a response.
  - **Password rules, lockout and enumeration are identity's.** The body is
    forwarded byte-for-byte, a `423` stays a `423` and carries its `Retry-After`
    only when it is digits, and **two different refusal causes produce
    byte-identical responses** — the test asserts that, not that a 401 exists.
  - **A revoked session is dead on the next request.** A `401` from identity on
    `/auth/me` drops the record and clears the cookie; a `503` does not, because
    treating an outage as a revocation signs everybody out whenever identity
    hiccups. Those two are different branches and both are tested.
  - **Rate limiting keys on the client address**, because a browser session has no
    principal yet: nothing in this package invents a principal, so the bucket a
    browser lands in is still derived from the socket.

  **No session store ships, and that is the decision.** `src/bff/session.ts`'s
  `Map` was not ported. `identity/internal/sessions/store.go` is the better design
  and cannot be used here: it is keyed by `token_digest` and resolves a *token* to a
  session, while the gateway needs the opposite direction — the browser's opaque id
  in, the identity token out — and nothing in identity performs that direction,
  because the digest is one-way by construction. Go's `internal/` rule forbids the
  import across modules and identity exposes no endpoint that does the inverse
  lookup. `internal/session` declares the interface, `internal/sessiontest` holds a
  fixture, `NewBff` **refuses to construct** a browser surface with a nil store, and
  `TestNoProductionFileImportsTheSessionDouble` runs `go list -deps ./cmd/...` to
  prove the fixture is not linked into the binary. A partial migration would have
  been worse than none: two services that each believe they own the session.

- **`mutation-gate.sh`: 39 properties, each shown red by breaking it.** A green
  suite is not evidence that a property is tested; a mutation is. Every mutation is
  verified to have *applied* before the suite runs, the tree is restored by copy
  rather than by `git checkout --` (which restores the last commit and silently
  deletes uncommitted work — it did, once), and three mutations that "did not bite"
  turned out to be about the recipe rather than about the code, and say so in a
  comment instead of being deleted.

- **`internal/equivalence` reaches the browser surface**: nine scenarios, **306
  comparisons**, and the runner can now send a body, two headers, a *duplicated*
  header, and a per-side sign-in exchange — because the session id is minted by the
  implementation under test and a single shared cookie would be a session neither
  side knows.

### Fixed

- **The problem document's field order, which the equivalence check found.** Every
  rejection this service wrote differed from the reference at **byte 2**, and not
  one of them differed in anything a client can read. `api.Problem` declares its
  fields alphabetically (`oapi-codegen` emits a struct in the order it finds them in
  the document's `properties` map, which is sorted) where `src/problem.ts` writes
  `type, title, status, detail, instance, code, trace_id`. `writeProblem` now
  hand-renders in the reference's order, `field` before `code` inside a 422's
  `errors`. This was invisible until now because the envelope was ported for five
  operations that all *declined* — an envelope nothing reaches is an envelope
  nothing has compared.

- **`writeRawJSON` overwrote the problem content type.** It set
  `application/json` unconditionally, so `writeProblem`'s `application/problem+json`
  was replaced on every problem document in the service: a correct body served with
  the media type that says "this is not a problem document". Now conditional, like
  `writeJSON`'s.

### Changed

- **A doubled `Sec-Fetch-Site` is no longer refused, and the first value wins.**
  Measured, not chosen: the reference answers `200` — with the cookie — to a
  request carrying `Sec-Fetch-Site: same-origin` **twice**. Two mistakes followed
  from getting this wrong. The origin gate joined the lines (the WHATWG `Headers`
  rule) and refused, which is a "stricter" gate that diverges; and `oapi-codegen`
  refused the repeated header before any handler ran, with a `text/plain` `400`
  that appears nowhere in `openapi/v1.yaml`. `collapseRepeatedHeaders` now reduces
  a repeated value to its first before the generated router sees it.

- **A `BFF` no longer registers a readiness probe.** `createApp({bff})` answers
  `{"deps":{}}`; the `identity` probe is registered by `runtimeOptions`, which
  reads `IDENTITY_URL`. Auto-registering it made `/readyz` differ from the
  reference in every browser scenario, at byte 9.

- **A logout identity could not revoke is `unreachable()`, not `unusable()`.**
  `src/bff/auth.ts`'s logout is `revoked ? 204 : unreachable()`. The port answered
  `unusable()` — a different `detail` and an extra log line. A decision, not a
  status, and the status alone would not have caught it.

### Added (earlier in this series)

- **A Go gateway, beside the TypeScript one, serving the same contract.**
  `gateway` is being rewritten in Go: `net/http` + `chi`, with `oapi-codegen`
  generating the server from `openapi/v1.yaml`, because the contract is the
  framework and no Gin, no Echo (`MVP-SCOPE.md`).

  **`src/` is NOT deleted and is not legacy.** It is the reference implementation
  and remains what serves traffic; the Go service is measured against it on every
  gate run. Deleting it is a later packet, once equivalence has been *proven*
  rather than asserted — a port and a deletion in one commit produce a diff where
  nobody can tell a porting bug from a mechanical edit, which is the review this
  rewrite most needs.

  What the Go service serves today is **three operations of seven**: `GET /healthz`
  and `GET /readyz`, plus both error envelopes, plus the four `/auth` routes behind
  `Options.BFF` (see above). The remaining three — `GET /v1/me` and the API-key and
  rate-limit surfaces behind `/v1/*` — are declared by the contract, need a subsystem
  this packet does not port, and answer the **v0 `404`**. A `501` would have been
  more truthful about the code and less true about the contract: `createApp({})`
  does not register `/v1/me` without a verifier and does not register `/auth/*`

  **And since this entry was written: the pass-through, the route table, and the
  principal assertion.** Those are the security core, and they are in Go. Eight
  properties, each a named test, each shown red by a mutation:

  1. The caller's credential never reaches an internal service — the inbound
     `Authorization` is never forwarded and neither is `Cookie`; gateway attaches
     the per-service `token` from the route table, or sends no `Authorization` at
     all when the entry has none.
  2. The path is **reconstructed**, not filtered. `path.Clean` is called nowhere:
     each segment is decoded, refused if it is `.`, `..`, empty or one containing a
     separator, and re-encoded with only its unreserved characters.
  3. Only `content-type` and `accept` cross outbound. The allowlist is asserted as
     a literal of exactly two names, in the response direction exactly one.
  4. `CheckRedirect` returns `ErrUseLastResponse` and every call carries a
     per-request deadline, so a followed redirect is not a way out of the route
     table and a hung upstream is a `503` rather than a hung gateway.
  5. `set-cookie` is dropped on the way back — session fixation, not tidiness.
  6. `cache-control: no-store` on every relayed response, overriding the service's
     own rather than forwarding it.
  7. `isRelayable(status)`: `status < 300 || (status >= 400 && status < 500)`.
  8. The route table is validated **before the process listens**, and every
     refusal names the rule that fired.

  And MD19's four: an assertion is **never** minted on a public route (refused at
  boot and again at the send site), is gateway's **own signature** and never the
  caller's token, is **bound to the upstream's origin** with a lifetime ceiling
  nobody may exceed, and carries **only the declared claims**.

  **What this does not make the Go service:** it does not verify tokens. The
  credential gate is a seam — `Options.Authenticate` is nil in every configuration
  this packet can build, because verification is a separate packet — and a gateway
  started from the environment therefore relays an anonymous request to a private
  route, which is exactly what `createApp({routes})` does when no `jwt` option was
  configured. The refusal, its status, its envelope and its position above the
  pass-through are already in place, so the packet that ports RS256 fills in one
  function and nothing else moves.

  `test/proxyMutations.sh` is the evidence: 27 mutations, each of which removes
  one property, runs that property's named test, and records that it went red —
  then restores the tree by the inverse substitution and re-runs to prove the green
  came back.

  The five operations it does not serve are unchanged: `GET /v1/me`
  and the four `/auth` routes answer the v0 `404`, for the reason below. What
  the Go service serves today is **two operations of seven plus the
  pass-through**: `GET /healthz`
  and `GET /readyz`, plus both error envelopes. The other five — `GET /v1/me` and
  the four `/auth` routes — are declared by the contract, need a subsystem this
  packet does not port, and answer the **v0 `404`**. A `501` would have been more
  truthful about the code and less true about the contract: `createApp({})` does
  not register `/v1/me` without a verifier and does not register `/auth/*`
  without an identity to ask, so the reference answers `404` too, and where the
  two implementations differ the TypeScript answer is the correct one.

  The ported pieces, each in the place the rule it serves already was:

  - **The error envelope**, from `src/problem.ts` into `internal/httpapi/problem.go`
    — core's RFC 9457 `problem+json` with the `code` and `trace_id` extensions, a
    fixed title per code, `errors[]` scoped to a `422`, `instance` as the path and
    never the query, and a `trace_id` equal to the `X-Trace-Id` header. An
    undeclared code is refused rather than rendered, where `src/problem.ts`
    rendered `title: undefined` into the JSON. Nothing writes a problem document
    yet, so it is reachable from the first Wave 3 handler and not before.
  - **Configuration arrives as an argument**, in the form Go needs a different
    mechanism for. `httpapi.New(Options)` takes its configuration;
    `httpapi.RuntimeOptions(Env)` is the only function in the module that reads
    one. Go's global is `os.Getenv`, which any package may call at any time, so
    the property is held by two checks that read the package's own sources: one
    file may call `os.Getenv` and one variable may be read.
  - **The contract is generated and the generator's output is committed**, with
    `bin/prime-go` regenerating and diffing it — because the Go router *is* that
    file, so a stale one does not fail to compile, it answers the old routes with
    the new contract's promises.
  - **`bin/prime-go`**, and `bin/prime` now runs it, so the declared gate covers
    both implementations rather than being two gates wearing one name.
  - **`Dockerfile.golang`** — distroless/static, at the repository root, and not
    named `*.go`, because `go build ./...` compiles every `.go` file in the tree.
    It is not named `Dockerfile` because that is the TypeScript image and this
    packet does not replace it; the rename lands with the deletion of `src/`.
  - **`internal/equivalence`** — the check that says the port is right rather
    than compiling. It stands the TypeScript reference up as a subprocess, drives
    the same requests at both, and compares status, `Content-Type`, the presence
    of the contract-declared headers and the body **byte for byte**: 24 cases × 3
    configurations = **72 comparisons, 0 differences**. The cases are derived from
    the generated registrations, so an operation added to the contract is compared
    the day it lands; what it does not cover — every error status but `404` — is
    asserted by a test rather than left for a reader to discover.

  `README.md` gains a *Go rewrite* section: the table of which operations are Go,
  which are still TypeScript, what the equivalence check covers, and what it does
  not.

### Fixed

- **Every problem document would have been served with the wrong media type.**
  `writeJSON` set `Content-Type: application/json` unconditionally, so
  `writeProblem` setting `application/problem+json` and then calling it produced
  the media type that says "this is not a problem document". Found by
  `TestAProblemIsTheDocumentedEnvelope`, which asserts the content type rather
  than decoding the body and stopping there — `AGENTS.md` asks for that on every
  handler and this is the case that needed it.

- **Every JSON body carried a trailing newline.** `json.Encoder.Encode` appends
  one to every value it writes, a convenience for a stream of values to a file,
  and Hono's `c.json()` does not — so 63 of the first 72 equivalence comparisons
  failed on one byte that no client would ever notice and every port would have
  shipped. `writeJSON` marshals with `json.Marshal` and writes the bytes.

- **`GET /v1/me` on the Go side is a 404 the reference agrees with**, rather than
  a 501. Recorded because the honest-looking answer was the wrong one, and because
  the next packet inherits the decision rather than re-deriving it.

- **`account_scope.yml` declares its one account-scoped route again.** `GET /v1/me`
  is the only route in `gateway` that can reach another account's data, and it was
  declared with no row at all: core's `scoping-bypassed` reads the `app.use` mounts
  above a row through `chain_gate` with a **three-line** window, and MD19's
  public-prefix exception had made the `/v1/*` mount's body four statements, so
  `jwt.requireJwt` fell to the fifth line and out of reach. One blank line inside
  that body is the whole of the fix, and it is argued at the mount because a
  security declaration that depends on a blank line is a fragility the next reader
  has to be told about.

  The row is now `accountScoped: true` with `accountFrom.via: requireJwt` at
  `src/middleware/jwt.ts:346`, **verified by the run** — `chain_gate` finds
  `requireJwt` at `src/index.ts:254` and `account-key-lost` does not fire — and
  `account-scope.nothing-scoped` is gone with it. This is the first packet in
  which this repository has had an account-scoped entry point that a machine could
  check.

  The Go implementation's registration of the same operation still has no row, and
  that is one honest `undeclared` rather than two. It is not a format limitation:
  two rows for one `(method, path)` do take two registrations. It is that neither
  alternative survives a run — a `false` row there cannot be refuted by any check
  (`handler_for` resolves `wrapper.X` to the generated wrapper and never reaches
  `internal/httpapi`), and a `true` row is a failure that cannot be cleared (chi
  mounts middleware with `r.Use(`, which `chain_gate` cannot match). Measured both
  sides in `REPORT-gateway-account-scope-ratchet-01.md` §3.

  `surface.minimum` stays **14**. It is not lowered to make a failure go away: it
  is why 14 registrations against 13 rows is a question somebody had to answer.

### Changed

- **`gate.yml` and `mise.toml`.** Four proofs (`go-vet`, `go-generated`,
  `go-equivalence`, and `ok` now bracketing three steps rather than two), a Go
  toolchain requirement, `miseTask: prime`, and `[tasks.prime]` — so `mise run
  prime` resolves here for the first time. The proof list is now at the schema's
  maximum of 8, which is recorded as a finding about the format.
- **`account_scope.yml`.** `internal/api/api.gen.go` joins `surface.sources` and
  `minimum` goes 7 → 14, which is only meaningful because
  `internal/api/stripbaseurl` removes the `options.BaseURL+` token from the
  generated registrations — without it the checker's own words are that the floor
  "is not being violated, it is unfalsifiable". `undeclared` goes 1 → 2: both
  implementations register `GET /v1/me` and a row cannot be scoped to a file, so
  the route is visibly uncovered rather than declared wrong. Recorded as a DECISION
  NEEDED in the file.
- **CI.** `setup-go` with `go-version-file: go.mod`, `git diff --exit-code` on
  `go.mod`/`go.sum`, and a step that reads the equivalence comparison count out of
  the run and fails under 72. `GATEWAY_EQUIVALENCE_REQUIRED=1` is set job-wide so
  the tier cannot skip. There is deliberately **no** `prime-go` job.
- **`pins.test.ts`** gained two cases and one flag. It drives `bin/prime` against a
  stand-in bun, which cannot run the equivalence reference, so it passes `--no-go`
  — and now asserts that the flag's skip banner appears and that an unknown
  argument is still refused.

- **A private upstream now learns who the caller is.** A `ROUTE_TABLE` entry that
  declares `principal` causes gateway to send that upstream a short-lived signed
  assertion of the verified caller, in a header of its own
  (`X-Cafaye-Principal`):

  ```sh
  ROUTE_TABLE='{"/v1/pantry/services":{"baseUrl":"http://pantry:8080",
                                       "principal":["sub","github_id"]}}'
  ```

  Before this, `proxy.ts` sent the per-upstream `token` and nothing else, and its
  own header said the cost out loud: *"an upstream cannot tell which caller sent a
  request."* That rule is unchanged and load-bearing — forwarding the caller's
  `Authorization` would make gateway a confused deputy — and it is precisely why a
  publisher write could not work: `pantry.current_publisher_id()` had nothing to
  compare. The caller was never missing. `src/index.ts` resolved it to a principal
  before the proxy ran; it was discarded at the boundary.

  **gateway's own signature, never the caller's token.** The caller's JWT was minted
  for a different audience and carries whatever the caller was given; forwarding
  it would make gateway a credential relay. So gateway signs its **own** statement with
  **its own** RS256 key — configured as `ASSERTION_SIGNING_KEY_FILE`, a path to a
  PKCS#8 PEM, and refused at startup if it is missing or malformed. It is a file
  path and not the PEM in a variable because an environment value appears in
  `docker inspect`, in `/proc/<pid>/environ` and in any crash dump. The existing
  JWKS machinery could not be reused for this: a JWKS is public keys by definition
  and cannot sign, and a key that can sign must not be one identity can mint
  everything with.

  **Four properties, each refused rather than defaulted, each with a mutation
  proof in `REPORT-mvp-guard-principal-01.md`:**

  1. **Never on a `public` entry** — that is what makes a route public. Refused at
     boot *and* refused again at the send site, and the send-site gate has its own
     test against a table `routeTable` would have refused, because a check no input
     can reach is not a check.
  2. **Not the caller's token, ever** — asserted byte for byte, and by the stronger
     reading that it does not verify against identity's key set at all.
  3. **Bound to the upstream and short-lived** — `aud` is that upstream's base URL
     origin, so a leaked assertion is worth nothing elsewhere; two minutes by
     default, and `ASSERTION_TTL_MS` is **refused above ten minutes**, because a
     lifetime nobody may exceed is the property and a default is only a default.
  4. **Minimal claims, declared per upstream** — exactly the names in `principal`,
     copied from the caller's token as identity signed them (`scope` stays a string;
     `github_id` crosses without gateway being taught its name). No wildcard. A name
     the token does not carry is **omitted**, so a publisher with no `github_id`
     reaches pantry as *no publisher record*. A name gateway owns — `iss`, `aud`,
     `exp`, `nbf`, `iat`, `jti` — is a refusal to boot.

  **An upstream that declared nothing gets no assertion at all.** Not an assertion
  with no claims: a token whose entire content is which gateway minted it. That is
  also what keeps the feature additive — with no signing key configured, gateway
  forwards exactly the headers it forwarded before, which is asserted rather than
  assumed.

  `kid` defaults to the RFC 7638 thumbprint of the public key, because two
  deployments both calling their key `gateway-1` is a key set in which an upstream
  silently verifies against the wrong one.

  **A defect found and fixed inside this packet, now a tripwire.** The first draft
  derived the published JWK with `exportJWK(privateKey)`. jose returns
  `kty, n, e, d, p, q, dp, dq, qi` for a private key — the whole private key, RSA
  primes included — and nothing about the result would have looked wrong, because
  RFC 7638 hashes only `e`, `kty` and `n` so the `kid` stayed correct and every
  signature still verified. `assertion.test.ts` now asserts the published JWK's
  field names **exactly**, which is the only shape that notices a library upgrade
  adding a fourth private parameter.

  **Still not built, and named rather than discovered:** no service reads the
  header yet, so an assertion configured today is minted and dropped; gateway does
  not publish its assertion key over HTTP, on purpose (it would be a new route on
  the public edge, a new operation in `openapi/v1.yaml`, six `account_scope.yml`
  anchors and a `surface.minimum` change with no standing to be made); and a
  leaked assertion is bounded but not revocable inside its window. The README's
  *Not built yet* carries all three.

- **A routed entry can declare itself public, and that is the only way to be
  let in without a credential.** A `ROUTE_TABLE` entry may carry `"public": true`,
  and that prefix is mounted **without** `jwt.requireJwt`:

  ```sh
  ROUTE_TABLE='{"/v1/catalog":{"baseUrl":"http://pantry:8080","public":true},
                "/v1/catalog/imports":{"baseUrl":"http://pantry:8080"}}'
  ```

  `GET /v1/catalog/items` now reaches `http://pantry:8080/items` with no
  `Authorization` header of any kind. Before it, **no** credential could reach
  any routed prefix: site's client claims gateway gates `/v1/*` on a `gateway-api`
  scope, `requireScope` is never called outside tests, `runtimeOptions` never sets
  `apiKeys`, gateway's key gate matches `/^apikey(?:\s|$)/i` while the SDK sends
  `Authorization: Bearer cafaye_…`, and `gateway-api` is not a scope identity has.
  Closing that the way the comment imagines is four repositories in sequence;
  this is one field, in a table a human already reads.

  **Per entry, default `false`, and no wildcard.** Every existing route behaves
  exactly as it did, which is what makes the field safe to add to a deployed
  gateway. Openness is decided by the **longest matching prefix** — the same rule
  the destination and the limiter already use — so a public read surface cannot
  hand its own write surface to the internet by sharing a name with it, and
  `/v1/me` and every unrouted `/v1/` path still answer an anonymous caller with
  `401`.

  **Rate limiting does not move.** A public route spends the `gateway-api` bucket
  like everything else under `/v1/`, so anonymous traffic stays bounded. The
  documented cost is that the bucket is keyed on the account, the key, or the
  client address, in that order — and an anonymous request has none of the first
  two, so **every anonymous visitor to a public prefix shares one budget**. A
  per-prefix allowance is named in the README's *Not built yet*, and this packet
  is what makes it urgent rather than tidy.

  **A `public` entry cannot carry a `token`, and that combination refuses to
  boot.** `public` is about the *caller* and `token` is gateway's own credential to
  the *service* — two questions, two answers — so an entry holding both is an
  operator who has not decided which they meant. Guessing would either hand an
  anonymous caller a credential-protected upstream or quietly answer `401` to a
  route the table calls open. The refusal names both ways out. `{"public":"true"}`
  is refused too: `ROUTE_TABLE` is JSON, and a string a reader takes for
  permission is the one value on this field that must never be coerced into it.

  `src/routes/publicRoute.test.ts` holds the five cases this has to answer —
  it serves, a non-public entry still `401`s, it is still throttled, it still
  refuses a nonsense value, and it leaks no upstream credential — with the
  mutation evidence in `REPORT-mvp-guard-public-route-01.md`.

- **Routing: a configured path prefix is forwarded to the service that owns it.**
  This is the packet `gateway`'s README has been promising since v0: a route table
  (`ROUTE_TABLE`) of prefix → `{baseUrl, token?}`, validated at startup, mounted
  as a pass-through on `/v1/*`. `GET /v1/pantry/items` reaches
  `http://pantry:8080/items`.

  **The credential rule is the content of it.** gateway attaches the credential; a
  caller's `Authorization` is never forwarded to a service, and neither is their
  `Cookie`. Forwarding it would make gateway a confused deputy — the caller
  authenticates to the edge and then chooses who they are behind it, and every
  property "gateway is the only door" rests on is gone. It is enforced by an
  allowlist of what crosses (`content-type`, `accept`, and the table's own
  token), because a deny list has to have thought of `Authorization`, `Cookie`,
  `X-Forwarded-For` and every header a future proxy invents. A table entry with
  no token is sent no `Authorization` at all, which is different from one gateway
  invented. `GET /auth/me` holds the same line for identity by taking the stored
  token.

  **Failures behind the edge are translated.** A 5xx, a 3xx and a dead socket
  become a `503` and one fixed sentence; the host, port, stack and `Location` go
  to the log, which records the target, the status and the shape of the body and
  never the body. A 2xx and a 4xx cross unchanged, because a 401 that became a
  200 reports a refusal as a success. A service also cannot write the browser's
  BFF session: `set-cookie` is not relayed, and that is session fixation arriving
  through the gateway rather than tidiness.

  **Every value in the table is a startup error**, for the reason
  `REDIS_URL=redis//redis` is: a prefix outside `/v1/`, a glob, a `.`/`..`
  segment, a base URL carrying a path or credentials, a token carrying a newline,
  and `{}` all refuse to boot. `/v1/me` is refused as a prefix because it is
  gateway's own route and an entry that can never fire is a claim rather than a
  configuration.

  The upstream path is **rebuilt** rather than forwarded — each segment decoded,
  refused and re-encoded — so a traversal is not filtered, it is not expressible.
  Routed traffic is authenticated and rate limited for free: both gates are above
  the mount. No retry, no discovery, no proxy library: `fetch` is the tool, and a
  retry would multiply load on a service that is already failing while the limiter
  counts one attempt.

  A **static table** is the design and not only the scope: `RouteTable` is a
  plain object, so the service registry that does not exist yet would *populate*
  it — a different `runtimeOptions`, nothing else changed.

- **`LICENSE`: gateway is MIT.** The repository shipped no licence file at all,
  which is not "unlicensed, therefore free" — it is **all rights reserved**,
  the default copyright position when a public repository grants nothing, so a
  stranger could not legally run, modify or resell any of it. `package.json`
  already declared `"license": "MIT"` and is now backed by the grant itself.

  MIT is the fleet decision and the reason is the service-registry model: gateway
  is the public edge every request enters through, so a consumer's first contact
  with the fleet's licensing is gateway's. MIT keeps adding gateway a decision about
  dependencies rather than about obligations; copyleft would attach one to every
  downstream consumer.

  The copyright line matches the three repositories that already shipped a
  licence (`cafaye-py`, `cafaye-rb`, `cafaye-ts`) exactly: `Copyright (c) 2026
  cafaye`. All fifteen now hold byte-identical licence text.

### Fixed

- **Two cross-tenant holes in the API-key store: a key id was a tenant.** D18
  measured gateway at zero negative tests, and the two that existed when this
  packet started were both in `memoryApiKeyStore` — the seam `TODO(guard-07)`
  moves to Redis, and the trait the future `/v1/api-keys` route will call.

  1. **`revoke(id)` took no account at all.** A key id is not a tenant: ids are
     displayed to a holder to tell two keys apart and handed to an operator for
     revocation, so any caller who learned one could name it. Any caller could
     therefore withdraw *any* account's credential — a cross-tenant **write**,
     and a denial of service wearing a support action's clothes. It now takes the
     account and refuses to touch a record that is not that account's:
     `revoke(accountId, id)`.
  2. **`list(accountId)` resolved ids through a map keyed by id alone.** Two
     accounts holding the same id made one account's listing return the *other*
     account's record — hash, prefix and scopes included, which is credential
     material — under its own query. Silent, because the record returned is real
     and well-formed. `byId` being keyed by id made a collision the only thing
     standing between a caller and another tenant's keys, and a UUID is not a
     guarantee, it is a probability. It now filters on the record's own
     `accountId` rather than trusting membership of an id set.

  Neither was reachable from a route today — gateway has no endpoint that issues or
  revokes a key, which the README says under "Not built yet". Both are load-bearing
  anyway, because the signature is what the next author and the next store
  implementation read. Both now refuse by **absence**: `revoke` on a foreign key
  is a no-op with no error and no return value, and leaves `revokedAt` at 0, so
  an attempt that missed its scoping leaves nothing an operator could mistake for
  a real withdrawal.

  **11 account-scoped entry points** enumerated and negatively tested, derived
  from the code rather than declared: `test/tenantEntryPoints.test.ts` reads the
  routes off Hono's own array, the account-scoped store methods off the interface
  declarations, and every `status: 403` in production source, and requires each
  to have a negative case named in `src/middleware/tenantIsolation.test.ts`. All
  four operation kinds are covered (read 5, list 1, update 3, delete 2) — delete
  because a service that scopes reads and forgets deletes is the common shape.

  **No `403` was found for a resource the caller cannot see, and none was
  added.** The only two `403`s gateway writes are a capability failure
  (`requireScope`: the token authenticated and lacks a scope) and an origin
  failure (`requireSameOrigin`) — both facts about the *caller*, which they
  already know, and neither naming a resource, so neither can confirm one exists.
  The distinction is asserted in both directions: a tenancy `403` would be a
  finding to fix, and a `404` for a capability would throw away a distinction the
  caller is entitled to.

  Two gateway-authored defects, both found by *running* the guards and written up
  in `REPORT-guard-11-isolation.md`: a listing fixture built through
  `createApiKeyAuth.issue` was a silent no-op (it is idempotent on the hash, so
  the id collision the case needed never happened, and the test passed with the
  filter deleted), and a Redis-key assertion that recomputed `bucket()`'s digest
  in the test passed with the digest deleted from `rateLimit.ts` — a copy of the
  production logic is not a check on it. Both now observe the real thing: the
  store, and the key `eval` was actually handed.

  Five divergences were planted and reverted, each caught by the named test; the
  transcript is in the report.

### Changed

- **`ApiKeyStore.revoke` takes an account.** `(id: string)` → `(accountId: string, id: string)`.
  A trait change rather than an internal edit, and the seven call sites in the
  suite were updated with it. A store implementation written from the old
  signature is a cross-tenant write waiting for a route.

- **`core: ^0.1.0` → `^0.2.0`. The declaration was the stale half, not the code.**
  gateway's content was already 0.2-shaped; the constraint was a number nobody
  re-read. `core` publishes `VERSION` = `0.2.0` (tag `v0.2.0`), and its
  `core.constraint-unmet` rule resolves a service's declared `core:` against it —
  so gateway failed CI **on its own declaration**, and the failure named the right
  file. Measured before and after, against core's contract checker:

  ```
  before   ^0.1.0  exit=1  FAIL core.constraint-unmet
  after    ^0.2.0  exit=0  OK, 1 warning
  ```

  This is the check `0.2.0`'s own changelog promised and could not perform. The
  brief's second claim — that gateway publishes no events under core's catalog
  names — **did not reproduce and is not a defect**: gateway has no event surface
  at all. `consumes: []` is accurate, there is no `exposes.events`, and no bus,
  outbox or publisher anywhere in `src/`. The 0.2 grammar and catalog accept an
  empty event surface, which is what a gateway that answers requests and
  subscribes to nothing should look like. Verified by reading the source, not by
  inferring it from the manifest.

### Fixed

- **`bin/prime` accepts a bun that is present and wrong.** The gate's only
  toolchain precondition was `command -v bun`, so a bun from a system install, a
  global upgrade or a stale CI image — anything ahead of mise's shims on `PATH` —
  ran the entire gate silently. The failure it produced was a red herring:
  `cannot find module 'hono'`, which names a *package*, points the reader at
  `package.json` and `bun.lock`, and says nothing about the runtime that caused
  it. This is the cafaye-rb lesson, reproduced here on bun: that gate failed on a
  Ruby that was on `PATH` and was not the one mise installed.
  - The gate now **names the pin and the version it found**, and exits **127** —
    the code it already used for an absent toolchain, because a wrong runtime is
    not a different kind of problem from a missing one. The check runs *before*
    the install, so nothing is spent before the refusal.
  - **The pin is read, not written.** `bin/prime` takes it from `package.json`'s
    `packageManager`, the field bun itself honours as an exact version, so there
    is no copy of the number in the script to drift. `pins.test.ts` already holds
    that field, `mise.toml`, the Dockerfile and compose to one number; a sixth
    copy here would be the only one nothing checks.
  - A pin that **cannot be read** is also a loud 127, not a skipped check. A gate
    that cannot find its own precondition cannot be debugged from its own output.
  - **Both directions are tested**, in `pins.test.ts`, against a stand-in bun
    first on `PATH` rather than asserted as text: a wrong version must exit 127
    naming both numbers, must **not** print `cannot find module`, and must not
    have printed an install banner; the pinned version must be admitted and reach
    `prime ok (bun 1.3.12)`. A check that only ever refuses is indistinguishable
    from a script that is simply broken.
  - The closing banner reports the version the check **admitted**, not a second
    reading of `--version` at the end of the run — a banner that re-reads the
    runtime can disagree with the check that let the run start.
  - **`Dockerfile` / `.dockerignore` / `test/dockerStage.test.ts` follow, in the
    same commit.** The suite now *executes* `bin/prime`, so the image needs it:
    `COPY bin ./bin`, `!bin` in `.dockerignore` (a directory needs the negation
    too, or the context drops everything under it), and `bin/prime` added to
    `SUITE_INPUTS`. Verified in the built image — both new tests run there, and
    the CI image-vs-repository diff still reports 19 test files in agreement. A
    check that runs on the host and not in the image is a check whose absence
    nobody notices, which is the exact defect `pins.test.ts` was written for.

### Added

- **`gate.yml` — the gate is now declared rather than discovered.** `bin/prime`
  exists and CI runs it, so the gate was never *missing*; what was missing was
  any statement of what it is worth. A developer here could run `bin/prime`,
  see a green result, and learn nothing about whether the suite could detect
  anything — replacing `bin/prime` with a script whose whole body is `exit 0`
  would have left this repository green. The declaration states the command
  (`bin/prime`), the entrypoint, two numeric floors, and five lines the gate's
  own output must contain. Written against `cafaye/core`'s
  `schemas/gate.schema.json` and checked by `harness/gate_check.py`, which now
  reports **0 failures, 2 warnings** here — both the expected
  `gate.requirement-unproven` for a bare command on PATH, which is the
  tri-state working and never moves the exit code.
  - **Two floors, not one, and the reason was measured.** `pass` is floored at
    **423** against a measured 428 — the house margin muse and courier use, so
    adding a test does not force a same-commit bump. `Ran … across N files` is
    floored at **19** exactly, with no margin, because deleting
    `test/noSkips.test.ts` took the suite from 428 to 423: the `pass` floor
    stayed **green** through a deleted test file and only the file-count floor
    caught it. The two are not redundant, which is not something a single floor
    could have told us.
  - **The declaration is red-proved four ways**, every one exiting 1: the
    deleted test file (`gate.floor` on `files`); a deleted `typecheck` script
    (`gate.proof-missing` on `typecheck`, and it was the *only* failure);
    `bin/prime` replaced by `exit 0` (all five proofs red at once); and the
    `pass` floor raised one above the measurement (`gate.floor` on `pass`).
    No assertion was weakened, no sleep added, no retry count raised.
  - **A silent typecheck skip is now a failure.** `bin/prime` probes for a
    `typecheck` script and, finding none, prints a line to stderr and
    continues to the suite — a green gate over a repository that had stopped
    type-checking, with the only evidence on a stream a summary scrolls past.
    The `typecheck` proof turns that into `gate.proof-missing`.

### Known

- **`mise run prime` does not resolve in this repository, and `gate.yml` does
  not pretend otherwise.** `mise.toml` carries `[tools]` and `[env]` and no
  `[tasks]` table, and `mise tasks` prints nothing. Six of the thirteen services
  declare `gate.miseTask: prime`; gateway's declaration names no task at all,
  because naming a task this repository does not have is `gate.task-missing` —
  a failure over a repository that is fine. `gate.command` names `bin/prime`,
  which is what AGENTS.md already tells a developer to run and what the `prime`
  CI job runs verbatim. Recorded rather than fixed: adding a `[tasks.prime]` is
  a change to how the repository is driven, not a declaration of what it
  already is.

### Fixed

- **A burst of forged tokens naming an unknown `kid` bought one JWKS fetch each,
  aimed at identity.** The refresh budget was a flag on the cached key set, set
  when the fetch *completed*. Every request already in flight when a refresh
  began therefore read the flag as unset and started a refresh of its own, so
  twenty-five simultaneous requests produced twenty-five fetches where the rule
  says one. Pre-auth, anonymous, and free to send: it needed no valid token,
  only a token-shaped string naming a key identity does not publish. The budget
  is now a cache-window number claimed **before** the await, so the burst gets
  one fetch and the rest are refused off the cached set with no network call. A
  refresh that *fails* spends the budget too — otherwise an unreachable identity
  is an unlimited fetch allowance for anyone naming a `kid`.
- **`X-Forwarded-For` accepted strings that are not addresses as bucket
  identities.** The filter was `[0-9a-f:.%]+`, which answers "is every character
  safe to write into a Redis key" rather than "is this an address". `deadbeef`,
  `cafe`, `...` and `999.1.1.1` all passed and each became a bucket of its own,
  so a caller able to put an entry in the trusted position minted a fresh
  allowance per request by varying a string that was never an address — the
  limiter was decorative in exactly the deployment that configures it. `clientIp`
  now parses with `isIP` from `node:net` (a runtime builtin, no new dependency),
  which also settles the `%zone` suffix the old charset had to tolerate. Real
  addresses in every shape a proxy emits are still read, and `::1` is still an
  address: a filter that refuses everything is the same defect pointing the other
  way.
- **An identity 5xx was dropped with no log line at all.** `call()` logs when
  the *transport* fails; an identity that is up and returning 500 — a broken
  deploy, an OOM, a panic — reached `unusable()` silently. Every login in a
  deployment failed with one status and nothing was recorded for an operator to
  correlate, which is a silent outage whose only signal is the browsers of its
  users. `unusable()` now records the target URL and the status. **Never the
  body**: a dependency's error page is exactly where a credential turns up, so
  the line records the shape of the answer and not its contents.

### Added

- **`src/edge.test.ts` — the public edge under attack.** Fifteen negative claims
  with the mechanism that makes each one true: no client-controlled outbound
  fetch (a body carrying `169.254.169.254` reaches identity as data, never as a
  target; no request header moves the target; a redirect from identity is not
  followed), path handling (thirteen spellings of `/v1/me` all meet the auth
  gate; a traversal out of `/v1` mints no session), header and log safety (CRLF
  in a path, CRLF in `X-Forwarded-For`, a policy name carrying a second
  structured-field item, an upstream error body), and the probe exemptions being
  exact paths rather than prefixes. No network: identity is an injected `fetch`
  and every key is generated in-process.
- **`test/noSkips.test.ts` — the suite cannot skip itself.** `bun test` exits 0
  on a run where every test was skipped, which is how an environment-gated tier
  gets added and then quietly never runs again. The Redis tier already carries
  two mechanisms against that (`GATEWAY_REDIS_REQUIRED=true` and the `redis` job's
  `0 pass` check) and both protect **one file**. This reads the suite's own source
  and fails on any `skip`, `skipIf`, `todo` or `only` outside a one-entry
  allowlist, naming the file in the failure, and separately asserts that the
  Redis tier still carries the `GATEWAY_REDIS_REQUIRED` guard. Its detector is
  assembled from arrays at runtime rather than written as a regex literal,
  because a literal matching `\.\s*(skip|skipIf)` matches its own source.

- **The README's stated reason the live Redis tier cannot run in the image was
  wrong, and a reader would have been misled by it.** It claimed "buildkit refuses
  `--network=host`". On Docker 29.4.0 the flag is **accepted** — and a `RUN` under
  it still cannot reach a server on the host's network, so the conclusion held
  while the mechanism did not. That is the worse combination: someone trying to
  close the gap would find the flag accepted, see a build that looked fine, and
  conclude the tier was easy to enable. Now states what was measured — the flag is
  accepted and buys nothing, and the real obstacles are the absent sidecar
  mechanism and the 30 MB of stage to install a server the `redis` job already
  runs.
- **`docker build --target test` now runs the same tests a host run does.** It ran
  **392 tests across 15 files** where a host run ran **399 across 16**. The seven
  missing were `pins.test.ts`, which sits at the repository root and which the test
  stage's `COPY` list — `src`, `test`, `openapi` — never named. So the image never
  executed the test that asserts the Bun pin in `package.json`, `mise.toml`, the
  Dockerfile and compose all agree: the check that would have noticed the image
  disagreeing with the repository was the one test the image did not run, and the
  build was green throughout. A test file the image does not have does not fail, it
  is not executed, so nothing in the build output said so.
  - **`test/dockerStage.test.ts` holds the `COPY` list to the repository.** It
    walks the tree for `*.test.ts` and fails when the test stage's copy chain does
    not name one, so adding a test file now fails `bin/prime` until the list names
    it. It runs wherever the suite runs — the laptop, kit's workflow, the image —
    because a check kept outside the suite is a check somebody has to remember.
  - **The `image` CI job diffs the image's test files against `find`.** The test
    above reads the Dockerfile and is therefore blind to `.dockerignore`: a
    `COPY src ./src` with an excluded subdirectory copies the rest and the build
    stays green, which was verified against buildkit rather than assumed. The suite
    emits every test file it discovered and CI compares the sets, so the check that
    reads the *built image* covers the half the Dockerfile reader cannot see.
  - **The comparison is over test files, not test counts**, on purpose: the live
    Redis tier skips in-image by design, so the pass count legitimately differs from
    a host run with Redis, and the file count cannot.
  - **The list stayed explicit rather than becoming `COPY . .`.** A whole-context
    copy is always a superset, which makes the tripwire vacuous — it would pass
    without saying anything — and it puts the doubles in `test/` one careless edit
    from the runtime stage. A new assertion holds the runtime stage to copying no
    test tree and no whole context.
  - `.dockerignore` also excluded `.gitignore`, `docker-compose.yml` and
    `Dockerfile`, so the `COPY` list could not name the three files `pins.test.ts`
    reads. The symptom was a hard `"/x": not found` at build time rather than a
    silent skip, but a list naming a path the build context does not contain is
    still a wrong list, and both files now carry the fix.
  - Both breaks were introduced on purpose and observed going red: a root-level
    test file the list omits, and a directory `.dockerignore` drops. In both cases
    `docker build --target test` stayed **green** at 417 across 17 and the new
    check reported the missing file.
- **One Redis error reply no longer wedges the connection for the life of the
  process.** `connectRedis`'s reader caught every `parseReply` failure, consumed
  no bytes and resolved no waiter, so an `-ERR` was re-parsed on every later chunk
  and every later command on that connection timed out. Because `lazyRedis` caches
  a connection and a counter store that cannot answer fails **open**, a gateway
  that saw one `-ERR` applied no rate limit at all until it restarted — with
  `/readyz` reporting `redis: unavailable` and nothing in the log saying why. An
  error reply is part of RESP, not a desync: Redis sends one deliberately and
  answers the next command normally, so `RedisReplyError` now carries the bytes it
  used and the reader consumes them and fails exactly one command. `parseReply`'s
  contract is unchanged — still an `Error`, still throws. Found by executing the
  GCRA script against a real server, which nothing had done before.

### Added

- **`openapi/v1.yaml`, and a test that holds it to the router in both
  directions.** gateway was the only service in the fleet with no OpenAPI document,
  so it was the one surface a generated client could not describe. The document is
  3.1.0 at `info.version: 1.0.0` — a new document, so there is no compatibility
  promise to keep — and it covers all seven routes `createApp` registers: the two
  probes, `GET /v1/me`, and the four `/auth` browser operations.
  - **The refusals are documented, not just the successes.** Every non-2xx
    response is `application/problem+json` and the shape is declared **once**, as
    `components.schemas.Problem`, with every error response referencing it — a
    document that only describes the happy path is the usual way an OpenAPI file
    becomes a lie, and refusing requests is most of what this service does. The
    `429` carries the whole rate-limit family: `RateLimit-Policy`, `RateLimit`,
    the un-prefixed trio, the `X-RateLimit-*` trio and `Retry-After`. The family is
    on the success responses too, because a client that renders a quota meter
    reads it from a `200`.
  - **The header says what the document leaves out, and how.** `ALL /v1/*` and
    `ALL /*` are `app.use(…)` mounts, not routes: Hono records every mount with the
    method `ALL`, so they are excluded as **exact method+path pairs** and never as
    a `/v1/` prefix. A route added under `/v1/` next year is a `GET` and is not
    covered by that carve-out; `GET /v1/me` is under that prefix and is in the
    document, which is the standing proof. A test asserts exactly that, and the
    header and the test name the same normalised keys, so the two cannot drift.
  - **Both directions were proved red.** A planted `GET /v1/api-keys` fails
    `documentedNotServed` with the file and line to fix; deleting `GET /v1/me`
    fails `unexplained`. Both were reverted.
  - **Seven departures from `core/docs/openapi-conventions.md` are recorded in the
    document's header as open decisions**, not resolved locally: `exposes` is
    still absent from `cafaye.yml` even though the document now exists; the
    browser surface and the probes are not under `/v1`; an API key is not a bearer
    JWT; the browser surface has a same-origin gate and no CSRF token; `404` and
    `500` are still the v0 `{error, message}` shape and gateway therefore produces
    no `not_found` or `internal` problem code; `/readyz`'s `503` is
    `application/json` (the conflict `identity` also records, so the ruling wants
    to be fleet-wide); and `Idempotency-Key` is not honoured on
    `POST /auth/register`. The two already open in `cafaye.yml` — RS256 only, the
    `scope` claim, the default issuer, and the three extra error codes — are
    referenced rather than restated.
- **`RATE_LIMIT_HEADERS` is exported from `middleware/rateLimit.ts`**, and
  `rateLimit.test.ts` asserts the list and what `announce` actually sets are the
  same set. The document has to name all eight fields, and a list written out in a
  YAML file is a list that can only fail for a name somebody remembered. A header
  added to the middleware and not to the document now fails the gate instead of
  reaching a client undocumented.
- **`PROBE_PATHS` is exported from `index.ts`.** The document declares a `429` on
  every operation *except* the two the limiter spares, and that exemption is a
  claim about this set rather than about two paths somebody typed into a test.
- **The Dockerfile's test stage copies `openapi/`.** Without it the tripwire would
  not run in the image that ships, and the suite would be green having checked the
  document in no tree at all.

- **CI, calling kit's reusable workflow.**
  `.github/workflows/ci.yml` calls
  `cafaye/kit/.github/workflows/ci.reusable.yml@master` with `language: bun`, and
  adds four jobs kit cannot own: `prime` (runs `bin/prime` itself and guards
  `bun.lock`), `redis` (a real `redis:7.4.1-alpine` for the live tier), `manifest`
  (validates `cafaye.yml` against core's fetched schema) and `image` (hadolint,
  `docker build --target test`, `docker compose build`).
- **The GCRA Lua is executed, in CI.** `rateLimitRedisLive.test.ts` runs the real
  script against a real `redis-server`; `bin/prime` still needs no server. The
  tier is gated on `GATEWAY_REDIS_URL`, and `GATEWAY_REDIS_REQUIRED=true` plus a
  summary check turn a skip into a failure — `bun test` exits 0 on a fully skipped
  file, so a green run is not by itself evidence the tier ran. It found the
  connection wedge above, and a difference the transcription had hidden: Redis
  returns a Lua number truncated toward zero, so `resetAt` and `retryAt` come back
  whole while the in-memory store carries fractions.
- **`packageManager: "bun@1.3.12"`**, and `pins.test.ts` asserting that the pin
  agrees across `package.json`, `mise.toml`, `Dockerfile`, `docker-compose.yml`
  and the workflow. `engines.bun` stays a floor rather than a pin. The pin existed
  only in `mise.toml`, which a contributor without mise never reads, and the
  comment above it claimed an agreement nothing checked. `pins.test.ts` also caught
  `bun.lock` recording the workspace name as `guard-worker-guard-01` — a worktree
  name from packet guard-01, committed because a lockfile is not a file anyone
  opens.
- **`bin/prime` is kit's bun template**: frozen install and typecheck before test,
  so the local gate and CI's are the same bytes rather than two that can disagree.

- **Sliding-window rate limiting.** GCRA in one atomic step, replacing the
  fixed-window counter. A fixed window hands out `limit` per aligned bucket, so
  `limit` requests one millisecond before the edge plus `limit` one millisecond
  after it is 2× the allowance inside two milliseconds; the boundary case is
  written out and asserted in both directions.
- **`RateLimitStore`, with two implementations.** `memoryRateLimitStore` is
  per-process and says so in its own source, in the README and in the compose
  notes — N replicas of it is an N× limit. `redisRateLimitStore` counts in
  Redis with one self-contained Lua script (a read-then-write pair is what admits
  N× the limit under a burst), keeps its keys under `gateway:rl:<prefix>:` and
  expires its own. `REDIS_URL` selects it; the URL is validated at startup and the
  connection opens on first use, so a typo refuses to boot and an outage does not.
  `rateLimitParity.test.ts` runs one behaviour table through both and requires
  byte-identical transcripts, so the trait is proven rather than asserted. No test
  in the default gate touches Redis or the network: the Redis path is driven by a
  transcription of the script, and the RESP2 encoder and parser are tested as pure
  functions. The script itself is executed against a real server by
  `rateLimitRedisLive.test.ts`, in CI only.
- **Key derivation in one order: account → API key → address.**
  `src/middleware/limitKey.ts` builds the bucket key from the *verified* principal,
  the id of a key the store looked up, and the client address, and never from a
  header value or an unverified token. Each tier is prefixed so an account id that
  equals an address cannot share a bucket, and the no-identity case is a named
  `ip:unknown` rather than a blank key. The account beats the key, so holding both
  is not a way to double one's rate.
- **`X-Forwarded-For` is read from the right, and only as far as the operator
  says.** `TRUSTED_PROXIES` is how many proxies append to the chain, and the
  address is taken at that hop counting from the end; with the default of `0` the
  header is not read at all and the socket peer is used. A chain shorter than the
  trusted run falls back to the peer, because a bucket that groups too many callers
  is the direction to be wrong in. This replaces keying on the first
  `X-Forwarded-For` hop, which the caller chose.
- **`RateLimit-*` response headers**, on allowed and refused requests alike:
  `RateLimit-Policy` and `RateLimit` as RFC 9651 structured fields per
  `draft-ietf-httpapi-ratelimit-headers-11` (§3 and §4 — there is no RFC for these
  fields yet, and the brief's RFC 9331 is L4S), the `RateLimit-Limit` /
  `-Remaining` / `-Reset` trio the same draft dropped in -08 and deployed clients
  still parse, and this repository's own `X-RateLimit-*`, whose `-Reset` is an
  absolute epoch instant. `t` is the effective window per §4.1.2, so it counts
  down rather than restating `w`. `Retry-After` on a 429 is the instant that
  request would next be admitted, never zero.
- **A per-route limit table** (`src/middleware/limits.ts`) with the policy name as
  the unit of accounting: it is half the counter key, so `/auth/login` (10/min),
  `/auth/register` (5/min) and the general API surface (600/min) are separate
  budgets and a caller brute-forcing logins cannot lock out every legitimate
  sign-up from that address. Longest matching prefix wins, on a path-segment
  boundary. `RATE_LIMIT_REQUESTS` and `RATE_LIMIT_WINDOW_MS` override the general
  allowance.
- **API keys** (`src/middleware/apiKey.ts`): `Authorization: ApiKey <secret>`,
  accepted on any route a token is. Only the SHA-256 is stored, only twelve
  characters are ever shown, the secret exists exactly once at issue and cannot be
  printed again, and `find` is the only lookup so a revoked key is dead on the very
  next request rather than being returned with a flag. A key sets the same
  `principal` a token does, so there is one scope gate in the repository rather
  than two that could disagree. `TODO(guard-07)`: the store is per process.
- **The counter store is a readiness dependency.** `REDIS_URL` registers
  `{"deps":{"redis":…}}` from the same connection the store uses, so `/readyz`
  cannot report a store the limiter is not counting in.
- App factory `createApp`, exported for tests and the only import the suite
  makes. Importing the module never opens a socket; the `Bun.serve` bootstrap
  is behind `import.meta.main`.
- `GET /healthz` — unconditional `200 {"status":"ok"}`. Liveness never touches a
  dependency.
- `GET /readyz` — `200 {"deps":{…}}`, or `503` naming the dependencies that are
  not ok. A probe that throws, rejects or answers with anything but `"ok"` counts
  as `unavailable`.
- JSON `404` for unknown routes and a flat JSON `500` for unhandled handler
  errors, with the detail logged rather than returned.
- Rate limiting skips both probe endpoints.
- `Dockerfile` (oven/bun slim, multi-stage, tests gate the image),
  `docker-compose.yml` (the service only), `bin/prime`, `mise.toml`, `AGENTS.md`
  and this changelog.
- `cafaye.yml` against `core`'s frozen manifest schema, with a
  `DECISION NEEDED` for the `exposes` block that needs a manager-owned OpenAPI
  document.
- `jose` as a dependency, and real JWT verification in place of the presence
  check. RS256 only, verified against identity's JWKS at
  `{IDENTITY_ISSUER}/.well-known/jwks.json`, with `iss`, `aud`, `exp`, `nbf` and
  a non-empty `sub` checked. The algorithm is gateway's decision, pinned in code and
  read from the header before any key is fetched, so `alg: none` and HS256 are
  refused without a network call.
- `createJwtVerifier` — `requireJwt` mounts on a path and puts
  `{ sub, scope, claims }` on the context; `requireScope("billing.read")` answers
  `403` for a verified caller without the scope, and `401` when it is mounted
  with no auth in front of it.
- A JWKS cache in the verifier: in memory, `300000` ms by default and
  configurable, with a fetch timeout so a hanging identity cannot hang the edge.
  An unknown `kid` buys exactly one forced refresh per cache window and is then
  refused, which is enough to follow a rotation and not enough to let a caller
  aim requests at identity. A failed fetch leaves the last good key set in place.
- `src/problem.ts` — core's error envelope (RFC 9457 `problem+json` with cafaye's
  extensions) and the single path every rejection takes. `401`, `403` and `503`
  carry `type`, `title`, `status`, `detail`, `instance`, `code`, and a `trace_id`
  that matches the `X-Trace-Id` response header. The underlying failure goes to
  the log, never to the caller.
- `GET /v1/me` — the demo route that proves the chain is wired: `200` echoing the
  verified principal, mounted behind `requireJwt` on `/v1/*`, rate limited, and
  absent entirely when no issuer is configured.
- `runtimeOptions` — the only place the environment is read: `IDENTITY_ISSUER`
  (issuer-only base URL, default `https://identity.localhost`),
  `IDENTITY_JWKS_URL`, `IDENTITY_JWKS_TTL_MS` and `GATEWAY_CLIENT_ID`. A malformed
  value is a startup error; an empty one is unset.
- `test/jwksServer.ts` — a stand-in identity serving a real JWKS from real RSA
  keys, so the suite tests verification rather than a mock of it. The Dockerfile
  copies it into the test stage only.
- The browser surface: `POST /auth/register`, `POST /auth/login`,
  `POST /auth/logout` and `GET /auth/me` in `src/bff/auth.ts`. gateway proxies each
  to identity's `/v1/users`, `/v1/session` and `/v1/me` over an injectable
  `fetch`, and maps the answers onto core's `problem+json` envelope. No new
  dependency: the cookie attributes come from `hono/cookie`.
- `__Host-bff-session`, `Secure` / `HttpOnly` / `SameSite=Lax` / `Path=/`, set on
  login and cleared on logout with every attribute repeated. A login answers
  `{expires_at}` and no token: the page gets a session id, and identity's token
  stays in gateway.
- `SessionStore` — `get` / `put` / `delete`, with expiry as the store's business —
  and `memorySessionStore`, a `Map` for v0 that drops a record on the read that
  finds it expired and sweeps expired ones once the map passes its bound. A
  session id is `crypto.randomUUID()`, minted on every login and never accepted
  from a caller. `TODO(guard-07)`: Redis.
- A same-origin gate on the three mutating `/auth` routes, mounted per route
  rather than on the prefix. `Sec-Fetch-Site: same-origin`, or an `Origin` whose
  host is the one the request was addressed to, or `403` — including
  `same-site`, `none`, `Origin: null` and a request stating neither. Both
  headers have to agree when both are present. `GET /auth/me` is not gated.
- `identityProbe` — identity's `/healthz`, bounded, never throwing — registered
  by `runtimeOptions`, so a configured `/readyz` names identity instead of
  reporting ready for an auth surface that cannot work. `Probe` and
  `ProbeStatus` moved to `src/probe.ts` so a module can offer a probe without
  importing the app factory that consumes it; `src/index.ts` re-exports both.
- `IDENTITY_URL` (default `http://localhost:8080`) — where the `/auth` calls are
  sent, as against `IDENTITY_ISSUER`, which is where tokens are verified. http(s)
  and no path; anything else is a startup error.
- `test/fakeIdentity.ts` — a programmable stand-in for identity's auth API,
  recording every call including the `Authorization` header, which is what lets
  the suite assert that the browser's cookie is never identity's token and that
  logout revokes the token the store is holding. Test stage only.

### Changed

- The `429` is core's `problem+json` envelope with `code: "rate_limited"`, like
  every other rejection, instead of `{"error":"rate_limited","message":…}`. The
  `X-RateLimit-Reset` absolute-instant convention is kept, and `X-RateLimit-Limit`
  and `X-RateLimit-Remaining` are sent beside it.
- A counter store that cannot answer now fails **open**, with the cost named in
  the source and the README: for as long as it is unreachable gateway applies no
  limit. Failing closed would hand a Redis outage to every caller as a `429`. The
  `RateLimit-*` headers are left off rather than guessed at, and the store is a
  readiness probe.
- The limiter is mounted **after** the auth gates, because the bucket is keyed on
  the strongest identity the request has and that is only known once something has
  proved who is asking. The cost is stated rather than hidden: a request the auth
  gate refuses is never counted, because an unverified token must not become a
  rate-limit key.
- `AppOptions.rateLimit` is now `{limits, store, trustedProxies, now}` rather than
  `{limit, windowMs}`, so a deployment can ship a per-route table and a shared
  store. An app built with no `rateLimit` option still runs unlimited, which is the
  honest v0 default; `rateLimit: {}` takes the shipped table.
- `Principal` gained an optional `accountId`, read once from the verified
  `account_id` claim. A token with no such claim is its own account and the
  rate-limit key falls back to `sub`.

- `requireJwt` is no longer a stub. Anything downstream of it is authenticated:
  the README's "no request may be treated as authenticated" line is gone with it.
- An identity outage is now `503 unavailable` rather than `401`: a caller whose
  token was fine must not be told to fix their credential because a dependency
  is down.
- `createApp` returns `Hono<AuthEnv>` so handlers get a typed principal, and
  takes optional `jwt` and `bff` options. An app built without them serves probes
  only: no issuer means nothing to verify a token against, and no identity means
  no session to mint.
- `problem` gained the codes the browser surface has to produce — `invalid_json`
  (400), `conflict` (409), `payload_too_large` (413), `validation_failed` (422)
  and `account_locked` (423) — and an optional `errors[]`, rendered on a 422 and
  nowhere else as core scopes it. `invalid_json`, `payload_too_large` and
  `account_locked` are identity's slugs for failures core does not name;
  DECISION NEEDED in `cafaye.yml`.
- A request body is read through a 4 KiB cap instead of `request.text()`, so an
  anonymous caller cannot choose how much of the edge one request buffers. A
  `Content-Length` over the cap is refused without a read; a body that only
  becomes too large is refused at the chunk that crosses it and the stream is
  cancelled.

### Known gaps

- `404` and `500` still answer `{ "error": …, "message": … }` with
  `application/json`, while everything else uses core's `problem+json`. Two shapes
  in one gateway is a wart, left deliberately: the envelope's `trace_id` has to
  match an `X-Trace-Id` that exists on every response, which is a trace-propagation
  middleware that does not exist yet. The `429` moved onto the envelope with the
  limiter that writes it. DECISION NEEDED in the README.
- The in-memory rate-limit store is single-instance only: a caller gets its
  allowance from *each* replica and counts reset on restart. `REDIS_URL` fixes it
  and the store is behind a trait, but the GCRA Lua has never been executed against
  a real `redis-server` — the client half is tested, the script body is reviewed.
  `TODO(guard-06)`.
- API keys are issued, hashed, scoped and revocable, and a key authenticates on
  any route a token does, but nothing hands one out: minting a credential is a
  control-plane action that wants an authenticated account and an audit trail. The
  store is also per process, so a key issued on one replica is invisible on the
  next. `TODO(guard-07)`.
- The address key is only as good as `TRUSTED_PROXIES`, and at the default of `0`
  every caller behind one NAT shares a bucket. A proxy that overwrites
  `X-Forwarded-For` is what makes it a real client key.
- RS256 only, per this packet's contract, where core's conventions also allow
  ES256; and the space-separated `scope` claim, where core's conventions call it
  `scopes`. DECISION NEEDED in `cafaye.yml`.
- No token lifetime ceiling. `exp` and `nbf` are checked; how long a token may
  live is not.
- Sessions are per process and per restart: a browser signed in on a replica that
  goes away is signed out, and a deploy signs everybody out. The `SessionStore`
  interface is the seam; Redis is `TODO(guard-07)`.
- `GET /auth/me` clears the session cookie when the record is gone or identity
  has withdrawn the session, so a browser stops presenting a cookie that can
  never work again.
- The origin gate refuses a mutating `/auth` request that states no origin at
  all, which includes every non-browser client until it sets `Origin`. That is the
  strict reading, and it is deliberate: the gate refuses what it cannot prove.
  A double-submit CSRF token, for clients that cannot set headers, is a later
  packet alongside the OIDC redirects.
- `/readyz` on a configured deployment now depends on identity. A browser surface
  that cannot mint a session is a gateway that should not be taking traffic, and
  liveness — which is what a restart acts on — is untouched.

[Unreleased]: https://github.com/cafaye/gateway/compare/v0.0.0...HEAD
[v0.0.0]: https://github.com/cafaye/gateway/releases/tag/v0.0.0
