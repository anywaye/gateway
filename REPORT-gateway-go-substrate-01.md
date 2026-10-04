# REPORT — gateway-go-substrate-01

**Branch:** `worker/gateway-go-substrate-01`
**Base:** `15cf59b` (merge of `worker/gateway-rename-guard-01`)
**Six commits.** Not pushed, not merged, not tagged.

---

## What the Go service can serve today

**Two operations of the seven `openapi/v1.yaml` declares, plus both error
envelopes.** `GET /healthz` answers `200 {"status":"ok"}`. `GET /readyz` answers
`200 {"deps":{}}` when no probes are registered and `503` with one named
dependency in `unavailable` when any is. `HEAD` works on both. An unknown path, a
wrong method, and the five operations whose subsystems are Wave 3 all answer the
**v0 `404`** — `{"error":"not_found","message":"no such route"}` with
`application/json`.

The other five — `GET /v1/me` and the four `/auth` routes — are declared by the
contract, need a subsystem this packet does not port, and decline. **A `501`
would have been more truthful about this codebase and less true about the
contract**, which is why they do not: `createApp({})` does not register `/v1/me`
without a verifier and does not register `/auth/*` without an identity to ask, so
the reference answers `404` there too, and the packet rules that the TypeScript
answer is the correct one.

Measured, from the real distroless image rather than a unit test:

```
docker build -f Dockerfile.golang -t cafaye/gateway-go .
docker run --rm -d -p 18099:18099 -e PORT=18099 cafaye/gateway-go

GET /healthz   -> 200 application/json  {"status":"ok"}
GET /readyz    -> 200 application/json  {"deps":{}}
GET /v1/me     -> 404 application/json  {"error":"not_found","message":"no such route"}
GET /nope      -> 404 application/json  {"error":"not_found","message":"no such route"}
```

`core's problem+json` envelope is ported and tested but **not yet reachable** —
the substrate's two refusals are the v0 `404` and `500`, which are the other
envelope. It is the floor the first Wave 3 handler stands on.

A started Go gateway reads **exactly one environment variable**, `PORT`. The other
six `runtimeOptions` reads belong to subsystems that are not ported, and a
variable an operator sets that changes nothing is worse than one they cannot
set: `IDENTITY_ISSUER` in a compose file looks configured and configures a `404`.

---

## The equivalence evidence, and its output

`internal/equivalence` stands the TypeScript reference up as a subprocess
(`test/equivalence/reference.ts`), builds the Go gateway in process, drives the
same requests at both, and fails where the answers differ.

```
equivalence: 24 cases x 3 scenarios = 72 comparisons, 0 differences
              (status, Content-Type, 12 compared headers, body bytes)
```

**The 24 cases, derived and hand-written, both.**

| | how | count |
|---|---|---|
| every operation the contract declares | read out of the generated registrations in `internal/api/api.gen.go`, which `bin/prime-go` holds in step with `openapi/v1.yaml` by regenerating and diffing | 7 |
| the edge | hand-written, and hand-written on purpose: wrong method ×3, `HEAD` ×2, the root, an unknown path, a path one segment too deep, a trailing slash, a doubled slash, the wrong case, a query string, a query on a refusal, a traversal, an encoded path, a 513-character path | 17 |

**The three scenarios.** `bare` (nothing configured), `oneProbeOk` (one
dependency healthy), `probesDegraded` (three dependencies: one healthy, one
refusing, one throwing a message carrying a host, a port and a credential, so the
comparison can prove none of them reach a body).

**Compared:** status, `Content-Type` value, the presence or absence of twelve
contract-declared headers (`X-Trace-Id`, `Set-Cookie`, `Retry-After`, the eight
`RateLimit-*`/`X-RateLimit-*`), and the body **byte for byte**.

**Excluded, and named rather than inferred:** `Date`, `Content-Length` and
`Connection`. They are written by the two transports, not by either service, they
are not in the document, and comparing them would make every run differ on
something neither side chose.

**`firstDifference()` names the first byte that differs**, because "the bodies
differ" over a 48-byte refusal body is a sentence nobody reads to the end.

### What it does not cover — asserted, not left to be discovered

`TestTheSurfaceThisComparesIsTheSurfaceTheSubstrateCanServe` reads the status enum
out of the generated file (plus the v0 `404`, which `V0Error` has no enum for)
and fails on any status that is neither producible nor named with a reason.

| producible | why |
|---|---|
| `200` | the two probes, and every operation once its subsystem is ported |
| `404` | the v0 envelope: an unknown path, a wrong method, and the five unported operations |

| cannot produce | why |
|---|---|
| `400` | the malformed-body check is on `registerUser` — Wave 3 |
| `401` | the bearer-token gate and the API-key store are Wave 3, and no verifier means nothing to authenticate against |
| `403` | `requireSameOrigin` and `requireScope` are Wave 3, and there is no browser surface to gate |
| `409` | `registerUser` is Wave 3, and the conflict is identity's to answer |
| `413` | the 4 KiB body cap is on `registerUser` — Wave 3 |
| `422` | no operation on this surface validates fields; identity's answers are forwarded, not re-derived |
| `423` | a locked account is identity's answer on login — Wave 3 |
| `429` | no limiter yet; `httpapi.ProbePaths` is the floor it will be built on |
| `503` | probes report per-dependency availability in `/readyz`'s **body**, not as a problem document |

So there is **no bearer token, no API key, no limiter, no `X-Trace-Id`, no
`Set-Cookie` and no upstream**, and therefore no problem document is compared.

### The two-scenario-list check

`test/equivalence/reference.ts` (TypeScript) and `scenarios.go` (Go) each name the
scenarios and cannot see each other at run time.
`TestTheGoSideHasAnAnswerForEveryScenarioTheReferenceHas` reads the reference's
names out of its source and fails on any mismatch **in both directions**. Without
it, a scenario on one side alone would compare nothing and report green.

---

## Five planted divergences, each reverted, each measured

The worker contract's §8. Every mutation was applied with a script that printed
the mutated line, so none of these is a mutation that silently failed to apply.

| mutation | outcome |
|---|---|
| trailing newline restored (`append(encoded, '\n')`) | **caught** — 63 of 72 differ |
| both `HEAD` registrations removed | **caught** — 6 of 72 differ, `status: typescript 200 go 404` |
| `/readyz` rendered through `json.Marshal(api.Readiness{Deps: deps})` | **caught on the second attempt** — 1 of 72 differ. See below. |
| `router.MethodNotAllowed` left at chi's default | **caught** — 8 of 72 differ, `status: typescript 404 go 405` |
| a probe that returns an error reported as `ok` | **caught** — 2 of 72 differ, `status: typescript 503 go 200` |

**The third one is the finding.** The mutation **PASSED on the first attempt**,
because the degraded scenario's three dependency names were `aperture, identity,
redis` — which is alphabetical. A sorted set renders identically whether the
gateway preserves registration order or sorts, so the ordering property was
untested and the check said nothing about it. Both sides now declare
`redis, identity, aperture`, both files say why, and the mutation bites. **Planting
a mutation and finding it does not fail is the only way to find that one** — a
reviewer reading `Options.Probes is a slice, not a map` would have believed it.

The gate's own teeth, also planted and reverted:

| mutation | outcome |
|---|---|
| a gofmt-invisible hand edit to `api.gen.go` | the regeneration step **reverted it silently** — which became its own fix, below |
| `openapi/v1.yaml`'s `liveness` summary changed, `api.gen.go` not regenerated | **caught** — `DOES NOT MATCH openapi/v1.yaml. Regenerating changed it: M internal/api/api.gen.go` |
| `step "go vet ./..."` renamed in `bin/prime-go` | **caught** — `gate.proof-missing: proof 'go-vet'` |
| `step "the generated server…"` renamed | **caught** — `gate.proof-missing: proof 'go-generated'` |
| the equivalence report removed from `bin/prime-go` | **caught** — `gate.proof-missing: proof 'go-equivalence'` |
| the Go toolchain pin removed from `mise.toml` | **caught** — `bin/prime-go: mise.toml pins no go toolchain`, exit 127 |

---

## Two real defects the checks found

**Every problem document would have been served with the wrong media type.**
`writeJSON` set `Content-Type: application/json` unconditionally, so
`writeProblem` setting `application/problem+json` and then calling it produced the
media type that says *"this is not a problem document"*. `AGENTS.md` names the fix
— assert the content type on every response, not just the shape — and
`TestAProblemIsTheDocumentedEnvelope` is that assertion. It found it because the
test checks the header rather than decoding the body and stopping there.

**Every JSON body carried a trailing newline.** `json.Encoder.Encode` appends one
to every value it writes — a convenience for a stream of values to a file — and
Hono's `c.json()` does not. 63 of the first 72 comparisons failed on it. It is
legal JSON and every client parses it identically, which is exactly why it would
have shipped: `writeJSON` now marshals with `json.Marshal` and writes the bytes,
which also means a marshalling failure happens **before** anything is written.

A third, in the gate: the regeneration step **silently reverted** a hand edit to
the generated file and reported green. That is arguably correct (the end state is
right) but it is a step that overwrites a file without saying so. It now takes a
`cksum` before and after and prints what it repaired.

---

## The trap the packet named, and what it cost

`oapi-codegen` emits `r.Get(options.BaseURL+"/healthz", …)`. Core's chi recogniser
requires a `/`-prefixed string literal as the **first** term after `(`;
concatenation is resolved in the *other* direction, because identity's own router
writes paths that way. So every generated registration is invisible.

Measured both ways on this tree, with all seven registrations mutated and reverted
afterwards:

```
with options.BaseURL+ present:
  FAIL account-scope.surface-thin: the declared sources register 8 entry point(s)
  and surface.minimum is 14 — and 6 further registration(s) in those sources could
  not be read at all, so this floor is not being violated, it is UNFALSIFIABLE
  0 account-scoped, 12 not-account-scoped, 0 stale, 1 undeclared, 6 unreadable

committed state (token removed):
  0 account-scoped, 12 not-account-scoped, 0 stale, 2 undeclared, 0 unreadable
```

**Yes, I deleted the token, and here is why it is a `//go:generate` line and not a
hand edit.** `bin/prime-go` regenerates and diffs, so a hand edit is a permanently
red gate; but the edit cannot be skipped either, because `route_defs` reads 0 over
a surface it saw none of and 0 over nothing prints exactly like 0 over everything.
`internal/api/stripbaseurl` is the second `//go:generate` line: it rewrites the
token out, prepends a header saying so, **and exits non-zero when it has nothing
to rewrite** — a post-processing step that silently does nothing is worse than no
step. `bin/prime-go` separately fails on a committed file that has regressed, and
matches the **shape** (`^\s*r\.(Get|Post|…)\(\s*[^"]`) rather than the token, so
it cannot fire on the comment that explains the step.

**What it cost, and it is a real cost: `undeclared` goes from 1 to 2.**

A declaration row is matched to a registration by `(method, path)` and **not** by
the file its `registeredAt` names — `registeredAt` is what `account-scope.stale`
reads and nothing else. Both implementations register `GET /v1/me`, so declaring
one row lands it on the **TypeScript** registration, whose inline handler
`c.get("principal")` genuinely does resolve an account (the finding this file
documents at length), and the Go registration is then left undeclared anyway:

```
FAIL declaration-contradicts-code: go-me (GET /v1/me) is declared
  accountScoped: false … and the registration line itself resolves an account
  … resolved account evidence at src/index.ts:247
FAIL undeclared: chi registers GET /v1/me at internal/api/api.gen.go:1191,
  which no entry point covers
```

So gateway goes from **1 failure to 2**, and both are the same finding. What I did
not do is delete a row, lower `minimum`, or drop `api.gen.go` from
`surface.sources` to make the number smaller — all three would turn a visible
finding into a green. Recorded in `account_scope.yml` as **DECISION NEEDED
(gateway-go-substrate-01)**: either `registeredAt` becomes part of the match, or the
format grows a per-source way to say "this file registers what the rows below
already declare". This is the first period in this fleet's history where two
implementations of one HTTP contract are live at once, and it is the last packet's
job to delete one of them.

---

## Everything measured on this tree

| check | result |
|---|---|
| `bin/prime` | **565 pass / 15 skip / 0 fail, Ran 580 across 25 files**, then the Go tier green, then `prime ok (bun 1.3.12)` |
| `bin/prime-go` alone | `suite: 31 passed, 0 failed`, `packages: 2 with tests`, `equivalence: RAN`, codegen byte-identical |
| `gofmt -l ./cmd ./internal` | clean |
| `go build ./...` / `go vet ./...` | clean |
| `docker build -f Dockerfile.golang .` | builds; image answers the four probes above |
| `docker build --target test .` | builds; **565 pass / 0 fail inside the image**, and the image's 25 test files diff clean against `find` |
| `docker compose build` | fails with `service "gateway" refers to undefined network platform` — **identical on the stashed baseline**; it needs `KIT_COMPOSE_DIR`, which the README already documents |
| `account-scope-check` | 14 readable, **0 unreadable**, 2 undeclared, 0 stale |
| `gate-check` | 0 failures, 3 warnings (all `requirement-unproven`, which is by design) |
| `floors-check` | `pass` 560/565, `files` 25/25 — **both floors raised to match, measured** |
| `reserved-check` | OK |
| `cafaye-contract` (with `CAFAYE_CORE`) | OK against core `664f70d`, 1 pre-existing warning: `exposes` is not declared — open decision 1 |
| `numeric-check` | 0 failures, 1 warning |
| `tenancy-check` | **FAILS — pre-existing.** Verified by `git stash`ing every change and re-running on the clean tree, where it fails identically: `tenancy.declaration-missing: tenancy.yml is not in …` |
| `bun run typecheck` | clean |
| `actionlint .github/workflows/ci.yml` | clean |

`gate.yml`'s proof list is now at core's schema maximum of **8**, which is a
finding about the format and is recorded where the next person hits it.

---

## What I deliberately did not do, and why

**Did not port the proxy, the auth verifier, the rate limiter, the BFF or the
API-key store.** Wave 3, separate packets, separate surfaces. This is the floor
they stand on, and a packet that also ports them cannot be reviewed as a port.

**Did not delete `src/`, `test/`, `Dockerfile` or `package.json`.** A port and a
deletion in one commit produce a diff where nobody can tell a porting bug from a
mechanical edit — precisely the review this rewrite most needs.

**Did not change `openapi/v1.yaml`.** The contract is the framework. Where the Go
side could not express something, that would be a finding, not a licence.

**Did not name the Go image `Dockerfile`.** The packet asks for a Dockerfile at the
repository root; the root `Dockerfile` is the TypeScript image and the packet also
says not to delete it. Both are satisfiable: **`Dockerfile.golang`**, at the root,
and not named `*.go` — `go build ./...` compiles every `.go` file in the tree, so
`docker/Dockerfile.go` fails with `illegal character U+0023 '#'`. The rename to
`Dockerfile` lands in the commit that deletes `src/`, not before, so there is never
a commit in which the name points at an implementation that is gone.

**Did not port `runtimeOptions` wholesale.** It reads six variables belonging to
subsystems that do not exist here. `RuntimeOptions` reads `PORT` and a test reads
the function's own source and fails on any other variable — so the next packet adds
the assertion with the variable rather than discovering the gap in review.

**Did not add `miseTask: prime-go` or a `prime-go` CI job.** `gate.command` is the
gate; two jobs running two tiers would be the gate existing twice, and the two
could disagree about what "the Go tier is green" means. `miseTask: prime` is set and
`bin/prime` invokes `bin/prime-go`.

**Did not filter the Go image's build context.** `.dockerignore` was written for
the TypeScript build, so `COPY . .` in `Dockerfile.golang` brings `src/` and `test/`
along — dead weight of the same kind pantry documents in its own header. Filtering
a `COPY` is how a test double reaches a shipped image, which is the failure
`test/dockerStage.test.ts` exists to prevent. Recorded in the Dockerfile's header
rather than fixed.

**Did not recover from a hung probe's goroutine.** `runProbe` runs the probe on its
own goroutine and selects against a deadline, because a deadline on a
`context.Context` does not interrupt a function that ignores it — so a probe that
hung would hang `/readyz`, and `/readyz` hanging is the one failure an
orchestrator cannot distinguish from a dead process. The cost is one leaked
goroutine per hung probe per request, and it is stated in `probe.go` rather than
hidden: there is no cancellation a function ignoring its context will observe, and
`runtime.Goexit` would unwind the probe's own deferred cleanup.

**Did not add a YAML parser.** `go.mod` has two dependencies, `chi` and
`oapi-codegen/runtime`. The checks that needed the contract read it *through the
generated registrations*, which `bin/prime-go` holds in step with the document.
That is a weaker statement than parsing the YAML and it is said out loud in
`routes_test.go`.

**Did not give `/readyz` a `map[string]ProbeStatus`.** `encoding/json` sorts map
keys; `Object.entries` does not. `Options.Probes` is a slice and `orderedDeps`
marshals by hand — and the mutation above is the measurement that the hand
marshalling is load-bearing.

---

## Findings outside the packet, named and specific

1. **`account_scope.yml` rows cannot be scoped to a file**, so two live
   implementations of one contract make a route registered by both permanently
   undeclared. DECISION NEEDED written into the file; needs core.

2. **`gate.schema.json` caps `proof` at 8** and gateway is at 8. The cap is not
   enforced by anything in core, so the next proof anybody wants here means folding
   one into a broader pattern or deleting one. Recorded in `gate.yml`.

3. **`gate.yml` cannot carry a floor on the equivalence comparison count**, because
   the line only exists on a run that found `bun` and a `minimum` would turn every
   developer's machine without bun into a red gate. The count is held in CI
   instead. A floor on something a legitimate environment cannot print is not a
   floor — but it does mean the *local* gate cannot catch a shrinking case list.
   The `suite: 31` floor cannot either, for the same reason the tier's own line
   exists. A `minimum` on the **case count** would work if the tier printed it on
   the skip path too; that is the successor's first cheap improvement.

4. **`tenancy-check` fails on this repository** — `tenancy.declaration-missing`,
   no `tenancy.yml`. Pre-existing, measured on the clean tree. Not this packet's
   to fix: gateway holds no customer rows, which is what that file would have to
   say, and writing it is a decision about the declaration rather than a
   consequence of anything here.

5. **`pins.test.ts` now needs `--no-go`**, because the stand-in bun it drives
   `bin/prime` with exits 0 for anything and cannot run the equivalence reference.
   The alternative was leaving `bin/prime-go` out of `bin/prime`, which is worse:
   then `gate.command` would not cover the Go tree and a Go change could ship
   through a green gate. Both new cases assert that the flag's banner appears and
   that an unknown argument is still refused, so the hole is covered rather than
   opened.

6. **`Dockerfile.golang` and `docker-compose.yml` are not wired together.**
   `docker compose build` builds the TypeScript image from `Dockerfile`; there is
   no `docker-compose.golang.yml`. Wiring a second compose file is a deployment
   decision — which image a deployment gets, and when the switch happens — and it
   belongs with the packet that deletes `src/`, or with the manager. Naming it in
   the report rather than inventing it.

---

## The successor's first move

**Wave 3: the bearer-token verifier.** It is the largest surface, it is what makes
`GET /v1/me` a real operation rather than a decline, and it is the one whose
absence forces `runtimeOptions` to read a single variable.

In order:

1. Flip `GET /v1/me` in `internal/httpapi/httpapi.go` from `notBuilt` to the real
   handler. `account_scope.yml`'s `go-me` row flips with it — from `false` to
   `true` with an `accountFrom` — and that is the first edit in the repository
   where a declaration and the code change in the same commit for a *reason*
   rather than a coincidence.
2. `RuntimeOptions` gains `IDENTITY_ISSUER`, `IDENTITY_URL`, `GATEWAY_CLIENT_ID`,
   `IDENTITY_JWKS_URL`, `IDENTITY_JWKS_TTL_MS`, and registers the `identity` probe.
   `TestTheRuntimeReaderReadsNoOtherVariable` is updated **in the same commit** —
   that test is the tripwire, and a variable added without it is a variable nobody
   reads.
3. `internal/equivalence` gains two scenarios (`identityOk`, `identityDown`) and
   `test/equivalence/reference.ts` gains the matching entries, with a real JWKS
   stand-in. The `401` and `503` rows in
   `TestTheSurfaceThisComparesIsTheSurfaceTheSubstrateCanServe` move out of
   `cannotProduce`, and the check starts comparing the problem document's
   `X-Trace-Id`, `trace_id` and media type for real.
4. The equivalence check's `ask` needs a request-header field, because a `401`
   cannot be reached without a credential. **Keep the trace id out of the body
   comparison** — both sides mint a fresh one per response, so a byte comparison of
   `trace_id` will fail on every run and the check must exclude that field rather
   than be loosened.

Then the limiter (`ProbePaths` is its floor), then the BFF, then the proxy. Each
is its own packet because each is its own surface, and each flips its own rows.