# HANDOFF — docs corrections 01

What the documentation packet found that is **not** documentation, plus what it
deliberately did not do. Written across three commits on
`worker/m39-gateway-docs-corrections-01`, the last of which is this file.
Four files touched: `README.md`, `AGENTS.md`, `cafaye.yml` (comments only) and
this one. No code.

## 1. Findings in code, recorded and not fixed

The packet said: if the code disagrees with a claim, fix the doc; if the code is
actually wrong, do not fix it — record it here. Three things qualify.

### 1.1 The Go limiter does not count forwarded traffic — a real gap, not a doc disagreement

**This one is a bug in the Go service and it is the largest of the three.** An edge
whose limiter does not run on the traffic it forwards is not limiting the traffic
that costs it money, and the reference does count it.

Measured on this tree, both sides frozen at the same instant with an allowance of
three per minute (`TestTheGoSideDoesNotCountRoutedTraffic`, which passes, so the
divergence is live):

```
GET /v1/pantry/items    typescript  429 + the whole RateLimit-* family
                        go          200 + no rate-limit headers at all
```

The cause is the mount order, and it is a consequence of a decision that is right
on its own terms:

- `internal/httpapi/httpapi.go:266-268` mounts the limiter as a chi `Use`
  **inside** the router.
- `internal/httpapi/httpapi.go:328-334` builds the chain
  `credentialGate → pass-through → router`, so anything a route table claims is
  relayed by a handler that wraps the router and never reaches a `Use` mounted
  within it.
- `src/index.ts` registers `app.use("*", limiter)` **before**
  `app.use("/v1/*", proxy)`, so the reference counts it.

Wrapping rather than mounting is deliberate and documented at `httpapi.go:311-327`
(chi's trie prefers `/v1/me` over a middleware, so a pass-through mounted *into*
the router would relay gateway's own route). The obvious fix — move the limiter out
and wrap the pass-through with it — puts the `/v1/*` verifier *after* the limiter,
which contradicts `AGENTS.md`: "a token that does not verify is answered 401 and
counted against nothing." So the fix is a reordering of the whole chain, not a
one-line move.

**Not fixed here: `internal/httpapi/httpapi.go` and `internal/httpapi/gate.go`
are owned by a live worker.** Documented in README under *The limiter does not
count forwarded traffic*, and listed in *Not built yet*.

### 1.2 `RequireScope` is implemented, tested, and called by nothing

`internal/auth/middleware.go:133` is the port of `requireScope`, and
`internal/auth/verifier_test.go` exercises it. `internal/httpapi/httpapi.go:162`
puts it on the `TokenVerifier` interface and `httpapi.go:139-142` says in as many
words that a later packet mounts it. **No production Go code calls it** — the only
three references in the tree are the definition, the interface declaration, and the
comment promising the mount.

So the capabilities half of what the verifier learns about a caller is parsed,
verified and then discarded. That is not a security hole on its own — a scope
check that is absent cannot be bypassed by presenting a token, because nothing
consults the scope either way — but it means the Go service's notion of "what may
this caller do" is entirely upstream's. The README now says so rather than letting
"bearer verification: ported" imply the whole of `src/middleware/jwt.ts`.

**Not fixed here: mounting it changes the router, which is the live worker's.**

### 1.3 The CI equivalence floor is 72 and a run makes 912

`.github/workflows/ci.yml:139`:

```sh
if [ "$comparisons" -lt 72 ]; then
```

The number a real run prints on this tree:

```
equivalence: 51 cases across 13 scenarios = 912 comparisons, 0 differences
```

So the floor is **under 8% of the work it is supposed to be a floor on**. Its
stated purpose is in the failure message — "fewer means the derived case list
shrank" — and a case list that lost 93% of itself would sail through it. The
derived half is protected elsewhere (the case list is read out of the generated
registrations), so the exposure is the hand-written remainder.

**Why the number is 72 and not 400-ish:** it was written when the tier ran 3
scenarios. It was raised as each packet landed and stopped being raised.
`gate.yml:330-331` deliberately carries **no** floor on this line, and that is
correct — the line only exists on a run that found `bun`, so a floor there would
turn every machine without bun red. The floor belongs in CI, where
`GATEWAY_EQUIVALENCE_REQUIRED=1` guarantees the line is printed.

**Two stale copies of the same number, left alone deliberately.** `gate.yml:330`
quotes the output as `equivalence: 24 cases x 3 scenarios = 72 comparisons` in the
comment explaining why it carries no floor — true of the tier when that comment was
written, not of it now. Both documents now say the floor is low and point here
(`README.md` in *CI*, `AGENTS.md` in the fourth-mechanism rule). `gate.yml` is a
gate definition rather than documentation, and `README.md:889`'s CI table says the
job "fails under 72", which is **true of the file as written**. A reader is told
the number is a floor on 912 and why it is not one yet; they are not told the
workflow does something it does not do.

**Not fixed here: `.github/workflows/ci.yml` is owned by a live worker.** This one
is a one-character-class change (72 → ~800) and it is the cheapest thing on this
list.

### 1.4 The structural cause, which is not a finding about any one packet

**No gate reads this repository's documentation.** `grep -rn README test/*.ts
*.test.ts` returns two files, and both mention the word in a comment about
something else (`test/dockerStage.test.ts`, `test/tenantEntryPoints.test.ts`). So
every claim corrected in this packet — "not ported — Wave 3", "two operations of
seven", "reads PORT", "a 578-test suite", "`{"deps":{}}`" — was free to rot
silently, and did, for four to six packets.

`internal/equivalence` is the closest thing to a precedent: it reads
`openapi/v1.yaml` and the generated registrations and holds them equal, so an
operation added to the contract is compared the day it lands. The equivalent for a
*document* would be a check that derives the port-status table from the source
(`Options.Verifier != nil` → `/v1/me` is served; `api-keys` absent from
`openapi/v1.yaml` → not ported) and fails when the prose disagrees. That is a
packet, not this one, and it is the one that stops this class rather than this
instance.

## 2. What this packet deliberately did not do

- **Did not edit code.** `git diff master...HEAD --stat` is three documentation
  files: `README.md`, `AGENTS.md`, `cafaye.yml`. `cafaye.yml` is a comment-only
  edit — every changed line begins with `#` — so the parsed manifest is byte-identical
  and `additionalProperties: false` has nothing new to reject.
- **Did not touch `.github/workflows/ci.yml`, `internal/httpapi/httpapi.go`,
  `internal/httpapi/gate.go`, `internal/ratelimit/*`, `internal/session/*`,
  `internal/sessionredis/*`, `CHANGELOG.md` or `src/`.** The three findings above
  are all in that list, which is why they are findings and not commits.
- **Did not rewrite the `REPORT-*` files**, including
  `REPORT-gateway-go-port-audit-01.md`, whose §0 and §3-10 this packet confirms.
  A report is a record of what a packet found on a date; correcting it would make
  the record a lie about itself. The audit's own tally ("11 of 15 non-test `src/`
  files have a Go counterpart") was itself superseded within two packets — the
  limits table and the session store both landed after it — so it reads as history
  and the README reads as the present tense. That split is deliberate.
- **Did not fix `docker compose config`,** which fails on the clean tree at
  `589525b` as well as here (checked by stashing). It is one of the two red causes
  `REPORT-gateway-go-port-audit-01.md` §4 names, and it is not documentation.
- **Did not claim the whole README is now true.** This packet corrected every
  port-status, Wave-N and sizing claim it could find and verify. It did not
  re-audit the endpoints table, the error-shape claims, or the `Not built yet`
  bullets that concern identity, pantry or core.

## 3. Verification

Every correction in the two commits was checked against the source or run, not
inferred. The load-bearing ones:

```
# what the shipped Go binary does, with nothing configured
$ go build -o /tmp/gw ./cmd/gateway && PORT=8099 /tmp/gw
$ curl -s localhost:8099/readyz
{"deps":{"identity":"unavailable"}}
$ curl -s -o /dev/null -w '%{http_code}\n' localhost:8099/v1/me
401
$ curl -s -H 'Authorization: Bearer not.a.token' localhost:8099/v1/me
{"type":"https://errors.cafaye.com/unauthorized",…,"detail":"token is malformed",…}
$ for i in $(seq 1 11); do curl -s -D- -X POST -d '{}' localhost:8099/auth/login; done
1..10  404  RateLimit-Limit: 10  RateLimit-Policy: "gateway-auth-login";q=10;w=60
11     429  {"type":"https://errors.cafaye.com/rate_limited",…}

# and the same two lines from the reference, so "both sides" is measured too
$ PORT=8098 bun run src/index.ts
$ curl -s localhost:8098/readyz
{"deps":{"identity":"unavailable"}}
$ curl -s localhost:8098/v1/me
{…,"detail":"a bearer token is required",…}   [401]

# the comparison's own count, which the README now quotes instead of asserting
$ GATEWAY_EQUIVALENCE_REQUIRED=1 go test -run TestTheGoGatewayAnswersAsTheTypeScriptOneDoes -v ./internal/equivalence
equivalence: 51 cases across 13 scenarios = 912 comparisons, 0 differences
(status, Content-Type, 12 compared headers, body bytes; 22 of them also compared
the request the upstream received)

# the counts the README states as counts
$ awk '/^var runtimeVariables/,/^}/' internal/httpapi/runtime_variables_test.go | grep -c '^\s*"'
15
$ bun test | tail -1
Ran 580 tests across 25 files.
$ grep -c api-keys openapi/v1.yaml
0
```

Gates, both tiers, on the committed tree:

```
$ bin/prime-go
suite: 227 passed, 0 failed        # equivalence RAN, not skipped
internal/api/api.gen.go regenerates byte-identically from openapi/v1.yaml
==> ok

$ bun run typecheck && bun test
565 pass  15 skip  0 fail          # the 15 are the GATEWAY_REDIS_URL tier
```

## 4. If there is a next quarter

1. Raise the CI floor (§1.3). One line, and it is the only one on this list that is
   a pure win with no ordering consequence.
2. Decide what the limiter should do about forwarded traffic (§1.1) — that is a
   cutover decision, not a documentation one, and it should be made before the
   chain is reordered.
3. `openapi/v1.yaml` needs `api-keys` operations before API keys are a porting job
   rather than a document job. That is a spec call and it is manager-owned, and it
   blocks the last substantive gap on the list.
4. The documentation gate (§1.4), which is what makes items 1–3 stay fixed.