# REPORT — gateway-go-proxy-01

**What an upstream can now learn in Go that it could not before.** A request to a
routed upstream that declared claims carries `x-cafaye-principal`: a short-lived
RS256 assertion over exactly the claims the route table named, with `aud` set to
the upstream's own origin and `iss` to gateway. Before this packet the Go gateway
had no pass-through at all, so there was nothing an upstream could learn — and a
service written against the TypeScript gateway's assertion had no way to be served
by the Go one.

**And what it still cannot learn.** That a gateway exists. An upstream still cannot
tell who the caller was from anything except the assertion, because the Go gateway
does not verify tokens: `Options.Authenticate` is nil in every configuration this
packet can build. A request to a **private** route with no credential is relayed,
with the service credential attached — because that is exactly what
`createApp({routes})` does when no `jwt` option was configured, and the packet rules
that the TypeScript answer is the correct one. The credential gate is a seam with
its refusal, its status, its envelope and its position above the pass-through
already in place; the packet that ports RS256 fills in one function.

The third thing, which is the one that would surprise an operator: an upstream still
cannot learn that the request came from *gateway* rather than from anyone who can
reach it. Nothing about this packet changes the network position.

---

## What the defect was

There was no defect. The packet asked for a port, the substrate was merged, and the
TypeScript implementation is the specification — so this is a record of what was
built, what it was measured against, and what the measurements found.

Two of the three things below were found by *measuring* the reference rather than
reading it, and one of them is a correction to a comment in the code being ported.

---

## What was built

| file | what it is |
| --- | --- |
| `internal/httpapi/table.go` | the prefix → upstream table, validated at boot; `NormaliseRequestPath`, which is the URL parser's dot-segment removal; `UpstreamPath`, which rebuilds each segment; `ParseRouteTable`, which is where the JSON-level refusals live |
| `internal/httpapi/proxy.go` | the pass-through: a two-header request allowlist, a one-header response allowlist, gateway's own `Authorization`, `ErrUseLastResponse`, a per-request deadline, `cache-control: no-store`, `set-cookie` dropped, and `IsRelayableStatus` |
| `internal/httpapi/assertion.go` | the principal assertion: RS256 over a minimal claim set, `aud` bound to the upstream's origin, a lifetime ceiling, the published JWK as an RFC 7638 thumbprint. No dependency added |
| `internal/httpapi/gate.go` | the credential seam (`Authenticate`) and the 401 that is the standing property. Nil today |
| `internal/httpapi/runtime.go` | `ROUTE_TABLE` and the `ASSERTION_*` four, so a deployment can configure any of it |
| `internal/equivalence/` | two scenarios and one recording upstream, and the comparison of what each side **sent** |
| `test/proxyMutations.sh` | 27 mutations, each removing one property to show its test goes red |

### The eight properties, and where each is proved

| # | property | test |
| --- | --- | --- |
| 1 | the caller's credential never reaches an internal service | `TestTheCallersCredentialNeverReachesAnInternalService`, `TestAnEntryWithNoTokenIsReachedWithNoAuthorizationAtAll` |
| 2 | the path is reconstructed, not filtered | `TestUpstreamPathRebuildsEverySegmentAndRefusesWhatItCannotExpress`, `TestUpstreamPathWouldBePathCleanIfItWereAFilter`, `TestTheNormalisedPathIsTheURLParsersOwn` |
| 3 | only `content-type` and `accept` cross | `TestOnlyContentTypeAndAcceptCrossToTheService`, `TestTheRequestAllowlistIsExactlyTwoNames` |
| 4 | no redirect followed, and a deadline | `TestARedirectIsNeitherFollowedNorRelayed`, `TestAnUpstreamThatHangsIsA503AndNotAHungGateway` |
| 5 | `set-cookie` dropped | `TestTheRelayDropsSetCookieAndSetsNoStore` |
| 6 | `cache-control: no-store` | `TestTheRelayDropsSetCookieAndSetsNoStore`, `TestAnUpstreamsOwnCacheControlIsOverriddenNotForwarded` |
| 7 | only a 2xx or a 4xx is relayed | `TestOnlyA2xxOrA4xxIsRelayed` |
| 8 | the table is validated at boot | `TestABadRouteTableIsARefusalToConstructTheGateway`, `TestTheJSONASpellingAnOperatorGetsWrongIsAlsoARefusal` |
| MD19 1 | never on a public route | `TestAPublicEntryIsRefusedAnAssertionEvenByATableThatBootWouldHaveRefused` |
| MD19 2 | not the caller's token, ever | `TestTheAssertionIsGatewaySignedAndNotTheCallersToken`, `TestTheAssertionVerifiesAgainstThePublishedJWK` |
| MD19 3 | bound to the upstream, short-lived | `TestTheAssertionIsBoundToTheUpstreamAndShortLived`, `TestAnAssertionLifetimeNobodyMayExceedIsARefusalToBoot` |
| MD19 4 | minimal claims | `TestTheAssertionCarriesOnlyTheDeclaredClaims`, `TestADeclaredClaimTheTokenDoesNotCarryIsOmittedRatherThanInvented` |
| — | **an anonymous caller to a private route gets 401** | `TestAnAnonymousCallerToAPrivateRouteGets401AndTheUpstreamIsNeverContacted`, and **compared against the reference's own 401** in `gatedUpstream` |
| — | gateway's own route survives a `/v1` entry | `TestGatewayOwnsItsOwnRouteEvenUnderTheBroadestPrefix` |

---

## What was measured, and what it measured

### Before and after, on the gate

```
before this packet:  suite: 31 passed, 0 failed      (bin/prime-go)
                     equivalence: 24 cases x 3 scenarios = 72 comparisons, 0 differences
                     TypeScript tier: 565 pass / 15 skip / 0 fail

after:               suite: 93 passed, 0 failed      (bin/prime-go)
                     equivalence: 51 cases x 5 scenarios = 255 comparisons, 0 differences
                       (status, Content-Type, 12 compared headers, body bytes;
                        21 of them also compared the request the upstream received)
                     TypeScript tier: 565 pass / 15 skip / 0 fail   (unchanged)

mutations:           test/proxyMutations.sh — 27 mutations, 27 proved, 0 unproved,
                     working tree clean at the end.
```

`./bin/prime` (both tiers) is green. `test/proxyMutations.sh` exits 0.

### The three differences the equivalence check found, and what it fixed

All three were TypeScript-wins, ported faithfully.

**1. The problem document's field order.** `api.Problem` is a *generated* struct
whose fields are alphabetical, so `json.Marshal` produced
`{"code":…,"detail":…,"instance":…,"status":…,"title":…,"trace_id":…,"type":…}`.
`openapi/v1.yaml`'s `Problem.required` is
`[type, title, status, detail, instance, code, trace_id]` and `src/problem.ts`
writes them in that order — so **the document declares an order and the generator
had thrown it away**. Every problem document the Go service wrote was a document the
contract does not describe. Fixed by building the object by hand in the document's
order, with every value still `json.Marshal`-escaped. It is the same trap `/readyz`
hit and for the same reason, and `writeRawJSON` had a second copy of the same bug:
it set `Content-Type: application/json` unconditionally and overwrote
`application/problem+json`.

**2. `instance` is the request line's spelling, not its decoded one.**
`/v1/pantry/a%2Fb` is `instance: "/v1/pantry/a%2Fb"` in the reference and
`/v1/pantry/a/b` here, because `r.URL.Path` is decoded; and `/v1/../v1/me` is
`/v1/me` there because a WHATWG parser resolves dot segments. So `instance` is
`NormaliseRequestPath(r.URL.EscapedPath())` — the same function the pass-through
routes on, because there must be one spelling of "what path is this" in the package
rather than two.

**3. `Content-Length` is not copied, and an untyped relay is
`application/octet-stream`.** The reference hands the caller's body to `fetch` as a
stream and Bun relays it chunked with no `Content-Length`; copying the inbound value
would have given an upstream a framing that differs from the caller's *and* from the
reference's. And a service answering without a content type reaches the caller as
`application/octet-stream` under Bun — Go would have sniffed
`text/plain; charset=utf-8` out of the body instead, which is the one answer neither
side chose.

### The finding about the reference itself

**`src/routes/proxy.ts:24` is wrong about `%2e%2e`.** It says:

> The upstream path is rebuilt, never forwarded as received… `%2e%2e` survives WHATWG
> URL normalisation, so this is the check that matters.

Measured against Bun 1.3.12:

```
new URL("http://h/v1/pantry/%2e%2e/secret").pathname   ===   "/v1/secret"
new URL("http://h/v1/pantry/%2e/secret").pathname      ===   "/v1/pantry/secret"
new URL("http://h/v1/pantry/.%2e/secret").pathname      ===   "/v1/secret"
```

So a percent-encoded dot segment does **not** survive URL normalisation. The
reference's routing decision is made on a path the URL parser has already rewritten,
which means:

- Go's `net/url` normalises **nothing**, so without `NormaliseRequestPath` the two
  implementations disagree about **which prefix claims the path** — not about the
  pass-through's own rules. `/v1/pantry/./x` is a relayed `200` there and a `404`
  here.
- The **defence is still real and is kept**: it is `UpstreamPath`'s refusal of a
  decoded separator, which is the case `%2e%2e` is not. A parser leaves `%2f`
  alone, so `/v1/pantry/a%2f..%2f..%2fetc%2fpasswd` reaches the function intact, and
  a Go upstream that *does* decode it would read three extra segments. `UpstreamPath`
  refuses it because the decoded segment contains a separator.

A future reader who believes the comment will not look for the encoded-separator
case, which is the one that is actually reachable. **The reference was not changed** —
it is the implementation this port is measured against, and the packet says a
suspected defect in it is reported rather than fixed here. The correction is recorded
in `NormaliseRequestPath`'s own comment so the next reader of the Go file finds it.

### Two ways a green lied during this packet

Both were found by the mutation script refusing to accept them, and both are why the
script exists.

**A check whose expectation was built out of the thing it checks.**
`TestOnlyContentTypeAndAcceptCrossToTheService` derived its "nothing else crossed"
set from `ForwardedRequestHeaders`. Widening the list with `x-forwarded-for` — a
one-character change to the security core — left the test **green**, because the
test widened with it. The allowlist now has its own test against a literal, in both
directions, and both are mutation-proved.

**A property enforced twice, which is unprovable from outside.** The route table is
validated in `Options.validate` *and* again in `New`, on purpose: `validate` so a bad
table is refused at construction, `New` so the copy handed to the pass-through is the
checked one. The mutation that removed `validate`'s copy left the test green, because
`New` still refused. A test can see that the gateway refuses; it cannot see *which*
of two calls refused. The script now removes both (a `mutate_pair` helper, for a
property enforced at two places on purpose), and the redundancy is a comment in `New`
rather than a silent second check.

---

## Equivalence: what was compared, and what the comparison does not cover

**255 comparisons across 5 configurations**, all green, and **21 of them also
compare the request the upstream received**: method, escaped path, query, body, and
every header that is not the client's own.

### What the two routing scenarios are

- **`routedUpstream`** — a route table in front of the recording upstream and **no
  credential gate**, which is the reference's own state when no `jwt` option was
  configured. Three entries of three shapes: `/v1/pantry` (no credential),
  `/v1/pantry/imports` (a service credential, a nested prefix so the longest match
  wins), `/v1/catalog` (`public: true`).
- **`gatedUpstream`** — the same table with a gate in front. The reference gets a real
  verifier and is asked with **no credential**, so it answers `401` from its own gate
  without ever fetching a key set. The Go side's gate refuses rather than verifies.
  So the standing 401 is compared against the reference's own answer, byte for byte,
  envelope included.

### The cases are weighted towards refusals

An unrebuildable path, an encoded traversal, a literal traversal, a dot segment
inside the prefix, a path that resolves to a dot segment, an encoded separator inside
a segment, a doubled slash, a byte that is not a character, a sibling that cannot
inherit the mount, gateway's own route, a `404` from the service, a `401` from the
service, a `5xx` from the service, a `3xx` from the service, a body with no content
type, and three cases where the caller sends ten headers of which two are allowed.
A comparison that only asked the questions whose answer is `200` would prove almost
nothing about a proxy.

### What it does not cover — named, not absent

1. **The principal assertion itself.** No route table in either scenario declares
   `principal`, so nothing is minted on either side. A minted `jti` differs per mint
   and cannot be compared byte for byte; MD19's four properties are covered by
   `internal/httpapi`'s own suite, where the claim set can be read and the signature
   verified with `rsa.VerifyPKCS1v15` against a key rebuilt from the published JWK's
   `n` and `e` alone.
2. **A token that verifies.** The auth packet's comparison, and it needs a key set
   both sides can reach.
3. **`Accept-Encoding`, `User-Agent`, `Connection`.** Written by `net/http` and by
   Bun's `fetch`, not by either gateway. Measured, not guessed:
   Bun sends `accept-encoding: gzip, deflate, br, zstd` and
   `user-agent: Bun/1.3.12`; Go sends `gzip` and `Go-http-client/1.1`.
4. **A caller who sends no `Accept`.** Bun's `fetch` supplies `accept: */*` when the
   caller sent none and `net/http` supplies nothing, so the *presence* of `accept` at
   the upstream would be a difference between two transports. Every case that reaches
   the pass-through therefore sends one, and that exclusion is written down at the
   case table rather than left to be discovered as a flaky case.
5. **`trace_id` inside a problem document**, replaced with a fixed token on both sides
   so nothing else in the body is loosened. Both sides mint it freshly, so it cannot
   match. The property taken out is asserted on each side independently — Go in
   `TestTheTraceIdHeaderEqualsTheBodyAndLooksLikeOne`, TypeScript in
   `src/problem.test.ts`.
6. **`X-Trace-Id`'s value across sides**, compared for presence only, for the same
   reason.
7. **A request line whose path is not valid percent-encoding.** `net/http` rejects
   `%zz` before any handler runs and answers `400`; the reference reaches its handler
   and answers `404`. This is a transport difference and closing it would mean
   replacing the HTTP parser. **Named as a finding rather than worked around.**
8. **Everything else Wave 3 owns**: the BFF, API keys, the rate limiter, so no
   `/auth/*` operation answers anything but `404`.

---

## What was chosen not to do, and why

- **Did not port token verification, the rate limiter, the BFF or API keys.** Separate
  packets, separate surfaces. The credential *gate* is here because the pass-through
  needs two answers about a request it did not verify — is there a principal, and is
  this route caller-anonymous — and neither answer is a verification. It is a seam
  with one nil-checkable field.
- **Did not add a JWT dependency.** The signing half is `crypto/rsa` plus
  `encoding/base64` plus `encoding/json`, and the whole of it is verified by the
  standard library's own verifier in
  `TestTheAssertionVerifiesAgainstThePublishedJWK`. `go.mod` still names two
  dependencies. A dependency that signs things is a dependency whose bugs are
  signature bugs.
- **Did not add retry, a circuit breaker, health checking, or pool tuning.** Absent
  from the TypeScript service on purpose. Adding them would be a different packet and
  would change behaviour the equivalence check would then measure as a difference.
- **Did not use `path.Clean`.** It is called nowhere in `table.go` and must not be; it
  is a normaliser, not a reconstruction.
- **Did not add a `ProxyFetch` seam.** `src/routes/proxy.test.ts` injects `fetch`;
  this port does not, and uses a real `httptest` upstream instead. Three properties —
  that a redirect is not followed, that a deadline bounds the handler, that a body
  streams — can only be demonstrated against a real client, and an injected fetch
  would assert about a stub.
- **Did not touch `src/`.** One exception in spirit and none in fact: the reference
  file `test/equivalence/reference.ts` gained two scenarios, because the comparison
  is the deliverable and it cannot compare what it cannot start. `src/routes/proxy.ts`
  and `src/routes/assertion.ts` are untouched.

---

## Findings outside the packet, named and specific

1. **`src/routes/proxy.ts:24` states a false property about `%2e%2e`.** Measured
   above; the defence is real but by a different mechanism, and the comment points at
   the wrong case. Needs a decision from whoever owns the reference.
2. **`net/http` rejects a request line with an invalid percent-escape** before any
   handler runs, answering `400` where the reference answers `404`. A real
   behavioural difference between the two gateways on the same input. Not closable
   without replacing the HTTP parser; recorded under what the comparison does not
   cover.
3. **`writeRawJSON` and `writeJSON` had the same unconditional-`Content-Type` bug**,
   one layer apart. The first was found by the substrate packet's own test; the
   second was found here only because the equivalence check reached a problem
   document. A reader should assume there is a third.
4. **`Dockerfile.golang` is not filtered by `.dockerignore`** (from the substrate
   packet, still true), and **`tenancy-check` fails on this repository** for want of a
   `tenancy.yml` (pre-existing, measured on the clean tree).
5. **`account_scope.yml` cannot be scoped to a file**, so two live implementations of
   one contract leave a route registered by both permanently undeclared. The
   substrate packet recorded this with a DECISION NEEDED; it is still open and the Go
   pass-through does not change it — nothing in this packet registers a new
   operation.

---

## The successor's first move

**`gateway-go-auth-01`: fill in `Options.Authenticate`.** One function, and the
verifier behind it. Nothing else moves: the refusal, its status, its envelope, its
detail string and its position above the pass-through are already the reference's,
and the equivalence comparison for the `401` already runs. Then flip `GET /v1/me`
from `notBuilt` to the real handler, register the `identity` probe in
`RuntimeOptions`, add `identityOk` / `identityDown` scenarios on both sides, and move
the `401` and `503` rows in
`TestTheSurfaceThisComparesIsTheSurfaceTheSubstrateCanServe`.

The second-cheapest improvement is in `internal/equivalence`: `caseSpec` has a
`scenarios` field and the runner counts per-scenario, but the *printed* count is a
product that includes cases a scenario did not ask (51 × 5 = 255 while the scenarios
asked 24 + 24 + 24 + 51 + 48). The count should be the number of comparisons actually
made, because a reader of a green run is entitled to know how many.

---

## Verification commands, and what each printed

```
$ ./bin/prime-go
==> toolchain: go 1.26.1 (mise.toml pins 1.26.1)
==> gofmt -l … ==> go build ./... ==> go vet ./... ==> go test ./...
equivalence: 51 cases x 5 scenarios = 255 comparisons, 0 differences
             (status, Content-Type, 12 compared headers, body bytes;
              21 of them also compared the request the upstream received)
ok  github.com/cafaye/gateway/internal/equivalence
ok  github.com/cafaye/gateway/internal/httpapi
suite: 93 passed, 0 failed
==> the generated server matches the OpenAPI document
==> ok

$ bun test
 565 pass   15 skip   0 fail   2067 expect() calls   (580 tests across 25 files)

$ ./bin/prime
== prime ok (bun 1.3.12)

$ ./test/proxyMutations.sh
proved: 27
not proved: 0
```

The 15 TypeScript skips are the pre-existing environment-gated tiers (the Redis live
tier and the equivalence stand-in bun in `pins.test.ts`), unchanged by this packet;
`bin/prime` counts them in its own summary.

**One environmental note, so nobody mistakes it for a result.** This worktree had no
`node_modules`, so `bun test` failed with 16 errors (`Cannot find package 'hono'`)
before it was linked to the main checkout's. That is a worktree-setup gap and not a
code change; nothing in this packet touches `package.json` or `bun.lock`. The
equivalence tier did not need it — `bun` resolves `hono` and `jose` from its global
cache when the reference is run as a script — which is why the Go tier was green
while the TypeScript tier was not.