# REPORT — mvp-guard-principal-01

**What an upstream can now learn that it could not before.** A `ROUTE_TABLE`
entry that declares `principal: ["sub", "github_id"]` now causes gateway to send
that upstream a header, `X-Cafaye-Principal`, carrying a compact JWS that gateway
signs with its own key over the declared claims and binds to that upstream's base
URL origin. `POST /v1/pantry/services` arrives at pantry carrying
`{"sub": "…", "github_id": "583454", "iss": …, "aud": "http://pantry:8080",
"exp": …, "jti": …}`. `pantry.current_publisher_id()` has something to compare.

**What it still cannot learn — the more useful half.** It cannot learn *what that
caller is allowed to do.* The assertion says who, on this route, signed by this
gateway, minutes ago. Authorising them is the upstream's own database, and that
is where it belongs. Two further limits, both named in the README's *Not built
yet* rather than left to be discovered:

- **No service reads the header.** Not pantry, not identity, nothing in this
  repository. MD19 asked for both halves written at once; this is gateway's half and
  the verifying half is `pantry`'s, which is the next packet. An assertion
  configured today is minted, forwarded, and dropped — which means the honest
  status of this work is *"the mechanism is proven, nothing consumes it yet."*
- **A leaked assertion is bounded but not revocable.** Useless on any other
  upstream and dead in two minutes, which is the bar MD19 set. It cannot be
  withdrawn inside its window: there is no per-assertion key id to denylist and
  no introspection endpoint to ask. "Minutes, not revocable" is the true sentence.

---

## 1. The defect, and how it was established to be real

`pantry/openapi/v1.yaml` declares **six operations and every one is `get`**. Nobody
can publish to the registry. The database half is built and merged (`00009`); the
blocker is that gateway physically cannot tell pantry who is calling.

`src/routes/proxy.ts:96` (at `5a0e9d5`):

```ts
const FORWARDED_REQUEST_HEADERS = ["content-type", "accept"] as const;
```

and `outboundHeaders` set `authorization: Bearer ${token}` where `token` is the
**per-upstream service credential**. The file's own header named the consequence:
*"an upstream cannot tell which caller sent a request. The per-upstream `token` is
a service credential, not a delegation, and no header here asserts who the caller
was."*

**This is a fact, not a bug, and it is load-bearing.** Forwarding a caller's
`Authorization` would make gateway a confused deputy: the caller authenticates *to
gateway* and then chooses who they are *downstream*. The packet's authority, MD19,
keeps that rule and rules around it rather than through it.

What was missing was not the rule. It was that `src/index.ts:158-165` puts
`c.get("principal")` on the context **before** the pass-through runs, and
`proxy.ts` never read it. The principal existed and was discarded at the proxy
boundary. That is the whole defect, and it is why the feature could be additive:
no existing route had to change behaviour to have its principal stop being thrown
away.

## 2. What was built

New file `src/routes/assertion.ts` (the signer, which knows nothing about HTTP),
`principal?: string[]` on `RouteTarget`/`ResolvedRoute` in `table.ts`, a third
outbound header in `proxy.ts`, and wiring plus environment reading in
`index.ts`.

```sh
ROUTE_TABLE='{"/v1/pantry/services":{"baseUrl":"http://pantry:8080",
                                     "principal":["sub","github_id"]},
              "/v1/catalog":{"baseUrl":"http://pantry:8080","public":true}}'
```

### The decisions the packet asked me to own

**The signing key's source — gateway's own, configured as a file path.**
The packet said to reuse the JWKS machinery "rather than inventing a second one
if you can". I reused the *library and the shape* and not the key, because a JWKS
is public keys by definition and cannot sign. Reusing identity's private key would
be the dangerous answer: a key that can sign is a key that can mint anything
identity can mint. So gateway holds its own RS256 key, `ASSERTION_SIGNING_KEY_FILE`,
a path to a PKCS#8 PEM.

*Why a path and not the PEM in a variable:* an environment value appears in
`docker inspect`, in `/proc/<pid>/environ` and in any crash dump. This repository
already refuses a base URL carrying a password for exactly that reason, so reading
a private key from an env var would have been inconsistent with a rule it enforces
next door. `readFileSync` plus a synchronous `createPrivateKey` means a missing
file *and* a malformed PEM are both startup errors — jose's `importPKCS8` is
async, and awaiting it would have made a bad key a 503 on every proxied request,
the one configuration mistake the repo's rules forbid. **There is no third case.**

*`kid` defaults to the RFC 7638 thumbprint.* Two deployments both calling their
key `gateway-1` is a key set in which an upstream silently verifies against the
wrong deployment's key. A thumbprint cannot collide. An explicit
`ASSERTION_SIGNING_KEY_ID` is still accepted for an operator publishing a key set
by hand, and the trade is stated in the source: a hand-published id is one gateway
cannot check, which is why it is not the default.

**Claim names — declared per upstream, read from the token.** The table says which
claims an upstream needs; gateway copies those *from the caller's verified token*,
not from its typed `Principal`. So `scope` crosses as the space-separated string
identity signed rather than the array gateway parsed it into, and `github_id` —
which is not a field on `Principal` at all — crosses without gateway being taught
its name. gateway is a signer here, not a translator: reshaping a claim would make
the assertion a *different* claim from the one identity verified.

*A name the token does not carry is omitted, not invented and not refused.* This
is the case that earns the design: MD19 wants a publisher with no row to get a
404-shaped "no publisher record" rather than a silently minted one, and that only
happens if a token with no `github_id` reaches pantry as a token with no
`github_id`.

**Lifetime — two minutes, refused above ten.** `ASSERTION_TTL_MS` above
`MAX_ASSERTION_TTL_MS` (600 000) is a refusal to boot naming the maximum. A
lifetime nobody may exceed *is* the property; a default is only a default.

**An upstream with no declared claims gets no assertion at all.** Not an assertion
carrying no claims — that is a token whose entire content is which gateway minted
it, costing a signature per request to say nothing. This is also what keeps the
feature additive: no declaration, no header.

### Why MD19's first property is enforced three times, on purpose

Property 1 — never on a public route — is refused at boot (`routeTable`) and again
at the send site (`proxy.ts:assertionFor`), with `assertion.ts` spreading gateway's
envelope *before* the declared claims so a declared `aud` could not overwrite it
even if the reserved-name check were removed.

**And that redundancy had to be made observable, or it would have been a green by
omission.** Because `routeTable` refuses `public` together with `principal`, there
is no way to reach a public entry that declares claims through `createApp` — so the
obvious test, using the real table, stays green whether or not `proxy.ts` checks
`route.public` at all. A check no input can reach is not a check. So
`assertion.test.ts` builds a `createRouteProxy` directly with a table `routeTable`
would have refused, and asserts the header is still absent, with a private sibling
in the same table that *does* get one as the control. Mutation 1b below exists only
to make that distinction checkable.

## 3. The tests, and the mutation evidence

`src/routes/assertion.test.ts` — **23 tests, 0 skips**, named by the property each
answers. `test/assertionMutations.sh` is the harness, committed so the evidence is
reproducible rather than a claim.

Every mutation: the diff is printed, **the mutated line is re-read out of the file
and printed** (a substitution that silently failed to apply is indistinguishable
from a working one), the named test is run by name, and the tree is restored by
**inverse substitution**. Measured result: **7 mutations, 7 proved red, 8 checks
green including the final clean-tree check, 0 failed.**

| # | Property | Mutation | Named test | Result |
| - | -------- | -------- | ---------- | ------ |
| 1a | never on a public route | `if (open === true && principal !== undefined)` → `if (false && …)` | `a public entry that declares principal claims refuses to boot` | 0 pass / **1 fail** → 1 pass |
| 1b | never on a public route | `if (route.public === true) return undefined;` → `… && route.principal === undefined` | `the send site refuses on its own` | 0 pass / **1 fail** → 1 pass |
| 2 | not the caller's token | `return assertion.mint(…)` → `return c.req.header("authorization")?.replace(/^bearer /i, "") ?? ""` | `the header is a different string, and not the caller's Authorization` | 0 pass / **1 fail** → 1 pass |
| 3a | bound to the upstream | `aud: subject.audience` → `aud: "https://everywhere.invalid"` | `the audience is the upstream it was minted for…` | 0 pass / **1 fail** → 1 pass |
| 3b | short-lived | `.setExpirationTime(seconds + Math.floor(ttlMs / 1000))` → `+ 86_400` | `it stops verifying once the window has passed` | 0 pass / **1 fail** → 1 pass |
| 4 | minimal claims | `...declared(principal, subject.claims)` → `...principal.claims` | `the declared names are there, in the token's own shape…` | 0 pass / **1 fail** → 1 pass |
| — | published JWK is public | `exportJWK(key.publicKey)` → `exportJWK(key.privateKey)` | `it carries no private parameter` | 0 pass / **1 fail** → 1 pass |

Mutation 2 is the exact refactor MD19's second property exists to stop, written as
the plausible bad edit rather than as a deletion. Mutation 4 is the wildcard the
field exists to prevent.

**MD18's standing promise, restated rather than assumed:** `an anonymous caller to
a private route still gets 401` — `describe("an anonymous caller to a private route
still gets 401")`, three tests, passing **with the signing key configured**,
because a feature that put a key in the path is exactly how it would break.
`publicRoute.test.ts` holds the same answer with no key; holding it here makes it a
property of the feature rather than of the default.

### A measurement the harness produced that I had not argued for

Mutation 4 (`...principal.claims`) did not only fail the minimal-claims
assertion — the failure payload showed `iss: "http://127.0.0.1:52773"` and
`aud: "gateway-test"`, i.e. **the caller's own `iss` and `aud` had overwritten
gateway's envelope**. The mutation is therefore the measurement of why the envelope
is spread first, arrived at before anyone made the argument for the ordering. It is
recorded in the harness's own header for the next reader.

## 4. A defect found inside this packet, and fixed

**The published JWK was the private key.** The first draft derived it with
`exportJWK(key.privateKey)`. Measured in this repository, not assumed:

```
exportJWK(privateKey) -> kty, n, e, d, p, q, dp, dq, qi      (the whole private key)
exportJWK(publicKey)  -> kty, n, e
```

RSA primes included. And **nothing about the result would have looked wrong**:
RFC 7638 hashes only `e`, `kty` and `n`, so the `kid` stayed correct (both
thumbprints measured identical), and every signature still verified. The only way
to catch it is to name the fields.

Fixed by having `AssertionKey` carry both halves and deriving the public JWK from
`publicKey`. `assertion.test.ts` now asserts the published field names **exactly** —
`["alg","e","kid","kty","n","use"]` — rather than "does not contain `d`", because
the failure mode is a *new* private parameter appearing in a library upgrade and an
exact list is the only shape that notices. Mutation 7 above proves that tripwire
bites.

## 5. Numbers, before and after

| | before (`5a0e9d5`) | after (`15d8523`) | delta |
|---|---|---|---|
| pass | **540** | **563** | **+23**, all in `src/routes/assertion.test.ts` |
| skip | 15 | 15 | 0 |
| fail | 0 | 0 | 0 |
| files | 24 | 25 | +1 |
| `tsc --noEmit` | clean | clean | — |

Every one of the 23 new tests is in the new file; no existing test was edited,
weakened or removed. The 15 skips are unchanged and are all
`src/middleware/rateLimitRedisLive.test.ts` — the one declared entry in
`test/noSkips.test.ts`'s allowlist, environment-gated on `GATEWAY_REDIS_URL`.

**Nothing was skipped.** No shard, no `--no-live`, no opt-out. The one tier this
machine cannot run is the live Redis tier, and it was already skipping before this
packet and still is; it is counted above in the skip row and is guarded by three
pre-existing mechanisms the packet did not touch.

**On the packet's stated floor.** The brief says *"531 pass, 15 skip, 0 fail at
`5a0e9d5`"* and warns that three test names exist in two packages each so a naive
count is one high. **That number does not reproduce.** Measured on this worktree at
`5a0e9d5` before a line was written:

```
 540 pass / 15 skip / 0 fail / 1987 expect() calls / Ran 555 tests across 24 files
```

and the repository's own `gate.yml` header independently records the same figure
(*"Re-measured on the public-route commit, `bin/prime` prints 540 pass / 15 skip /
0 fail, `Ran 555 tests across 24 files`"*), with its `pass` floor set at 535
*"against a measured 540"*. The brief's 531 appears to be stale; the figure I
diffed against is 540 and it comes from two independent places. For completeness
on the de-duplication warning: a JUnit dump of the run shows **555 testcase
elements, 555 distinct `(classname, name)` pairs** — so no de-duplication applies
to this suite's count — while **13 names do appear under two `classname`s** (11
`parity: memory` / `parity: redis` pairs and two shared `runtimeOptions` names),
which is the warning's trap, and a naive name-only count would be 542.

**`gate.yml`'s floors are deliberately unchanged.** `pass: 535` against a measured
563 and `files: 24` against 25. The repository's own reasoning is that a floor at
exactly today's number "has to be raised by hand before a single test can be
added, and a ratchet nobody can move is a ratchet that gets deleted", and the
5-test margin absorbs this packet's 23. Raising them is a manager's call and is not
mine to make silently.

**`account-scope-check` is unchanged: 1 failure before, 1 failure after**, and that
one is the pre-existing documented `undeclared GET /v1/me` that
`account_scope.yml` explains at length. Warnings 7 → 7, stale anchors 0 → 0. The
six `registeredAt` anchors moved with the imports (121→157, 123→159, 240→280,
241→281, 242→282, 243→283) and are updated in the same commit, along with the prose
in that file that names the same lines. **No new registration was added** — see §6.

## 6. What I chose not to do, and why

**No `/.well-known/jwks.json` endpoint.** The public half is available from
`publicJwk()`, so wiring a route is small, and it is deliberately not done. It
would add a route to the **public edge of the gateway**: a new operation in
`openapi/v1.yaml` (held to the router by `test/openapiDocument.test.ts` in both
directions), six `registeredAt` anchors in `account_scope.yml`, and a
`surface.minimum` change this packet has no standing to make — all of it for
something no *caller* needs. Upstreams are already configured out of band; they
receive gateway's `token` the same way. The key travels the road the `token` does.
This is also why `surface.minimum` stays 7.

**No claim beyond what an upstream declared.** MD19 asked for "publisher id and
the scopes the upstream is declared to need", and the more general form — "which
claims a given upstream gets" — is what I built, because `github_id` is not a
field gateway knows and teaching it one claim name would be worse than not knowing
any. The generality is one string array.

**No wildcard.** `"*"` is a refusal to boot. It is the one entry that would turn
"minimal claims" into the caller's whole JWT, and it is exactly the outcome the
field exists to prevent, arrived at by an operator trying to be helpful.

**No `aud` binding on the route prefix, only on the upstream origin.** A prefix
binding would need a cafaye-aware verifier, so it would bind only in deployments
that opted into it and be silently unenforced everywhere else. A binding that is
*available* rather than enforced is documentation wearing a control's clothes.
MD19's word is "upstream", and the origin is what satisfies it, checkable by any
JWT verifier that has never heard of cafaye.

**Nothing outside `gateway` was touched.** `pantry`, `identity`, `site` and `core`
are untouched; `worker/guard-v1-me-01` was not merged, branched from, or built
from — the worktree is on `master` (`5a0e9d5`) as the brief's trap section
required, verified before a line was written. No containers, images or volumes
were created or started; this packet is Node and runs no Docker at all.

## 7. Findings outside the packet

1. **The brief's floor (531) does not reproduce; the real figure is 540**, from two
   independent measurements — §5. Worth correcting wherever it is quoted from.
2. **`exportJWK` on a private `KeyObject` returns the private key.** This is a
   jose 6.2.12 behaviour, not a gateway bug, and it is the kind of thing any future
   cafaye component publishing a key set will get wrong the same way. The fix and
   the tripwire are here; the *finding* belongs to whoever writes the next one.
3. **A pre-existing documented `account-scope.undeclared` for `GET /v1/me`** —
   already written up in `account_scope.yml` and in
   `REPORT-identity-account-scope-01.md §6.7`, and `core`'s to fix, not gateway's.
   Named here so the `account-scope-check` exit-1 is not mistaken for something
   this packet introduced.
4. **A proxied `2xx` carries no `RateLimit-*` headers**, because `relay` builds a
   fresh `Response`. Pre-existing, already recorded in `publicRoute.test.ts` and the
   README, and untouched here — but it becomes sharper now: a private upstream
   receiving an assertion has no way to learn what budget the caller spent.
5. **The process lesson, because it cost me real work.** My first version of the
   mutation harness reverted with `git checkout -- <file>`, which is the correct
   way to revert a mutation *and* the fastest way to destroy every uncommitted
   edit in that file. It wiped my in-progress `table.ts` and `proxy.ts`, and it
   left three mutations sitting in the then-untracked `assertion.ts` because
   `git checkout` refuses untracked paths — which is how I spent ten minutes
   debugging a cross-file test failure that was really three live mutations. The
   harness now reverts by **inverse substitution**, commits its source first, and
   refuses to run if the tree is not clean at the end. A mutation harness is a tool
   that edits source, and it has to be as careful about the developer's
   uncommitted work as about its own.

## 8. What I would do next

1. **`pantry`'s verifying half** — read `X-Cafaye-Principal`, verify against
   gateway's key, and expose `current_publisher_id()` from it. Until that lands this
   packet's output is dropped on the floor, and MD19's "both halves written"
   stands at one.
2. **The publisher write surface** (`openapi/v1.yaml` operations, router, the two
   tripwires to invert), with the three mechanical costs MD19 already measured:
   `account_scope.yml`'s registeredAt anchors, `kit`'s fleet ratchet row, and
   `00009`'s edge-before-release ordering rule.
3. **Decide whether to publish the assertion key over HTTP.** Two upstreams needing
   it is the trigger, and the trigger is named in the README so it is a decision
   rather than a drift.
4. **A `jti` denylist**, if a leak inside a two-minute window ever turns out to
   matter. It has not, so it has not been built.