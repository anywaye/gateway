# REPORT — gateway-go-bff-01

**The browser-facing surface and API keys, in Go.** `internal/httpapi/bff.go`,
`internal/session`, `internal/sessiontest`, and five corrections to the substrate
the equivalence check forced out.

Branch `worker/gateway-go-bff-01`. Not pushed, not merged. 83 Go tests green,
`bin/prime-go` green, `bin/prime` green including its TypeScript tiers, 306
equivalence comparisons green, 39 mutations red-then-green.

---

## 1. The MD18 defects. Found, measured, and NOT fixed.

`MD18` in `moon/DECISIONS.md` measured three mismatches between the gateway's
API-key gate and `identity`'s actual keys. **This packet ported the behaviour
faithfully and did not fix any of them**, because a port that silently repairs a
security-adjacent mismatch across four repositories is unreviewable and the fix is
not mine to make. Here is each one, re-measured today, with both ends of the wire.

### 1.1 The SDK sends a scheme the gate does not match

| | |
|---|---|
| what the SDK sends | `Authorization: Bearer cafaye_…` — `site/node_modules/cafaye-ts/dist/cafaye/credentials.js` |
| what the gate matches | `/^apikey(?:\s|$)/i` — `gateway/src/middleware/limitKey.ts:195`, and `/^apikey +(\S+)$/i` at `gateway/src/middleware/apiKey.ts:352` |
| consequence | a key presented by the only client in the fleet is **not recognised as a key at all**; `hasApiKeyScheme` returns false, the request falls through to the token gate, and the bearer token is presented to a JWT verifier that has no JWKS |

Two spellings of the same wrong answer, in two files, which is worth noting: fixing
one would leave the other.

### 1.2 The key SHAPE is wrong, and mismatched between two files

| | |
|---|---|
| the gateway's regex | `/^caf_[A-Za-z0-9_-]{43}$/` — `gateway/src/middleware/apiKey.ts:210,229`, so the generator mints `caf_` + 43 |
| identity mints | `cafaye_` + 43 — `identity/internal/apikeys/apikeys.go:75` |

**`cafaye_…` does not match `^caf_[A-Za-z0-9_-]{43}$` even though it starts with
`cafe`.** The gate's own shape check therefore rejects every key identity has ever
minted, before the store is consulted. This is the defect with the widest blast
radius of the three: the other two are a wrong scheme and a non-existent scope, and
this one means a *correct* credential is refused.

### 1.3 The `guard-api` scope does not exist

`identity/internal/apikeys/apikeys.go:238-241` declares
`accounts:read, accounts:write, accounts:delete, oidc_clients:write,
audit_log:read, account_invitations:write`. `guard-api` is in none of them and in
no other file in `identity`. `site/src/lib/pantry.ts:41`'s comment — *"Guard's
route table gates `/v1/*` on the `guard-api` scope"* — is false of the shipped
code.

### What I did about it

Nothing, in `src/` and nothing in Go, and that is the correct answer for this
packet:

- **The API-key gate is not in this packet.** The brief says so explicitly ("Do not
  port the proxy, auth verification, or the rate limiter"), and there is no Go API-key
  code to be wrong in. `grep -rn 'caf_'` over `internal/` returns nothing.
- **The fix is four repositories in order** — add a scope to identity, change the
  scheme, change the prefix, wire the store — and `MD18` already lays out the order.
  It is also gated on an identity that can issue a key at all
  (`identity/internal/httpapi/apikeys.go:76` is owner-only and
  `sessionCredentialOnly` refuses a token at `:595`).
- **What I would do first:** fix `apiKey.ts`'s prefix to `cafaye_`. It is the
  smallest of the three, it is contained in one repository, and until it is fixed
  the other two cannot even be observed — the store is never consulted for a key
  identity minted. Then the scheme. Then the scope, which is the only one that
  needs a decision about what a gateway is *for*.

If the manager wants this packet to fix any of them, say so and I will — but it
would be a different packet with a different brief, and it should be reviewed as one.

---

## 2. The session store: DEFERRED, and why that is not a punt

The brief's rule is binary: either identity's store is used, or the packet says
plainly that it is deferred and why. There is no third option. **This is the second
one, and the reason is a measurement rather than an estimate.**

`identity/internal/sessions/store.go` is genuinely the better design. `NewSession`
takes a **`TokenDigest`**, not a token, so the store has no code path that can
produce a raw credential. `ErrNotFound` is **one error** for "no such token, a
revoked token, an expired token, and a token belonging to a deleted user" — one
status code, one response time, and four distinguishable answers is four ways to
enumerate users. Expiry is a `WHERE expires_at > $1` clause rather than a comparison
the caller is trusted to remember.

**And it cannot be used, for four independently sufficient reasons.**

1. **The direction is wrong.** `Store.ByToken(ctx, q, token, now)` takes a *token*
   and hashes it. What the gateway needs is the inverse: `SessionStore.Get` is
   handed the opaque id the browser holds and must return the identity token to put
   in a `Bearer` header for `/v1/me`. Nothing in that package performs that
   direction and nothing *can*, because the digest is one-way by construction —
   which is exactly why `NewSession` takes one.
2. **Go's `internal/` rule forbids the import.** `github.com/cafaye/identity/
   internal/sessions` is importable only from `github.com/cafaye/identity/...`.
   `gateway` is a different module, so the compiler would refuse it even with the
   direction right. Reaching it means identity publishing that package outside
   `internal/`, which is a change to identity's public surface.
3. **There is no HTTP route that does the inverse lookup**, so "just call identity"
   has no endpoint to call.
4. **Adding one would be a new and dangerous capability**: an endpoint that turns a
   cookie id into a bearer token is a token-minting API aimed at somebody else's
   cookie.

So the alternative was a `sync.Map` in the binary — a per-process store that signs a
browser out on the next restart, in the one service whose entire claim is that it
holds a credential so the page does not have to. I judged that copying the worse
design into the language that makes the better one easier to write is worse than a
documented deferral, and I did not ship it.

**How the deferral is enforced rather than promised:**

- `internal/session` declares `Session` and `SessionStore` in a leaf package, so
  `internal/sessiontest` can implement it without importing the package it stands in
  for. The package comment holds the whole measurement.
- `NewBff` **refuses to construct** a browser surface with a nil store. Four routes
  that cannot tell a signed-in user from a stranger are not a gateway, and a
  deployment cannot accidentally serve them on nothing.
- `internal/sessiontest` is the only implementation in the module.
- `TestNoProductionFileImportsTheSessionDouble` runs **`go list -deps ./cmd/...`**
  and fails if the fixture is in the shipped binary's import graph. A first version
  of that check banned the import string from every non-test `.go` file under `cmd/`
  and `internal/`, and went red on `internal/equivalence/scenarios.go` — a file only
  ever imported by a `_test.go`. The rule it enforced was "no test-support file may
  name this package", which is not the rule anybody wanted; the rule is "no
  **shipped** code may name it". The import graph is that rule, derived.
- With no `Options.BFF` at all, the four routes decline with the reference's `404`,
  which is exactly `createApp({})`'s answer.

**What this costs, stated rather than hidden.** A Go gateway has nowhere to put a
browser session, so `/auth/*` cannot be reached from the environment — `Options.BFF`
is built in-process by the tests and by `internal/equivalence`, and `RuntimeOptions`
still reads only `PORT`. That is now in the README's "Not built yet" list as its own
line, and it is the successor packet's first move.

**I did not land a half-migration.** There is one service, one store interface, and
zero implementations in the binary.

---

## 3. What the equivalence check found — five real defects

Four of the five were in code the substrate packet already had. All five are fixed,
each with a test that is red before the fix and green after.

### 3.1 The problem envelope's field order (substrate, and the one that mattered)

```
typescript  {"type":"…","title":"Unauthorized","status":401,"detail":…,"instance":…,"code":…,"trace_id":…}
go          {"code":…,"detail":…,"instance":…,"status":…,"title":…,"trace_id":…,"type":…}
first difference at byte 2
```

`api.Problem` declares its fields **alphabetically** — `oapi-codegen` emits a struct
in the order it finds them in the document's `properties` map, and that map is
sorted — where `src/problem.ts` writes them in declaration order. Byte-identical
content, byte 2 different, and **not one client would ever read the difference.**

It survived the substrate packet because that packet ported the envelope for five
operations that all **declined**. An envelope nothing reaches is an envelope nothing
has compared. That is the generalisable lesson and it is in the README.

`writeProblem` now hand-renders in the reference's order, with `field` before `code`
inside a 422's `errors` (`api.FieldError` is alphabetical for the same reason and the
reference's literal is `{ field, code }`), every string escaped by `encoding/json`,
and only the punctuation written by hand. `orderedDeps` in `httpapi.go` had the same
defect and already had the same fix; these are the only two places this repository
builds JSON as text.

### 3.2 `writeRawJSON` overwrote the problem content type (substrate)

```
Content-Type: typescript "application/problem+json"   go "application/json"
body:     identical on both sides
```

`writeRawJSON` set `application/json` unconditionally, after `writeProblem` had set
`application/problem+json`. A correct body served with the media type that says
"this is not a problem document". Now conditional, like `writeJSON`'s — and the
reason is in both functions' comments, because the same bug already lived in
`writeJSON` once and was found by a test that asserted the header rather than
decoding the body.

### 3.3 A `BFF` auto-registered a readiness probe (this packet, first draft)

```
body: typescript {"deps":{}}
      go          {"deps":{"identity":"ok"}}
first difference at byte 9
```

`createApp({bff})` answers `{"deps":{}}`: `identityProbe` is registered by
`runtimeOptions`, which reads `IDENTITY_URL`. `Options.Probes` is now exactly the
reference's list, registered by hand, in registration order — and
`TestABrowserSurfaceRegistersNoProbeAndTheReferenceAgrees` asserts the empty form so
this cannot come back.

### 3.4 A doubled `Sec-Fetch-Site` was refused; the reference serves it (measured)

```
status:   typescript 200   go 403
Set-Cookie: typescript present   go absent
```

**The reference answers `200`, with the cookie, to a request carrying
`Sec-Fetch-Site: same-origin` twice.** Two mistakes followed from getting this wrong:

1. `isSameOrigin` joined the lines — the WHATWG `Headers` rule, and what the first
   version of this file did — so it saw `same-origin, same-origin`, which is not
   `same-origin`, and refused. A "stricter" gate that diverges.
2. `oapi-codegen` refuses a repeated header parameter before any handler runs, with
   a **`text/plain` 400** that appears nowhere in `openapi/v1.yaml`.

Fixed by `collapseRepeatedHeaders`, which reduces a repeated value to its first
before the generated router sees it, and by `firstValue` in the gate.
`TestAHeaderSentTwiceTakesTheFirstValue` sends `same-origin, cross-site` and
`cross-site, same-origin` and asserts the first value's answer in both directions;
`TestTheParameterRefusalIsUnreachableForTheDeclaredHeaders` doubles both contract
header parameters and asserts the request reaches its handler, so `paramRefusal`'s
docstring claim that it is unreachable for them is measured rather than asserted.

### 3.5 A logout identity could not revoke said the wrong thing (this packet)

```
detail: typescript "the authentication service could not be reached"
        go          "the authentication service answered with something unusable"
```

`src/bff/auth.ts`'s logout is `revoked ? 204 : unreachable()`. The port answered
`unusable()`, which is a different `detail` **and an extra log line**. A decision,
not a status: `unreachable` means identity was not reached, `unusable` means it was
reached and said something the contract does not cover, and a caller that can tell
those apart learns whether identity is up. The port now answers `unreachable()`, and
`TestANonRevokingLogoutIsUnreachableNotUnusable` drives `200`, `500` and `429`.

---

## 4. Equivalence: what was compared, and what was not

**306 comparisons — 24 base cases × 9 configurations — plus the browser cases.**
Compared on status, `Content-Type`, the presence of 12 contract-declared headers, and
the body byte for byte.

The nine scenarios: `bare`, `oneProbeOk`, `probesDegraded`, and six browser
configurations — `bff`, `bffBadCredentials`, `bffUnknownAccount`, `bffAccountLocked`,
`bffIdentityBroken`, `bffSessionWithdrawn`. The last five are the packet's equivalence
list translated into configurations, so a wrong-password refusal and an
unknown-account refusal are compared in two scenarios with **different upstream
bodies and different slugs**, which is what makes their byte equality mean something.

**Derived, not typed:**

- The contract cases come from the generated registrations in `internal/api/api.gen.go`,
  which `bin/prime-go` holds in step with the document by regenerating and diffing.
- The four `/auth` cases in the browser half are the same, filtered to the browser
  paths — so an operation added to `/auth` is compared the day it lands.
- `canSignIn` is derived from a scenario's own identity overrides, not from a list of
  scenario names. The first version had both, and they were two lists of one fact: a
  scenario that stopped refusing a login would keep being asked the signed-in cases
  and `signIn` would fail about the wrong thing.
- `TestTheGoSideHasAnAnswerForEveryScenarioTheReferenceHas` reads the reference's
  scenario keys out of its **source** — one language cannot see the other's list.

**One normalisation, and what keeps it honest.** `trace_id` is replaced with a
constant before comparison. It is 32 hex characters of `crypto/rand`, generated per
response on both sides, so it can never agree; comparing it would fail every problem
document forever and the "fix" would be to make the field constant, which is the
opposite of what it is for. **What is not normalised is its presence or its shape**:
`TestBothSidesCarryAWellFormedTraceId` asserts, for every problem document both sides
produced in a run, that there is exactly one, that it is 32 hex characters, and that
it equals the `X-Trace-Id` header — and that it saw at least one such document, so a
run where none were produced fails rather than passing vacuously.

### What the comparison does NOT cover

- **A revoked key and a valid key.** The packet lists them in the equivalence list.
  They belong to the API-key gate, which is another packet, and there is no Go
  API-key code, so a case would compare two `404`s and call it agreement about keys.
  This is the one item in the packet's own equivalence list that is not delivered,
  and it is not deliverable by this packet.
- **`/v1/me` with a bearer token.** No verifier in Go, so it declines with `404` and
  so does `createApp({})`. Correct, and not evidence of equivalence for the
  authenticated API surface.
- **Rate limiting and the upstream pass-through.** Wave 3.
- **The session id's VALUE.** Both implementations mint their own, so a shared header
  would be a session neither knows. Compared as presence; asserted directly in
  `bff_test.go` that the cookie is the key the record is stored under.
- **Response time.** Not measured anywhere. The enumeration property is argued from
  the byte-identical answers, not from timing, and timing is the half of enumeration
  nobody in this repository measures.
- **What a real session store does.** Every comparison runs against
  `internal/sessiontest`, a `Map`. So "the port's answers given a working store" is
  proven; "a deployment has somewhere to put a session" is not, because that is the
  deferral in §2.
- **The fixture expiry is a real constraint with a real failure date.**
  `hono/cookie` **refuses** to serialise a cookie expiring more than 400 days out —
  it throws, and the reference's `onError` turns that into a `500`. The first
  fixture, `2031-03-04`, made the reference answer `500 {"error":"internal_error"}`
  to a successful login while the Go service answered `200` and set the cookie. The
  fixture is now `2027-01-15`, inside the window. **This is a real divergence between
  the two implementations and it is not a porting mistake on either side:** the
  reference cannot issue a session longer than about a year and the Go service can.
  Whether the Go service *should* is a decision about session lifetimes, so it goes
  in this report rather than into a line changed to make a check green.
  `internal/equivalence/scenarios.go` states the window and the fact that the fixture
  will need a new literal when 2027-01-15 passes.

---

## 5. Every property, and the mutation that shows it

`./mutation-gate.sh` — **39 mutations, 39 bit, 0 did not.** Each one breaks exactly
one property, is verified to have **applied** (grep for the mutated text after the
edit, and fail loudly if it is absent), runs the suite, and is restored.

The list, by the property it attacks: the gate accepting `same-site`; the gate
comparing `Origin` by scheme; a request stating no origin being let through;
disagreeing signals resolved the wrong way; the `__Host-` prefix dropped; the cookie
losing `HttpOnly`; `SameSite=Strict`; the clearing cookie dropping `Path`/`Secure`;
the login body carrying the identity token; the session id coming from the caller; an
already-expired session accepted; a `423` collapsing into a `401`; `Retry-After`
dropped; a non-numeric `Retry-After` echoed; the `401` detail being identity's own
body; a refused credential still storing a record; the user document as a filter
rather than an allowlist; the user fields in the wrong order; a registration minting a
session; the body re-encoded rather than forwarded verbatim; the 4 KiB cap off by
nine bytes; an identity outage treated as a revocation; a withdrawal not dropping the
record; a forgotten session keeping its cookie; a logout silently reporting success;
signing out leaving the record; a down store answering `401`; a hung `Doer` not
bounded; a panicking `Doer` not recovered; the `503` naming identity's address; a
declined operation answering `501`; a BFF auto-registering a probe; a non-revoking
logout answering `unusable`; the envelope's field order; `writeRawJSON` overwriting
the content type; a doubled header joined instead of collapsed; the duplicate-header
collapse not installed.

### Five places the recipe found MY TESTS wrong

A mutation that does not bite is either an untested property or a broken test, and
both are worth more than a green.

1. **Five "the cookie was not cleared" assertions were vacuous.** They read
   `sessionCookieValue(res) != ""`, and a *clearing* cookie is
   `Set-Cookie: __Host-bff-session=; Max-Age=0` — its value is the empty string, so
   "cleared" and "never sent" were the same observation. Split into
   `setsSessionCookie`, `clearsSessionCookie` (no value **and** an expiry in the
   past — a bare empty value is a cookie set to `""`, not a deletion) and
   `hasSessionCookie`. All five now bite.
2. **Nothing asserted that a refused credential leaves nothing in the store**, so a
   mutation that stored a session on the `401` path stayed green.
3. **Nothing drove a panicking `Doer`**, so the recovery in `within` was unproven and
   the mutation that removed it could not bite.
4. **Nothing asked `/readyz` about a dependency that is up and answering `500`**, so
   the probe's own status branch was unproven. Both ways down are now cases, and they
   are different code paths.
5. **Three mutations were unreachable rather than passing.** Breaking only the
   header's body-cap bound did nothing because `httptest.NewRequest` always sets
   `Content-Length`; naming only the lockout test for the "refused login stores a
   record" mutation proved half a thing because the mutation was in the `401` branch;
   and "the probe's error names the host" **cannot** bite, because `runProbe`
   collapses every non-nil error to the closed two-value `unavailable` and the error
   never reaches `/readyz`'s body — there is no byte to change. Each says so in a
   comment rather than being deleted, and each was replaced with a mutation of the
   observable half.

### And one place the recipe destroyed work

`mutation-gate.sh`'s first version restored each mutated file with
`git checkout -- "$file"`. **That restores the last commit**, so running it with
uncommitted changes in the tree silently deleted them — three files' worth, on the
run that found the envelope ordering. The restore is now a **copy**, taken once over
every `.go` file under `cmd/` and `internal/` (derived by walking, not listed) and
verified by checksum after every mutation. Re-doing the lost work cost about fifteen
minutes and is the single most expensive mistake in this packet.

---

## 6. What I deliberately left alone, and why

**The API-key gate, the JWT verifier, the limiter, the pass-through.** The brief
excludes all four and each is another packet. `/v1/me` still declines with the
reference's `404`.

**A double-submit CSRF token.** The README says the origin gate *is* the defence and
that adding one would be "a second thing to get right for the same protection". The
concrete reason is in `RequireSameOrigin`'s docstring and it is worth repeating here:
the only thing the server holds is a session id it cannot read — the cookie is
HttpOnly by design — so a second cookie would be readable by the very cross-site
script the first one hides from, and the "token" would be compared against a value
the *attacker* supplied. That is not a second defence; it is the same defence with
the secret moved somewhere public.

**`OPTIONS`, `.well-known`, the authorization-code flow.** Excluded by the brief, and
correctly: a browser signs in with email and password through this service today.

**A lockout at the edge.** Documented as a later decision. Forwarding identity's `423`
is the whole of this packet's lockout behaviour.

**An endpoint that issues an API key.** Excluded by the brief and correct: the
missing piece is the *caller*, not the capability, and issuing a credential wants an
authenticated account, an audit trail and its own rate limit.

**Any change to `src/`.** It is the reference. One thing I did change is
`test/equivalence/reference.ts`, and only to add scenarios — it is a test fixture,
not the implementation. **No production TypeScript file was touched**, so a
behavioural difference between the two services cannot be a difference *I* introduced
in the reference. §3.4 is the one place where I nearly did: the first version of the
port refused a doubled header "because that is stricter", and the equivalence check
said the reference serves it, so the direction of the fix followed the evidence.

**`openapi/v1.yaml`.** No operation was added, removed or changed, so `account_scope.yml`
and core's `surface.minimum` need no edit from this packet, and `api.gen.go`
regenerates byte-identically (`bin/prime-go` proves it).

**The `400 text/plain` the generator would emit for an unknown header parameter.**
`collapseRepeatedHeaders` names two headers and does not derive them from
`api.gen.go`; parsing the generated file for parameter declarations at run time is
more machinery than two constants justify. The tripwire is the equivalence check,
which compares every operation the document declares — a new header parameter would
appear there as a red rather than as a surprise. Said here because it is a limit and
not a feature.

**Removing the in-memory reader bound on request bodies.** There are two bounds — the
declared `Content-Length` and an `io.LimitReader` — and `httptest.NewRequest` always
sets the header, so a mutation of the reader alone is invisible. That is a fact about
what the suite can see, not a gap: the reader is there for a request whose
`Content-Length` lied or was absent, and the header check is there so the common case
costs no read. Both stay.

---

## 7. Outside the packet, named

1. **`bin/prime-go`'s regenerate-and-diff did not catch the envelope ordering** and
   could not have: the document did not change, only what the code did with it. Not a
   defect in the gate, but it is worth knowing that regenerate-and-diff proves the
   *document* is honoured and says nothing about the *code* that reads it.
2. **`hono/cookie`'s 400-day cap is a deployment-visible ceiling the contract does
   not mention.** `openapi/v1.yaml` declares no maximum session lifetime, and
   `identity` mints whatever it likes, so an identity that issued a two-year session
   would produce a `500` at the edge rather than a session. Anyone setting identity's
   session TTL should know the reference's ceiling is about a year. **This is the
   clearest candidate for a follow-up decision** and I did not make it.
3. **`internal/equivalence/scenarios.go` imports a test fixture from a non-test
   file**, which is why the first version of the session-double guard was red and
   why the guard now reads the import graph. Two similar rules, one of them wrong,
   and the wrong one read like a principle.
4. **The fixture expiry has a shelf life.** `internal/equivalence/scenarios.go`
   says so in the code, and the day `2027-01-15` passes this check will start failing
   on a date rather than on a defect. It needs a new literal, and it needs whoever
   picks that up to read the comment first.

---

## 8. What I would do next, in order

1. **Fix `apiKey.ts`'s prefix to `cafaye_`** (§1.2). One line, one repository, and
   until it is fixed the other two MD18 defects are unobservable.
2. **Decide where a browser session lives.** This is the deferral in §2 and it is a
   design question, not an implementation one: identity's store is keyed by digest
   and cannot be inverted, so the options are (a) a gateway-side store — Redis, the
   `TODO(guard-07)` the reference already names — with identity's session TTL
   honoured as data, or (b) a token-format that is itself the cookie, encrypted and
   authenticated, with no store at all. (b) is stateless and is what several BFFs
   do; (a) is revocable, which the contract wants ("a leaked assertion is bounded but
   not revocable" is the same complaint about assertions). **I recommend (a)**, and
   the reason is revocation: `POST /auth/logout` already tells the caller "the token
   may outlive this" in the `503` case, and a design that cannot revoke makes that
   the common case rather than the exception.
3. **Teach `RuntimeOptions` to build a `BFF` from `IDENTITY_URL`** and register the
   `identity` readiness probe there — the same commit, because `createApp({bff})`
   answers `{"deps":{}}` and the two must not come apart.
4. **Decide the 400-day cookie ceiling** (§7.2) before anyone sets identity's session
   TTL above it.

---

## 9. Verification, as measured

Every command below was run from the worktree with a bounded `timeout`. Nothing was
left running. No container, image or volume was created; nothing was pruned; the
shared Go build cache was not cleared.

```
$ timeout 900 ./bin/prime-go
  suite: 83 passed, 0 failed
  packages: 3 with tests
  equivalence: RAN — the summary line is above
    equivalence_test.go: 24 cases x 9 scenarios = 306 comparisons, 0 differences
                         (status, Content-Type, 12 compared headers, body bytes)
  internal/api/api.gen.go regenerates byte-identically from openapi/v1.yaml
==> ok

$ timeout 1800 ./bin/prime
==> prime ok (bun 1.3.12)

$ timeout 1200 ./mutation-gate.sh
snapshot: 19 file(s) under cmd/ and internal/, to be restored by copy
mutation gate: 39 bit, 0 did not
```

**Counted skips: none.** The equivalence tier ran — `bun` was on `PATH`, so
`GATEWAY_EQUIVALENCE_REQUIRED` was never consulted and nothing was skipped. No tier
was sharded, no `--no-live` flag was used, and no Redis or Postgres was needed: the
data path here is `Doer` and `SessionStore`, both injected, which is the point of
the seams. `internal/sessiontest`'s `Fail` type exercises the store-is-down path and
`TestAHungIdentityIsBounded` the unbounded-dependency path, both without a socket —
and `TestNoFileInThisPackageTalksToARealSocket` reads this package's own sources to
keep it that way, so "no real dependency" is a measured property and not a claim.

**Before and after, for the five findings in §3**, measured by
`./measure-findings.sh` on the same machine. That script applies each fix's
**inverse** mutation and asks the equivalence check how many of its 306 comparisons
differ, so each "before" is a run and not a recollection:

```
$ ./measure-findings.sh
finding (§3)                                        before    after
--------------------------------------------------------------------------
the port as it stands                                   n/a        0
3.1 the problem envelope's field order                101        0
3.2 writeRawJSON overwrites the content type          101        0
3.3 a BFF auto-registers an identity probe             12        0
3.4 a doubled Sec-Fetch-Site is joined                  6        0
3.5 a non-revoking logout answers unusable               2        0
```

**101, not the 13 I first wrote down,** and the correction is worth keeping rather
than quietly overwriting: the field order and the content type each affect **every
problem document in every browser scenario**, not just the ones the first failing run
managed to print before it aborted in `signIn`. The honest number is the one measured
with the suite able to finish. The five are not additive — a document can differ in
bytes *and* in content type — so 101 + 101 + 12 + 6 + 2 is **222
difference-instances across five independent defects**, against a ceiling of 306 × 5.

The shape of each number is the interesting part:

- **3.1 and 3.2 are both 101**, because both apply to every problem document the
  browser surface produces. Two defects, identical reach, invisible for the same
  reason: an envelope the substrate ported for five operations that all *declined*.
- **3.4 is 6** — exactly the six browser scenarios. A defect that only exists where
  the surface is mounted cannot show up in `bare`, and a suite that only asked the
  bare configuration would have called it absent.
- **3.5 is 2** — only the two scenarios where a logout's revocation answer is not a
  revocation.

After all five: **306 comparisons, 0 differences.**

---

## 10. Process hygiene, and a leak I found but did not fix

**Nothing of mine is left running.** After the final gate I scanned every `bun`,
`go test` and `reference.ts` process on the machine and checked each one's working
directory: no process has `wt-m39-gateway-go-bff-01` as its cwd.

**Two `reference.ts` processes from OTHER worktrees are still running**, and I left
them alone because the contract says not to touch another session's work:

```
pid  2188  cwd …/wt-m39-gateway-go-substrate-01/internal/equivalence   elapsed 2:41
pid 37824  cwd …/wt-m39-gateway-go-proxy-01/internal/equivalence      elapsed 0:52
```

Note that `wt-m39-gateway-go-substrate-01` is **not in `git worktree list`** — that
worktree appears to have been removed while its process was still running, which is
the one hazard §7 of the worker contract names and it has already happened once.

**The leak itself is a finding, and it is in code this packet made worse.**
`internal/equivalence`'s `standUpReference` kills the reference in a `stop`
closure, registers it with `t.Cleanup`, *and* calls it explicitly in the loop — so
there are three paths that should each reap it and evidently one that does not. The
most likely culprit is that `stop()` is only reached when the loop completes: an
`ask` that calls `t.Fatalf` aborts the test, `t.Cleanup` fires for every reference
staged so far, and a reference started in the same iteration is never reached by
either path. It only shows up when something fails.

I did not fix it. It is in `internal/equivalence`, which is shared, and a
concurrency change to the harness belongs with whoever owns the equivalence check's
next substantive change rather than at the end of a packet about the browser
surface. **It is harmless to correctness** — a leaked reference holds an ephemeral
port and answers only the requests made to it — and it costs a process per failed
run.

The successor's first five seconds on this: `t.Cleanup(stop)` unconditionally, and
drop the explicit `stop()` call so there is one path rather than three.
