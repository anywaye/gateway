# REPORT: `gateway-session-store-01` — a session store the Go binary can build

Worker: `m39-gateway-session-store-01`. Branch: `worker/m39-gateway-session-store-01`.

The packet's first deliverable was an answer, not code: **two recorded claims were
to be verified rather than inherited**, because a claim in a document is a
reader's premise and both of them decide which of two shapes the answer takes.

Both hold. The recorded reason was right. That is worth stating plainly, because
the shape this packet takes next is the expensive one — path (a), a real store —
and it is taken on the strength of a measurement rather than on the strength of a
comment that happened to agree with what the author wanted to build.

---

## Q1. Does identity's session store really key on `token_digest` and resolve in one direction only?

**Yes. Verified in the schema and in the code, and the verification is stronger
than the claim it checks: the token is not in the table at all.**

Three independent pieces of evidence, and the third is the one that settles it.

**1. The schema has no column for the presented value.**
`cafaye/identity/migrations/00003_sessions.sql:21-47`:

```sql
CREATE TABLE sessions (
    id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    token_digest text        NOT NULL,
    expires_at   timestamptz NOT NULL,
    ...
);
CREATE UNIQUE INDEX sessions_token_digest_key ON sessions (token_digest);
```

and the file's own header, lines 3-12: *"login mints one 256-bit random token,
hands it to the client twice … and stores only its SHA-256."*

**2. The only read takes a token and hashes it.**
`cafaye/identity/internal/sessions/store.go:86-90`:

```go
func (s *Store) ByToken(ctx context.Context, q db.Querier, token string, now time.Time) (Session, error) {
	const query = `
		SELECT ` + sessionColumns + `
		FROM sessions
		WHERE token_digest = $1 AND expires_at > $2`
```

The whole read surface of the table is `Create`, `ByToken`, `Revoke(id)`,
`RevokeAllForUser`. There is no function anywhere in identity that takes a hash or
an id and returns a token.

**3. Therefore the inverse lookup is not merely unimplemented, it is unimplementable
from that table.** `internal/session`'s comment states this as a design property
and this is where it comes from: `NewSession` takes a `TokenDigest` precisely so
that no code path in identity *can* produce the raw credential. "Nothing there
performs that direction" is an understatement that flatters identity's design —
the value is not stored, so there is nothing to perform it from.

The row's `id` is `gen_random_uuid()`, identity's own id. It is not the gateway's
cookie value, and the gateway never learns it: the BFF mints its own
`crypto.randomUUID()` per login precisely so session fixation needs an id the
attacker did not choose (`internal/session`'s `Put` comment, and `login` in
`internal/httpapi/bff.go`). So even a hypothetical identity endpoint keyed on that
id would not be the thing the gateway is asking for.

**The second half of the recorded claim also holds: identity exposes no inverse
lookup over HTTP.** `/v1/session` in `cafaye/identity/openapi/v1.yaml:470` carries
exactly two operations, `post:` (line 471, login) and `delete:` (line 634, revoke
by the token the caller presents) — no `get:`. And identity's non-`internal`
packages are three: `client`, `client/generated`, `cmd/identity`. None of them
names a session. So there is no third route either: not the Go package, not the
table, not an endpoint.

**Consequence for this packet:** the recorded reason is correct and stays. What
changes is only that it no longer implies there is nothing to do — see the decision
below.

---

## Q2. Does Go's `internal/` rule actually forbid the import?

**Yes — and this one is answered by the compiler rather than by reading, because
that is the only way to answer a question about what a build system permits.**

A throwaway module in a scratch directory, with `replace` pointing at the identity
checkout, importing `github.com/cafaye/identity/internal/sessions`:

```
module probe
go 1.26.1
require github.com/cafaye/identity v0.0.0
replace github.com/cafaye/identity => /Users/kaka/Code/any/moon/cafaye/identity
```

```
$ go build ./...
/Users/kaka/Code/any/moon/cafaye/identity/internal/platform/db/seam.go:6:2: missing go.sum entry for module providing package github.com/jackc/pgx/v5 …
main.go:4:2: use of internal package github.com/cafaye/identity/internal/sessions not allowed
```

`use of internal package … not allowed` is the go command's own refusal, from
`cmd/go/internal/load/pkg.go`, because the importer is not within
`github.com/cafaye/identity/…`. Note the shape of the failure: it arrives
*alongside* unresolved-dependency errors and not instead of them, so a reader who
skimmed the first three lines would have concluded "the import failed for want of
a dependency". It did not. The last line is the one that matters and it is the
one that was easy to miss.

So both halves of `internal/session`'s recorded justification are facts. Reaching
identity's store would mean identity publishing that package outside `internal/`,
which is a change to another service's public surface and is not this
repository's to make.

---

## The decision: path (a), gateway owns its sessions in Redis

Both claims hold, and neither of them blocks path (a). They block exactly one
route — "reuse identity's table" — and that route was never going to be correct:
it would have handed the service that mints credentials the job of remembering
them in the clear, which is the exact property identity's schema is built to
prevent.

**So: gateway owns its sessions, in Redis, over the RESP2 transport it already
speaks, sharing one client with the limiter.**

What made this cheap is a fact in the tree rather than a decision taken here:
`RuntimeOptions` already reads `REDIS_URL`, already builds
`ratelimit.NewLazyRedis`, and already hands that one connection to the limiter
(`internal/httpapi/runtime.go:150`, `counterStore` at line 407). So:

- **One client, one socket, one mutex.** `LazyRedis.Connect()` caches the
  connection, so the limiter's `Eval` and a session store's `GET`/`SET`/`DEL` are
  the same `*ratelimit.Connection` and the same command-in-flight-at-a-time lock.
  The packet's warning is the reason it is done this way and not by copying
  `resp.go`: two implementations of one protocol start disagreeing, which is
  exactly the defect this repository just fixed in the limiter.
- **It is the equivalent shape, not the degraded one.** A per-process `sync.Map`
  would be a port of the *worse* of two designs into the language that makes the
  better one easier to write, which is what `internal/session` refused. Redis
  means a browser's session survives a restart and is shared by every replica.

### What the store has to reproduce, taken from `src/bff/session.ts`

The port's own convention is to find what the reference specifies and reproduce
it. Read against that file, the contract is narrower than "three methods":

| property | the reference | what the Redis store must do |
|---|---|---|
| key shape | a `Map` keyed by the id gateway minted | `gateway:sess:<id>` — asserted id, asserted namespace, no caller bytes in a key |
| expiry | `expiresAt` from the token, compared on read | the value carries `expiresAt`; `SET … PX` is a backstop, never the source of truth |
| absent vs expired | one answer: `null`, and the record is dropped on the way out | `GET` nil → absent; `expiresAt <= now` → `DEL`, return absent |
| the boundary | `expiresAt <= now()` — **`<=`, not `<`** | the same operator, or a session lives one millisecond longer here than there |
| `delete` of an absent id | succeeds | `DEL` of an absent key succeeds |
| an already-expired `put` | stored, then reads back as absent | stored, clamped to a 1 ms TTL, reads back as absent |
| `maxSessions` | a bound on retained memory, "not a cap: a live session is never evicted" | no bound, and none needed — that is what a shared store is |

Two rows are the ones a careless port gets wrong, and both are called out above
because they are the ones where the naive implementation is *more* correct
looking. `<=` becomes `<` and a session outlives its token. An already-expired
`put` gets refused for having no TTL, and the BFF turns a login into a 500 over a
token identity had already minted and already expired.

### The one genuinely new property: a session id is caller input

The limiter has `AssertBucket` because an `account_id` claim becomes a Redis key.
**The same hazard is here and the recorded reason does not mention it**: `Get` is
handed the `__Host-bff-session` **cookie**, which is whatever the caller sent.
`Put` is gateway-minted and safe; `Get` and `Delete` are not. A store that
concatenates that value into a key lets a caller choose arbitrary keys in
gateway's namespace, and `Delete` gives them a delete.

So the id is asserted at construction and at every key-shaped operation, against
the shape gateway actually mints. This is a finding rather than a transcription:
the reference has no equivalent because a `Map` cannot be escaped by a crafted
key, which is precisely why the hazard only appears when the map becomes a shared
store.

### What this does NOT do

Recorded here because the next reader will wonder, and a silent "no" is how a
defensible limit becomes an accident:

- **It does not delete or weaken `internal/sessiontest`'s guard.** The double is
  still a fixture, and `TestNoProductionFileImportsTheSessionDouble` still runs.
  The Redis store is a second implementation, not a replacement for the tripwire.
- **It does not make the session store optional.** A gateway with `REDIS_URL` and
  no `IDENTITY_URL` still serves no browser surface; a gateway with `IDENTITY_URL`
  and no `REDIS_URL` refuses to build one, because a per-process store is the
  thing this packet exists to stop. `/auth/*` on nothing is `404`, which is what
  `createApp({})` does — and that stays a **configuration**, not a fallback.
- **It does not store a digest.** Gateway has to return the token to put it in a
  `Bearer` header for `/v1/me`, so the token is stored in the clear in Redis.
  That is the reference's posture (`Map<id, token>`) and the honest one, but it is
  a different posture from identity's and it is named rather than glossed.
- **It does not touch `/v1/me`, the route table, the proxy, the assertion, or the
  limiter.** Other packets own those surfaces.
- **It does not register an `identity` readiness probe from `New`.** That is
  `runtimeOptions`' job, and the existing comment in `httpapi.Options.Probes`
  records the measurement for why: `createApp({bff})` answers `{"deps":{}}`, so a
  probe added in the wrong place makes `/readyz` differ from the reference at
  byte 9.

---

## What landed, and how it was proved

`internal/sessionredis` is the store. It reproduces `src/bff/session.ts` rather than
inventing a session model, row by row:

| the reference does | this store does |
|---|---|
| `Map` keyed by the minted id | `gateway:sess:<id>`, prefix fixed, no operator knob |
| `expiresAt` compared on read: `expiresAt <= now()` | the same comparison, the same **inclusive** boundary |
| expired record dropped on the way out | `GET` then `DEL`, the same read-is-the-sweep reasoning |
| `delete` of an absent id succeeds | `DEL` of an absent key succeeds |
| an already-expired `put` is stored, reads back absent | stored, `PX` clamped to `1`, reads back absent |
| `maxSessions` bounds retained memory, never evicts a live session | no bound, and none needed |

It is built on `internal/ratelimit`'s client and `RuntimeOptions` hands **the same
`*LazyRedis`** to the limiter and to the store. `sessionredis` declares its own
one-method `Commands` and a `Connecter` for the lazy client rather than widening
`ratelimit.LazyRedis`, so `internal/ratelimit` gained nothing and lost nothing — the
change is confined to `counterStore`'s and `probeList`'s return type, and the nil
check there is now on a concrete pointer where a typed-nil interface would have been
the trap.

Two properties the reference cannot have, both found while porting:

- **A session id is caller input on `Get` and `Delete`.** It arrives in the cookie.
  The reference has no such hazard — a `Map` cannot be escaped by a crafted key —
  which is exactly why the hazard only appears when the map becomes a shared store.
  An id that is not the canonical lowercase UUID `login` mints is **absent** and
  issues no command, so no caller byte reaches a key. On `Put` the asymmetry is the
  other way and is deliberate: that id is gateway's, minted one line above the call,
  so a bad one is a defect here and is **refused**.
- **The token is stored in the clear**, because `Get` must return it. A digest could
  not answer, so this is forced by the BFF's claim rather than chosen. It is named
  in the package comment and in `README.md` rather than glossed, and `describe()`
  reports a reply by shape so no error path can log a credential.

### The wiring, which was the untested half

The gap was never the interface — it was that **nothing went from "these variables
are set" to "the routes are served"**. Every existing test built `Options{BFF: …}`
with the fixture, so a gateway with no store and a gateway with a store were
indistinguishable from outside.

`internal/httpapi/runtime_session_test.go` closes that, and it runs against a **real
`redis-server` started in-process on a free port**:

```
$ go test ./internal/httpapi/ -run 'Runtime|Session|Configured|Unconfigured|Browser' -v
--- PASS: TestARuntimeGatewaySignsInAndReadsItsOwnSession (0.03s)
--- PASS: TestASessionSurvivesTheProcessThatCreatedIt (0.03s)
--- PASS: TestANoStoreMeansNoBrowserSurfaceRatherThanADegradedOne (0.00s)
--- PASS: TestAnUnconfiguredGatewayDeclinesTheFourRoutesAsTheReferenceDoes (0.00s)
--- PASS: TestAConfiguredBrowserSurfaceAnswersItsOwnRoutesRatherThanDecliningThem (0.00s)
--- PASS: TestAnUnusableIdentityURLIsARefusalToBoot (0.00s)
ok  	github.com/cafaye/gateway/internal/httpapi	0.752s
```

No `GATEWAY_REDIS_URL` and **no skip**: the server is executed by the test, so a
developer with no Redis gets a *failing* test that says so rather than a passing one
that proved nothing. That is the fourth instance in this repository of a gated tier
that could go green without running — the limiter's `TestMain` exiting 0 before
`m.Run`, the equivalence tier's skip into a void, and the codegen step's `|| true`
are the other three — and the shape here is deliberate rather than accidental.

The headline assertion is the whole exchange, not a status: login → cookie →
`/auth/me` with the cookie → logout → the same cookie is `401`. And
`TestASessionSurvivesTheProcessThatCreatedIt` builds a **second gateway from the same
environment** and reads the first one's session — the property a `Map` cannot have,
and the reason this packet exists rather than a refusal.

### The guards, as a pair

`internal/sessiontest`'s `TestNoProductionFileImportsTheSessionDouble` proves the
**fixture** is not linked. `internal/sessionredis`'s `TestTheShippedBinaryLinksThisStore`
asserts the **real** store **is**. A guard that only ever says "no" cannot notice that
the "yes" stopped happening, and that is precisely the shape of the gap this closed —
so the inverse guard is not decoration.

### Planted divergences, because a guard has to be shown to fail

Three, each reverted, each caught by the named test:

| planted | caught by | how |
|---|---|---|
| `browserSurfaceFromEnv` always returns nil | `TestARuntimeGatewaySignsInAndReadsItsOwnSession`, `TestASessionSurvives…`, `TestAConfiguredBrowserSurface…` | the four routes answered `404` — with the message naming the defect |
| the expiry check removed | `TestTheExpiryBoundaryIsInclusive` | `a session expiring exactly now is live=true, want false`, and the `DEL` never issued |
| the id assertion removed | `TestCallerSuppliedBytesNeverReachAKey` | `GET gateway:sess:../../config` — caller bytes in a key |

### The narrow gate

```
$ bin/prime-go
==> ok

suite: 187 passed, 0 failed
packages: 6 with tests
```

The one line to read rather than skip past is
`ratelimit: DID NOT RUN — GATEWAY_REDIS_URL is unset`, which is the **limiter's**
gated tier and is unchanged by this packet. The session store's Redis tier is
`internal/httpapi`'s and it ran in the same invocation — a `redis-server` is started
by the tests themselves, which is why it is not listed among the skips.

`go test -race ./internal/sessionredis/ ./internal/httpapi/` is also green.

---

## Left for a successor

1. **The `identity` readiness probe.** `RuntimeOptions` now reads `IDENTITY_URL` and
   builds the browser surface, but registering the `identity` probe is still
   elsewhere's job — `New` must not do it, because `createApp({bff})` answers
   `{"deps":{}}` and a probe there changes `/readyz` at byte 9. The successor who
   owns the remaining `runtimeOptions` variables should register it *and* confirm the
   probe order still renders identity-then-redis.
2. **Equivalence coverage for the wired surface.** `internal/equivalence`'s browser
   scenarios build `Options{BFF: …}` by hand and so still use `sessiontest`. They
   are correct — they compare the PORT, not the deployment — but there is now a
   second, stronger set of assertions in `runtime_session_test.go`, and the two
   should be reconciled rather than left to drift. The TypeScript reference uses a
   `Map`, so a browser scenario comparing both implementations cannot use Redis on
   the Go side without also giving the reference a store; that is a real constraint
   on that packet, not an oversight here.
3. **`REDIS_PREFIX` for sessions.** The limiter takes a sub-namespace; the session
   store deliberately has no operator-settable prefix (one namespace is one thing to
   reason about). If two gateways must share one Redis with separate session
   namespaces, the prefix becomes a knob and belongs in `REDIS_PREFIX` — a change to
   one variable, not to this design.