# REPORT: `gateway-api-keys-01` — the `/v1/api-keys` allowance, and what porting API keys would take

Worker: `m39-gateway-api-keys-01`. Branch: `worker/m39-gateway-api-keys-01`.

Two questions, and they have different shapes. **The first is a number**, and it
is settled by the shape of a table that is already in the tree. **The second is a
contract**, and it is not settled here: it is enumerated, priced, and handed back.

The headline of the first is that the Go gateway already matched the reference and
still does — so the answer is "no code change", which is the least satisfying shape
a packet can have and the one most worth writing down carefully, because "I looked
and it was fine" and "I did not look" produce the same diff.

---

## Q1. Is `/v1/api-keys` at 60/min a deliberate tightening or a typo?

**Deliberate. It stays. The Go side matched before this packet and matches now —
verified byte for byte, not read off a table.**

### 1.1 What the reference actually does (measured, not read)

`src/middleware/limits.ts` is the specification, so it was executed rather than
believed. Both implementations, same eight paths:

| path | reference | Go |
| --- | --- | --- |
| `/v1/api-keys` | `60`/60s `gateway-api-keys` | `60`/60s `gateway-api-keys` |
| `/v1/api-keys/` | `60`/60s `gateway-api-keys` | `60`/60s `gateway-api-keys` |
| `/v1/api-keys/key_abc` | `60`/60s `gateway-api-keys` | `60`/60s `gateway-api-keys` |
| `/v1/api-keys?x=1` | `60`/60s `gateway-api-keys` | `60`/60s `gateway-api-keys` |
| `/v1/api-keysfoo` | `600`/60s `gateway-api` | `600`/60s `gateway-api` |
| `/v1/apikeys` | `600`/60s `gateway-api` | `600`/60s `gateway-api` |
| `/v1/me` | `600`/60s `gateway-api` | `600`/60s `gateway-api` |
| `/v1/` | `600`/60s `gateway-api` | `600`/60s `gateway-api` |

Identical, including the two rows a permissive matcher gets wrong.

**The resolution rule that produces the 60** is longest-prefix-on-a-path-segment-
boundary, in `limits.ts:124-150` and `limits.go:337-345`:

- `/v1/` claims `/v1/api-keys` — `path.startsWith("/v1/")`, because the entry ends
  in a slash;
- `/v1/api-keys` claims itself and its subtree — the entry has no trailing slash, so
  `claims` is `path === prefix || path.startsWith(prefix + "/")`;
- `/v1/api-keys` is 11 characters and `/v1/` is 4, so the longer one wins;
- `/v1/api-keysfoo` and `/v1/apikeys` match neither, and fall to `/v1/`'s 600.

The segment boundary is the load-bearing half and it is asserted in both trees
(`limits.test.ts:102`, `limits_test.go:236`). Without it, a prefix would claim by
name and a new top-level route would inherit an allowance for free.

### 1.2 Two things in the packet's framing that the numbers do not say

The packet's heading calls the entry "LOOSER than the default it inherits". **60 is
a tenth of 600 — it is tighter**, and the packet's own body says so ("allowed a tenth
of the traffic"). The question worth asking is therefore not "why is this looser",
which has no answer, but "why is a nested entry *tighter* than its parent", which
does.

The packet also calls `/v1/` "the anonymous bucket above it". **It is not
anonymous.** `src/index.ts:251` mounts the bearer gate on `/v1/*`, so `gateway-api`
is drawn by authenticated traffic; only `/auth/*` and an entry the route table marks
`public` reach the limiter with no credential. The comparison that matters is
therefore between two authenticated buckets, not between a credential surface and
the open internet.

### 1.3 The argument from the shape of the table

**Every entry in this table that names a new bucket is strictly cheaper than the
bucket it inherits. There is no exception.**

| entry | limit | policy | inherits from | ratio |
| --- | --- | --- | --- | --- |
| `/auth/register` | 5 | `gateway-auth-register` | `/auth/` 60 | 1/12 |
| `/auth/login` | 10 | `gateway-auth-login` | `/auth/` 60 | 1/6 |
| `/auth/logout` | 30 | `gateway-auth-logout` | `/auth/` 60 | 1/2 |
| `/auth/` | 60 | `gateway-auth` | default 600 | 1/10 |
| `/v1/` | 600 | **`gateway-api`** | default 600 | 1/1 — same name, same bucket |
| `/v1/api-keys` | 60 | `gateway-api-keys` | `/v1/` 600 | 1/10 |

The single entry that is not cheaper than what it inherits is `/v1/` — and it is not
cheaper **because it is not a new bucket**. It reuses the default's own policy name
`gateway-api` at the default's own 600. It is the same row written twice, and
`PolicyResolver` in Go exists precisely to make "same name" mean "same bucket".

So the table has exactly one way to add a nested entry: **make it cheaper, and give
it a name.** `/v1/api-keys` is the only entry on the `/v1` side that uses it.

This is the part of the answer that a copy-paste mistake does not produce. The
plausible typo mechanism is a dropped digit — `600` becoming `60` — and that
mechanism would land on an arbitrary number. It landing on *both* "strictly tighter
than my parent" *and* "the one number the table already spends on a named security
surface" is the wrong outcome for an accident and the obvious outcome for a choice.
The **direction** is the half of the number that the decision is about, and the
direction was chosen.

The honest counter-argument: 60 is also `/auth/`'s number, so copy-paste from the
`/auth/` block is a live mechanism too, and it would produce exactly this row. That
is why the argument above is about the invariant rather than about the number's
provenance — the invariant establishes that a *decision* was made about direction,
and it is compatible with the number itself having been copied. Both stories agree
on what the table does, which is the only thing that has to be settled here.

### 1.4 The argument from what the endpoint does

The entry's own comment says the reason: *"Minting and revoking credentials is a
write on the security surface."* Placed against the two other credential-adjacent
rows, that puts 60 where it is:

- **`/auth/login` is 10/min** because a password is **guessable work**. The
  per-minute number is what makes guessing slow.
- **`/auth/register` is 5/min** because account creation is the most abusable thing
  on the edge.
- **`/v1/api-keys` would mint a machine credential**: 32 CSPRNG bytes behind
  `caf_` (`apiKey.ts:209-213`). There is no dictionary and no brute force — the
  guessability argument that sets 10 and 5 does not apply, and pretending otherwise
  would be a rate limit doing no work.

But it is not cheap to leak either. A key is **durable**: it works until somebody
revokes it, it does not expire on its own, and a holder may never look at the list
that would show it. That is a different risk from guessing, and it is a risk with a
blast radius of "a standing credential for as long as nobody notices".

So the ordering the table already encodes is the right one: *guessable* work at 5
and 10, *durable credential issuance* at 60, *ordinary API traffic* at 600. Sixty is
the middle of the table's own logic, not an outlier in it.

### 1.5 Which half of the entry is actually load-bearing

**The name, not the number.**

The policy name is half the counter key (`limits.ts:8-14`), so `gateway-api-keys`
is what makes this row a *separate* bucket: a caller cannot spend its
credential-minting allowance by making ordinary API traffic, and exhausting one
cannot throttle the other. That is the security property, and it would survive the
number being raised to 600.

The number's job is narrower: bounding how fast one compromised session can fan out
into standing credentials. That is worth something, and 600/min would be a weaker
bound, but no value of it stops an attacker holding a valid credential — a caller
with a session can mint 60 or 600 keys, and both are more than a legitimate client
ever needs (a client mints a handful over its lifetime).

**The reference's own header already disclaims the number.**
`limits.ts:46-54`: *"The numbers are a starting point, not a measurement: nothing in
this repository has watched a real caller."* By the standard the file sets for
itself, 60-vs-600 is a configuration choice rather than a correctness property.

### 1.6 A correction to that disclaimer, which makes the number matter more

The header offers an escape hatch:

> *"an operator with a real traffic shape replaces this table with their own through
> `RATE_LIMIT_TABLE`"* — `limits.ts:53`

**That environment variable does not exist.** `RATE_LIMIT_TABLE` appears exactly
once in the whole repository — in the sentence above. `runtimeOptions`
(`src/index.ts:383-425`) reads `RATE_LIMIT_REQUESTS` and `RATE_LIMIT_WINDOW_MS`, and
both of those write the **default row only** (`src/index.ts:409-410`); nothing reads
a per-route entry from the environment on either side.

So the honest statement is the opposite of the one the header makes: **the shipped
number is not operator-tunable in a deployment today, in either language.** That
raises the stakes on 60 slightly, and it cuts in favour of it being deliberate —
a value nobody can override is a value somebody chose. It is a separate finding
rather than something to fix here, and it is named in `CHANGELOG.md`.

### 1.7 The parity finding: the reference's suite does not hold this number, and the Go tree's does

This is the part worth acting on, and it was measured by planting the mutation the
packet was worried about — `60` → `600` — in both trees.

**In the reference, the mutation is invisible:**

```
$ bun test src/middleware/limits.test.ts
 17 pass, 0 fail, 71 expect() calls
```

`limits.test.ts:74-78` asserts the **policy name** and no number:

```ts
test("/v1/api-keys is its own, tighter surface", () => {
  const limit = resolveLimit(table, "/v1/api-keys");
  expect(limit.policy).toBe("gateway-api-keys");
});
```

while pinning the number for every neighbouring entry (10 at line 39, 5 at line 47,
600 at line 71). That is a coherent position rather than an oversight — the name is
the half that cannot be adjusted without changing which bucket callers share — but
it means **the reference's suite would not notice this number changing in either
direction.**

**In the Go tree, four assertions catch it:**

```
--- FAIL: TestTheShippedTableIsTheOneTheReferenceShips//v1/api-keys
        limits_test.go:90: limit for "/v1/api-keys" is 600, want 60
--- FAIL: TestV1APIKeysIsItsOwnTighterSurface
        limits_test.go:215: limit is 600, want 60
--- FAIL: TestTheResolverGivesTheLimiterANameAndTheNumbersBehindIt//v1/api-keys
        limits_test.go:561: "gateway-api-keys" resolved to limit 600, want 60
--- FAIL: TestEveryShippedRouteDrawsItsOwnNamedAllowance//v1/api-keys
        runtime_limits_test.go:180: "/v1/api-keys" drew q=600, want q=60
```

The last of those is the strong one: it reads `q=` out of the `RateLimit-Policy`
header through the **whole HTTP stack** — header reduction, bearer gate, limiter —
so it holds the number a caller actually sees rather than the number in a map.

**The consequence, stated carefully:** parity here is currently held by the *Go*
suite, not by the reference. The Go side cannot drift without a red gate; the
reference could drift silently and the Go tests would then be *right* and *different*.
That is the safe direction to fail in, and it is the argument for leaving the four
assertions exactly as they are.

**A gap this exposes, and does not close:** the equivalence tier cannot see this row
at all. `internal/equivalence/equivalence_test.go:75-76` says so — *"The rest of
Wave 3. No API keys, so no `/v1/api-keys/*` operation answers anything but `404`"* —
because the tier derives its routes from the contract, and the contract does not
name `/v1/api-keys` (§2). So `GATEWAY_EQUIVALENCE_REQUIRED=1` passing tells you the
two implementations agree on every route **either of them declares**, and this path
is not one of them.

### 1.8 What changed

No number moved, on either side.

`internal/ratelimit/limits.go` gained the argument as a comment on the
`/v1/api-keys` row — the row's existing comment is copied from the reference and
states the *intent* ("its own budget") without recording that the number was
checked. That gap is exactly how the next reader re-raises this. `limits_test.go`
was **not** touched: the packet's ownership note limits it to changes that make Go
match the reference, and a new Go-only invariant assertion is not that.

The comment names the invariant, the counter-argument, and the four assertions, so
the next person to read a number that looks wrong learns what was already considered
rather than starting over.

### 1.9 What would change this answer

Stated so the decision is falsifiable rather than merely made:

- **A measurement.** Anything showing a legitimate caller needs more than 60
  issuances a minute. Nothing in this repository has watched a real caller, and
  neither has anyone else yet — which is the whole basis of the file's own
  disclaimer, and the reason this answer is "deliberate, and revisable by a
  deployment with data" rather than "deliberate, permanently".
- **A document that names `/v1/api-keys`.** §2 argues the entry is a
  pre-declaration for a route that does not exist yet. Once the route is real, the
  row stops being a prediction and becomes an assertion about traffic, and the right
  number is arguable on the route's actual shape.
- **A worked traffic shape** — say, a CI system that mints a key per job on a shared
  runner — where 60/min would throttle something legitimate. That is the case the
  number was never tuned against, and it is the one to watch.

None of those is a reason to diverge the Go side from the reference now. If one of
them arrives, it is a packet that changes `src/middleware/limits.ts` **first**, and
the Go side follows.

---

## Q2. Can API-key management be ported to Go?

**No — and the reason is worth stating precisely, because "no generated server to
hang handlers on" undersells it.** Three operations would have to be **added** to
`openapi/v1.yaml`. That is a contract change, and it is the wrong shape for a port:
a port makes two implementations agree about a contract that already exists.

The packet asks for the operations if they are absent. They are absent, and §2.5
enumerates all three. §2.6 says what else in the tree would have to move with them,
which is the part that makes this a manager decision rather than a worker one.

### 2.1 What `src/middleware/apiKey.ts` actually serves

Five exports, and only **three** of them are HTTP operations. The distinction
matters because a reader who counts five will over-scope the work.

| export | kind | HTTP operation? |
| --- | --- | --- |
| `generateApiKey`, `hashApiKey`, `apiKeyPrefixOf` | helpers | no — pure functions, and `hashApiKey`/`apiKeyPrefixOf` have no route in either language |
| `memoryApiKeyStore` | a store | no — a v0 implementation of the trait |
| `createApiKeyAuth().authenticate` | **middleware** | **not a route** — mounted on `*` at `src/index.ts:184-188`, and it authenticates rather than serves |
| `createApiKeyAuth().issue` | operation | **yes** — no route calls it in either language |
| `ApiKeyStore.list` / `.revoke` | operations | **yes** — no route calls them in either language |

So the file's three *management* operations have **no HTTP surface at all, in
either language**. `grep -rn "api-keys"` across the repository returns the limit
table entry, the tests, and the docs — never a registered route.
`tenantIsolation.test.ts:326-327` says so as an assertion:

```ts
expect(app.routes.map((route) => `${route.method} ${route.path}`)).not.toContain("GET /v1/api-keys");
expect((await app.request("/v1/api-keys")).status).toBe(401);
```

**This reframes Q1.** The `/v1/api-keys` row is not a rate limit for a live route.
It is an **allowance declared for a route that does not exist yet** — a
pre-declaration, held to 60 because the author was thinking about what the surface
*would* deserve. That is a third reason the number is deliberate, and it is
stronger than the two in §1.3 and §1.4: nobody mistypes a number for a route they
have not written, because there is no request to have mistyped it on. It is a
number chosen **before** the question of traffic existed, which is exactly what a
starting-point-not-a-measurement number looks like.

It also means the row is currently **inert on the wire**: no route claims
`/v1/api-keys`, so nothing in either implementation ever draws
`gateway-api-keys`. The four Go assertions that catch a `60`→`600` mutation are
asserting the resolution *rule* produces that number for that path, not that any
caller is throttled by it today.

### 2.2 What `openapi/v1.yaml` declares: nothing

The document declares seven operations across seven paths (`/healthz`, `/readyz`,
`/v1/me`, `/auth/register`, `/auth/login`, `/auth/logout`, `/auth/me`) and **zero**
`api-keys` operations. The `apiKeyCredential` **security scheme** at
`openapi/v1.yaml:767-789` is a different thing and is easy to mistake for
coverage: it declares how a caller *presents* a key, and it is referenced by
`GET /v1/me`'s `security:` (line 389) — but there is no operation that *manages* one.

The document even says so itself, at lines 787-789:

> *"Nothing in gateway hands a key out yet — see 'Not built yet' in the repository
> README. A client holding one today is talking to a deployment that issued it out
> of band."*

So the absence is **recorded, not accidental**. That is worth saying plainly: this
is not an oversight the audit discovered, it is a deliberate state the document
states.

### 2.3 Why the Go router cannot have a route the document does not name

Three mechanisms, and they compound:

1. **The Go router IS the generated file.** `internal/api/api.gen.go` is
   `oapi-codegen` output from `openapi/v1.yaml`, and `oapi-codegen` emits one
   `r.Get(...)`-style registration per declared operation. `grep -c "ApiKey" internal/api/api.gen.go`
   returns **0** — there is no identifier to grep for, because nothing in the
   document produced one.
2. **The route/document test holds both directions.**
   `internal/httpapi/routes_test.go:136-180` walks chi's live router with
   `chi.Walk` and compares it to the registrations parsed out of the generated
   file. A route the document does not declare is "a gateway answering something
   nobody contracted for"; a declaration the router does not serve is "a document
   promising an answer the service will not give". Both are test failures.
3. **The gate proves the generated file is current.** `bin/prime-go` regenerates
   `api.gen.go` and diffs it. A hand-written route added beside the generated one
   would be caught — and the `stripbaseurl` step, per AGENTS.md, means a
   registration the recogniser cannot read is an *invisible* one, which is why the
   parser at line 57 refuses to match nothing.

The TypeScript side is held the same way: `test/openapiDocument.test.ts` reads
`app.routes` and the document and fails in both directions, and its `EXCLUSIONS`
list is exactly two entries — `ALL /v1/*` and `ALL /*`, both mounts — with an
assertion at line 257 that no exclusion can match an operation, so a new route
under `/v1/` cannot fall into a carve-out.

### 2.4 The awkward consequence: it is not only the Go side

This is the part that changes what the packet is.

Adding operations to `openapi/v1.yaml` **obliges the TypeScript reference to grow
matching routes in the same commit**, or `test/openapiDocument.test.ts` goes red on
the tree that is currently the specification. The document does not describe what
Go has implemented; it describes what *gateway* answers, and gateway answers it in
TypeScript until `src/` is deleted.

So this is not "port the missing piece to Go". It is **"add a feature to the
reference, then add it to the port."** The order matters and cannot be reversed:
the contract first (a deliberate change), then the reference implementation, then
the Go one — with the equivalence tier gaining the ability to compare the new
routes at each step.

### 2.5 The operations that would have to be added

Enumerated for a decision, **not written into the document.** Shapes come from
`src/middleware/apiKey.ts`; the `RateLimit-*` headers on every success response are
mandatory by `test/openapiDocument.test.ts`, which reads the header names from
`RATE_LIMIT_HEADERS` rather than from a typed list — so all eight appear on each
`2xx` as well as on the `429`.

**1. `POST /v1/api-keys` — mint a key**

```yaml
/v1/api-keys:
  post:
    tags: [api]
    operationId: createApiKey
    security: [ { bearerToken: [] }, { apiKeyCredential: [] } ]
    requestBody:
      required: true
      content:
        application/json:
          schema: { $ref: '#/components/schemas/CreateApiKeyRequest' }
    responses:
      '201':  # ApiKeySecret — the ONLY time `key` is ever returned
        # + all eight RateLimit-* headers
      '400': MalformedBody
      '401': Unauthenticated
      '422': ValidationFailed      # a blank or multi-word scope — `requireScopes`, apiKey.ts:373
      '429': Throttled
      '500': InternalError
      '503': Unavailable
```

The request body is `{ scopes: string[] }`. **`accountId` is not a field** — it is
taken from the verified principal, and its absence is the tenancy boundary. A
document that let a caller name `accountId` would describe the cross-tenant bug as
a feature.

The response is `IssuedApiKey` (`apiKey.ts:47-54`): `{ key, prefix, id }`, with
`key` the only time it exists and no endpoint anywhere able to print it again.

**2. `GET /v1/api-keys` — list the caller's keys**

```yaml
    get:
      tags: [api]
      operationId: listApiKeys
      security: [ { bearerToken: [] }, { apiKeyCredential: [] } ]
      responses:
        '200':  # ApiKeySummary[] — id, prefix, scopes, revokedAt. NOT `hash`.
        # + all eight RateLimit-* headers
```

`204` is available for the empty case; the document would have to pick.

**3. `DELETE /v1/api-keys/{id}` — revoke one**

```yaml
  /v1/api-keys/{id}:
    delete:
      tags: [api]
      operationId: revokeApiKey
      security: [ { bearerToken: [] }, { apiKeyCredential: [] } ]
      parameters:
        - $ref: '#/components/parameters/ApiKeyId'   # `key_<uuid>`
      responses:
        '204':  # unconditional — see below
        # + all eight RateLimit-* headers on the 204
        '401': Unauthenticated
        '429': Throttled
        '500': InternalError
```

Two new schemas (`CreateApiKeyRequest`, `ApiKeySecret`/`ApiKeySummary`) and one new
parameter. **`Problem.code` needs no change** — every refusal above maps onto the
nine codes already at lines 966-975.

### 2.6 Three decisions the packet cannot make, and why each is not a detail

**1. Does the listing response carry `hash`?** `ApiKeyRecord` (`apiKey.ts:57-68`)
has six fields, one of which is `hash`. Rule 1 at the top of the file says only the
hash is *stored*; rule 2 says only a prefix is ever *shown*. `list`'s doc comment
says it returns records "for display". Those are compatible only if `hash` is
stripped at the wire boundary — so `ApiKeyRecord` needs a display projection, and
nothing in either tree builds one. Serialising the record as-is would return a
SHA-256 digest of every credential the account holds, which is not the secret but
is not something an endpoint should hand over either. **A `404` here is the
difference between a projection and a dump, and it is a schema decision.**

**2. Is `DELETE` on a key that is not yours a `204` or a `404`?** `revoke` is
specified to refuse **by not acting** — no error, no return value
(`apiKey.ts:161-174`) — and `tenantIsolation.test.ts` asserts that a cross-tenant
revoke leaves `revokedAt` at 0. The reference's rule is that cross-tenant is
**absence**, not a distinguishable status, and `AGENTS.md` is explicit that a `403`
here is a finding to fix. An unconditional `204` is the shape consistent with both.
But **the document cannot say "there is no `404`" without the sentence explaining
why**, because every other operation in this document 404s on a missing resource
and a reader will assume the same here. This needs a stated decision.

**3. Is there a scope requirement on any of the three?** `requireScope`
(`src/middleware/jwt.ts:255`) exists and works, and `tenantIsolation.test.ts:491`
mounts it on a test app — but **no route in `createApp` uses it.** A caller with
any valid credential could otherwise mint, list and revoke keys. `AGENTS.md`'s
step 5 says a new route adds `requireScope(...)` after the gate. Which scope, and
whether revocation needs a *different, weaker* scope than issuance (an operator
revoking a compromised key is a recovery path, and gating it on the same capability
as minting means a compromised issuance-capable caller can also destroy the audit
trail) — **that is an authorization policy question, and it is the manager's.**

### 2.7 What else in the tree moves with it

Not the code — the *guards*. This is the part that decides whether the packet is
small or large.

| guard | what it does today | what a new route does to it |
| --- | --- | --- |
| `test/openapiDocument.test.ts` | holds document ↔ `app.routes` both ways | requires matching routes in **`src/`** |
| `internal/httpapi/routes_test.go` | holds router ↔ generated file both ways | the generated file grows 3 registrations; `len(declared) < 7` at line 179 must move |
| `test/tenantEntryPoints.test.ts` | derives account-scoped routes, store methods, and every `403` from source; asserts the kind counts `{ read: 5, list: 1, update: 3, delete: 2 }` (line 176) | **`GET /v1/api-keys` joins the derived route set at line 334**, which currently asserts `["GET /v1/me"]`; three account-scoped routes and three new negative cases, and the counts move |
| `test/noSkips.test.ts` | fails on any `skip`/`todo`/`only` outside a one-entry allowlist | unaffected — but the new Go tests must not reach for a skip to make the Redis-backed store pass |
| `internal/equivalence` | derives its routes from the document | **three new routes become comparable for the first time** — the tier's own header (line 75) currently excludes them |
| `README.md` "Not built yet" | lists "A Go gateway has no bearer-token verifier and no API keys" | must change, and a live worker owns README |

The `tenantEntryPoints` row is the one to read twice. Its comment at line 168-174
says `write` is "deliberately absent: gateway issues no key on any route, so there
is no request that *creates* account-scoped state for a caller to be refused."
**Adding `POST /v1/api-keys` makes that sentence false**, and the `OperationKind`
union gains a fifth member — which is the guard telling a feature author that the
feature has a tenancy surface. The derivation is what makes that automatic: a route
that takes an account fails the gate until its negative case exists, and the case
must be named in `tenantIsolation.test.ts`.

### 2.8 What this costs, in the order the work would happen

Stated so the decision can be weighed, and **not attempted here**:

1. **A decision** on §2.6's three questions (projection, `404` or `204`, scopes).
2. **The document** gains 3 paths, 2 schemas, 1 parameter — with the header's
   "Open decisions" list extended, since all three are contract changes rather than
   translations.
3. **The reference** gains the routes and the handlers in `src/`, keeping
   `openapiDocument.test.ts` green. `internal/ratelimit/limits.go` and
   `limits.ts` **do not change** — the `/v1/api-keys` row stops being inert at this
   point and starts being enforced, and the two sides already agree about that.
4. **`tenantEntryPoints.test.ts`'s derived set and counts**, plus three negative
   cases in `tenantIsolation.test.ts`.
5. **The Go port**, once the reference is the thing being compared against.
6. **A shared `ApiKeyStore`.** `memoryApiKeyStore` is per-process
   (`apiKey.ts:124-129`), and `TODO(guard-07)` says so. A Go port inherits the same
   problem, and the sibling packet already decided gateway **owns** its per-process
   state in Redis over the RESP2 transport `internal/ratelimit` already speaks — so
   this is one shared client with the limiter, not a fork.

**The honest summary:** step 1 is the packet. Steps 2-5 are mechanical once 1 is
answered, and 6 is already decided elsewhere. What makes this a contract change
rather than a port is entirely step 1 plus the obligation in §2.4 to change the
reference in the same commit.

---

## Gates

| gate | result |
| --- | --- |
| `./bin/prime-go` | **ok** — 230 passed, 0 failed across 6 packages with tests |
| generated server | `stripbaseurl` rewrote 7 registrations; `internal/api/api.gen.go` regenerates byte-identically from `openapi/v1.yaml` |
| `gofmt -l internal/ cmd/` | clean |
| `go vet ./...` | clean |
| `go build ./...` | ok |
| `GATEWAY_EQUIVALENCE_REQUIRED=1 go test ./internal/equivalence/` | pass — **51 cases across 13 scenarios = 914 comparisons, 0 differences** (status, Content-Type, 12 compared headers, body bytes; 22 also comparing the request the upstream received) |
| planted mutation, Go tree (`60`→`600`) | **4 assertions fail**, as quoted in §1.7 |
| planted mutation, reference (`60`→`600`) | **17 pass / 0 fail** — the gap §1.7 is about |
| Redis tier | did not run — `GATEWAY_REDIS_URL` is unset on this machine. This packet does not touch `internal/ratelimit`'s store, and CI's `redis` job is the tier that runs it |

`openapi/v1.yaml`, `internal/httpapi/httpapi.go`, `.github/workflows/ci.yml`,
`README.md`, `AGENTS.md`, `cafaye.yml` and `src/**` were not modified. Both planted
mutations were reverted; `git status src/` is empty.