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

**Not by porting. It is a contract change, it obliges both implementations in the
same commit, and three of the shapes are not decided anywhere.** The audit's
"structurally blocked" is correct; §2.4 is what "structurally" means and §2.5 is
what it would cost.

*(Section drafted in the Q2 commit.)*

---

## Gates

| gate | result |
| --- | --- |
| `gofmt -l internal/ratelimit/` | clean |
| `go vet ./internal/ratelimit/` | clean |
| `go test ./internal/ratelimit/ ./internal/httpapi/` | pass |
| `GATEWAY_EQUIVALENCE_REQUIRED=1 go test ./internal/equivalence/` | pass — **51 cases across 13 scenarios = 914 comparisons, 0 differences** |
| planted mutation, Go tree (`60`→`600`) | **4 assertions fail**, as quoted in §1.7 |
| planted mutation, reference (`60`→`600`) | **17 pass / 0 fail** — the gap §1.7 is about |

`openapi/v1.yaml`, `internal/httpapi/httpapi.go`, `.github/workflows/ci.yml`,
`README.md`, `AGENTS.md`, `cafaye.yml` and `src/**` were not modified. Both planted
mutations were reverted; `git status src/` is empty.