# REPORT — mvp-guard-public-route-01

**What a public route now means for a deployment, in one sentence:** one entry in
`ROUTE_TABLE` may now carry `"public": true`, and that prefix is forwarded with no
caller credential — still rate limited, still refused for every other path, and
never carrying an upstream token, so a deployment can serve a public catalog read
without minting a credential it has no way to issue.

Branch `worker/guard-mvp-guard-public-route-01`, off `master` at `bafb296`. Two
commits. Not pushed, not merged — §2 of the worker contract reserves that for the
manager, and the packet's "Done means" line asking for a push is overridden by it.

---

## 1. The defect

The MVP directive is that `site → guard → identity/pantry → Postgres` runs end to
end locally. It did not, and MD18 measured why: **no credential could get through
guard's `/v1/*` at all**, for four independent reasons at once.

| # | what | where |
|---|---|---|
| 1 | site's client claims guard gates `/v1/*` on a `guard-api` scope. `requireScope` is never called outside tests — there is no scope gate. | `site/src/lib/pantry.ts:41`, `guard/src/index.ts:158` |
| 2 | `runtimeOptions()` declares `apiKeys` and handles it at `:140` but never sets it, so the key gate is unreachable in a running process. | `guard/src/index.ts:287` |
| 3 | the SDK sends `Authorization: Bearer cafaye_…`; guard's key gate matches `/^apikey(?:\s\|$)/i` and its key shape is `caf_` + 43 while identity mints `cafaye_` + 43. | `limitKey.ts:195`, `apiKey.ts:210,229`, `apikeys.go:75` |
| 4 | `guard-api` does not exist in identity's `AllScopes()`, and the only mint route is owner-and-session-only. | `apikeys.go:238-241`, `httpapi/apikeys.go:76` |

Closing it the way site's comment imagines is four repositories in sequence. MD18
rules instead that a `ROUTE_TABLE` entry may declare itself public. That is this
packet.

**How I proved the blocker was real** — I did not re-derive MD18; I read the four
call sites and confirmed the shape of each:

```
$ grep -rn "requireScope" src/     # never in index.ts, only jwt.ts and tests
$ grep -n "apiKeys" src/index.ts   # declared at 58, handled at 140, never set
$ grep -n "API_KEY_SCHEME" src/middleware/limitKey.ts
195:const API_KEY_SCHEME = /^apikey(?:\s|$)/i;
```

What I could not reproduce, and say so plainly: I did **not** run
`site → guard → identity` end to end. Doing so needs `identity` and `pantry`
built and running, neither of which is in this worktree, and the packet forbids
touching either. The blocker is MD18's measurement, read rather than re-measured.

---

## 2. What I changed

### `src/routes/table.ts` — the field and its validation

`RouteTarget` gains `public?: boolean`. Validated in **the same pass** as
`baseUrl` and `token` (`:155-190`), not as a later sweep — a field only checked
once the table is otherwise whole is a field whose rule has already been half-kept
by the time it runs.

Two refusals, and **the contradiction is refused rather than resolved**:

1. **A non-boolean.** `true`, `false` and absent mean something; everything else
   refuses. `{"public":"true"}` is what an operator writes when they mean public
   and have not checked that JSON has no booleans-as-strings. Coerced it is a
   route serving anyone — including `"false"`, which would open the route as
   surely as `"true"`.
2. **`public: true` with a `token`.** The two are different credentials answering
   different questions: `public` is about the **caller**, `token` is guard's own
   credential to the **service**. Guessing which one was meant would either hand an
   anonymous caller a credential-protected upstream, or quietly `401` a route the
   table calls open. Neither is visible from the running service, so it does not
   boot and the message names both ways out.

### `src/index.ts` — the gate

One line inside the existing `/v1/*` token gate:

```ts
if (c.get("principal")) return next();
if (routes !== null && isPublicRoute(routes, new URL(c.req.url).pathname)) return next();

return jwt.requireJwt(c, next);
```

`isPublicRoute` is a new export in `table.ts` that reads `resolveRoute` — the
**same function** the pass-through below it already calls. That is the property
worth having: the entry that mounts without a credential is the entry that
forwards. Two scans would be two spellings of "which prefix claims this path", and
a routing rule tightened in one would leave the other deciding who may reach it.
`public` also rides along on `ResolvedRoute`, so openness and destination come off
one winning entry rather than two independent lookups.

### What deliberately did **not** move

- **Rate limiting.** The limiter is mounted below the token gate and is untouched.
- **The API-key gate.** Still above it, so a caller who presents a key is judged
  on the key whether or not the route is public.
- **`/v1/me`.** Registered before the pass-through and unreachable from a table
  (`checkPrefix` refuses the prefix), so it can never be public.
- **`requireScope` and `apiKeys`.** Both correct, both separate packets, and each
  would turn this green **red** against today's identity — a scope that does not
  exist, and a store with no issuing endpoint. Left alone.
- **`site/src/lib/pantry.ts:41`.** Its comment becomes true next packet. Left
  alone, per the brief.
- **Every other repository.** Only `guard` was touched.

---

## 3. The tests, and the mutations that prove they bite

### The five the packet names

| # | test | file |
|---|---|---|
| 1 | a public entry serves an anonymous request — **the one that proves the packet does something** | `publicRoute.test.ts` |
| 2 | a non-public entry still answers an anonymous caller with **401** | `publicRoute.test.ts` |
| 3 | the public route is still rate limited — the 429 arrives | `publicRoute.test.ts` |
| 4 | startup refuses a non-boolean `public`, and refuses `public: true` with a `token` | `publicRoute.test.ts`, `table.test.ts` |
| 5 | a public entry does not leak the upstream token to the caller | `publicRoute.test.ts` |

Plus 6 more in `table.test.ts` and 12 more in `publicRoute.test.ts` — the
longest-prefix rule (a public `/v1/catalog` with a private `/v1/catalog/imports`
underneath), the segment-boundary case (`/v1/catalogx` is not open), `/v1/me` and
unrouted `/v1/` still `401`, a caller's own credential still not forwarded, and the
positive control that `public: false` with a `token` is ordinary.

### Mutations — verified in the file, not asserted by exit status

The sentence "the proxy path runs without `jwt.requireJwt`" has **three**
implementations and only one is this packet. Each mutation was applied with a
Python replace that asserted it matched exactly once, then **read back out of the
file with `grep`** before the suite was run, then reverted and re-verified.

| mutation | result | which tests went red |
|---|---|---|
| **A** — delete the public branch from `index.ts` (feature absent) | `11 pass / 6 fail` | "a public entry serves an anonymous caller" (the packet's test 1), both rate-limit tests, the leak test |
| **B** — `if (routes !== null)` with no `isPublicRoute` (**the `/v1/*` bug**) | `13 pass / 4 fail`; whole suite `534 pass / 6 fail` | **the packet's test 2** and 3 siblings, plus 2 pre-existing `proxy.test.ts` tests |
| **C** — disable the `public` + `token` refusal | `24 pass / 1 fail` | `` `public: true` with a token, which is two credentials and one undecided operator `` |
| **D** — `checkPublic` returns `Boolean(value)` | `24 pass / 1 fail` | `` a `public` that is not a boolean, which is the one that matters `` |

Mutation **B** is the one worth a reviewer's attention. It is the failure mode the
packet names — reporting that `/v1/*` now serves anonymously — and it is green on
test 1 while red on test 2. A suite that only asserted "a public route works"
would have shipped it. The two tests are not redundant; they are the two
implementations.

Verification that the mutations were actually in the file, for B:

```
$ grep -n "routes !== null" src/index.ts
185:      if (routes !== null) return next();     <- the mutated gate
225:  if (routes !== null) {                      <- unrelated, unchanged
```

And after revert: `185:      if (routes !== null && isPublicRoute(routes, new URL(c.req.url).pathname)) return next();`

### `bin/prime`, before and after

```
before (master @ bafb296):   517 pass   15 skip   0 fail   Ran 532 tests across 23 files
after  (this branch):        540 pass   15 skip   0 fail   Ran 555 tests across 24 files
```

23 tests added: 17 in the new file, 6 in `table.test.ts`.

### Skipped, named and counted

`15 skip`, and all 15 are one file. Measured, not assumed:

```
$ bun test src/middleware/rateLimitRedisLive.test.ts
 0 pass   15 skip   0 fail   Ran 15 tests across 1 file
```

`GUARD_REDIS_URL` is unset — `bin/prime` never sets it, by design — so the live
Redis tier is skipped in full. That is the same count as before this packet (the
gate's own prose said 14; see §5). Nothing else in the suite skipped.

### Gate floors, moved in the commit that moved them

```
                        declared   measured   verdict
pass   (was 462)  ->        535        540    below
files  (was  21)  ->         24         24    exact
```

`pass` keeps the file's existing five-test margin; `files` stays exact, for the
reason already recorded in that block (a file count does not move when a test is
added, so margin there is pure loss). `gate_check.py --prove`: **0 failures, 2
warnings**, both pre-existing `gate.requirement-unproven` on the declared bun and
npm requirements, which that checker explicitly does not run.

---

## 4. A regression I introduced, and fixed

`account_scope.yml` pins `registeredAt: {file: src/index.ts, line: N}` for six
routes. My comment expansion above the token gate shifted every registration down
by six lines, and the account-scope checker said so:

```
master, before the packet:    1 failure   (undeclared GET /v1/me)
after the packet, unamended:  7 failures  (6 x account-scope.stale, + that one)
after the fix (commit 2):     1 failure   (undeclared GET /v1/me)
```

The remaining failure is **master's, not mine**: `GET /v1/me` is undeclared, and
`worker/guard-v1-me-01` is another session's open packet holding the fix. Not
taken. The six line numbers were re-derived from `src/index.ts` — each read back
out of the source and asserted equal to the hand-computed value before the write —
rather than typed in, so this table cannot silently disagree with the code again.

I did not see this on the first run because `bin/prime` does not run
`account_scope_check.py`. It is a separate checker and a separate CI concern.

---

## 5. Findings outside the packet

**a. gate.yml's floors were below the tree, and its skip count was wrong.** Both
were pre-existing. `floors_check.py` reported `declared 462 / measured 517 / below`
and `declared 21 / measured 23 / below`. `gate_check.py` **cannot see this
direction at all** — it only reports a floor above the tree. Separately, three
current-tense claims in `gate.yml` said the live tier skips **14** tests where the
tree prints **15**. Both fixed in commit 1; the header block's historical
measurement at `97d83e9` is left as written, with a dated note beside it. The
pattern — a declared floor that stops being a check because nobody moves it — has
now happened twice in this file, which is worth a watcher rather than a third
correction.

**b. A proxied `2xx` carries no `RateLimit-*` headers at all.**
`proxy.ts`'s `relay()` returns a **fresh** `Response`, so the headers the limiter
set on the outgoing response are discarded. Measured:

```
PROXIED HEADERS: [["cache-control","no-store"],["content-type","application/json;charset=utf-8"]]
```

Pre-existing and packet-independent. It matters **more** after this packet: a
throttled anonymous caller now has no way to learn its budget except by being
`429`'d, and `RateLimit-Retry-After`-style hints do not exist for it. Not fixed —
changing relay semantics has real consequences and is its own packet.

**c. `cache-control: no-store` on a public route, whose stated reason is now
false.** `relay()` adds it unconditionally, and the comment says why: *"proxied
traffic is authenticated"*. A `public` entry is not authenticated. The header is
still the safe direction and still wrong for a catalog read that `MVP-SCOPE.md`
says may be edge-cacheable. Documented in the README's *Not built yet* rather than
changed, because relaxing it per entry needs a decision about what guard will
vouch for in a shared cache.

**d. `RATE_LIMIT_REQUESTS` cannot lower the `/v1/` allowance.** `limits.ts:64` has
a shipped `/v1/` route entry (limit 600, policy `guard-api`), and `runtimeOptions`
overrides only the table's `default` — `routes` is passed through verbatim. The
README does say the per-route entries are not overridable in v0, but the
consequence for `/v1/` specifically is the whole API surface rather than just the
auth routes, and I found it only because I tried to use it and got three 200s
where I expected a 429. An operator who lowers `RATE_LIMIT_REQUESTS` expecting to
bound their API traffic does not bound `/v1/*`.

**e. `GET /v1/me` is undeclared in `account_scope.yml`** — another session's
packet (`worker/guard-v1-me-01`, commit `ca7ca70`, unmerged). Left alone; see §4.

**f. `site/src/lib/pantry.ts:41`'s comment** is still false of the shipped code
and becomes true next packet. Left alone, per the brief.

---

## 6. What I would do next

1. **MD18 packet 2 — pantry.** Two bugs that stop it booting in
   `caf.dev.compose.yaml` at all: `dockerfile: docker/Dockerfile` names a path
   that does not exist, and the service reads `PANTRY_DATABASE_URL` while the
   compose sets `DATABASE_URL`. Unblocked by this packet and needs no guard work.
2. **MD18 packet 3 — the whole-stack compose and the e2e assertion.** The thing
   the MVP directive actually asks for. Unbuildable until 1 and 2 land.
3. **A per-prefix rate-limit allowance**, and it is now urgent rather than tidy:
   an anonymous read surface wants a generous number, and every anonymous visitor
   currently shares one budget with everything else under `/v1/`. The limit table
   is code and the prefixes are configuration, so this is the pairing packet.
4. **Per-entry `cache-control`**, from (c).
5. **`requireScope`, then `apiKeys`,** in that order, and both blocked behind
   identity growing a `guard-api` scope. Adding either now turns a green packet
   red against today's identity.

---

## 7. Checklist

- [x] Committed to `worker/guard-mvp-guard-public-route-01`, off `master @ bafb296`. **Not pushed, not merged** — §2 reserves that for the manager, and overrides the packet's "Pushed to your branch".
- [x] Two commits, neither filler: the feature, and the regression the feature introduced.
- [x] Every command bounded by `timeout` (the longest bound was 660s against a gate declared at 900s).
- [x] `15 skip` named, counted, and traced to one file by running that file alone.
- [x] Every "fixed" claim carries a before/after measurement (§3 mutations, §4 the regression, §5a the floors).
- [x] README variable table, routing section and *Not built yet*; CHANGELOG; both gate floors — all in commit 1.
- [x] Four mutations, each verified present in the file by `grep` before the run and reverted after.
- [x] Findings outside the packet in §5, named and specific.
- [x] No container, image, or volume left running. Nothing was started. The three containers visible on the host (`searxng-core`, `searxng-valkey`, a Kamal buildkit) and the `redis-server` on `127.0.0.1:6379` all predate this session — the redis process started `Fri Oct 2 21:22`, this worktree `Oct 4 02:18`.
- [x] No other session's worktree, branch or container touched.