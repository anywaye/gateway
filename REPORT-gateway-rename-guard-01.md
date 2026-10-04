# REPORT — gateway-rename-guard-01

Renaming the service from `guard` to `gateway`, end to end, and proving the rename
broke nothing. Branch `worker/gateway-rename-guard-01`. The sweep itself is
`ac00b3a` (the manager's recovery of the work a dropped session left uncommitted);
this report covers the gate, the three defects found afterwards, and every
`guard` occurrence that is still in the tree and why it stays.

---

## 1. The floor, measured

The packet asked for a baseline and warned that an unmeasured floor is not a
floor. So I measured one, on both sides, in the same hour, with the same bun.

`f0c6a35` is the commit the sweep was applied on top of, so it *is* clean master
for this purpose. I checked it out into a throwaway worktree, ran the frozen
install and the suite there, and measured it rather than reasoning backwards from
the current tree.

| | pass | skip | fail | tests | files | `expect()` calls |
|---|---|---|---|---|---|---|
| `f0c6a35` — clean master, pre-sweep | 563 | 15 | 0 | 578 | 25 | 2062 |
| `ac00b3a` — the sweep, as the drop left it | **561** | 15 | **2** | 578 | 25 | 2062 |
| `5bdd42e` — this branch, now | 563 | 15 | 0 | 578 | 25 | 2062 |

`./bin/prime` exits 0 on the branch head. **The count did not move, and I can say
that because I ran it on both trees rather than asserting it.**

**On counting tests.** The runner's 578 is the number to quote. A count of
distinct test *names* is not 578 and never was: there are 535 `test(...)` call
sites, **532 distinct names**, and three names that each appear twice —
`401 for ${name}` (`src/middleware/jwt.test.ts`), `an empty variable is unset,
not a value` (`src/index.test.ts`), and `no cookie is a 401 and identity is
never called` (`src/bff/auth.test.ts`). Each pair is two `describe` blocks in one
file. The 578 is higher than 535 because some sites are in loops over generated
cases. Any before/after comparison that quotes a name count is comparing two
different numbers.

**On the skips — 15, named.** All 15 are in one file,
`src/middleware/rateLimitRedisLive.test.ts`, and all for the documented reason:
`GATEWAY_REDIS_URL` is unset, so the tier that executes `GCRA_LUA` against a real
`redis-server` does not run. Confirmed by running that file alone: `0 pass, 15
skip, 0 fail`. This is the one gated tier `AGENTS.md` describes, and
`test/noSkips.test.ts` — which passes, and is itself the third of the three
mechanisms that keep a skip from reading as a pass — is what holds it to that.
The baseline skipped the same 15, so the rename moved the skip count by zero.

**What I did not run.** `docker build --target test .` and
`docker compose build`. The packet scopes this packet out of containers, and the
machine is shared. I am not claiming they pass. What closes the gap they would
have covered is that the sweep **added and deleted nothing**: `ac00b3a` is 63
files, all `M`, zero `A`/`D`/`R`, and the set of `*.test.ts` paths is identical
between `f0c6a35` and the branch head. The Dockerfile's explicit `COPY` list, the
thing AGENTS.md says must be updated in the same commit that adds a test file,
cannot have gone stale because no test file was added.
`test/dockerStage.test.ts` reads that Dockerfile and asserts the copy chain — 18
pass, 0 fail, inside the suite.

---

## 2. Three defects the rename caused

The first gate ever run against this tree was **red**: 561 pass, 2 fail. Both
failures were the sweep's, and both are the same mistake wearing different
clothes — **the rename changed text that was not the name but described it.**

### 2.1 A byte count — `src/middleware/rateLimitRedis.test.ts`

```
expect(written).toBe("*2\r\n$3\r\nGET\r\n$10\r\ngateway:rl:k\r\n");
                                   ^^^  what?        ^^^^^^^^^^  was rewritten
```

`$10` is the RESP bulk-length header. Ten is the byte length of the *old*
namespace, `guard:rl:k`. The sweep renamed the key in the input and renamed it
inside the expected string, and left the number that *describes* it. The test
therefore asserted an encoder that truncates every key it writes, and the only
reason it was ever right is that it was written before the key was long enough
to expose it. Correct is `$12`.

The count is now commented in place, because the reason it is written out rather
than computed is a real property and not an oversight: a length derived from the
string it is checking cannot catch an encoder that got the length wrong, and the
test immediately below exists for exactly that. A rename therefore *must* change
this number by hand, and `12` is what `gateway:rl` weighs.

### 2.2 An asserted error message — `src/routes/table.test.ts`

```
.toThrow(/guard's own route/)     →  .toThrow(/gateway's own route/)
```

Production now says *"routeTable: /v1/me is gateway's own route and is served
before the pass-through"*. The test matches that message by pattern rather than
constructing it, so it followed the string into the wrong name. The production
string is worth asserting rather than reconstructing — the wording is load-bearing
in that message — so the fix is to follow it, not to weaken the assertion.

### 2.3 Two all-caps headings — `src/routes/proxy.ts`

```
//   3. AN UPSTREAM FAILURE IS GUARD'S TO TRANSLATE.        → GATEWAY'S
//   4. THE CREDENTIAL IS GUARD'S. See below.               → GATEWAY'S
```

The sweep missed these because the headings are set in caps and the replacement
matched the lowercase token. **This is a comment, so no test catches it, and I
want to be exact about the strength of that claim:** the evidence it was wrong is
the eleven occurrences of `gateway` in the eleven lines immediately below it —
including *"The reason is what forwarding it would turn gateway into"* — not a
red run. The two sentences assign responsibility to the process doing the
translating and to the process choosing the credential. "A guard's failure" is
not a sentence that prose could have meant. Treat this one as argued, not proven.

### The class, stated once

Both red tests and the comment are the same failure: **a rename has two blind
spots, and both are derived text.** One is *case variants* (`GUARD` survives a
lowercase replacement). The other is *counts and quantities* (`$10` is not the
name, it is a fact about the name, and no search for the name finds it). A sweep
that greps for the token can only ever be as good as the token.

I hunted for further instances of that class rather than assuming there were
none, and here is what the hunt returned:

- **Every case variant of the old name** across all 76 tracked files: two hits,
  both `src/routes/proxy.ts`, both now fixed. After the fix, exactly one line in
  the whole tree capitalises it — `REPORT-guard-08-edge.md:7`, discussed in §4.
- **Numeric literals adjacent to a string containing the new name**: three hits.
  One is the `$12` just fixed; the other two are `$1` and `$2` SQL placeholders
  quoted in a comment in `test/tenantEntryPoints.test.ts`.
- **My own sweep had the bug once.** `git grep -E '\b(GUARD|Guard)\b' f0c6a35`
  returned *nothing*, silently and with exit 0, because git's ERE has no `\b`.
  Taken at face value that would have told me the baseline had no all-caps
  occurrences and I had found a novel bug. Re-run without `\b`, the baseline has
  exactly the two `proxy.ts` sites. A check that quietly matches nothing is worse
  than one that fails, and it nearly made this report wrong.

---

## 3. Every remaining `guard`, accounted for

**93 lines / 105 occurrences** across the 76 tracked files. Not one is a missed
rename. The classification below is produced by a priority-ordered classifier
over `git ls-files | grep`, so the buckets are derived from the tree rather than
asserted by me; each line lands in exactly one bucket and the total reconciles.

| # | what it is | lines | why it stays |
|---|---|---|---|
| 1 | the GitHub repository: URL, or a path inside the checkout | 8 | outward-facing; not mine to rename |
| 2 | a `REPORT-*` filename | 12 | history: the file a dispatched packet wrote |
| 3 | a past worktree directory (`guard-worker-guard-01`) | 4 | history: what the checkout was called |
| 4 | a past git branch (`worker/guard-v1-me-01`) | 9 | history: branches are named at dispatch |
| 5 | a dispatched packet id in a document title | 3 | history |
| 6 | a dispatched packet id in prose or code (`TODO(guard-06)`) | 40 | history — AGENTS.md's own rule |
| 7 | ordinary English: *the tripwire* | 17 | **the other sense of the word** |
| | **total** | **93** | of 93 lines, none uncounted |

The rules are tested **most specific first**, which matters: a worktree path
(`/Users/kaka/Code/any/moon/cafaye/guard-worker-guard-08`) matches both "the
repository" and "a past worktree", and only the ordering puts it in the bucket
that says what it actually is. Two of my earlier drafts of this classifier
disagreed with each other because of exactly that, and I did not keep either
number until the buckets reconciled and I read bucket 7 verbatim.

**Bucket 7 is the point of the packet.** `guard` in this repository has always
had two meanings and only one of them was the service. These 17 are all the
first: *"worse than the traffic it was guarding against"*, *"A guard has to be
shown to fail"*, *"the failure guard cares about"*, *"the stale-exclusion
guard"*, *"still carries the `GATEWAY_REDIS_REQUIRED` guard"*, *"guarded by
three"*. Renaming any of them would delete a sentence. AGENTS.md's "A guard has
to be shown to fail" is a rule about tripwires, not a statement about the
service's name — and it is the rule this very report is working under.

**Buckets 1–6 are all the same rule from AGENTS.md:** *"A packet id that names a
dispatched packet is history, and history keeps its name."* The two forms differ
because they mean different things, and a sweep that cannot tell them apart
either corrupts history or points the next packet at a name that is not on disk.

For scale: `gateway` went from 239 occurrences at `f0c6a35` to 969. Of the old
name's forms, `GUARD_REDIS_URL`, `GUARD_REDIS_REQUIRED`, `GUARD_IMAGE_TEST`,
`GUARD_CLIENT_ID`, `GUARD_OWNED`, `GUARD_OTEL_ENDPOINT` and the `guardKeys`
helper are **all** gone — every environment variable and every identifier.

---

## 4. Judgment calls a reader might have made differently

**`REPORT-guard-08-edge.md:7` — "Guard is better than the packet assumed".** The
one place in the tree where the old name is used as *the service*, in prose. I
left it, and this is the decision I would most expect a reviewer to challenge.
My reasoning: the same file records the worker's own contemporaneous identity —
`Worker guard-08-edge`, worktree `/Users/kaka/Code/any/moon/cafaye/guard-worker-guard-08`,
branch `worker/guard-08`, remote `git@github.com:cafaye/guard.git` — and every
other line of it is a timestamped account of what happened at the time. The
alternative is a report edited after the fact, which is not a report. If you want
the sentence modernised, that is a defensible call and it is one line.

**The repository name.** `cafaye.yml:119`, `kit.ref:5`, `openapi/v1.yaml:260` and
the two CHANGELOG compare/release links still say `cafaye/guard`. The packet
forbids renaming the repository, and I confirmed rather than assumed it: `git
remote -v` on this worktree is `git@github.com:cafaye/guard.git`. So these are
correct, not stale. Note the consequence — the manifest's `name: gateway` and its
`repository.url: cafaye/guard` now disagree on purpose, and a reader who does not
know that will file it as a bug.

**`test/openapiPaths.test.ts:174,181` — `guard-06` inside a fixture.** These two
lines are *synthetic header text* fed to a header-parsing function and its
expected output. `guard-06` is arbitrary content in a string literal, so
renaming it changes nothing and would only make the fixture less obviously
distinct from real DECISION NEEDED headers. Left alone.

**`test/noSkips.test.ts:130` — the test *name* says "carries the guard".** In the
tripwire sense, and it is the name of a test that exists to police skips. A
rename of that name would have been the packet corrupting its own tripwire.

**The GitHub repository is the manager's.** Not renamed, not pushed, no tag, no
merge to master. `origin` is untouched.

---

## 5. What I verified, and how

The packet asked me not to assume the documents agree. I checked each one
against the tree rather than against my memory:

- **`AGENTS.md` Layout block** — every path it names still exists. Extracted the
  block, checked all 26 extension-bearing paths against the filesystem: **0
  missing**. The block is selective (it inventories the interesting files, not
  all 51 tracked files in those areas), so "agrees" here means *no rename moved a
  file out from under a path the block names*. None did.
- **`README.md`** — `# gateway`, "The cafaye public gateway", and the endpoint
  table's six rate-limit policy names (`gateway-api`, `gateway-auth`,
  `gateway-auth-login`, `gateway-auth-register`, `gateway-auth-logout`,
  `gateway-api-keys`) each exist as a key in `DEFAULT_LIMIT_TABLE` in
  `src/middleware/limits.ts`.
- **`cafaye.yml`** — `name: gateway`, `team: gateway`, `contact:
  gateway@cafaye.com`; `repository.url` deliberately still `cafaye/guard`.
- **`openapi/v1.yaml`** — the only `guard` outside the repo URL is *"guarding"* in
  a comment. `test/openapiDocument.test.ts` holds this document to the router in
  both directions and passes.
- **`package.json` / `Dockerfile` / `docker-compose.yml`** — name `gateway`, image
  `cafaye/gateway:dev` in both, compose service and hostname `gateway`,
  `account_scope.yml` `service: gateway`.
- **`.github/workflows/ci.yml`** — 9 `gateway` references, correct; its one
  remaining `guard` is *"the lockfile guard"*, the tripwire sense. Note that CI
  also renamed `GUARD_IMAGE_TEST` → `GATEWAY_IMAGE_TEST` and the
  `GATEWAY_REDIS_*` variables; those must agree with the code, and
  `test/dockerStage.ts` (18 pass) is what holds the image-tag half.

---

## 6. Found outside the packet — not fixed, handed over

**`src/routes/assertion.ts` has no row in the `AGENTS.md` Layout block.** The
block lists `src/routes/table.ts` and `src/routes/proxy.ts` and skips
`assertion.ts` entirely — a non-test source file, of the three kinds the block
otherwise lists. That file is the `mvp-guard-principal-01` packet's work, and
AGENTS.md's own prose argues at length about the rules it implements (*"A
credential crossing to a service is gateway's to choose"*) without naming it as a
file. Smaller gaps in the same block: `test/dockerStage.ts` (the helper, though
its `.test.ts` is listed) and `test/assertionMutations.sh`.

**Why I did not fix it:** this packet changes names and nothing else, and the
block's *selection criterion* — which of the 51 files earn a row — is a judgment
call the packet did not hand me. Adding a row is a documentation change to a
document the rename otherwise did not need to touch. It is one line when someone
decides it should be three.

**Two lesser things, same bucket:** the Layout block names `bin/prime` without an
extension, so a check keyed on file extensions misses it — noted because it is
exactly the "my sweep is wrong, not the repo" trap, and it would have produced a
false "one path missing" reading. And `.github/workflows/ci.yml:195` reads *"this
job is what makes gateway's one of the linted"* — grammatical, pre-existing, and
not mine to tidy during a rename.

---

## 7. What I would do next

1. **Manager decision on the repository name.** The service is `gateway` and the
   repo is `cafaye/guard`. That is coherent only while someone knows it. If the
   repo is ever renamed, `kit.ref:5`, `cafaye.yml:119`, `openapi/v1.yaml:260` and
   the two CHANGELOG links all have to move together or the compare links rot.
2. **One line in `AGENTS.md`** for `src/routes/assertion.ts`.
3. **If a rename ever sweeps a `cafaye` service again**, the two blind spots in
   §2 are the whole lesson: grep case-insensitively *and* for the caps variants,
   and read the diff for numbers rather than trusting the token count. A renamed
   service that also changes the length of a string it appears in is a test that
   silently stops testing.

## Commits on this branch

- `ac00b3a` — the sweep, banked by the manager after the session drop. Not mine.
- `4a8d43a` — the byte count and the error pattern: the two red tests.
- `5bdd42e` — the two all-caps headings in `proxy.ts`.
- this report.

Gate green at every commit. Nothing pushed, nothing merged, no tag.