# REPORT — gateway-account-scope-ratchet-01

**What I was sent:** `kit`'s fleet ratchet row for `gateway` was describing a
repository that no longer existed, and in the middle of it `gateway` had lost the
only account-scoped entry point its security declaration ever had.

**Branches:** `worker/gateway-account-scope-ratchet-01` in
`cafaye/gateway` (worktree `wt-m39-gateway-account-scope-01`), and
`worker/kit-account-scope-ratchet-01` in `cafaye/kit` (worktree
`wt-m39-kit-account-scope-ratchet-01`, created by me — see §7). Neither is pushed
and neither is merged.

---

## 1. The defect, in two halves

### 1.1 The ratchet row was never re-measured

`worker/gateway-go-substrate-01` landed the Go service beside the TypeScript one
and rewrote `account_scope.yml` to declare **both** surfaces — `surface.minimum:
14`, seven operations registered twice. That work is sound and is argued at
length in that file's header.

What did not happen is that anybody re-measured `kit`'s row for `gateway`. The
row still read:

```yaml
  - repo: gateway
    exit: 0
    counts: {account-scoped: 1, not-account-scoped: 6, stale: 0, undeclared: 0, failures: 0, warnings: 6}
```

against a tree that measured:

```
records exit=0 and the checker exited 1
records account-scoped=1 and the run measured 0
records not-account-scoped=6 and the run measured 12
records undeclared=0 and the run measured 2
records failures=0 and the run measured 2
records warnings=6 and the run measured 7
```

So the row claimed `exit: 0` and `account-scoped: 1` about a repository whose
checker exits 1 and has no account-scoped row at all. **This was a stale row, not
a wrong declaration** — the important distinction, because it meant the fleet gate
was reporting a finding it had already been told about and nobody had written
down.

### 1.2 The service had lost its only account-scoped row

`GET /v1/me` is the one route in `gateway` that can reach another account's data.
D18 made it account-scoped; MD19's signed principal assertion is what makes the
resolution checkable. It had **no row at all**, and `account-scope.undeclared`
fired twice — once for each of the two registrations of it.

The previous packet wrote this off as a format limitation. It is not, and §3 has
the measurement.

---

## 2. Before and after, with the commands that produced it

Instrument: `cafaye/core/harness/account_scope_check.py`, run through
`cafaye/kit/.venv/bin/python3` (a bare `python3` has no `yaml`).

**BEFORE — `kit`'s fleet checker, whole fleet, master:**

```
$ cd cafaye/kit && .venv/bin/python3 tests/account_scope_fleet_check.py \
    --repos-dir /Users/kaka/Code/any/moon/cafaye
gateway: FAIL
    FAIL account-scope.undeclared  (x2 rows)
        hono registers GET /v1/me at src/index.ts:247, which is in a file
        surface.sources names and which no entry point covers
    records exit=0 and the checker exited 1
    records account-scoped=1 and the run measured 0
    records not-account-scoped=6 and the run measured 12
    records undeclared=0 and the run measured 2
    records failures=0 and the run measured 2
    records warnings=6 and the run measured 7
site: FAIL
    … (pre-existing, not this repository — see §8)
TALLY: 9 in-scope repositories checked — 7 match their recorded state exactly, 2 do not.
FAIL account-scope-fleet: gateway FAIL; site FAIL
exit 1
```

**AFTER — core's checker on this branch:**

```
$ .venv/bin/python3 core/harness/account_scope_check.py cafaye/wt-m39-gateway-account-scope-01
FAIL account-scope.undeclared: chi registers GET /v1/me at internal/api/api.gen.go:1191,
  which is in a file surface.sources names and which no entry point covers
  (6 × WARN account-scope.contradiction-unreadable — unchanged, the six TypeScript
   rows whose handlers are inline arrows or bare `bff.` members)

  account-scoped     GET /v1/me  (src/index.ts:278)
  not-account-scoped GET /healthz  (internal/api/api.gen.go:1185)
  … 12 not-account-scoped rows …
  undeclared         GET /v1/me  (internal/api/api.gen.go:1191)

FAIL: 1 account-scoped, 12 not-account-scoped, 0 stale, 1 undeclared,
      0 unreadable — 1 failure(s), 6 warning(s)
exit 1
```

**AFTER — `kit`'s fleet checker, whole fleet, with `gateway` resolved to this
branch through a symlink (so the row is measured against the branch and not
against master):**

```
$ cd cafaye/wt-m39-kit-account-scope-ratchet-01
$ .venv/bin/python3 tests/account_scope_fleet_check.py --repos-dir <tree-with-no-MVP-SCOPE-above-it>

repo       exit  scoped not-scp stale undcl fails warns blind  state
gateway    1       1      12     0     1     1     6     0  OK
site       1       0       0     6     0    10     7     1  FAIL

TALLY: 9 in-scope repositories checked — 8 match their recorded state exactly, 1 do not.
FAIL account-scope-fleet: site FAIL
exit 1
```

**7 match / 2 do not → 8 match / 1 do not**, which is the packet's bar. `gateway`
matches its row in **both** directions: `account-scoped` and `warnings` are back
to the numbers the row already recorded, and the three that moved were re-measured
rather than reworded.

**`./bin/prime`, this branch:**

```
== prime ok (bun 1.3.12)
  565 pass / 15 skip / 0 fail — Ran 580 tests across 25 files [3.32s]
  equivalence: RAN — 24 cases x 3 scenarios = 72 comparisons, 0 differences
  suite: 31 passed, 0 failed (Go tier)
```

The 15 skips are `src/middleware/rateLimitRedisLive.test.ts` and nothing else —
`bin/prime` never sets `GATEWAY_REDIS_URL`, so that tier skips by design and the
gate is green. That is a skip, not a pass, and it is named here because nothing
else names it. Gate floors in `gate.yml` (`pass: 560`, `files: 25`) did **not**
move: this packet added no test, because the change is a declaration and a blank
line, not a behaviour.

### 2.1 The packet's literal command will still say FAIL until the merge

The packet's command is

```
$ cd cafaye/kit && .venv/bin/python3 tests/account_scope_fleet_check.py \
    --repos-dir /Users/kaka/Code/any/moon/cafaye
```

`--repos-dir` walks the directory, so it measures `cafaye/gateway` — which is
`master`, and my commits are not merged because the merge is not mine. Run from
`kit`'s **branch**, that command says:

```
gateway       1       0      12     0     2     2     7     0  FAIL
    records account-scoped=1 and the run measured 0
    records undeclared=1 and the run measured 2
    records failures=1 and the run measured 2
    records warnings=6 and the run measured 7
    records account-scope.nothing-scoped (warn) x0 and this run found it x1
    records account-scope.undeclared (fail) x1 and this run found it x2
TALLY: 7 match their recorded state exactly, 2 do not.
```

and it is **correct to**: the row records the repository this packet produces, and
`cafaye/gateway` on master is not that repository yet. The symlinked run in §2 is
the one that measures the branch, and it is how the `pantry` row in the same file
was re-measured before it. `not-account-scoped: 12` already matches on master,
which is the one count that does not depend on this packet.

After the merge, the literal command and the symlinked one are the same command.

---

## 3. Why `/v1/me` could not be declared, and what it actually was

Two blockers, measured. Neither is the format, which is what the previous packet
recorded.

### 3.1 The chain window — one blank line

`scoping-bypassed` does not read the registration line for a Hono route. It reads
the `app.use` mounts registered **above** the row's line (`chain_gate`, and
`Recogniser.chain_read`, which `core-hono-inline-01` added for exactly this route)
and asks three questions of each: is it above, does its pattern cover this path,
does it name `accountFrom.via` on its own line or within **`HANDLER_WINDOW: 3`**
lines below it.

The mount at `src/index.ts` covered `/v1/me` and was above the route. The window
did not reach `jwt.requireJwt`, because MD19's public-prefix exception had made
the mount's body four statements and put the call on the fifth line.

```
  before: FAIL account-scope.scoping-bypassed: me: registered at
          src/index.ts:247, which does not go through requireJwt
  after:  the same three statements with no blank line between them;
          chain_gate reads requireJwt at src/index.ts:254 — VERIFIED
```

The mutation was planted and confirmed to be in the file by grep (`grep -n 'app.use("/v1/\*"\|jwt.requireJwt' src/index.ts`
printed both lines) before the checker was run, and the `registeredAt` anchors
were moved with it so the only difference between the two runs is the blank line.

**This is a whitespace-only change to a security gate, and I want that on the
record rather than buried.** It is argued at the mount in `src/index.ts` for
exactly that reason. `HANDLER_WINDOW: 3` is a defensible bound — an unbounded
window would find the middleware for some other route further down and call a
bypass covered — and three lines is simply too few for a gate with two exceptions
in front of the call. The margin is **zero**: a fourth guard on that mount pushes
the call out of the window and `me` goes red. That is the correct loud failure,
but it is a failure this repository's own `bin/prime` does not police, because
`bin/prime` does not run core's checker. **See §9.**

I did **not** take the cheaper way to the same green: mounting the body by a bare
symbol (`app.use("/v1/*", jwtGate)`) makes `chain_gate` return `composed=True`,
which silences `scoping-bypassed` rather than satisfying it. That is a false green
and it is the defect the working rules name by name.

### 3.2 The format was never the problem — two rows for one (method, path) work

`gateway-go-substrate-01`'s `DECISION NEEDED` said a row cannot be scoped to a
file, so one row lands on one registration and the other reads as uncovered. The
first clause is true (`registeredAt` is only what `account-scope.stale` reads) and
the conclusion is wrong: `classify` marks each registration **taken** and scans
for the next untaken one, so two rows for the same `(method, path)` take two
registrations. `me` taking `src/index.ts:278` while `internal/api/api.gen.go:1191`
stayed unmatched is the proof, in the run above.

What actually blocks the Go row is that **neither honest answer survives a run**,
and both were measured rather than argued.

**`accountScoped: false, reason: none`** — 0 findings, because `GetCurrentPrincipal`
calls `notBuilt` and writes the v0 `404`. And nothing can refute them:
`handler_for` resolves every `wrapper.X` on those seven registration lines to
`internal/api/api.gen.go` — the forwarding method in the generated wrapper — and
`_hops` from that file is `[]`, so `contradiction` reads `api.gen.go` and one hop
below it and **never opens `internal/httpapi/httpapi.go`**. Five mutations were
planted and reverted; the script asserted each was in the file before running:

| planted `GetCurrentPrincipal` | `go-me` findings |
|---|---|
| control: `notBuilt(w, r)` | NONE |
| `principal.AccountID` (exported field, as Go writes it) | NONE |
| `&principal.account` (unexported, matches core's `RESOLVED` shape) | NONE |
| `payload["account_id"]` (claim read) | NONE |
| `c.Get("principal")` | NONE |

A `false` row nobody can refute, on the one route this file exists to describe, is
the permissive direction the packet names: the fleet would believe a route is
unscoped when the day comes that it is not. **Not written.**

**`accountScoped: true, accountFrom.via: requireJwt`** — fires, and the failure is
**true**: the Go router mounts all seven operations behind nothing and
`openapi/v1.yaml` gives `/v1/me` a `security:` block. It is also **permanent**:
`chain_gate` looks for `app.use(`/`.use(`, chi mounts middleware with `r.Use(`, so
no middleware added to the Go router can ever satisfy it and the failure cannot be
cleared by doing the work. A ratchet row red forever with a condition whose end is
unreachable is the switch that rule 2 exists to refuse. **Not written.**

**`account-scope.undeclared` is the answer that is both true and actionable:** the
packet that ports the bearer gate to `internal/httpapi` has to write the row to go
green. It costs one honest failure instead of two, and `kit`'s row carries a
`condition:` naming that end.

### 3.3 One route declared twice, or two routes?

**One contract, two registrations, and today two different security properties.**
The answer the packet asks for:

- For `undeclared`, which is decided by registrations in the source: **two**. The
  checker reads `surface.sources` and finds seven registrations in
  `src/index.ts` and seven in `internal/api/api.gen.go`, and `classify` treats
  them as fourteen separate facts. `surface.minimum: 14` is right and stays 14.
- For a reader of the service: **one route, and the honest `minimum` does not
  change** — because both registrations exist until the packet that deletes
  `src/`, and on that day its source leaves `surface.sources`, seven rows go with
  it, and `minimum` returns to 7 in that commit.

The `DECISION NEEDED` I found is *not* the one the previous packet recorded. It is
in §6.

---

## 4. What I changed

**`cafaye/gateway`, commit `66e33af`:**

- `account_scope.yml` — added `me`: `GET /v1/me`, `accountScoped: true`,
  `accountFrom: { via: requireJwt, file: src/middleware/jwt.ts, line: 346 }`,
  `registeredAt: src/index.ts:278`. Rewrote the three prose blocks that said the
  route could not be declared, with the measurements that replaced them. Rewrote
  the file header's "this file cannot declare" sentence. Moved five
  `registeredAt` anchors down by one for the blank line, then up by 32 for the
  comment at the mount. `surface.minimum` untouched at 14.
- `src/index.ts` — deleted one blank line inside the `/v1/*` mount's body, and
  argued the coupling in 30 lines at the mount.
- `CHANGELOG.md`, `README.md` — house style; the README's "six `registeredAt`
  anchors" was a pre-Go number and is now "a `registeredAt` anchor **on each
  implementation**", which is the fact that is actually true and is the coupling
  this packet is about.

**`cafaye/kit`, commit `812cc45`** (see §7):

- `tests/account_scope_fleet_ratchet.yml` — the `gateway` row re-measured,
  `exit: 1`, with a `condition:` naming what the tolerated failure is and what
  ends it.
- `tests/account_scope_fleet_scope.yml` — a stale fingerprint. See §5.

**`MVP-SCOPE.md` was not touched**, and neither was `site`, `core`, or any
repository other than `gateway` and `kit`.

---

## 5. The other defect: the vendored scope copy did not run at all

One of the packet's four coupled references, and the verification the packet asked
for found a real failure in it.

`kit/tests/account_scope_fleet_scope.yml` carried `fingerprint:
9fec5592…` — which is the hash of the in-scope list **as it stood before the
rename** — while its own `inScope` said `gateway`:

```
$ .venv/bin/python3 -c "import hashlib;print(hashlib.sha256(chr(10).join(
  ['identity','courier','guard','site','parlor','pantry','caf','kit','core']
  ).encode()).hexdigest())"
9fec5592376e521dd4c34adfeab238b8cd64f243fbe9a618a6d556ab91a434a9
```

The consequence is the part that matters, and it is not cosmetic. `--scope`
defaults to the scope decision above the fleet root, so on every developer machine
`moon/MVP-SCOPE.md` is readable, the directive wins, and the fingerprint is never
computed. It is reached **only when there is no directive** — which is precisely
the case this file exists to vendored-for. Measured, on a tree with no
`MVP-SCOPE.md` above it:

```
BEFORE  COULD NOT RUN: … records fingerprint 9fec5592… and its own list hashes to
        cba94d5e…. The file disagrees with itself, so the list it carries is not
        the list it claims.
        exit 2

AFTER   SCOPE-READ: tests/account_scope_fleet_scope.yml (vendored — no MVP-SCOPE.md
        beside the fleet) puts 9 repositories in the MVP: identity, courier,
        gateway, site, parlor, pantry, caf, kit, core
        SCOPE-FINGERPRINT: cba94d5ec791faa15e522e4d58440e83a307ba072fb054a73d16d02db29d81a2
        …runs…
```

Every run that needed the vendored copy exited 2 having checked **nothing**, on
the machines it was written for. A developer's green and a CI runner's green were
two different gates and only one of them existed. Same failure shape the packet
warns about with a bare `python3`: a gate that cannot be shown to have run is not
a gate.

Re-derived in the same commit as the list it fingerprints, with the command the
file's own header prints.

---

## 6. Findings outside this packet — named, not fixed

**1. `core`'s `HANDLER_WINDOW: 3` cannot read gateway's `/v1/*` gate.**
`chain_gate` reads `lines[number-1 : number+3]`, and a gate with two exceptions in
front of the call needs four. The honest fix is core's, not gateway's: raise the
window, or make it a per-recogniser budget like `carries_handler` and `chain_read`,
or record the budget in the declaration so a service knows how tall a gate may be
and why. §3.1.

**2. `core` cannot follow a generated forwarding method, so all seven `go-*` rows
are verified against the wrong file.** `handler_for` resolves
`wrapper.GetCurrentPrincipal` to `internal/api/api.gen.go`, and `_hops` from that
file is `[]`, so `contradiction` never opens `internal/httpapi/httpapi.go`. Every
Go row in this declaration is checked against the generated wrapper rather than
the code it describes. Harmless **today** — measured, `evidence_in` over the masked
`internal/httpapi/httpapi.go` returns `None`, so there is nothing there to find —
and a silent hole the day it is. This also means `account-scope.contradiction-
unreadable` reads 6 when 7 rows are unreadable, which is why the fleet's own
blindness rule B4 cannot see it. The fix belongs in `handler_for`: a Go method on
a wrapper type should resolve to the method, and then one hop to the interface's
implementation.

**3. `internal/httpapi` mounts all seven operations behind nothing.** Not a
finding against a declaration — a finding against the rewrite. `openapi/v1.yaml`
gives `/v1/me` a `security:` block and `chi` mounts it with `r.Get(…, wrapper.
GetCurrentPrincipal)` and nothing in front. Nothing leaks today because the handler
is `notBuilt`, and the moment authentication is ported it is the porting packet's
first job. Worth naming because a contract's `security:` block is a claim about a
route, and the Go router currently contradicts it on all seven.

**4. `account_scope.yml`'s six `contradiction-unreadable` warnings are not about
the Go rows** — they are the TypeScript rows whose handlers are inline arrows or
bare `bff.` members, which `handler_for` cannot resolve. Recorded exactly in
`kit`'s row so a seventh is red rather than a slower slide. Left alone: core
resolving `bff.register` needs the local-variable-to-module hop that only a
TypeScript-aware index could do, and it is not this packet's.

**5. `site` is FAIL and is not mine.** It failed before I started
(`surface-missing` ×3, `surface-thin`, `fleet.blind.proved-nothing` — the
declaration names three `route.ts` files that are not in the tree). Left untouched
per the packet; it belongs to a repository with work in flight under another
manager.

**6. Nothing of anyone else's is in my tree.** `wt-m39-gateway-rename-muse-01`,
which the packet named as live, no longer exists — the directory is gone and
`kit` had exactly one worktree (its own `master`, clean) when I started. I did not
touch `cafaye/kit`'s `master`; the kit change is on a branch in a worktree I
created.

---

## 7. Two branches, and why

The packet gave me a `gateway` worktree and named four coupled references, two of
which live in `cafaye/kit`. So the kit half is on
`worker/kit-account-scope-ratchet-01`, in
`cafaye/wt-m39-kit-account-scope-ratchet-01` — created by me, per the worktree
naming rule, branched from `master` at `6dd6eba`. **The manager merges two
commits, not one:**

| repo | branch | commit |
|---|---|---|
| `cafaye/gateway` | `worker/gateway-account-scope-ratchet-01` | `66e33af` |
| `cafaye/kit` | `worker/kit-account-scope-ratchet-01` | `812cc45` |

Neither is pushed. Neither is merged. Nothing else was committed anywhere.

---

## 8. What I deliberately did not do

**I did not lower `surface.minimum`.** It is 14 and it stays 14, with 13 rows over
14 registrations. `undeclared` is decided by the registrations in the source and
never by this file's row count, so lowering it would buy nothing and cost the only
decrease-detector the surface has. It did its job in this packet: it is the reason
14-against-13 is a question somebody had to answer rather than a coincidence.

**I did not remove `internal/api/api.gen.go` from `surface.sources`.** That would
make `undeclared` read 1→0 and take seven rows with it, and it would be a green
bought by not looking.

**I did not declare the Go `/v1/me` `accountScoped: false`.** It would have made
`gateway` exit 0 and this report a paragraph shorter. It is also an assertion no
run can refute (§3.2), on the one route in the file that reaches another
account's data, and the packet says explicitly that the permissive direction is
the dangerous one. One honest `undeclared` is the price.

**I did not declare it `accountScoped: true` either.** True today, permanent
forever (§3.2).

**I did not silence the check to get a green.** The cheap version of this packet
was to mount the `/v1/*` body by a bare symbol so `chain_gate` returns
`composed=True` and `scoping-bypassed` has nothing to say. That is a false green.

**I did not fix core.** Findings §6.1 and §6.2 are defects in
`cafaye/core`'s checker and I was not asked to edit that repository and did not.

**I added no test.** See §9 — that is the one place where I think this packet is
incomplete, and I would rather say so than bury it.

---

## 9. What I would do next, in this order

1. **Close the unprotected window.** Nothing in `bin/prime` runs core's checker, so
   if somebody adds a fourth guard to the `/v1/*` mount, `account-scope.undeclared`
   and `scoping-bypassed` change in a repository whose own gate stays green —
   which is the exact failure the working rules describe. The guard is one test:
   read `account_scope.yml`, find every `accountScoped: true` row, resolve its
   `via` in the `app.use` mounts above its `registeredAt` line inside
   `HANDLER_WINDOW`, and fail when it cannot. Derived by content, not by a list of
   known gates. It costs one `pass` floor in `gate.yml` and no new file, so the
   `files` floor does not move. **I ran out of room to add it and measure it; I am
   naming it rather than shipping it unverified.**
2. **Delete `src/`'s source from `surface.sources` and return `minimum` to 7** in
   the packet that removes the TypeScript implementation. In that commit, because
   a floor that has to be lowered later is a floor somebody forgets.
3. **The Go authentication packet.** It writes `go-me`, and `kit`'s `condition:`
   names that as the end of the tolerated failure.
4. **File §6.1 and §6.2 against `core`.** Both are cheap and both are silent.
5. **Re-measure `site`'s row** when its work lands. It is the last FAIL in the
   fleet and it is not mine to retire.

---

## 10. Self-check

- [x] Committed to branches. Not pushed, not merged.
- [x] Every commit is worth a reviewer's attention — two commits, one per
      repository, each with its measurements in the message.
- [x] Every command was bounded by a `timeout` (the longest were `./bin/prime` at
      900 s and the two full fleet runs at 300–600 s).
- [x] Anything skipped is named and counted: the 15 Redis-tier skips in §2, and the
      fact that the vendored-scope path was unreachable before the fix and is
      reachable after (§5). No test shard was left unrun.
- [x] Every claim of "fixed" has a before/after measurement: §2 (the fleet tally),
      §3.1 (the blank line), §5 (the fingerprint).
- [x] `REPORT-gateway-account-scope-ratchet-01.md` exists and is committed.
- [x] Findings outside the packet are named and specific: §6, six of them.
- [x] No container, image or volume left running. Nothing was started; the fleet
      checker is a subprocess and the TypeScript reference is stood up and torn down
      by `bin/prime`'s own equivalence tier.
- [ ] One thing is not done: §9.1. Named rather than claimed.