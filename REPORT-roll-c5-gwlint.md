# roll-c5-gwlint — gateway's CI: the lint is real, the "panic" is not

**Branch:** `roll/c5-gwlint`  **Worktree:** `/Users/kaka/Code/any/moon/wt/roll-c5-gwlint`
**Commits:** `785eeab` (lint), `8fa2196` (ci/compose), plus a recovered-recovery commit `2b4e996` from the previous attempt.

---

## 0 — The headline

The packet's row said gateway's `bin/prime` fails on a **real nil-verifier panic**
in the token-verification path. **That is not what the CI log says.** The failing
tests fail because the CI runner has no `redis-server` binary on `PATH`, and the
`panic:` line the triage quoted is a *fixture string in a passing test*. The third
red job, `image`, fails on a Docker Compose network that is undefined when the
override is used alone — the suite *inside* the image had already passed.

Three real causes, three fixes:

| job | real cause | fix |
|---|---|---|
| `bin/prime` | no `redis-server` on the runner; the runtime session tests exec it and fail loudly by design | install it in the job (`8fa2196`) |
| `ci (kit) / go` | 86 lint findings under kit's config | fixed, `0` findings (`785eeab`) |
| `image` | `docker compose build` → `service "gateway" refers to undefined network platform` | declare `platform` in the override (`8fa2196`) |

---

## 1 — The "nil-verifier panic", reproduced and shown not to be one

### 1.1 The string is a test fixture, and the test passes

The exact string the triage quoted appears exactly once in the tree:

```
$ grep -rn "nil pointer dereference in the token verifier" internal/
internal/httpapi/bff_test.go:1211:  panic("identity: nil pointer dereference in the token verifier")
```

It is the body of a fake identity `Doer` in `TestAPanickingIdentityIsA503AndNotADeadGateway`.
That test asserts the *opposite* of the packet's claim: a dependency that crashes
must become a `503` on one request, not a dead gateway. The recover that makes it
true lives in `internal/httpapi/bff.go`'s `within`. Run:

```
$ go test ./internal/httpapi/ -run TestAPanickingIdentityIsA503AndNotADeadGateway -v
=== RUN   TestAPanickingIdentityIsA503AndNotADeadGateway
2026/10/14 01:50:26 gateway: identity call failed: POST /v1/session panicked: identity: nil pointer dereference in the token verifier
--- PASS: TestAPanickingIdentityIsA503AndNotADeadGateway (0.00s)
PASS
```

The `gateway: identity call failed: … panicked: …` line is the production
`log.Printf` for a recovered panic — it is the test *working*. The triage read a
nearby log line as the failure of a different test.

### 1.2 The three tests the triage named fail on Redis, not on the verifier

The names the triage listed — `TestARuntimeGatewaySignsInAndReadsItsOwnSession`,
`TestASessionSurvivesTheProcessThatCreatedIt`,
`TestAConfiguredBrowserSurfaceAnswersItsOwnRoutesRatherThanDecliningThem` — are
the `internal/httpapi` runtime session tests. They call `startRedis`, which
`exec`s the `redis-server` binary on purpose (a URL an operator set could be
unreachable while the run stayed green). The CI `bin/prime` job log, run
`38414218374`, job `115359248239`:

```
runtime_session_test.go:52: this test needs a real `redis-server` on PATH and there
is none, so the session store's wire commands are unproven. … exec: "redis-server":
executable file not found in $PATH
```

Reproduced locally by hiding the binary:

```
$ PATH="/usr/bin:/bin:/usr/sbin:/sbin" go test ./internal/httpapi/ -run TestARuntimeGatewaySignsInAndReadsItsOwnSession
    runtime_session_test.go:52: this test needs a real `redis-server` on PATH and there is none …
FAIL
```

**Mechanism:** the test design deliberately fails instead of skipping, and CI's
`bin/prime` job never installed Redis. The verifier is never reached.

**Fix:** install `redis-server` in the `bin/prime` job. This is not weakening a
test — the suite still requires a real Redis.

### 1.3 Is there a nil verifier anywhere? No.

`RuntimeOptions` builds the verifier unconditionally
(`internal/httpapi/runtime.go`), exactly as the reference passed `jwt:`. The
nil-verifier shape is only reachable through the library constructor
`New(Options{})`, which no shipped path uses. `internal/auth/verifier.go` was not
touched by this packet except for two `errorlint` verbs.

---

## 2 — The lint: 86 in CI, all of them fixed

Run exactly as the task names it:

```
golangci-lint run --config /Users/kaka/Code/any/moon/cafaye/kit/lint/golangci.yml ./...
```

**Important measurement:** golangci-lint's defaults hide findings
(`max-same-issues: 3`, `max-issues-per-linter: 50`). The 86 in CI is the *capped*
number; `bodyclose` alone has 66 findings and only 3 are ever printed. All counts
below are the **uncapped** run
(`--max-issues-per-linter=0 --max-same-issues=0`), because a capped run can be
green on a tree that is not.

| stage | findings |
|---|---|
| CI at `f0fabc2` (as reported by the action, caps on) | 86 |
| start of this run, `2b4e996` (caps on / caps off) | 31 / **102** |
| after this packet (caps on / caps off) | **0 / 0** |

Measured at `2b4e996` with caps removed: `bodyclose 69, noctx 8, errcheck 7,
errorlint 5, staticcheck 3, unconvert 2, unused 8`. The 71 of those that the caps
hid across a run are why a capped `golangci-lint` can exit non-zero on 102
findings while printing 31.

### 2.1 The mechanism of the bodyclose count (the interesting one)

`bodyclose` reports every call whose **static type mentions
`*net/http.Response`** as an HTTP response whose body must be closed at the call
site. The test helpers (`h.do`, `send`, `answer`) all returned `*http.Response`,
so every one of their ~66 call sites was a finding — even though the bodies are a
`httptest.ResponseRecorder` buffer or a `strings.Reader`, with no socket behind
them, and the *production* code under test closes the real ones.

The fix is structural, not a pile of `//nolint`s: the helpers now return a named
type, `testResponse`, that embeds `*http.Response`. Field access is promoted
(`res.StatusCode`, `res.Header`), the five helpers that need the bare response
take `testResponse`, and a helper that genuinely needs `*http.Response` takes
`.Response`. `bodyclose` no longer sees a network response at the call site,
because there is not one.

The three **production** bodyclose findings (`bff.go:266`, `bff.go:350`,
`proxy.go:273`) are the genuine false-positive shape the task allows: the
response is built and handed to a caller that closes it (`drain`,
`relayUpstream`). Each carries a targeted `//nolint:bodyclose // <reason>`; the
lint's own remediation cannot see through the hand-off.

### 2.2 Everything else, by linter

- **noctx** — `net.Listen` → `(*net.ListenConfig).Listen` (4 test sites);
  `exec.Command` → `exec.CommandContext` (3);
  `tls.DialWithDialer` → `(*tls.Dialer).DialContext` (`internal/ratelimit/redis.go`).
- **errcheck** — five `fmt.Fprintf(stderr, …)` in `proxy.go` assigned to `_, _ =`;
  two `defer …Close()` wrapped as `defer func() { _ = … }()`.
- **errorlint** — the trailing `%v` on a wrapped error → `%w` (`jwks.go`,
  `assertion.go`, `runtime.go`, `verifier.go` ×2).
- **unconvert** — `string(id)` where `api.APIKeyID = string`; `string(field.Code)`
  where `Code` is already `string`.
- **staticcheck** — a tagged switch in `redis.go`; an embedded-field selector in
  `testkeys.go`; a dead `Sigined` field in a test struct.
- **unused** — eight dead test helpers (`hasSessionCookie`, `sortedNames`,
  `(*upstream).reset`, `(*recorder).only`, `(*fixedClock).advance`,
  `principalWith`, `caseSpec.runsUnder`) and one dead const
  (`fixtureExpiryWindowDays`).
- **misspell** (US locale) — the previous attempt's commit; kept.

### 2.3 No exclusions

Nothing was excluded in config, and no file was skipped. The only suppressions are
the three production `//nolint:bodyclose` lines with a stated reason.

### 2.4 The commands the numbers come from

```sh
# before, and after: same command, caps OFF, because caps hide findings
git archive 2b4e996 | tar -x -C "$BEFORE" && cd "$BEFORE"
golangci-lint run --config /Users/kaka/Code/any/moon/cafaye/kit/lint/golangci.yml \
  --max-issues-per-linter=0 --max-same-issues=0 ./...      # 102 issues

cd /Users/kaka/Code/any/moon/wt/roll-c5-gwlint
golangci-lint run --config /Users/kaka/Code/any/moon/cafaye/kit/lint/golangci.yml \
  --max-issues-per-linter=0 --max-same-issues=0 ./...      # 0 issues
golangci-lint run --config /Users/kaka/Code/any/moon/cafaye/kit/lint/golangci.yml ./...  # 0, caps on
```

---

## 3 — The gate

```
$ ./bin/prime
…
==> ok

== prime ok
```

Exit `0`. (`bin/prime` → `bin/prime-go`: toolchain assertion, build, vet,
`go test -count=1 -v ./...`, generated-code currency.)

## 4 — The image job

`docker build --target test .` (the in-image suite) **passes**: exit `0`, and the
`test` stage prints `Redis server v=7.4.11` before `go vet ./... && go test
-count=1 -v ./...`. Redis is present because the `test` stage copies
`redis-server` from the `redis:7-bookworm` stage. So the `image` job's failure is
**not** downstream of any test or panic — the suite had already passed. It is the
*next* step:

```
$ docker compose build
service "gateway" refers to undefined network platform: invalid compose project
```

`docker-compose.yml` is an **override** meant to be merged with kit's base
(`-f <kit>/templates/compose/docker-compose.yml -f ./docker-compose.yml`), and the
`image` job runs it alone. A service that names an undeclared network is a
project-parse error. `8fa2196` declares `networks: platform:` (empty, so it merges
on top of kit's with nothing to override). Verified:

```
$ docker compose config                              # standalone
rc 0
$ docker compose -f <kit>/…/docker-compose.yml -f ./docker-compose.yml config
rc 0
```

---

## 5 — What I deliberately did NOT do

- **Did not touch `cafaye/kit`.** Its config is the contract; the caps behaviour
  is reported, not edited.
- **Did not weaken or skip any test.** No `skip`, `Skip`, `t.Skip`, `//go:build`
  exclusion, or `|| true` was added. `test/noSkips.test.ts`'s Go analogue is
  untouched.
- **Did not push or merge.**
- **Did not "fix" a nil verifier that is not there.** No production auth code was
  changed for the packet's stated defect, because the defect is not in the auth
  code.
- **Did not fix the `ci (kit) / go` job's test step** — see below: it is not
  fixable from this repository.

### The finding this leaves open (successor's first move)

**`ci (kit) / go` will still be red after the lint is fixed, for the same Redis
reason.** kit's reusable `go` job runs `go test -race -count=1 ./...` and
`workflow_call` gives a reusable workflow no `services:` and no environment input
(`required-tier` only escalates a failure; there is no URL/service input). So the
three runtime session tests, which exec a local `redis-server`, will fail in that
job exactly as they failed in `bin/prime`.

This is a real design conflict, not a one-line fix, and it needs a decision that
is out of this packet's scope:

1. **kit grows a Redis capability** for the `go` job (a `services:` block or an
   env input), or
2. **gateway gates the runtime session tests** the way the ratelimit live tier is
   gated (require an env; print a counted skip otherwise), and its own jobs set
   it — which trades the repo's "no silent skip" stance for a green shared job.

Option 2 is the one that fits kit's current shape, but it is a change to the
repo's testing philosophy and to `test/noSkips`'s analogue, so it should be its
own packet with the fleet's input. Reproduce with:

```
go test -race -count=1 ./internal/httpapi/   # on a runner with no redis-server
```
