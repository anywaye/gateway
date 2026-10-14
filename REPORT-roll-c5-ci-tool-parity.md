# REPORT roll-c5-ci-tool-parity

## The two seams

Gateway runs its Go tests in two places for two different reasons, and both
were red on a missing binary rather than on a defect.

* **The kit `go` job.** `internal/httpapi/runtime_session_test.go` starts a real
  `redis-server` by *execing* the binary on a free port (`startRedis` via
  `exec.LookPath("redis-server")`) and **fails** when it is absent. That refusal
  is the tier's design: a green that has not exercised the wire commands is a
  green about nothing. kit's shared `go` job runs `go test -race -count=1 ./...`
  over the caller's tree and installed nothing, so the same suite was red on
  `exec: "redis-server": executable file not found in $PATH`. The defect is not
  in the tests; the job had not been taught to provide what they exec.

* **The service's `bin/prime` job.** `roll-c5-lint-parity` added
  `golangci-lint run --config <kit/lint/golangci.yml> ./...` to `bin/prime-go`
  at the pinned version `2.14.0` (`mise.toml`), with a `command -v
  golangci-lint` guard that exits 127 when the binary is absent. Locally the
  tool is on PATH via `mise install`; CI's `prime` job installed Go and
  `redis-server` and ran `bin/prime` but never ran mise, so the step exited
  127. Local green, CI red, same shape.

## What changed in kit

* `.github/workflows/ci.reusable.yml` — new input `test-packages` (space-separated
  apt package names, default `''`) and a new step `test-packages` in the `go`
  job:

  ```yaml
  - name: test-packages
    if: ${{ inputs.test-packages != '' }}
    run: sudo apt-get update -qq && sudo apt-get install -y ${{ inputs.test-packages }}
  ```

  Empty by default so adoption never turns a green repo red. The description
  names the class (binaries the tests *exec* rather than dial) and the
  gateway instance. The step is before `test` and after `lint`, so the linter
  never pays for an apt install it does not need.

## What changed in gateway

* `.github/workflows/ci.yml` — the caller side of both seams:

  * `ci` job (`ci (kit)`): `with: test-packages: redis-server` beside `versions`.
    The comment names the three tests that need it and that the same binary is
    installed directly in `prime` below.

  * `prime` job: new step `golangci-lint, the version mise.toml pins` before
    `bin/prime`. It reads the pin out of `mise.toml` (`"golangci-lint" =
    "2.14.0"`), derives the runner arch, fetches
    `https://github.com/golangci/golangci-lint/releases/download/v${version}/...`,
    installs to `$HOME/.local/bin`, appends that dir to `$GITHUB_PATH` and
    prints `golangci-lint --version`. The version is never typed here; one pin
    (`mise.toml`) decides both, and `bin/prime-go`'s version check proves the
    installed binary is the pin.

* `bin/prime-go` — new step `the CI jobs install every tool this gate
  requires`, the durable control for the class:

  * Requirement set is **derived, not listed**: `command -v <tool>` in
    `bin/prime` / `bin/prime-go` (gate tools the script refuses without) and
    `exec.LookPath("<binary>")` in `*_test.go` (binaries the tests exec).
    Today: `go`, `golangci-lint`, `redis-server`.

  * Two jobs are checked differently because they provide tools differently.
    Both run the suite, so both need the test binaries: `prime` installs them
    itself, `ci (kit)` hands them to kit via `test-packages`. Gate tools only
    reach `prime` (kit's `go` job never calls `bin/prime`).

  * Comments are stripped before the search and `install` must share a line
    with the tool, so prose mentioning the tool cannot satisfy the check
    (the `stripbaseurl` header lesson). `go` is satisfied by
    `actions/setup-go`.

  * Empty requirement set, empty job block, or missing workflow all fail
    loudly — a check that cannot read its subject is not a check that passed.

## The check that keeps the class from recurring

A shell-level check in `bin/prime-go` (not a second workflow, not a skipped
test). A new `command -v` guard or a new `exec.LookPath` call reds the gate
the developer runs, naming the tool and the job that must install it, before
the 127 or the missing-package red could happen in CI.

## Controls — red must go red

All three were measured on this tree with `bin/prime-go`:

* `redis-server` removed from `prime` job's `run: sudo apt-get install -y
  redis-server` → `::error::the CI 'prime' job does not install
  'redis-server'` and exit 1.

* `golangci-lint` install step removed from `prime` job → `::error::the CI
  'prime' job does not install 'golangci-lint', which bin/prime-go refuses
  to run without (it exits 127)` and exit 1.

* `test-packages: redis-server` removed from `ci` job → `::error::the CI 'ci
  (kit)' job does not hand kit a 'test-packages' value naming 'redis-server'`
  and exit 1.

Each is the class's general form, not a hand-written list.

## Verification — green must be green

Locally on the same commit, with the kit tree at `cafaye/kit@fd383c9`
(the `test-packages` seam) beside the service:

```
# the gate a developer runs — the same command CI's prime job runs
$ bin/prime
==> toolchain: go 1.26.1 (mise.toml pins 1.26.1)
==> the CI jobs install every tool this gate requires
CI tools: 'prime' installs go golangci-lint redis-server; 'ci (kit)' passes redis-server to kit
...
suite: 272 passed, 0 failed
packages: 8 with tests
==> ok
== prime ok

# the shared job's test command, with the binary the seam provides
$ go test -race -count=1 ./...
ok  github.com/cafaye/gateway/internal/httpapi  5.980s   # three redis-backed tests pass
ok  github.com/cafaye/gateway/internal/ratelimit 1.1s
...

# kit's own gate, static phase
$ bash tests/validate.sh --static-only
PASS .github/workflows/ci.reusable.yml (yaml.safe_load_all)
```

CI's `bin/prime` job now installs `golangci-lint` at the mise pin and
`redis-server`; kit's `go` job installs `test-packages` before `go test`,
so `ci (kit) / go`'s test step passes on the merged tree. The two
verdicts are the same binary the developer ran.

## Files

* `cafaye/kit/.github/workflows/ci.reusable.yml` — `test-packages` input
  and `test-packages` step in `go` job.
* `gateway/.github/workflows/ci.yml` — `test-packages: redis-server` on
  `ci` job; `golangci-lint` pinned install on `prime` job.
* `gateway/bin/prime-go` — derived CI-tool check.
