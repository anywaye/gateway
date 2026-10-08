# REPORT-gateway-full-gate-m132 — gateway master full-gate evidence (verification-only)

- Packet: m132, existing-behavior release-readiness gate. No product or test
  source changed, no gates loosened.
- Repo worktree: `/Users/kaka/Code/any/moon/wt/gateway-m132-gate`
  (branch `m132-gateway-gate`)
- Reference tree checked: `/Users/kaka/Code/any/moon/cafaye/gateway` master HEAD.
- Revision: `4c150504771811925e057d269825215ebbb05c5b`
  (`m121: live Redis tier proof against launch stack — 14 passed, 0 failed, 0 skipped`)
- Pre-gate state: worktree HEAD equals the reference master HEAD, and
  `git status --porcelain` was clean (no uncommitted partial work from the
  prior attempt was present — nothing to keep or discard).
- Date: 2026-10-08 (UTC).

## Command (run exactly once)

```
./bin/prime
```

- Run in background per the worker contract, output captured to per-worktree
  files (basename `gateway-m132-gate`, no shared `/tmp/gate.log`):
  - `/private/var/folders/3b/kt90wy3d66lftws_dwtxxglm0000gn/T/gate-gateway-m132-gate.log` (19348 bytes, exact output)
  - `.../gate-gateway-m132-gate.exit` (`0`)
  - `.../gate-gateway-m132-gate.start` (`2026-10-08T02:27:30Z`)
- Kept, not committed. Polled to completion; never rerun, never patched.
- No flags: `bin/prime` takes none (unknown arguments exit 2 by design).
- Gate shape observed: `bin/prime` -> `bin/prime-go` plus final `== prime ok`.

## Live Redis tier handling

- `GATEWAY_REDIS_URL`, `GATEWAY_REDIS_REQUIRED`, and
  `GATEWAY_EQUIVALENCE_REQUIRED` were all unset at dispatch, so the gate ran
  exactly as declared and the live Redis tier took its documented skip path.
- No shared service was started, stopped, or configured. A listener does answer
  `PING` on `127.0.0.1:6379` on this host, but wiring the gate to it would have
  meant pointing the suite at a service this run does not own, so it was
  deliberately left unused and the tier is recorded as a counted skip below.

## Result

- Exit: `0`
- Elapsed: ~22s wall (start `2026-10-08T02:27:30Z` to gate-output mtime
  `02:27:52Z`)
- Final line: `== prime ok`
- Step banners, all present in the captured log:
  - `==> toolchain: go 1.26.1 (mise.toml pins 1.26.1)`
  - `==> the publish caller publishes the image and the chart`
  - `==> gofmt -l` (`every file under ./cmd and ./internal is gofmt-clean`)
  - `==> go build ./...`
  - `==> go vet ./...`
  - `==> go test ./...`
  - `==> the generated server matches the OpenAPI document`
    (`internal/api/api.gen.go regenerates byte-identically from
    openapi/v1.yaml, carries the v2.8.0 header, and its registrations are
    readable`; `stripbaseurl: rewrote 7 route registration(s) in api.gen.go`)
  - `==> ok`
  - `== prime ok`
- Toolchain: `go version go1.26.1 darwin/arm64`; image tag `1.26` matches the
  pin's major.minor.

## Test counts (read off the captured log, gate not rerun)

- `suite: 252 passed, 0 failed`
- `packages: 8 with tests`
- Direct grep of the log: `--- PASS:` 252, `--- FAIL` 0, `--- SKIP:` 13,
  `^ok` package lines 8, `^(FAIL|--- FAIL|panic)` matches 0.
- Per-package durations (`ok <package> <duration>`):
  - `cmd/gateway` 1.369s
  - `internal/auth` 2.801s
  - `internal/equivalence` 2.224s
  - `internal/httpapi` 10.162s
  - `internal/ratelimit` 6.143s
  - `internal/sessionredis` 6.666s
  - `internal/sessiontest` 6.679s
  - `internal/telemetry` 7.039s
  - `internal/api`, `internal/api/stripbaseurl`, `internal/session`,
    `internal/testkeys`: no test files.

## Skips (all declared, none hidden)

- `ratelimit: DID NOT RUN — ... GATEWAY_REDIS_URL is unset. Set
  GATEWAY_REDIS_URL=redis://127.0.0.1:6379 to run the GCRA script against a
  real server, or GATEWAY_REDIS_REQUIRED=1 to make this a failure.`
- `skips: 13 of 13 declared (all of them the live Redis tier), and 1 t.Skip()
  call site`
- All 13 `--- SKIP:` lines are `internal/ratelimit` live-tier tests (server
  ping/pong, reply decoding, script integers, error-reply isolation, script vs
  memory parity incl. randomised limits, burst admission, shared bucket,
  connection loss, key expiry, debt accounting, charset).
- Single skip call site: `internal/ratelimit/live_test.go:179`
  (`t.Skip("no GATEWAY_REDIS_URL: the live Redis tier did not run")`).

## Failures

- None. Exit 0, zero `--- FAIL`, zero `FAIL`/`panic` lines.

## Secrets

- None present. The captured log is compiler/test output only; nothing
  redacted because nothing secret appears. No credentials were read, set, or
  passed during this run.

## Commit

- This report is the only file added/committed by this run. Product and test
  source untouched; `git status` after the run shows only this report as a new
  file. No push (manager merges).
