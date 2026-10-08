# REPORT-local-gate-m118 — gateway local gate evidence (verification-only)

- Packet: m118, verification-only. No product code changed.
- Repo: gateway worktree `/Users/kaka/Code/any/wt/gateway`
- Branch: `worker/m118-local-gateway-gate`
- Revision: `af6bd3d3e28918b5e12783954336491e978e6026` (master at dispatch;
  `af6bd3d Merge worker/gateway-w95-publish: ... chart-dir charts/gateway/ ...`)
- Date: 2026-10-08 (UTC)
- Pre-reads: `AGENTS.md` and exact `bin/prime` gate (wrapper around
  `bin/prime-go`; no flags) before running.

## Command (run exactly once)

```
timeout 1800 ./bin/prime > /tmp/gate-m118-gateway-local.log 2>&1; echo $? > /tmp/gate-m118-gateway-local.exit
```

- Ran in background per the worker contract; polled, never rerun, never patched.
- No install/launch, no container stop/modify, no publish/deploy command.
- Gate shape observed: `bin/prime` -> `bin/prime-go` plus final `== prime ok`.

## Result

- Exit: `0`
- Elapsed: `12s` wall (`/tmp/gate-m118-gateway-local.start` to `.end` delta)
- Final line: `== prime ok`
- Evidence files (kept, not committed):
  - `/tmp/gate-m118-gateway-local.log` (19347 bytes, full log)
  - `/tmp/gate-m118-gateway-local.exit` (`0`)
  - `/tmp/gate-m118-gateway-local.start` / `.end` (wall-clock bounds)

## Step banners (all present, ANSI-stripped)

```
==> toolchain: go 1.26.1 (mise.toml pins 1.26.1)
==> the publish caller publishes the image and the chart
==> gofmt -l
==> go build ./...
==> go vet ./...
==> go test ./...
==> the generated server matches the OpenAPI document
==> ok
== prime ok
```

- Toolchain: `go version go1.26.1 darwin/arm64`; image tag `1.26` = pin
  major.minor.
- gofmt: `every file under ./cmd and ./internal is gofmt-clean`.
- Publish: `.github/workflows/publish.yml calls kit's composed publish
  workflow with push: true, grants packages: write, and points at
  charts/gateway/ — whose Chart.yaml version 0.1.0 is the substrate's
  targetRevision 0.1.0`.
- Generated: `internal/api/api.gen.go regenerates byte-identically from
  openapi/v1.yaml, carries the v2.8.0 header, and its registrations are
  readable`.

## Test counts (read off the captured log, gate not rerun)

- `suite: 252 passed, 0 failed` (matches `gate.yml` measured 252)
- `packages: 8 with tests`
- Direct grep of the log: `--- PASS: 252`, `--- FAIL: 0`, `--- SKIP: 13`,
  `ok: 8`
- `FAIL` lines: none (`grep -E '^(FAIL|--- FAIL)'` -> no match)

## Skips (all declared, none hidden)

- `ratelimit: DID NOT RUN — ... GATEWAY_REDIS_URL is unset. ...`
- `skips: 13 of 13 declared (all of them the live Redis tier), and 1 t.Skip() call site`
- The 13 `--- SKIP:` lines are all `internal/ratelimit` live-tier tests
  (ping/pong, GCRA script vs memory store, burst, expiry, error replies,
  charset, shared bucket, connection loss).
- Single skip call site: `internal/ratelimit/live_test.go:179`
  (`t.Skip("no GATEWAY_REDIS_URL: the live Redis tier did not run")`).
- `GATEWAY_REDIS_URL` / `GATEWAY_REDIS_REQUIRED` were unset: skip-by-design
  path, same as `gate.yml` documents.

## Failure summary

- None. Exit 0, zero `--- FAIL`, all six `gate.yml` proofs present in the log
  (`suite`, `go-mechanical`, `publish`, `go-generated`, `ratelimit`, `ok`).

## Tree hygiene

- `git status` clean before the run; after this report, the only change is
  this file. Committed on `worker/m118-local-gateway-gate`, not pushed.
- No credentials or secret-bearing output in the log or this report (the gate
  is hermetic; no tokens involved).
