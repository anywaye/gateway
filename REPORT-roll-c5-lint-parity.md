# REPORT — roll-c5-lint-parity: the fleet's lint is unpinned, so the local gate and CI disagree by 37 findings

**Where:** `golangci-lint`'s invocation in `cafaye/kit/.github/workflows/ci.reusable.yml` (the `lint` step), gateway's `.github/workflows/ci.yml`, and gateway's `bin/prime` / `bin/prime-go`.

Branch `roll/c5-lint-parity`. Not pushed, not merged.

---

## 1. The measured split

The same tree, the same config, two answers:

```
$ golangci-lint run --config ../kit/lint/golangci.yml ./...           # local, 2.6.2
0 issues.

$ /tmp/gobin/golangci-lint run --config ../kit/lint/golangci.yml ./...  # 2.14.0, --max-same-issues 0
37 issues, all:
  net/http/httptest.NewRequest must not be called. use net/http/httptest.NewRequestWithContext (noctx)
```

The config is byte-identical (kit's `lint/golangci.yml`, read at `../kit/lint/golangci.yml` locally and at `.kit/lint/golangci.yml` in CI after sparse checkout). The tool is not: the workflow invoked `golangci/golangci-lint-action@v9` with no `version:` pin, so it installed whatever the action considered current (2.14.0 at time of measurement), and a newer `noctx` flags `httptest.NewRequest` (deprecated in Go 1.23 in favour of `NewRequestWithContext`) in contexts 2.6.2 does not reach.

With the default `max_same_issues` filtering, 2.14.0 shows only 3 of the 37 (the rest hidden as `34/37 issues with text "net/http/httptest.NewRequest must not be called..." were hidden`). CI would have shown `X 14 issues found` at the time the packet was written (before the previous commit fixed 4 of them), and would show 37 today if the lint step ran on this tree at `HEAD~1`.

One previous commit in this circle (`d7d8a68`, "lint: the noctx findings the merged AUTH packet left behind") fixed 4 findings (3× `httptest.NewRequest` in `internal/httpapi/assertion_test.go` + 1× `net.Listen` in `internal/ratelimit/redis_auth_test.go`), which is why the count moved from 14-evidence to 37-measured-today: the 37 is the remainder.

A fourth class of the same blind spot (`net.Listen`) was added by the Redis AUTH packet and caught by CI after merge, because the gateway gate did not run the lint at all.

---

## 2. What the gate now runs

### 2.1 The lint is now part of the gate

`bin/prime-go` has a new step `golangci-lint run` between `go vet` and `go test`:

- **Tool presence is required.** If `golangci-lint` is not on PATH, the gate fails with exit 127 and a message naming `mise install` — not a skip. A step that quietly skips when the linter is absent is the whole defect.
- **Version is checked.** The pinned version is read from `mise.toml` (`"golangci-lint" = "2.14.0"`) and compared against `golangci-lint --version`. A mismatch fails the gate. This is the same shape as the Go toolchain pin (two files, one gate, one check).
- **Config is resolved, not assumed.** The step searches for kit's config at `.kit/lint/golangci.yml` (CI, sparse checkout), `../kit/lint/golangci.yml` (moon workspace, local), and `lint/golangci.yml` (fallback). If none exists, the gate fails. The config is not copied into the service repo — kit's own header says why ("Not copied into a service repo") and a copy is a second policy to drift.
- **Findings fail the gate.** `golangci-lint run --config <kit-config> ./...` exits non-zero on any finding, and under `set -e` that fails the gate.

### 2.2 The version is pinned in both places

| File | Before | After |
|------|--------|-------|
| `mise.toml` | no `golangci-lint` pin | `"golangci-lint" = "2.14.0"` |
| `cafaye/kit/.github/workflows/ci.reusable.yml` | `uses: golangci/golangci-lint-action@v9` with no `version:` | `version: v2.14.0` added |

A bump touches both in the same commit — otherwise local and CI disagree, which is the defect this packet exists to close. The packet's "Do not" explicitly forbids pinning only in the action and not locally.

### 2.3 Step order

```
gofmt -l  →  go build  →  go vet  →  golangci-lint run  →  go test  →  generated-code currency
```

Lint after vet, before test. Kit's CI does `install → build → lint → test` — same work, same order, same config, same version.

---

## 3. The findings fixed

Every `httptest.NewRequest` in the tree is gone. 37 sites across 12 files, mechanical replacement:

```
httptest.NewRequest(m, url, body)
→ httptest.NewRequestWithContext(context.Background(), m, url, body)
```

`context` import added where a file lacked it (8 files). Behaviour-preserving: `context.Background()` is the same context `httptest.NewRequest` used internally.

| File | Sites | Context import added |
|------|-------|---------------------|
| `internal/httpapi/bff_test.go` | 6 | already had it |
| `internal/httpapi/httpapi_test.go` | 1 | already had it |
| `internal/httpapi/observability_test.go` | 1 | already had it |
| `internal/httpapi/runtime_session_test.go` | 1 | already had it |
| `internal/httpapi/vhost_test.go` | 8 | yes |
| `internal/httpapi/runtime_limits_test.go` | 9 | yes |
| `internal/httpapi/proxy_test.go` | 3 | yes |
| `internal/httpapi/runtime_routing_test.go` | 2 | yes |
| `internal/httpapi/pantry_shipped_table_test.go` | 2 | yes |
| `internal/httpapi/problem_test.go` | 2 | yes |
| `internal/ratelimit/key_test.go` | 1 | yes |
| `internal/ratelimit/fixture_test.go` | 1 | yes |

No `//nolint` directives. No production code changed. No config copied.

Previous commit `d7d8a68` already fixed 4 findings (the `assertion_test.go` and `redis_auth_test.go` sites the packet's evidence was written against); this commit fixes the remaining 37.

---

## 4. The controls (red must go red)

All three controls are about the GATE, not the fixes:

### 4.1 Green, real tree — gate fails on injected finding

```
$ cat > internal/httpapi/inject_test.go <<'GO'
  package httpapi
  import ("net/http/httptest"; "testing")
  func TestInjectedNoCtx(t *testing.T) { _ = httptest.NewRequest("GET", "/", nil) }
  GO
$ ./bin/prime-go > /tmp/log 2>&1; echo "exit: $?"
  exit: 1
  # lint step: "httptest.NewRequest must not be called. use httptest.NewRequestWithContext (noctx)"
```

Gate fails with non-zero exit when a `noctx` finding is injected. Verified.

### 4.2 RED control — gate without the lint step does not fail

Stashed the new lint step and re-ran the same injection on the tree as it stands on `master`:

```
$ git stash push -m "temp" --keep-index
$ cp inject_test.go internal/httpapi/inject_test.go
$ ./bin/prime-go > /tmp/log 2>&1; echo "exit: $?"
  exit: 0    # lint not run, injection not caught
$ git stash pop
```

The gate as it stands on `master` (without the lint step) does not fail on the injected finding. The new step discriminates. Reverting just the lint step makes the check go red.

### 4.3 Green, real tree — clean tree passes

```
$ ./bin/prime-go > /tmp/log 2>&1; echo "exit: $?"
  exit: 0
$ ./bin/prime > /tmp/log 2>&1; echo "exit: $?"
  exit: 0    # bin/prime wraps bin/prime-go and prints "== prime ok"
```

Clean tree passes with no false positive. Verified.

### 4.4 Independent verification

```
$ golangci-lint --version
  golangci-lint has version 2.14.0 built with go1.26.1

$ golangci-lint run --config ../kit/lint/golangci.yml ./...
  0 issues.

$ golangci-lint run --config ../kit/lint/golangci.yml ./... --max-same-issues 0
  0 issues.
```

The version CI installs (2.14.0, pinned via `version: v2.14.0` in kit's workflow and `"golangci-lint" = "2.14.0"` in `mise.toml`) reports zero issues over the tree. Quoted in the commit message.

---

## 5. The exact command a manager copies to reproduce CI's verdict locally

```sh
mise install                          # installs golangci-lint 2.14.0 as pinned in mise.toml
golangci-lint run --config ../kit/lint/golangci.yml ./...
# or, equivalently, the gate itself:
./bin/prime-go                        # runs the same lint with the same config and version, plus the rest of the gate
./bin/prime                           # wrapper that runs bin/prime-go and prints "== prime ok"
```

In CI, the same lint runs via `golangci/golangci-lint-action@v9` with `version: v2.14.0` and `args: --config=${{ github.workspace }}/.kit/lint/golangci.yml` (kit's `ci.reusable.yml`, `go` job, `lint` step). The config is fetched by sparse checkout of `cafaye/kit` at `lint/`.

---

## 6. What is not in this packet

- The prose hits naming `GATEWAY_EQUIVALENCE_REQUIRED` in `Dockerfile:83`, `README.md:947`, `AGENTS.md:408`, `CHANGELOG.md:639`, `gate.yml:347` — all describing a tier that no longer exists. Named in `ci.yml`'s header as a separate packet.
- The `TODO(guard-07)` shared store, the API keys, the scope check, the limiter counting forwarded traffic, per-service readiness probes — all in the README's "Not built yet" list. Not this packet.
