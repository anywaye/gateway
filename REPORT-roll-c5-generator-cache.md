# REPORT-roll-c5-generator-cache

## The three defects, in the order the job failed for them

1. **exit 127 — `golangci-lint` not on PATH.** Closed by `roll-c5-ci-tool-parity`
   (merged): the `prime` job installs the linter at mise.toml's pin, `redis-server`
   for the exec'ing session tests, and the kit lint-config checkout.
2. **`kit's lint config not found`.** Closed by `a4a5ba3`: the job sparse-checks
   out kit beside the repository (`.kit/lint`).
3. **`regeneration FAILED` — the one this packet owns.** `internal/api/generate.go`
   ran the generator as `go run <module>@<version>`, which resolves in a throwaway
   module context: Go fetches the tool's module *and its whole transitive graph*
   at run time. The pre-seed step (`f5f9cad`) downloaded only the tool's own
   module, so on a fresh runner the offline regeneration
   (`GOPROXY=file://$GOMODCACHE/cache/download`, which `bin/prime-go` forces)
   died on the first missing dependency zip (`kin-openapi`, `speakeasy-api/...`,
   `go.yaml.in/yaml/v3`, `x/mod`, `x/text`). Locally green, CI red — the same
   local/CI split `roll-c5-lint-parity` closed for the linter, in the one place
   nobody had measured.

## The seam: the preferred `tools.go` route

`tools.go` (build tag `tools`) blank-imports `cmd/oapi-codegen`. `go mod tidy`
records the tool and its graph in `go.mod`/`go.sum`; `go mod download` fills it;
`setup-go`'s cache (keyed on `go.sum`) carries it across runs. The alternative
(throwaway-module pre-seed in CI) was rejected: it would leave the tree not
declaring the tool it runs, i.e. the deeper problem unfixed.

The `//go:generate` line drops `@v2.8.0` and runs `go run <module>` in this
module's context. This is the load-bearing half: an `@version` invocation ignores
this module's `go.mod`, so no download of *this* module could ever have filled
its graph, and shared modules (notably `golang.org/x/text`, which this module
pins newer than the tool does) would resolve to versions the main-module cache
was never asked to hold.

Version discipline: one copy, in `go.mod` (taken there by `go get` reading the
old pin out of `generate.go`, never retyped). `bin/prime-go`'s header assertion
now reads the expected version out of `go.mod` instead of carrying its own
`v2.8.0` literal; the CI step carries no version at all (plain `go mod
download`). The CI `go.mod`/`go.sum` untouched guard keeps its intent — neither
the download nor the in-module generate rewrites the manifests — with a comment
saying so. The regeneration still fails loudly when the generator cannot run;
nothing was softened.

## Proofs

- **RED:** fresh empty `GOMODCACHE`, regen exactly as `bin/prime-go` invokes it
  (file:// proxy, `GOSUMDB=off`) → `reading .../oapi-codegen/v2/@v/v2.8.0.zip:
  no such file or directory`, `generate.go: running "go": exit status 1`,
  `api.gen.go` untouched.
- **GREEN (mechanism):** same empty cache, `go mod download`, then the identical
  offline regen → exit 0, `stripbaseurl: rewrote 10 route registration(s)`,
  `api.gen.go` byte-identical. (Scratch cache removed afterwards.)
- **Local gate:** `bin/prime` exit 0. Regeneration verdict:
  `internal/api/api.gen.go regenerates byte-identically from openapi/v1.yaml,
  carries the v2.8.0 header, and its registrations are readable`.
  Suite 272 passed / 0 failed, 8 packages, 13/13 declared skips, lint 2.14.0
  clean, `go mod tidy` clean, `go build`/`go vet` clean with the tag excluded.
- **RED control (seam is load-bearing):** the RED run above is exactly the job
  with the tool's graph absent — offline regen fails. Removing `tools.go` (and
  its `go.mod` entries) returns to that state: `go run <module>` cannot resolve
  a package no module provides.
- **Independent verification (STILL OWED):** a `bin/prime` CI run on a pushed
  branch with a cold module cache. This worker does not push; the manager merges
  and pushes, and the regeneration step's verdict from that run belongs in the
  merge commit message.
