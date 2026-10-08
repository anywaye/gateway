# REPORT-gateway-license-m166 — first-party proprietary license migration

Branch `gateway-license-m166`, on top of `master @ 13f9227`. Not pushed, not merged.
Tree clean at handoff (two commits, both local).

## What this packet did

Moved Gateway's first-party license declarations from MIT to Cafaye's
proprietary notice, in this repository only. No release published, no product
behavior changed, no workflows/dependencies/docs-broadly touched.

## Changed files (commit 8507bfe)

| File | Change |
|---|---|
| `LICENSE` | Replaced MIT grant text with Identity's proprietary text, byte-for-byte (`cmp` clean) |
| `openapi/v1.yaml` (`info.license`) | `name: MIT` + `url: https://opensource.org/license/mit` → `name: Proprietary - All rights reserved. See LICENSE in the cafaye/gateway repository.` (no `url`; mirrors identity's `info.license` shape with gateway's own repo named) |
| `README.md` (`## License`) | `MIT. See LICENSE. package.json declares the same thing.` + the "MIT is what keeps adding it…" paragraph → `Proprietary. See LICENSE.` + third-party preservation line |

## Exact checks and results

- `cmp /Users/kaka/Code/any/moon/cafaye/identity/LICENSE LICENSE` → identical (exit 0, no output).
- Repo-wide scan of tracked files for first-party grant surfaces
  (`opensource.org`, `MIT License`, `"license":`, `license: MIT`, `name: MIT`,
  `SPDX`, `LABEL … license`, across `*.yaml/*.yml/*.md/*.go/*.json/*.toml`,
  plus `Dockerfile`, `docker-compose.yml`, `charts/gateway/*`, `cafaye.yml`,
  `go.mod`): after the edit, zero hits outside `REPORT-*`/`HANDOFF-*` history
  files and `CHANGELOG.md` history entries (both deliberately preserved).
- `ruby -ryaml YAML.load_file('openapi/v1.yaml')` → `YAML OK`,
  `info.license == {"name" => "Proprietary - All rights reserved. See LICENSE in the cafaye/gateway repository."}`.
- Codegen currency (same-commit rule from `internal/api/generate.go`):
  `GOFLAGS=-mod=mod GOPROXY="file://$(go env GOMODCACHE)/cache/download" GOSUMDB=off go generate ./internal/api/`
  → exit 0 (`stripbaseurl: rewrote 7 route registration(s)`), and
  `git status` shows `internal/api/api.gen.go` unmodified — the committed
  generated file already matches the edited document, as expected
  (`oapi-codegen` does not emit `info.license` into the Go server).
- No Go source changed, so no `gofmt`/`vet` surface was touched. No Docker,
  full prime, E2E, image/chart build, or publish run, per the brief.

## Preserved third-party notices

None removed: the tree carries no third-party license headers or `NOTICE`/
`THIRD-PARTY` files (searched `Apache License`, `BSD … License`,
`Copyright (c)`/`©` across `*.go`/`*.ts` — zero hits), so there was nothing
to preserve beyond leaving every dependency manifest and vendored byte
untouched, which this packet did. The new `LICENSE` itself states that
third-party components remain under their own licenses, and the README
`## License` section repeats that line.

## Historic-MIT limitation (read before acting on this)

Git history and `CHANGELOG.md` still record that Gateway was MIT-licensed
(e.g. `CHANGELOG.md:1005-1009`, "gateway is MIT"). That is history, not a
grant: it says past revisions were distributed under MIT, which this packet
cannot and does not rewrite. Anyone distributing or relying on a pre-m166
revision must read that revision's own `LICENSE`. This packet changes only
the current tree's license/metadata surfaces.

## Gateway-specific notes for the next reader

- The README's old line claimed "`package.json` declares the same thing" —
  the repository has no `package.json` (Go-only since the cutover at
  `f87c891`), so that clause was stale as well as MIT; it is gone.
- No documented third-party/license-holder issue was found in Gateway, so
  per the brief the migration proceeded rather than stopping.
- `charts/gateway/Chart.yaml` carries no license field and `cafaye.yml`
  carries none — nothing to update there.
