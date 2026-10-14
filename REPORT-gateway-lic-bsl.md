# REPORT-gateway-lic-bsl — gateway's licence is now a Business Source License 1.1

Branch `ops/w0-lic-services-a-gateway`, two commits on top of
`1821faf tg-c1: handoff report`. Not pushed, not merged, no branch switched.
This repository only — no other worker's tree was read or written.

## What this packet was for

OPS-P1 part 2. `CAFAYE-OPS.md` OPS-D2 splits the fleet's licences: the
framework (`core`, `cafe`, `kit`, `pantry`) under MIT or Apache-2.0, the
services under a **Business Source Licence** — free to run, free to self-host,
never to offer a competing service — and `conductor` and the artifact
distribution closed (`/Users/kaka/Code/any/moon/CAFAYE-OPS.md:176`,
`/Users/kaka/Code/any/moon/CAFAYE-OPS.md:879`). Gateway was carrying the
proprietary notice from `m166`
(`REPORT-gateway-license-m166.md:16`, which records that its own parent grant
was MIT at `CHANGELOG.md:1039`), and this packet moves it to the services'
grant. Three other workers hold the same packet for `identity`, `courier`
and `parlor`.

## What changed, and where

Two commits:

| commit | files |
|---|---|
| `lic-bsl: LICENSE is now a Business Source License 1.1, Licensed Work gateway` | `LICENSE` |
| `lic-bsl: the contract and the README name the new grant instead of proprietary` | `README.md`, `openapi/v1.yaml`, `CHANGELOG.md` |

| file | what it says now |
|---|---|
| `LICENSE` | BSL 1.1: Licensor `Cafaye`, Licensed Work `gateway`, Additional Use Grant `None`, Change Date `2030-10-10`, Change Licence `Apache-2.0`, then MariaDB's Terms, Covenants and Notice verbatim |
| `openapi/v1.yaml` (`info.license`) | `name: Business Source License 1.1. See LICENSE in the cafaye/gateway repository.` — was `name: Proprietary - All rights reserved. See LICENSE in the cafaye/gateway repository.` |
| `README.md` (`## License`) | the grant, its five parameters as a table, and what the BSL does and does not grant |
| `CHANGELOG.md` | one `### Changed` block under `## [Unreleased]` (`CHANGELOG.md:9`) |

Nothing else in the tree states a first-party grant. That is a measurement, not
an assumption: a case-insensitive grep over the tracked tree for
`proprietary|all rights reserved|\bMIT\b|Apache-2|SPDX|source-available|
copyright|©` returns the four files above plus `REPORT-*` and `CHANGELOG.md`
history, and nothing else. There are no README badges to fix — a grep for
`badge` in `README.md` is empty.

### The BSL text, and what was substituted

The parameters are the brief's. Everything else is MariaDB's published BSL 1.1
text, taken from `https://mariadb.com/bsl11/` and cross-checked against a
real-world adopter's file (`MaterializeInc/materialize`, `LICENSE`, whose
parameter block is the shape this one uses). The only editorial choice worth
naming is the spelling: the brief writes "Change Licence", the published text
writes "Change License", and **the published spelling won**. A licence text is
the one place in this repository where house style yields to the words being
quoted — the Covenants say "Not to modify this License in any other way", and
respelling the body is a modification nobody asked for. The *value* is the
brief's: `Change License: Apache-2.0`.

The old notice's third-party sentence is kept, below a rule, at the foot of
`LICENSE` — third-party components remain under their own licences and
notice, nothing here asserts Cafaye ownership over third-party work. The
repository has no third-party licence headers or `NOTICE` file to preserve:
the same measurement `REPORT-gateway-license-m166.md:44` made (a grep for
`Apache License`, `BSD . License`, `Copyright (c)` and `©` across the Go
sources) is still empty.

## Gateway has no manifest licence field, and cannot grow one

This is the one place the packet's premise does not fit this repository, and it
is a finding rather than an omission.

- `cafaye.yml` is gateway's manifest and carries no licence declaration. It
  **cannot** carry one: it conforms to `core`'s frozen manifest schema, which
  is `"additionalProperties": false` at
  `/Users/kaka/Code/any/moon/cafaye/core/schemas/cafaye.manifest.schema.json:7`,
  with a closed property list of `consumes`, `core`, `dependencies`,
  `description`, `environments`, `exposes`, `kind`, `language`, `name`,
  `owner`, `repository` and the reserved tombstones. A `license:` key would be
  a **validation failure**, which `AGENTS.md` says in terms — a field the
  schema does not define is a failure, not a comment. The prior packet
  recorded the same absence (`REPORT-gateway-license-m166.md:66`).
- `charts/gateway/Chart.yaml` carries no `license` field and Helm's `license`
  is not part of a `cafaye.yml`-style contract; nothing in the fleet reads it.
- `go.mod` has no licence field to update, and `package.json` no longer exists
  — gateway has been Go-only since the TypeScript cutover, which is why
  `m166` deleted the stale "`package.json` declares the same thing" clause
  (`REPORT-gateway-license-m166.md:62`).

So no manifest can be left disagreeing with `LICENSE`, because no manifest
states a grant. The brief's `parlor`-style `"license": "UNLICENSED"` case has
no counterpart here; that is one of the four workers' jobs, not this one's.

## Verification, with real exit codes

| command | exit | result |
|---|---|---|
| `ruby -ryaml YAML.load_file('openapi/v1.yaml')` | 0 | `YAML OK`, `info.license == {"name" => "Business Source License 1.1. See LICENSE in the cafaye/gateway repository."}` |
| `GOFLAGS=-mod=mod GOPROXY="file://$(go env GOMODCACHE)/cache/download" GOSUMDB=off go generate ./internal/api/` | 0 | `stripbaseurl: rewrote 10 route registration(s)`; `git status` then showed `internal/api/api.gen.go` **unmodified** |
| `grep -rni license internal test bin .github` | 1 | no matches — nothing in source, tests or the gate reads a licence string, so no gate surface was touched |
| `bash /Users/kaka/Code/any/ops-doc/refs/check.sh <changed files>` | 0 | see the run's own output |

The codegen run is the check that matters and it is not a formality: `LICENSE`
is not a source file, but `info.license` lives inside `openapi/v1.yaml`, and
`internal/api/api.gen.go` is generated from that document — a stale generated
router is a gate failure, so the edit had to be proved not to move it. It did
not. `bin/prime` was not run: the change reaches no Go, TypeScript, test or CI
file, and `gofmt`/`vet`/`bun test` had nothing to read.

## Deliberately not changed, and why

Each of these is a hit for the sweep's own pattern that is not this
repository's grant:

- `charts/gateway/values.yaml:132` — "closed-source charts and their secrets
  ride a pull-based system". That is DEPLOYMENT.md's rule about chart contents
  and secret values, not a statement that gateway is closed-source. Rewriting
  it would change a deployment rule while touching a licence packet.
- `CHANGELOG.md:1039-1052` and `REPORT-gateway-license-m166.md` — dated
  records of what the grant was. OPS-D3's principle is that a reversal is "a
  fact a reader can check, not a footnote they must discover"
  (`/Users/kaka/Code/any/moon/CAFAYE-OPS.md:177`); editing history into
  agreement with the present is how the drift this packet exists to prevent
  gets hidden. The CHANGELOG now carries both, in order.

## The disagreement, flagged and implemented as written

**`Additional Use Grant: None` does not grant self-hosted production use, and
OPS-D2 says the services are free to self-host.** The two sentences are not
reconcilable and I am reporting rather than quietly fixing it.

The BSL's first Terms paragraph grants "the right to copy, modify, create
derivative works, redistribute, and make **non-production** use", and the
third paragraph says that anything not complying with the licence "purchase[s]
a commercial licence from the Licensor … or … refrain[s] from using the
Licensed Work" (`LICENSE`). With no Additional Use Grant there is no
production grant, so a self-hoster running `gateway` in production on their own
box is outside the licence and needs a commercial licence from Cafaye. That is
narrower than "free to run, free to self-host"
(`/Users/kaka/Code/any/moon/CAFAYE-OPS.md:176`, `:879`).

I implemented the parameter as the brief specified and left it at `None`,
because the brief also says the grant wording is uniform across the fleet and
that a reader must be able to diff two repositories and see only the Licensed
Work name differ. One worker inventing an Additional Use Grant breaks exactly
that property, and a fleet-wide licence change that four workers execute four
different ways is worse than one they all execute one way. The fix belongs to
the manager, and it is one line in four repositories:

```
Additional Use Grant: You may make production use of the Licensed Work to run
your own infrastructure and your own users, and you may self-host it. You may
not offer the Licensed Work, or a derivative of it, to third parties as a
hosted, managed or competing service.
```

That sentence is OPS-D2's own description of the grant, and it is the shape
Materialize and CockroachDB use. Note that it needs the "competing service"
half to be meaningful — "never to offer a competing service" is the
restriction the Additional Use Grant exists to carry, and a grant with no such
restriction would be a plain permissive licence rather than a BSL. **Until the
manager takes it, the README and CHANGELOG I wrote describe the grant the file
actually makes, not the promise the decision row makes**, and the CHANGELOG
entry says so out loud rather than leaving the next reader to find the gap.

## What is left

Nothing in this repository. The fleet items that remain are the manager's:

1. The Additional Use Grant above, applied uniformly to gateway, identity,
   courier and parlor in one pass, or an explicit decision that the services
   really are non-production-only.
2. The `docs` licence page OPS-P1 names
   (`/Users/kaka/Code/any/moon/CAFAYE-OPS.md:177`), which has to state the
   services' BSL alongside the framework's permissive grants — a different
   repository's packet, named here so it is not discovered late.
3. A rebase onto `master` when the manager merges; nothing in this branch
   touches a file the `tg-c1` handoff left open.

Two untracked files were in the worktree when I arrived —
`brief-lic-services-a.txt` and `brief.txt`. They are the dispatcher's, not the
repository's, and both are still untracked. Neither is committed.
