#!/usr/bin/env bash
# ci/pipeline.sh — gateway's pipeline, on the instabox backend or any other.
#
# WHY A SERVICE NEEDS ONE. The backend's job is only to provide an
# environment and call this script; the gate, the build and the ship are the
# project's. `bin/prime` already exists and `bin/publish` does not need to —
# gateway ships no chart — so this file is the wiring between them that
# Actions used to hold, moved into the repository where it can be run by
# hand, by a sandbox, or by a runner.
#
# WHERE THE FACTS COME FROM: `ci/ci.yml` IN THIS REPOSITORY.
# Every fact this file uses about how the repository is built — the toolchain
# pin in mise.toml, the gate entrypoint, and the PATH entry CI adds — is
# visible in that workflow file, and THAT FILE IS THE SOURCE OF TRUTH. When
# the workflow changes, change this file with it.
#
# WHAT THE BACKEND PROVIDES (kit's backends/README.md is the contract):
# WORKSPACE, GH_TOKEN, CI. Anything else this repository's pipeline needs it
# declares, and the backend materializes it from `~/ci-env.d/<project>.env`.
#
# THE DATABASE. This repository's gate starts no Postgres on Actions (no
# `services:` block names one) and needs none here either. The `redis (live
# tier)` job runs a URL-gated tier against a container, but it is a separate
# job precisely because kit's shared shape cannot own it — this pipeline runs
# the `bin/prime` job's steps, not that job's.
#
# GATE CONCURRENCY. Nothing in this file sets CI_GATE_SERIAL: which projects
# need it is recorded in kit's backends/README.md, and gateway is not one of
# them.
set -euo pipefail

# ---------------------------------------------------------------------------
# gateway
# ---------------------------------------------------------------------------
# `run from anywhere`: the repository root is derived from this file, not from
# the caller's cwd.
#
# THE PIPELINE NEVER MOVES THE CHECKOUT, and this is not a style choice. A
# pipeline that `git fetch`es + `git reset --hard`s destroys any tree it is
# run against to verify. The AGENT owns the checkout's position — it fetches
# the commit and resets before calling in (see kit's agent.sh) — and a
# pipeline that also resets is a pipeline that deletes a worker's uncommitted
# packet. The gate runs on whatever tree it is given, which is the only
# property that makes it a verification tool.
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_DIR"
REPO_NAME="$(basename "$REPO_DIR")"

WORKSPACE="${WORKSPACE:-$(cd "$REPO_DIR/../.." && pwd)}"
export CI="${CI:-1}"
export WORKSPACE

log() { printf '\n== %s\n' "$1"; }

log "pipeline: $REPO_NAME at $REPO_DIR"

# ===========================================================================
# THE GATE. `bin/prime`, the entrypoint `ci/ci.yml`'s `prime`
# job names. A gate the workflow names and the pipeline does not is a
# pipeline that is green while testing nothing — read the file, do not
# assume.
# ===========================================================================
GATE=(./bin/prime)

# ===========================================================================
# PATHS THIS REPOSITORY'S CI ADDS. The one `echo … >> $GITHUB_PATH` line in
# `ci/ci.yml` (`golangci-lint, the version mise.toml pins`
# installs into `$HOME/.local/bin`), in the order the workflow appends it.
# Without it the gate fails for a reason that has nothing to do with the
# tree — `bin/prime-go` exits 127 with no linter on PATH.
# ===========================================================================
PATHS=("$HOME/.local/bin")

if [ "${#PATHS[@]}" -gt 0 ]; then
  for d in "${PATHS[@]}"; do
    # One entry per directory, in the order the workflow appends them: PATH is
    # searched front to back and a later entry must not shadow an earlier one.
    export PATH="$d:$PATH"
  done
fi

log "the toolchain the repository pins"
# `mise install` materializes the versions in mise.toml; `mise exec` runs the
# gate under them, so a developer, a runner and this sandbox all use the same
# compiler. When there is no mise.toml, or no mise, the gate runs on whatever
# this machine ships — which is what the workflow does on a runner without
# the setup step, and is reported rather than hidden.
UNDER_MISE=0
if [ -f mise.toml ] && command -v mise >/dev/null 2>&1; then
  mise install
  GATE=(mise exec -- "${GATE[@]}")
  UNDER_MISE=1
elif [ -f mise.toml ]; then
  echo "pipeline: mise.toml is present and mise is NOT on PATH — the gate runs on the machine's own toolchain"
fi

# The prefix the setup commands below run under: the gate's toolchain
# without the gate. A helper rather than a slice, because an empty array
# under `set -u` is an unbound variable on the older bash a hand-run may
# use.
under_toolchain() {
  if [ "$UNDER_MISE" = 1 ]; then
    mise exec -- "$@"
  else
    "$@"
  fi
}

log "the generator's dependency graph, in the module cache"
# ci.yml's step of the same name: `bin/prime-go` regenerates
# `internal/api/api.gen.go` OFFLINE through a file:// proxy over the module
# cache, so a graph that was never fetched is a regeneration that cannot run.
# The generator is declared in this module (the blank import in `tools.go`),
# so one `go mod download` fills its whole transitive graph. THERE IS NO
# VERSION HERE: the one copy lives in `go.mod`, and a literal would be a
# second pin beside it.
under_toolchain go mod download

log "redis-server, which the runtime session tests exec"
# ci.yml's step of the same name: `internal/httpapi`'s runtime session tests
# start a real `redis-server` by EXECUTING THE BINARY rather than dialing a
# URL, so a machine with no Redis binary fails three tests loudly. CI
# installs it unconditionally via apt; here an install is attempted the same
# way when the machine has apt-get, and otherwise the gate fails honestly
# below naming the missing binary rather than passing against nothing.
if ! command -v redis-server >/dev/null 2>&1; then
  if command -v apt-get >/dev/null 2>&1; then
    sudo apt-get update -qq && sudo apt-get install -y redis-server
  else
    echo "pipeline: no redis-server on PATH and no apt-get to install it with."
    echo "pipeline: the runtime session tests fail honestly below rather than passing against nothing."
  fi
fi

log "kit's lint config, which bin/prime refuses without"
# ci.yml's `kit (lint config)` step: kit's `lint/golangci.yml`, sparse-checked
# out beside the repository at `.kit/lint/golangci.yml`. The config is NOT
# copied — kit's own header says why ("Not copied into a service repo") and a
# copy is a second policy to drift. `bin/prime-go` resolves it from `.kit/`
# or from kit beside the tree (`../kit`); on a sandbox the sibling checkout
# may already sit at `$WORKSPACE/anywaye/kit`, so link it rather than cloning
# a second copy. When neither exists the gate fails with the message it
# already carries, rather than running the linter with no config (which exits
# 0 on a file the config rejects).
if [ ! -f .kit/lint/golangci.yml ] && [ -f "$WORKSPACE/anywaye/kit/lint/golangci.yml" ]; then
  mkdir -p .kit/lint
  ln -sfn "$WORKSPACE/anywaye/kit/lint/golangci.yml" .kit/lint/golangci.yml
  echo "pipeline: linked kit's lint config from the sibling checkout"
fi

log "golangci-lint, the version mise.toml pins"
# ci.yml's step of the same name: `bin/prime-go` runs `golangci-lint run`
# over kit's config and exits 127 when the binary is not on PATH — the
# refusal working, not a defect. `mise install` above provides the pinned
# version; this step is for a machine whose gate still cannot find it, and it
# reads the version out of mise.toml rather than retyping it. The RELEASE
# ARCHIVE is pinned by version, never the installer script at a moving ref.
if ! command -v golangci-lint >/dev/null 2>&1; then
  version="$(sed -n 's/^"golangci-lint" *= *"\(.*\)"/\1/p' mise.toml)"
  if [ -z "$version" ]; then
    echo "pipeline: mise.toml pins no golangci-lint, and bin/prime-go refuses" >&2
    echo "pipeline: to run without the binary. Restore the pin rather than" >&2
    echo "pipeline: installing whatever GitHub calls current." >&2
    exit 1
  fi
  arch="$(uname -m)"
  case "$arch" in
    x86_64) arch=amd64 ;;
    aarch64 | arm64) arch=arm64 ;;
  esac
  base="https://github.com/golangci/golangci-lint/releases/download/v${version}"
  archive="golangci-lint-${version}-linux-${arch}.tar.gz"
  tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/gateway-lint.XXXXXX")"
  trap 'rm -rf "$tmpdir"' EXIT
  curl -sSfL "$base/$archive" | tar -xz -C "$tmpdir"
  mkdir -p "$HOME/.local/bin"
  install -m 0755 "$tmpdir/golangci-lint-${version}-linux-${arch}/golangci-lint" "$HOME/.local/bin/golangci-lint"
  trap - EXIT
  rm -rf "$tmpdir"
  golangci-lint --version
else
  golangci-lint --version
fi

log "the gate"
# The command is a list, so a multi-word gate works without eval and nothing
# a project writes here is re-parsed.
"${GATE[@]}"

log "the gate left the lockfiles alone"
# ci.yml's `go.mod and go.sum are untouched` step: `bin/prime` runs `go
# build` and `go test`, and neither rewrites the manifests — but a `go get`
# or a `go mod tidy` left in a dependency bump would resolve a different tree
# than the one committed, and the run would stay green while doing it.
if ! git diff --exit-code -- go.mod go.sum; then
  echo "pipeline: bin/prime moved go.mod or go.sum — the build is no longer against the committed tree" >&2
  exit 1
fi
echo "pipeline: go.mod and go.sum unchanged by the gate"

if [ "${CI_DRY_RUN:-0}" = "1" ]; then
  log "gate passed; CI_DRY_RUN=1, not shipping"
  exit 0
fi

# ---------------------------------------------------------------------------
# NO SHIP STEP, and that is the point. gateway carries no chart/Chart.yaml:
# release work is a separate workflow so a red test can never publish, and
# the gate is the whole run. A service with a chart keeps the publish block
# (`./bin/publish --service-dir .`) instead of this comment.
# ---------------------------------------------------------------------------
SHIPPED=""
echo "pipeline: no chart/Chart.yaml — nothing to publish; the gate is the whole run"

# ---------------------------------------------------------------------------
# the last line a log tail reads
# ---------------------------------------------------------------------------
# Naming WHAT shipped and the COMMIT it was built from is the whole point of
# this line: `agent[<project>]: shipped <sha>` says the pipeline returned 0,
# and this says what that meant. A run that shipped nothing says so.
COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
if [ -n "$SHIPPED" ]; then
  log "pipeline: shipped $REPO_NAME $SHIPPED at $COMMIT"
else
  log "pipeline: passed $REPO_NAME at $COMMIT (nothing published)"
fi
