#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_DIR"
REPO_NAME="$(basename "$REPO_DIR")"

WORKSPACE="${WORKSPACE:-$(cd "$REPO_DIR/../.." && pwd)}"
export CI="${CI:-1}"
export WORKSPACE

log() { printf '\n== %s\n' "$1"; }

log "pipeline: $REPO_NAME at $REPO_DIR"

GATE=(./bin/prime)

PATHS=("$HOME/.local/bin")

if [ "${#PATHS[@]}" -gt 0 ]; then
  for d in "${PATHS[@]}"; do
    export PATH="$d:$PATH"
  done
fi

log "the toolchain the repository pins"
UNDER_MISE=0
if [ -f mise.toml ] && command -v mise >/dev/null 2>&1; then
  mise install
  GATE=(mise exec -- "${GATE[@]}")
  UNDER_MISE=1
elif [ -f mise.toml ]; then
  echo "pipeline: mise.toml is present and mise is NOT on PATH — the gate runs on the machine's own toolchain"
fi

under_toolchain() {
  if [ "$UNDER_MISE" = 1 ]; then
    mise exec -- "$@"
  else
    "$@"
  fi
}

log "the generator's dependency graph, in the module cache"
under_toolchain go mod download

log "redis-server, which the runtime session tests exec"
if ! command -v redis-server >/dev/null 2>&1; then
  if command -v apt-get >/dev/null 2>&1; then
    sudo apt-get update -qq && sudo apt-get install -y redis-server
  else
    echo "pipeline: no redis-server on PATH and no apt-get to install it with."
    echo "pipeline: the runtime session tests fail honestly below rather than passing against nothing."
  fi
fi

log "kit's lint config, which bin/prime refuses without"
if [ ! -f .kit/lint/golangci.yml ] && [ -f "$WORKSPACE/anywaye/kit/lint/golangci.yml" ]; then
  mkdir -p .kit/lint
  ln -sfn "$WORKSPACE/anywaye/kit/lint/golangci.yml" .kit/lint/golangci.yml
  echo "pipeline: linked kit's lint config from the sibling checkout"
fi

log "golangci-lint, the version mise.toml pins"
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
"${GATE[@]}"

log "the gate left the lockfiles alone"
if ! git diff --exit-code -- go.mod go.sum; then
  echo "pipeline: bin/prime moved go.mod or go.sum — the build is no longer against the committed tree" >&2
  exit 1
fi
echo "pipeline: go.mod and go.sum unchanged by the gate"

if [ "${CI_DRY_RUN:-0}" = "1" ]; then
  log "gate passed; CI_DRY_RUN=1, not shipping"
  exit 0
fi

SHIPPED=""
echo "pipeline: no chart/Chart.yaml — nothing to publish; the gate is the whole run"

COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
if [ -n "$SHIPPED" ]; then
  log "pipeline: shipped $REPO_NAME $SHIPPED at $COMMIT"
else
  log "pipeline: passed $REPO_NAME at $COMMIT (nothing published)"
fi
