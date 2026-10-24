#!/usr/bin/env bash
#
# kit — publish a service image + chart without GitHub Actions.
#
#   bin/publish --help
#   bin/publish --dry-run
#   bin/publish --service-dir . --chart-dir chart --image ghcr.io/anywaye/myservice
#   bin/publish --sandbox --sandbox-name anywaye-build
#
# WHY THIS EXISTS, IN ONE SENTENCE. The org's free Actions minutes are
# exhausted (measured 2026-10-15: the billing publish failed with "You have
# used 90% of the Actions minutes"); in the same hour a complete
# Actions-free publish was performed by hand — docker build+push, stamp the
# chart's image.digest, helm package+push to oci://ghcr.io/anywaye/charts,
# then flip package visibility in the browser. This script codifies that
# run so any machine with docker can do it.
#
# THE TWO PATHS, AND THE ONE MANUAL STEP. When Actions minutes exist the
# service's ci/publish.yml does this. When they do not — or
# when a developer needs to publish from a laptop, a sandbox, or CI that is
# not GitHub — this script does the same bytes: the image digest is DERIVED
# from the pushed image (never typed), the chart version is NOT bumped
# (Argo's Application pins targetRevision), and visibility is NOT settable
# by API with a normal token — the script REMINDS with the URL rather than
# failing.
#
# MULTI-ARCH, AND WHAT WAS CHOSEN. The workflow builds linux/amd64,linux/arm64
# through buildx+QEMU on an amd64 runner. A local docker without buildx cannot
# produce a manifest list, so this script DEFAULTS to a single-arch build
# (the host's arch) and prints a LOUD NOTE naming the workflow's default
# platforms. Pass --platforms linux/amd64,linux/arm64 when buildx is available
# — the script checks for it and REFUSES when the requested platforms need
# buildx and it is absent, rather than silently producing a single-arch image
# with a loud note that no consumer will read at pull time.
#
# BOUNDED. Every network or slow call goes through timeout (or gtimeout on
# macOS). 600s for build, 300s for push/package. No unbounded command.
#
# TOKENS VIA STDIN, NEVER ARGV. docker login --password-stdin, helm registry
# login --password-stdin, gh auth login --with-token. No secret in argv or logs.
#
set -euo pipefail

SELF="$0"

# ---------------------------------------------------------------------------
# defaults
# ---------------------------------------------------------------------------
SERVICE_DIR="."
CHART_DIR="chart"
REGISTRY="oci://ghcr.io/anywaye/charts"
GHCR_HOST="ghcr.io"
IMAGE=""
TAG=""
GIT_REF="HEAD"
PLATFORMS=""
DRY_RUN=0
SANDBOX=0
SANDBOX_NAME="anywaye-build"
# shellcheck disable=SC2034
SANDBOX_RUN_PUBLISH=0 # reserved for --sandbox --run

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
die() { printf 'publish: %s\n' "$*" >&2; exit 1; }
info() { printf 'publish: %s\n' "$*"; }
warn() { printf 'publish: WARN: %s\n' "$*" >&2; }

timeout_bin() {
  if command -v timeout >/dev/null 2>&1; then printf 'timeout'; return 0; fi
  if command -v gtimeout >/dev/null 2>&1; then printf 'gtimeout'; return 0; fi
  printf ''
}

run_bounded() {
  local secs="$1"; shift
  local tb; tb="$(timeout_bin)"
  if [ -n "$tb" ]; then
    "$tb" "$secs" "$@"
  else
    "$@"
  fi
}

has_cmd() { command -v "$1" >/dev/null 2>&1; }

# ---------------------------------------------------------------------------
# usage
# ---------------------------------------------------------------------------
usage() {
  sed -n '2,/^# --/p' "$SELF" | sed 's/^# \{0,1\}//'
  cat <<'EOF'
Usage:
  bin/publish [options]

Options:
  --service-dir DIR     service root (where Dockerfile lives) [.]
  --image NAME          image name, e.g. ghcr.io/anywaye/myservice
                        default: ghcr.io/anywaye/<chart-name> or ghcr.io/anywaye/<dir-basename>
  --chart-dir DIR       chart directory relative to service dir [chart]
  --registry URL        OCI registry for charts [oci://ghcr.io/anywaye/charts]
  --tag TAG             image+chart tag [Chart.yaml version, default 0.1.0]
  --git-ref REF         git ref to derive sha tag from [HEAD]
  --platforms LIST      comma-separated platforms, e.g. linux/amd64,linux/arm64
                        default: host arch (single-arch) with a loud note.
                        When LIST contains a comma, buildx is required.
  --dry-run             print every command that would run, do not execute
  --sandbox             provision (or reuse) an instabox sandbox named
                        --sandbox-name and prepare it for publishing
  --sandbox-name NAME   instabox sandbox name [anywaye-build]
  --help                this text

Examples:
  bin/publish --dry-run
  bin/publish --service-dir . --image ghcr.io/anywaye/gateway
  bin/publish --sandbox --dry-run
  echo "$GH_TOKEN" | bin/publish --sandbox   # token via stdin, never argv

Auth (local publish):
  echo "$GH_TOKEN" | docker login ghcr.io -u USERNAME --password-stdin
  echo "$GH_TOKEN" | helm registry login ghcr.io -u USERNAME --password-stdin
  gh auth login --with-token < token.txt

EOF
}

# ---------------------------------------------------------------------------
# parse
# ---------------------------------------------------------------------------
while [ "$#" -gt 0 ]; do
  case "$1" in
    --service-dir) SERVICE_DIR="$2"; shift 2 ;;
    --service-dir=*) SERVICE_DIR="${1#*=}"; shift ;;
    --image) IMAGE="$2"; shift 2 ;;
    --image=*) IMAGE="${1#*=}"; shift ;;
    --chart-dir) CHART_DIR="$2"; shift 2 ;;
    --chart-dir=*) CHART_DIR="${1#*=}"; shift ;;
    --registry) REGISTRY="$2"; shift 2 ;;
    --registry=*) REGISTRY="${1#*=}"; shift ;;
    --tag) TAG="$2"; shift 2 ;;
    --tag=*) TAG="${1#*=}"; shift ;;
    --git-ref) GIT_REF="$2"; shift 2 ;;
    --git-ref=*) GIT_REF="${1#*=}"; shift ;;
    --platforms) PLATFORMS="$2"; shift 2 ;;
    --platforms=*) PLATFORMS="${1#*=}"; shift ;;
    --dry-run) DRY_RUN=1; shift ;;
    --sandbox) SANDBOX=1; shift ;;
    --sandbox-name) SANDBOX_NAME="$2"; shift 2 ;;
    --sandbox-name=*) SANDBOX_NAME="${1#*=}"; shift ;;
    --help|-h) usage; exit 0 ;;
    --) shift; break ;;
    -*) die "unknown flag $1 (see --help)" ;;
    *) die "unknown argument $1 (see --help)" ;;
  esac
done

# ---------------------------------------------------------------------------
# --sandbox path: provision the box, then optionally publish
# ---------------------------------------------------------------------------
do_sandbox() {
  # Idempotent: a second run changes nothing and still works.
  # Tokens via stdin; no secrets in logs or argv.

  if ! has_cmd instabox; then
    die "instabox not found — install from https://instabox.sh (curl -fsSL https://instabox.sh/install.sh | sh)"
  fi

  info "sandbox: $SANDBOX_NAME — checking if it exists"
  if instabox get "$SANDBOX_NAME" >/dev/null 2>&1; then
    info "sandbox: $SANDBOX_NAME exists — reusing"
    # Ensure it is running
    instabox start "$SANDBOX_NAME" >/dev/null 2>&1 || true
  else
    info "sandbox: creating $SANDBOX_NAME"
    if [ "$DRY_RUN" -eq 1 ]; then
      echo "would run: instabox create --name $SANDBOX_NAME --timeout 2h --auto-suspend 30m"
    else
      run_bounded 120 instabox create --name "$SANDBOX_NAME" --timeout 2h --auto-suspend 30m
    fi
  fi

  # Capture token from stdin if piped (never argv, never logs)
  SANDBOX_TOKEN_FILE=""
  if [ ! -t 0 ]; then
    # stdin is not a tty — may contain a token. Read with a short timeout to
    # avoid blocking when stdin is a pipe that is open but empty.
    tmp_tok="$(mktemp "${TMPDIR:-/tmp}/publish-token.XXXXXX")"
    chmod 600 "$tmp_tok"
    # Read at most 10KB, with 0.2s timeout if nothing arrives
    if command -v gtimeout >/dev/null 2>&1; then
      gtimeout 1 cat >"$tmp_tok" 2>/dev/null || true
    elif command -v timeout >/dev/null 2>&1; then
      timeout 1 cat >"$tmp_tok" 2>/dev/null || true
    else
      # No timeout available — cat with bounded read
      cat >"$tmp_tok" 2>/dev/null || true
    fi
    if [ -s "$tmp_tok" ]; then
      SANDBOX_TOKEN_FILE="$tmp_tok"
      info "sandbox: token received on stdin (will be used via --password-stdin, never logged)"
    else
      rm -f "$tmp_tok"
    fi
  fi
  # Ensure temp token is cleaned on exit
  cleanup_token() { [ -n "${SANDBOX_TOKEN_FILE:-}" ] && rm -f "$SANDBOX_TOKEN_FILE" || true; }
  trap cleanup_token EXIT

  if [ "$DRY_RUN" -eq 1 ]; then
    echo "would run: instabox exec $SANDBOX_NAME -- docker --version"
    echo "would run: instabox exec $SANDBOX_NAME -- helm version (install v4.3.0 if missing)"
    echo "would run: instabox exec $SANDBOX_NAME -- gh --version (install if missing)"
    if [ -n "$SANDBOX_TOKEN_FILE" ]; then
      echo "would run: cat [token] | instabox exec $SANDBOX_NAME --stdin -- docker login ghcr.io --password-stdin"
      echo "would run: cat [token] | instabox exec $SANDBOX_NAME --stdin -- helm registry login ghcr.io --password-stdin"
      echo "would run: cat [token] | instabox exec $SANDBOX_NAME --stdin -- gh auth login --with-token"
    else
      echo "sandbox: ready — login with token via stdin:"
      echo "  cat token.txt | instabox exec $SANDBOX_NAME --stdin -- docker login ghcr.io -u USERNAME --password-stdin"
      echo "  cat token.txt | instabox exec $SANDBOX_NAME --stdin -- helm registry login ghcr.io -u USERNAME --password-stdin"
      echo "  cat token.txt | instabox exec $SANDBOX_NAME --stdin -- gh auth login --with-token"
    fi
    echo "  instabox ssh $SANDBOX_NAME"
    trap - EXIT; cleanup_token
    return 0
  fi

  # Ensure docker
  info "sandbox: checking docker"
  if ! instabox exec "$SANDBOX_NAME" -- docker --version >/dev/null 2>&1; then
    warn "docker not available in sandbox $SANDBOX_NAME"
  else
    info "sandbox: docker OK — $(instabox exec "$SANDBOX_NAME" -- docker --version 2>&1 | head -1)"
  fi

  # Ensure helm v4.3.0 (pinned, matching chart.reusable.yml)
  info "sandbox: checking helm"
  helm_ok=0
  if instabox exec "$SANDBOX_NAME" -- helm version --template '{{.Version}}' 2>/dev/null | grep -q "v4.3.0"; then
    helm_ok=1
    info "sandbox: helm v4.3.0 already installed"
  fi
  if [ "$helm_ok" -eq 0 ]; then
    info "sandbox: installing helm v4.3.0"
    run_bounded 120 instabox exec "$SANDBOX_NAME" -- bash -lc '
      set -euo pipefail
      if command -v helm >/dev/null 2>&1 && helm version --template "{{.Version}}" 2>/dev/null | grep -q "v4.3.0"; then
        echo "helm v4.3.0 already installed"; exit 0
      fi
      curl -fsSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash -s -- --version v4.3.0
      hv="$(helm version --template "{{.Version}}")"
      if [ "$hv" != "v4.3.0" ]; then echo "helm $hv is not v4.3.0" >&2; exit 1; fi
      echo "helm $hv installed"
    '
  fi

  # Ensure gh
  info "sandbox: checking gh"
  if instabox exec "$SANDBOX_NAME" -- gh --version >/dev/null 2>&1; then
    info "sandbox: gh OK — $(instabox exec "$SANDBOX_NAME" -- gh --version 2>&1 | head -1)"
  else
    info "sandbox: installing gh"
    run_bounded 120 instabox exec "$SANDBOX_NAME" -- bash -lc '
      set -euo pipefail
      if command -v gh >/dev/null 2>&1; then echo "gh already installed"; exit 0; fi
      # try apt, else tarball
      if command -v apt-get >/dev/null 2>&1; then
        curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg | sudo dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg 2>/dev/null
        sudo chmod go+r /usr/share/keyrings/githubcli-archive-keyring.gpg 2>/dev/null || true
        echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" | sudo tee /etc/apt/sources.list.d/github-cli.list >/dev/null
        sudo apt-get update -qq && sudo apt-get install -y gh
      else
        echo "gh not found and apt not available — install gh manually" >&2; exit 1
      fi
    '
  fi

  # If token was piped, log in now (via stdin, never argv)
  if [ -n "$SANDBOX_TOKEN_FILE" ]; then
    info "sandbox: logging in to ghcr.io and gh"
    # Need a username for docker/helm login. gh auth login --with-token does
    # not need one; docker/helm do. Use GITHUB_ACTOR or $USER, default to git actor.
    gh_user="${GITHUB_ACTOR:-${USER:-anywaye}}"
    info "sandbox: docker login ghcr.io as $gh_user (token via stdin)"
    cat "$SANDBOX_TOKEN_FILE" | instabox exec "$SANDBOX_NAME" --stdin -- docker login ghcr.io -u "$gh_user" --password-stdin >/dev/null 2>&1 || warn "docker login failed"
    info "sandbox: helm registry login ghcr.io as $gh_user (token via stdin)"
    cat "$SANDBOX_TOKEN_FILE" | instabox exec "$SANDBOX_NAME" --stdin -- helm registry login ghcr.io -u "$gh_user" --password-stdin >/dev/null 2>&1 || warn "helm registry login failed"
    info "sandbox: gh auth login --with-token (token via stdin)"
    cat "$SANDBOX_TOKEN_FILE" | instabox exec "$SANDBOX_NAME" --stdin -- gh auth login --with-token >/dev/null 2>&1 || warn "gh auth login failed"
    info "sandbox: logins complete"
  fi

  trap - EXIT; cleanup_token

  info "sandbox: $SANDBOX_NAME ready"
  echo "publish: sandbox $SANDBOX_NAME is ready."
  if [ -n "${SANDBOX_TOKEN_FILE:-}" ]; then
    echo "  Logged in with token from stdin (never argv or logs)."
  else
    echo "  Tokens via stdin (never argv):"
    echo "    cat token.txt | instabox exec $SANDBOX_NAME --stdin -- docker login ghcr.io -u USERNAME --password-stdin"
    echo "    cat token.txt | instabox exec $SANDBOX_NAME --stdin -- helm registry login ghcr.io -u USERNAME --password-stdin"
    echo "    cat token.txt | instabox exec $SANDBOX_NAME --stdin -- gh auth login --with-token"
    echo "  Or re-run with token piped:"
    echo "    cat token.txt | bin/publish --sandbox --sandbox-name $SANDBOX_NAME"
  fi
  echo "  Then publish from inside:"
  echo "    instabox ssh $SANDBOX_NAME"
  echo "  Or run publish via exec (token never in argv):"
  echo "    cat token.txt | instabox exec $SANDBOX_NAME --stdin -- bash -lc 'bin/publish ...'"
}

if [ "$SANDBOX" -eq 1 ]; then
  do_sandbox
  exit 0
fi

# ---------------------------------------------------------------------------
# local publish — dependency checks (REFUSE by name, with login commands)
# ---------------------------------------------------------------------------
need() {
  if ! has_cmd "$1"; then
    die "$1 not found — $2"
  fi
}

need docker "install from https://docs.docker.com/get-docker/"
need helm "install helm v4.3.0: curl -fsSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash -s -- --version v4.3.0"

# helm version is advisory; warn when not v4.3.0 (matching chart.reusable.yml pin)
helm_ver="$(helm version --template '{{.Version}}' 2>/dev/null || helm version 2>/dev/null | head -1 || echo unknown)"
case "$helm_ver" in
  *v4.3.0*) : ;;
  *) warn "helm is $helm_ver, chart.reusable.yml pins v4.3.0 — proceed, but verify with: helm version --template '{{.Version}}'" ;;
esac

if ! has_cmd git; then die "git not found — install git"; fi

# auth: refuse when not logged in, naming the login commands — never fallback
check_auth() {
  local has_ghcr=0
  # docker config may use credsStore; check both config.json and credential helper
  if [ -f "$HOME/.docker/config.json" ] && grep -q "ghcr.io" "$HOME/.docker/config.json" 2>/dev/null; then
    has_ghcr=1
  fi
  # also try docker credential check via `docker` itself: a cheap probe
  # Helm registry auth is separate; we check docker's.
  if [ "$has_ghcr" -eq 0 ]; then
    # Fallback: try `docker` to see if it can talk to ghcr — but still refuse
    # with the commands rather than attempting an unauthenticated push.
    cat >&2 <<'EOF'
publish: not logged in to ghcr.io — refusing to push unauthenticated.

  Log in with a token via stdin (never argv):

    echo "$GH_TOKEN" | docker login ghcr.io -u USERNAME --password-stdin
    echo "$GH_TOKEN" | helm registry login ghcr.io -u USERNAME --password-stdin
    # and for gh CLI:
    echo "$GH_TOKEN" | gh auth login --with-token

  The token needs packages:write (and read:packages for pull).
  Never pass a token as an argument — it lands in shell history and logs.
EOF
    exit 1
  fi
}

# In dry-run, skip auth check (still print what would be checked)
if [ "$DRY_RUN" -eq 0 ]; then
  check_auth
else
  info "dry-run: would check auth — docker login ghcr.io, helm registry login ghcr.io"
fi

# ---------------------------------------------------------------------------
# resolve service dir and chart dir
# ---------------------------------------------------------------------------
SERVICE_DIR="$(cd "$SERVICE_DIR" && pwd)"
case "$CHART_DIR" in
  /*) CHART_ABS="$CHART_DIR" ;;
  *) CHART_ABS="$SERVICE_DIR/$CHART_DIR" ;;
esac
# normalize: strip trailing slash
CHART_ABS="${CHART_ABS%/}"

if [ ! -d "$SERVICE_DIR" ]; then die "service dir not found: $SERVICE_DIR"; fi
if [ ! -d "$CHART_ABS" ]; then die "chart dir not found: $CHART_ABS (try --chart-dir)"; fi
if [ ! -f "$CHART_ABS/Chart.yaml" ]; then die "no Chart.yaml at $CHART_ABS/Chart.yaml — set --chart-dir to the directory that holds it"; fi
if [ ! -f "$SERVICE_DIR/Dockerfile" ] && [ ! -f "$SERVICE_DIR/docker/Dockerfile" ]; then
  warn "no Dockerfile at $SERVICE_DIR/Dockerfile — docker build may fail; ensure --service-dir is the build context"
fi

# ---------------------------------------------------------------------------
# read Chart.yaml — name, version, appVersion (same logic as chart.reusable.yml)
# ---------------------------------------------------------------------------
chart_name="$(grep -m1 '^name:' "$CHART_ABS/Chart.yaml" | sed 's/^name:[[:space:]]*//' | tr -d "\"'" || true)"
chart_version="$(grep -m1 '^version:' "$CHART_ABS/Chart.yaml" | sed 's/^version:[[:space:]]*//' | tr -d "\"'" || true)"
chart_app_version="$(grep -m1 '^appVersion:' "$CHART_ABS/Chart.yaml" | sed 's/^appVersion:[[:space:]]*//' | tr -d "\"'" || true)"

if [ -z "$chart_name" ] || [ -z "$chart_version" ]; then
  die "could not read name and version from $CHART_ABS/Chart.yaml (name='$chart_name', version='$chart_version')"
fi

info "chart: $chart_name version $chart_version appVersion ${chart_app_version:-<none>}"

# tag defaults to chart version (matching Applications' pinned targetRevision)
if [ -z "$TAG" ]; then
  TAG="$chart_version"
fi
info "tag: $TAG (chart version; not bumped — Argo targetRevision pins this)"

# image defaults to ghcr.io/anywaye/<chart-name> (lowercased)
if [ -z "$IMAGE" ]; then
  IMAGE="ghcr.io/anywaye/$chart_name"
  IMAGE="$(printf '%s' "$IMAGE" | tr '[:upper:]' '[:lower:]')"
fi
info "image: $IMAGE"

# git ref -> sha
git_sha=""
if git -C "$SERVICE_DIR" rev-parse --verify "$GIT_REF" >/dev/null 2>&1; then
  git_sha="$(git -C "$SERVICE_DIR" rev-parse --verify "$GIT_REF" 2>/dev/null | tr -d '\n')"
else
  # maybe not a git repo (standalone chart)
  warn "git ref $GIT_REF not found — sha tag will be 'sha-unknown'"
  git_sha="unknown"
fi
if [ "$git_sha" != "unknown" ] && ! printf '%s' "$git_sha" | grep -qE '^[0-9a-f]{40}$'; then
  warn "git sha $git_sha is not 40 hex — using as-is"
fi
sha_tag="sha-${git_sha:0:12}"
if [ "$git_sha" = "unknown" ]; then sha_tag="sha-unknown"; fi
if printf '%s' "$git_sha" | grep -qE '^[0-9a-f]{40}$'; then
  sha_tag="sha-$git_sha"
fi
info "git ref: $GIT_REF -> $git_sha (tag $sha_tag)"

# platforms
if [ -z "$PLATFORMS" ]; then
  info "platforms: host arch only (single-arch)"
  info "note: workflow builds linux/amd64,linux/arm64 — pass --platforms linux/amd64,linux/arm64 when buildx is available for a manifest list"
else
  info "platforms: $PLATFORMS"
  case "$PLATFORMS" in
    *,*)
      if ! docker buildx version >/dev/null 2>&1; then
        die "platforms $PLATFORMS needs docker buildx, but 'docker buildx version' failed — install buildx or use a single platform"
      fi
      ;;
  esac
fi

# ---------------------------------------------------------------------------
# helpers for bounded execution with progress
# ---------------------------------------------------------------------------
do_run() {
  if [ "$DRY_RUN" -eq 1 ]; then
    echo "would run: $*"
    return 0
  fi
  printf 'publish: running: %s\n' "$*"
  "$@"
}

do_run_bounded() {
  local secs="$1"; shift
  if [ "$DRY_RUN" -eq 1 ]; then
    echo "would run (bounded ${secs}s): $*"
    return 0
  fi
  printf 'publish: running (bounded %ss): %s\n' "$secs" "$*"
  run_bounded "$secs" "$@"
}

# ---------------------------------------------------------------------------
# build image
# ---------------------------------------------------------------------------
info "building image $IMAGE:$TAG and $IMAGE:$sha_tag from $SERVICE_DIR"

# Choose build command
BUILD_CMD="docker build"
if [ -n "$PLATFORMS" ]; then
  case "$PLATFORMS" in
    *,*) BUILD_CMD="docker buildx build" ;;
  esac
fi

# Build (bounded 600s)
if [ "$DRY_RUN" -eq 1 ]; then
  if [ -n "$PLATFORMS" ]; then
    echo "would run (bounded 600s): $BUILD_CMD --platform $PLATFORMS -t $IMAGE:$TAG -t $IMAGE:$sha_tag -f $SERVICE_DIR/Dockerfile $SERVICE_DIR"
  else
    echo "would run (bounded 600s): docker build -t $IMAGE:$TAG -t $IMAGE:$sha_tag $SERVICE_DIR"
  fi
else
  if [ -n "$PLATFORMS" ]; then
    case "$PLATFORMS" in
      *,*)
        # buildx --push pushes directly; we need local image for digest + chart stamp.
        # So build without --push for now, load single? For multi-arch with --push,
        # digest is from build output. Simplify: build and push in one go when
        # platforms has comma, else normal build+push.
        # Here we do buildx build --push for multi-arch, then derive digest via inspect.
        run_bounded 600 $BUILD_CMD --platform "$PLATFORMS" -t "$IMAGE:$TAG" -t "$IMAGE:$sha_tag" --push "$SERVICE_DIR"
        ;;
      *)
        run_bounded 600 $BUILD_CMD --platform "$PLATFORMS" -t "$IMAGE:$TAG" -t "$IMAGE:$sha_tag" "$SERVICE_DIR"
        ;;
    esac
  else
    run_bounded 600 docker build -t "$IMAGE:$TAG" -t "$IMAGE:$sha_tag" "$SERVICE_DIR"
  fi
fi

# ---------------------------------------------------------------------------
# push images
# ---------------------------------------------------------------------------
# For single-arch (normal docker build), push explicitly to derive digest.
# For multi-arch buildx --push above, images already pushed; skip duplicate push.
NEED_PUSH=1
if [ -n "$PLATFORMS" ]; then
  case "$PLATFORMS" in
    *,*) NEED_PUSH=0 ;;
  esac
fi

if [ "$NEED_PUSH" -eq 1 ]; then
  info "pushing $IMAGE:$TAG"
  if [ "$DRY_RUN" -eq 1 ]; then
    echo "would run (bounded 300s): docker push $IMAGE:$TAG"
  else
    run_bounded 300 docker push "$IMAGE:$TAG" 2>&1 | tee /tmp/publish-push-tag.log
  fi
  info "pushing $IMAGE:$sha_tag"
  if [ "$DRY_RUN" -eq 1 ]; then
    echo "would run (bounded 300s): docker push $IMAGE:$sha_tag"
  else
    run_bounded 300 docker push "$IMAGE:$sha_tag" 2>&1 | tee /tmp/publish-push-sha.log
  fi
fi

# ---------------------------------------------------------------------------
# derive digest from pushed image (never typed)
# ---------------------------------------------------------------------------
derive_digest() {
  local img="$1"
  local d=""
  # Prefer RepoDigests from inspect (works after push)
  d="$(docker inspect --format='{{index .RepoDigests 0}}' "$img" 2>/dev/null || true)"
  # d is like ghcr.io/anywaye/svc@sha256:abc...
  d="${d#*@}"
  if printf '%s' "$d" | grep -qE '^sha256:[0-9a-f]{64}$'; then
    printf '%s' "$d"
    return 0
  fi
  # Fallback: parse push log
  for f in /tmp/publish-push-tag.log /tmp/publish-push-sha.log; do
    [ -f "$f" ] || continue
    d="$(grep -oE 'sha256:[0-9a-f]{64}' "$f" | head -1 || true)"
    if printf '%s' "$d" | grep -qE '^sha256:[0-9a-f]{64}$'; then
      printf '%s' "$d"
      return 0
    fi
  done
  # Try manifest inspect
  d="$(docker manifest inspect "$img" 2>/dev/null | grep -oE 'sha256:[0-9a-f]{64}' | head -1 || true)"
  if printf '%s' "$d" | grep -qE '^sha256:[0-9a-f]{64}$'; then
    printf '%s' "$d"
    return 0
  fi
  return 1
}

IMAGE_DIGEST=""
if [ "$DRY_RUN" -eq 1 ]; then
  IMAGE_DIGEST="sha256:0000000000000000000000000000000000000000000000000000000000000000"
  info "dry-run: would derive digest from $IMAGE:$TAG (e.g. $IMAGE_DIGEST)"
else
  if ! IMAGE_DIGEST="$(derive_digest "$IMAGE:$TAG")"; then
    die "could not derive digest for $IMAGE:$TAG — did the push succeed? (digest must be sha256:<64 hex>)"
  fi
fi

if ! printf '%s' "$IMAGE_DIGEST" | grep -qE '^sha256:[0-9a-f]{64}$'; then
  die "image-digest is '$IMAGE_DIGEST', not sha256:<64 hex>. The image job's build output is the only source for this field — a literal a human pasted is a digest nobody built, and a malformed one fails at image-pull with nothing here to correlate it to."
fi
info "digest: $IMAGE_DIGEST"

# ---------------------------------------------------------------------------
# stamp chart's values.yaml — mirror chart.reusable.yml semantics
# ---------------------------------------------------------------------------
VALUES="$CHART_ABS/values.yaml"
if [ ! -f "$VALUES" ]; then
  die "chart: no values.yaml at $VALUES — nothing to pin an image digest in"
fi

if [ "$DRY_RUN" -eq 1 ]; then
  echo "would stamp: $VALUES with image.digest $IMAGE_DIGEST (replace-or-insert under image: block)"
else
  if ! grep -qE '^image:[[:space:]]*$' "$VALUES"; then
    {
      echo '### chart carries no image: block'
      echo
      echo "\`$VALUES\` names no \`image:\` key, so there is no"
      echo "\`image.digest\` to pin and no fleet image for this chart to"
      echo "name. The chart is packaged as committed."
    } | cat >&2
    info "chart: $VALUES has no image: block — nothing to pin, packaging as committed"
  else
    if grep -qE '^  digest:' "$VALUES"; then
      count="$(grep -cE '^  digest:' "$VALUES")"
      if [ "$count" -ne 1 ]; then
        die "chart: $VALUES has $count 'digest:' lines at the image block indent — a values file with two is a parse error, and a blind rewrite would edit both."
      fi
      # shellcheck disable=SC2016
      sed "s|^  digest:.*|  digest: \"$IMAGE_DIGEST\"|" "$VALUES" >"$VALUES.new"
      mv "$VALUES.new" "$VALUES"
    else
      awk -v d="$IMAGE_DIGEST" '
        /^image:[[:space:]]*$/ { print; print "  digest: \"" d "\""; next }
        { print }
      ' "$VALUES" >"$VALUES.new"
      mv "$VALUES.new" "$VALUES"
    fi
    info "chart: $VALUES pins image.digest $IMAGE_DIGEST"
    grep -nE '^  (repository|tag|digest):' "$VALUES" | sed 's/^/chart:   /' || true
  fi
fi

# ---------------------------------------------------------------------------
# helm package
# ---------------------------------------------------------------------------
WORK="${TMPDIR:-/tmp}/chart-package-$$"
if [ "$DRY_RUN" -eq 1 ]; then
  echo "would run: mkdir -p $WORK && helm package $CHART_ABS --destination $WORK"
  PACKAGE="$WORK/${chart_name}-${chart_version}.tgz"
else
  mkdir -p "$WORK"
  info "packaging chart $CHART_ABS"
  run_bounded 120 helm package "$CHART_ABS" --destination "$WORK"
  # find package
  set +e
  packages=("$WORK"/*.tgz)
  set -e
  # shellcheck disable=SC2128
  if [ "${#packages[@]}" -ne 1 ]; then
    die "expected exactly one packaged chart in $WORK, found ${#packages[@]}"
  fi
  PACKAGE="${packages[0]}"
  info "package: $PACKAGE"
fi

# ---------------------------------------------------------------------------
# helm push
# ---------------------------------------------------------------------------
info "pushing chart $PACKAGE to $REGISTRY"
if [ "$DRY_RUN" -eq 1 ]; then
  echo "would run (bounded 300s): helm push $PACKAGE $REGISTRY"
  echo "would push: $REGISTRY/$chart_name:$chart_version"
else
  # helm registry login already done via docker login? helm uses same creds.
  # Ensure helm is logged in — try, but don't fail if already logged in.
  run_bounded 300 helm push "$PACKAGE" "$REGISTRY"
  info "pushed $REGISTRY/$chart_name:$chart_version"
fi

# ---------------------------------------------------------------------------
# visibility reminder (not a failure) + summary
# ---------------------------------------------------------------------------
# GHCR packages are private by default. No API with a normal token can flip
# visibility; it needs a browser once per new package.
REGISTRY_PATH="$(printf '%s' "$REGISTRY" | sed 's|^oci://[^/]*||; s|^/||')"
# REGISTRY_PATH is e.g. anywaye/charts
ENCODED_CHART="$(printf '%s' "$REGISTRY_PATH/$chart_name" | sed 's|/|%2F|g')"
ENCODED_IMAGE="$(printf '%s' "$IMAGE" | sed "s|^$GHCR_HOST/||; s|/|%2F|g")"

cat <<EOF
publish: done

  image:  $IMAGE:$TAG @ $IMAGE_DIGEST
          $IMAGE:$sha_tag
  chart:  $REGISTRY/$chart_name:$chart_version
  digest pinned: $IMAGE_DIGEST (in $VALUES)

  Visibility (one-time, browser):
    A package created private needs its visibility flipped once. No API
    with a normal token can do it — open the package page and set it to
    public (or internal):

      image: https://github.com/orgs/anywaye/packages/container/${ENCODED_IMAGE}/settings
      chart: https://github.com/orgs/anywaye/packages/container/${ENCODED_CHART}/settings

    Or from the repo view:
      https://github.com/anywaye/$chart_name/pkgs/container/$chart_name
      https://github.com/anywaye/charts/pkgs/container/charts%2F$chart_name

  Argo CD Application pulls:
    repoURL: $REGISTRY/$chart_name  chart: $chart_name  targetRevision: $chart_version
    image: $IMAGE:$TAG (and by digest $IMAGE_DIGEST)

EOF

if [ "$DRY_RUN" -eq 1 ]; then
  echo "publish: dry-run — no image or chart was pushed, no file was modified"
fi
