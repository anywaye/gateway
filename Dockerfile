# syntax=docker/dockerfile:1.7
# gateway — the anywaye public gateway. Go, distroless, multi-stage.
#
#   docker build -t anywaye/gateway:dev .        # the runtime image
#   docker build --target test .                # the gate: vet + test, in the image
#   docker compose build                         # the runtime image, same Dockerfile
#
# ------------------------------------------------------------------------------
# THERE IS ONE SHIPPED DOCKERFILE AND THIS IS IT
# ------------------------------------------------------------------------------
#
# There were two: `Dockerfile` built the TypeScript service and `Dockerfile.golang`
# built this one beside it, each with a header explaining why the other was not
# being replaced. That arrangement ended with the TypeScript service, and the
# second file went with it rather than being left as a duplicate of this one —
# two files building the same binary is the arrangement where a reader has to
# guess which one `docker build .` uses, and a guess is not a build.
#
# The parts of `Dockerfile.golang` worth keeping are kept, and they are marked
# below where they appear. The parts that were about Bun are gone rather than
# reworded: a comment that explains a choice the file no longer makes is a false
# premise, and a reader who trusts it is worse off than one who reads no comment.
#
# ------------------------------------------------------------------------------
# WHY IT IS AT THE REPOSITORY ROOT AND NOT NAMED `docker/Dockerfile.go`
# ------------------------------------------------------------------------------
#
# The name is load-bearing and the trap was measured, not guessed:
# `go build ./...` compiles every `.go` file in the tree, so a file named
# `docker/Dockerfile.go` is a Go source file to the go command, and a directory
# holding only that file is still a package. The build stops with
#
#     docker/Dockerfile.go:1:1: illegal character U+0023 '#'
#
# `pantry/Dockerfile`'s header records the same measurement. This file avoids it
# twice over: it is at the root, which is where `pantry` and `identity` both put
# theirs, and it is not named `*.go`, which is the part that actually breaks.
#
# ------------------------------------------------------------------------------
# STRICTNESS NOTES (read before loosening anything)
# ------------------------------------------------------------------------------
#
#   - `distroless/static`, never `debian-slim`. This service holds no rows, runs no
#     migration and opens no connection at boot, so nothing needs migrating and the
#     shell is not bought. `pantry` and `identity` made the same call for the same
#     reason. There is no `curl` and no `sh` in here, which is why the compose
#     healthcheck is a flag on this binary rather than a request from outside it.
#
#   - The test stage is a gate, not a report: an image whose suite is red does not
#     build. Run it with `docker build --target test .`; `docker compose build`
#     builds the runtime target only, so it does not execute this stage (buildkit
#     skips stages the target does not depend on). It is STRICTLY STRONGER than a
#     host run of the Go tier: it carries a `redis-server`, so the three browser-
#     surface tests that fail rather than skip when there is none actually run.
#
#     It is a separate stage rather than a step in `build` because the reason the
#     TypeScript image had to keep it out of the runtime graph — that a stage in the
#     graph drags the dev dependencies into the shipped image — has no Go
#     equivalent. The runtime stage below copies one file out of `/out` and shares
#     no filesystem with either of the others. What is left is only cost: a
#     `docker build .` that ran the whole suite on every image build would make the
#     image slower to iterate on than it needs to be, so the gate stays an explicit
#     target.
#
#   - `go test -count=1 -v ./...`, and BOTH FLAGS ARE LOAD-BEARING. `-count=1`
#     defeats the test cache, because a gate that can report a stale green is a gate
#     that reports what it ran last. `-v` is because `go test` DISCARDS a passing
#     package's output entirely: without it, a tier that skips prints its skip into
#     a void and the build log reads as a green that verified everything.
#
#     There is such a tier in here today. `internal/equivalence` needs `bun` to
#     stand the TypeScript reference up, and this image has no bun, so it prints
#
#         equivalence: DID NOT RUN — bun is not on PATH, so the TypeScript
#         reference cannot be stood up.
#
#     and the build goes on. `internal/ratelimit`'s live tier prints its own marker
#     for the same reason, for the other variable: it is gated on
#     `GATEWAY_REDIS_URL` naming a server rather than on a `redis-server` binary
#     being on PATH, so the binary this stage carries does not turn it on. Both are
#     skips this stage REPORTS rather than asserts, and the assertion lives in
#     `bin/prime-go`, which counts those lines and fails when
#     `GATEWAY_EQUIVALENCE_REQUIRED=1` or `GATEWAY_REDIS_REQUIRED=true` — which CI
#     sets. A gate in the image that insisted on this would fail every build, since
#     no Go image is going to install Bun to compare against an implementation
#     being deleted; a gate in the image that said nothing about it would be the
#     "green about nothing" this repository has been bitten by twice. Reported here,
#     asserted there.
#
#   - `COPY . .` in `source`, which is the opposite of the TypeScript image's
#     explicit COPY list, and the reason it is safe here is structural rather than
#     hopeful. `go test ./...` finds a package by walking the tree, so a named list
#     of paths would be a subset somebody maintains by hand — and a test file the
#     build context does not carry does not fail, it is not run. The Bun image kept
#     an explicit list because it had to; here the whole-context copy is what lets
#     the suite be the tree rather than a list, and the stage that carries it shares
#     no filesystem with the shipped one. `.dockerignore` is what keeps the context
#     honest, and the CI `image` job diffs the test files the built image discovered
#     against `find`, which is the half reading this file cannot see.
#
#   - `go mod download` against a committed `go.sum` with `GOFLAGS` unset. Go has no
#     `--locked`, so that pair is what makes two builds of one commit the same
#     artefact: a build cannot silently resolve a newer module.
#
#   - No init/tini. The Go process is PID 1 through the exec form, so SIGTERM
#     reaches it and `cmd/gateway`'s drain is the whole shutdown story.
ARG GO_VERSION=1.26

# ------------------------------------------------------------------- source
# One copy of the tree, shared by the gate and the build, so a change to the
# sources invalidates one layer rather than two. It is not the shipped stage and
# nothing is copied out of it except `/out/service`, from `build`.
FROM golang:${GO_VERSION} AS source
WORKDIR /src
# go.mod/go.sum first: the dependency layer caches until the manifests change.
COPY go.mod go.sum ./
RUN go mod download
COPY . .

# --------------------------------------------------------------------- test
#
# The comment block below is about the `redis-tool` stage this one copies from. It
# is written here rather than above that `FROM` so it sits with the step whose
# behaviour it explains, and the stage itself is defined first because a
# `COPY --from` names a stage that has to exist.
FROM redis:7-bookworm AS redis-tool

# `redis-server`, COPIED IN RATHER THAN INSTALLED.
#
# Three tests in `internal/httpapi` run the browser surface against a real Redis,
# and `startRedis` deliberately FAILS when there is no `redis-server` on PATH: a
# suite that skips the wire commands is a green that proves nothing, which is this
# repository's standing objection to a tier that can pass by not running. So an
# image without Redis does not get a smaller test stage, it gets a RED one — which
# is what `docker build --target test` reported until this step existed.
#
# Copied out of the official Redis image rather than `apt-get install`ed, for two
# reasons. An apt pin has to be a Debian revision, and a Debian revision stops
# being in the mirror when Debian supersedes it — so a "pinned" apt install is a
# build that breaks on a date nobody chose. And `golang:1.26` already has the
# `libssl.so.3` and `libcrypto.so.3` the Redis binary links against, because both
# images are Debian bookworm; a different base would need the libraries copied too,
# which is the point where "copy one binary" stops being one line.
#
# `7-bookworm` is a floating tag and this is the one place in this file that is not
# pinned, deliberately: it builds a throwaway test stage and ships nothing, so the
# artifact this file produces — the runtime image below — does not depend on it.
# Written as a literal rather than an `ARG` because hadolint reads
# `FROM ${REDIS_IMAGE}` as an UNTAGGED image (DL3006), and a suppression comment on
# the line that names the tool is worse than one fewer knob.
#
# IT IS ALSO A STAGE THE RUNTIME BUILD NEVER TOUCHES. `redis-tool` is above `test`
# rather than beside it only because `COPY --from` needs it to already exist, and
# buildkit builds only the stages the requested target depends on — so `docker
# build .` pulls no Redis and `docker build --target test .` does. Measured rather
# than assumed: `docker history anywaye/gateway:dev` carries five layers above the
# distroless base — WORKDIR, COPY, USER, EXPOSE, ENTRYPOINT — and none of them is
# this one.
FROM source AS test
COPY --from=redis-tool /usr/local/bin/redis-server /usr/local/bin/redis-server
RUN redis-server --version && go vet ./... && go test -count=1 -v ./...

# -------------------------------------------------------------------- build
FROM source AS build
ENV CGO_ENABLED=0 GOOS=linux
RUN go build -trimpath -ldflags="-s -w" -o /out/service ./cmd/gateway

# ------------------------------------------------------------------ runtime
FROM gcr.io/distroless/static-debian12:nonroot AS runtime
WORKDIR /app
COPY --from=build /out/service /app/service
# nonroot, not root. There is no shell in this image, so a compromised process
# cannot curl-and-pipe.
USER nonroot:nonroot
EXPOSE 8080
# The service is stateless: no connection pool to close, no schema to migrate and
# nothing to flush, so SIGTERM is the whole shutdown story and cmd/gateway handles
# it. That it is the WHOLE story is a consequence of what this service is, not a
# claim beyond it: the counter store, the identity connection and the upstream
# connections are all lazy or dialled per request, and each may change what
# shutdown has to do.
ENTRYPOINT ["/app/service"]