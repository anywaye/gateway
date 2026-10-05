# HANDOFF-test-ts.md — what `test/*.ts` asserted, and what is still holding it

Written in the commit that deleted the TypeScript build surface
(`package.json`, `bun.lock`, `tsconfig.json`). **None of the five `test/*.ts`
files could be ported to Go by the worker that wrote this, because every Go test
in this repository lives under `internal/` and `internal/` was explicitly out of
that worker's scope.** So this file does the next best thing: it says, assertion
by assertion, which ones already have a Go counterpart and which ones do not.

The distinction that matters: a file whose assertions are all covered can be
deleted. A file with an assertion nobody holds is a hole, and a hole that is
named is a ticket. A hole that is deleted quietly is the failure this packet
exists to prevent.

---

## Deleted, with the assertion and where it lives now

### `test/noSkips.test.ts` — PORTED, not deleted quietly

Its property: **no test in this repository may skip itself, except one declared
tier.**

It lived as a source-reading test over the TypeScript suite. It is now a block in
`bin/prime-go`, with two mechanisms instead of one:

| assertion | where it is now |
|---|---|
| "the only skip in the suite is the declared one" | `bin/prime-go`, `skips:` line — a runtime count of `--- SKIP:` lines against a ceiling of 13 |
| "the declared skip is still present, not merely permitted" | same block — a source count asserting `t.Skip(` has exactly **one** call site and that it is `./internal/ratelimit/live_test.go` |
| "no source file outside the suite declares a gated environment" | same block — the source count is tree-wide over `./cmd ./internal` |
| "at least one test file was found to check" | **NOT PORTED, and not needed here.** The equivalent defect would be the skip count reading `0` on a machine with no Redis, and the `ratelimit` block above already fails a run whose tier went quiet. |

**The one real weakening, stated rather than buried.** The TypeScript version
asserted *equality* with an allowlist. This asserts a *ceiling* of 13, because
the legitimate count is 13 without Redis and 0 with it, and a gate that is right
in one environment and red in the other is a gate people learn to disable. The
consequence: **deleting the live Redis tier whole leaves 0 skips, which is under
the ceiling and therefore passes.** That case is caught by
`GATEWAY_REDIS_REQUIRED=1` (which turns "no Redis" into a failure) and by the
`redis` CI job, which forces the tier. It is not caught by this block, and the
block's comment says so.

### `pins.test.ts` — PORTED for the two assertions that were still live

Ten tests. Five of them were about the Bun pin and died with Bun. Two were about
`bun.lock`. One (`the engines floor admits the pin rather than excluding it`) was
about `package.json`. That leaves two, and **both were live checks on Go files
that nothing else read**:

| assertion | where it is now |
|---|---|
| "the Dockerfile builds on that toolchain" | `bin/prime-go`, `image tag:` line — Dockerfile's `ARG GO_VERSION` must be the major.minor prefix of mise.toml's pin |
| "compose passes the pin through rather than repeating it" | same block — `docker-compose.yml`'s `GO_VERSION` likewise |

This mattered more than it looked. `grep -n GO_VERSION` across the repository
returned exactly one hit — `docker-compose.yml:151`, which is the thing being
asserted, not an assertion of it. Nothing in CI checked it either. So mise.toml's
comment ("`Dockerfile`'s ARG GO_VERSION is 1.26, the tag the image builds with")
was, before this commit, an unverifiable claim about two files. It is checked now.

The remaining assertion, "an unknown argument is still refused", is preserved as
`bin/prime`'s `exit 2` branch and was verified:

```
$ ./bin/prime --no-go ; echo $?
bin/prime: unknown argument: --no-go
  bin/prime takes no flags. The Go tier is the whole gate; run
  './bin/prime-go' for the tier alone and 'mise run prime' for this.
2
```

---

## LEFT IN PLACE — assertions with no Go counterpart

These files are kept, unrunnable and inert, because `internal/` was out of scope
for the worker that wrote this. They import `../src/index` and other deleted
modules, so they cannot run today and their retention costs nothing but disk.

**They are interdependent and must be retired as a group.** `openapiDocument.test.ts`
imports `./openapiPaths`; `tenantEntryPoints.test.ts` and the deleted
`noSkips.test.ts` imported `./dockerStage`. Deleting half of the cluster breaks
the imports of the half that still holds an uncovered assertion.

### `test/tenantEntryPoints.test.ts` — SECURITY. This is the important one.

It enumerates every account-scoped entry point **derived from the source**, and
requires each one to have a negative case in a named test file. Its own header
states the reason in one line: *"a scoping nobody can find is a scoping nobody
has ever run."* It also asserts that the only 403s in production source are the
capability gate and the origin gate, and that both are about the caller rather
than about a resource that exists.

| assertion | Go counterpart |
|---|---|
| "the account-scoped routes are exactly the ones the derivation finds" | **partial.** `account_scope.yml` + core's `account-scope-check` (owned by another worker) and `internal/httpapi/routes_test.go` |
| "every account-scoped route has a negative case" | **partial.** See `TestTheRouterServesExactlyWhatTheGeneratedDocumentDeclares` (`routes_test.go:133`), but that is a doc-vs-router comparison, not a per-entry-point negative case |
| "the probes serve no account and are exempt from the limiter" | **COVERED** — `TestTheProbePathsAreStillNeverCounted` (`runtime_limits_test.go:339`) |
| "every store operation taking an account is in the table" | **NOT COVERED.** `tenantEntryPoints.test.ts` is the only place that enumerates store operations taking an account. There is no Go equivalent, because the session store's account-scoped methods are asserted behaviourally in `internal/sessionredis` but nothing *enumerates* them |
| "the only 403s in production source are the capability gate and the origin gate" | **NOT COVERED.** Nothing greps production Go source for 403 sites and checks the set |
| "both 403s are about the caller, not about a resource that exists" | **NOT COVERED** |
| "the count is the number this file claims" / "no entry point is listed twice" | **NOT APPLICABLE** — a uniqueness property of a list that will not exist in Go |

**What is lost if it is deleted:** the *enumeration* property. The behavioural
negative cases survive; the check that the enumeration is *complete* does not.
That is the difference between "we tested the three entry points we know about"
and "there are three entry points", and only the second one catches the new one.

**The port, for whoever has `internal/`:** a `*_test.go` under `internal/` that
walks the AST of `internal/httpapi` and `internal/session`, collects every
function taking an account (or reading a claim) and every `WriteHeader(403)`,
and fails when the set is not exactly the one a table names. Go's `go/ast` makes
this *easier* than the TypeScript version, which hand-rolled a comment-stripping
regex reader.

### `test/openapiDocument.test.ts` — document hygiene, not covered

| assertion | Go counterpart |
|---|---|
| "every operation the document describes is a route the router serves" | **COVERED** — `TestTheRouterServesExactlyWhatTheGeneratedDocumentDeclares` (`routes_test.go:133`), `TestTheServerImplementsEveryOperationTheDocumentDeclares` (`routes_test.go:212`), `TestEveryOperationIsEitherServedOrDeclined` (`httpapi_test.go:316`), and `bin/prime-go`'s regenerate-and-diff |
| "the problem envelope is one component, referenced rather than restated" | **COVERED** — `TestAProblemIsTheDocumentedEnvelope` (`problem_test.go:36`) |
| "the document names every rate-limit field the limiter announces" | **COVERED** — `TestEveryRateLimitFieldIsAnnouncedOnEveryAnsweredRequest` (`limiter_test.go:332`); `internal/ratelimit/limiter.go:388` says the fields are read from the document rather than spelled from memory |
| "every operation the limiter counts declares the 429, and the probes do not" | **PARTIAL.** `TestTheProbePathsAreStillNeverCounted` (`runtime_limits_test.go:339`) covers the probe half. The "the limiter counts" half is asserted in Go behaviour but not read back out of the document |
| "it declares OpenAPI 3.1.0, which is the version the fleet publishes" | **NOT COVERED** |
| "it declares `info.version`, and this is a new document so it starts at 1.0.0" | **NOT COVERED** |
| "the media types it names are the two gateway actually emits" | **NOT COVERED** |
| "every operation the document describes declares a 500, and that one is not a problem document" | **NOT COVERED** |
| the four mount-exclusion tests | **NOT APPLICABLE** — they were about Hono mounts the Go server does not have |

**The four NOT COVERED rows are all assertions about `openapi/v1.yaml` itself**,
not about the Go code. The cheapest home for them is core's document checker
(`tenancy-check` / `numeric-check` already read the OpenAPI document), not a
per-service test.

### `test/openapiPaths.ts` + `test/openapiPaths.test.ts` — kept only as `openapiPaths`'s reader

`openapiPaths.ts` is a hand-written YAML reader whose whole purpose was to
compare the document against a **Hono** router. Neither side exists. Its twenty
tests are mostly about the *reader's own refusal behaviour* — indentation, a
path-item field that is not an operation, an error message that names the file.

The reader survives only because `openapiDocument.test.ts` imports it. Retire it
in the same commit that retires that file.

### `test/dockerStage.ts` — property already moved, reader kept only as an import

**Verified, not assumed:** the property is asserted in
`.github/workflows/ci.yml`, in the `image` job, at two places:

- ~line 494: asks the *built* image which `*_test.go` files it holds and diffs
  that set against `find` in the repository.
- ~line 507: `docker export` the runtime image and fail if any path from the
  repository is in the flattened filesystem.

Neither was edited by this worker (that file belongs to another). The reader
itself — a Dockerfile COPY-list parser with no gateway consumer, per its own
header — is kept only because `tenantEntryPoints.test.ts` imports `findFiles`
from it. It can go with the cluster.

---

## One more thing the packet said to leave alone, and what the check found

`test/proxyMutations.sh` and `test/assertionMutations.sh` were flagged as "Go
mutation gates — verify before assuming". Verified:

- **`test/proxyMutations.sh` IS a Go gate.** `proxyMutations.sh:74` runs
  `go test ./internal/httpapi/ -count=1 -run "^${want}$"`. **Leave alone.**
- **`test/assertionMutations.sh` is NOT.** It runs `bun test` at lines 76 and 98,
  and every mutation it applies targets a file under `src/routes/` —
  `src/routes/table.ts`, `src/routes/proxy.ts`, `src/routes/assertion.ts` — all
  deleted at f87c891. **It cannot run and it proves nothing.** It was not deleted,
  because the packet said not to, but it is dead weight with a green-looking
  header, and it should be deleted or ported in the same commit that retires the
  cluster above.

---

## Summary for whoever picks this up

| file | action needed | blocked on |
|---|---|---|
| `test/tenantEntryPoints.test.ts` | **port the enumeration** — security, uncovered | `internal/` scope |
| `test/openapiDocument.test.ts` | port 4 document-hygiene assertions | `internal/` or core's document checker |
| `test/openapiPaths.ts`, `test/openapiPaths.test.ts` | delete with `openapiDocument.test.ts` | nothing |
| `test/dockerStage.ts` | delete with `tenantEntryPoints.test.ts` | nothing |
| `test/assertionMutations.sh` | delete or port to `go test` | nothing |
| `test/proxyMutations.sh` | none — it is a live Go gate | — |

Also worth knowing: `gate.yml`'s deleted `files` proof was the **structural**
detector (a file count), and its replacement `suite` proof is a **count**. A test
file deleted along with its tests is caught; one deleted *separately* is no
longer distinguishable. That trade is recorded in `gate.yml`'s header.