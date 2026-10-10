# HANDOFF — gateway TG-C1 (shared-surface enforcement)

Branch: `tenancy/gateway-tgc1`. Commit: `32f000e` (the only commit this packet
lands; the manager merges and pushes).

## What this packet did

Closes the three gaps the brief named, in the order the brief set — contract
first, then the scope mount, then the limiter.

### 1. API keys (gap 3) — contract first, then code

`openapi/v1.yaml` declares three `api-keys` operations and the generated
router mounts them:

- `POST /v1/api-keys` — mint. Body `{scopes}` → `201 {key, prefix, id}`.
- `GET /v1/api-keys` — list. → `200 [{id, prefix, scopes, revokedAt}]`.
- `DELETE /v1/api-keys/{id}` — revoke. → `204` unconditionally.

`internal/auth/apikey.go` is the port: 32 CSPRNG bytes behind `caf_`, only the
SHA-256 stored, the first twelve characters shown once at issue, the
`ApiKeyStore` seam (`Issue`/`ByHash`/`List`/`Revoke`), and the key gate
(`ApiKeyGate`) mounted in front of the bearer gate on the API surface. A key
sets the account's principal (a key *is* the account), so the limiter keys on
`apikey:<id>` ahead of the address.

**Three decisions, each recorded where it is enforced:**

- The listing never returns the `hash` — a digest is not the secret, but the
  listing is the one place every credential an account holds appears at once.
- A revoke of a key that is not the caller's is a `204` no-op, not a `404` or
  a `403` — cross-tenant is absence, and a distinguishable status would confirm
  that a guessed id once existed. Enforced in `MemoryApiKeyStore.Revoke`.
- The three routes require authentication but **no specific scope** — no scope
  vocabulary is wired to routes, and inventing one is a product decision. The
  `gateway-api-keys` rate-limit entry already gives the surface its own bucket.
- The account is never a field — it is the verified principal's, so a document
  that let a caller name the account would describe the cross-tenant bug as a
  feature.

The store is one process. `TODO(guard-07)`'s shared store is the packet that
closes that; it is the same shape the reference's own v0 store had.

### 2. The scope gate (gap 1)

`ROUTE_TABLE` entries gain an optional `scopes` array, and `scopeGate`
(`internal/httpapi/httpapi.go`) mounts `RequireScope` on a route that
declares them. This is the capabilities half of what the verifier proves about
a caller, which was implemented and tested but mounted by nothing.

The gate runs after the credential gate and before the limiter, so the order
the house rule names holds: a credential is established before a capability is
checked, and a caller refused for capability is counted against nothing — the
same rule an unverified token gets.

- A `public` entry cannot declare scopes and refuses to boot (a public route
  has no verified caller to check against). Enforced in `ValidateRouteTable`.
- A route with no `scopes` field forwards every verified caller, which is what
  every deployed route already means — the field is additive.
- Gateway's own routes (`/v1/me`, `/v1/api-keys`) are exempt: they are not
  forwarded traffic, so a broad `/v1` table entry cannot scope-gate or relay
  them. `isGatewayOwned` is the single enumeration.

### 3. The limiter counts forwarded traffic (gap 2) — already fixed

This was **already fixed in the tree** before the packet started. The limiter
is wrapped around the pass-through in `everyRequest`, and the old
`TestTheGoSideDoesNotCountRoutedTraffic` was renamed and inverted to
`TestTheGoSideCountsRoutedTraffic` (the fix made it fail, which is the signal
to replace a test rather than adjust one). What was stale was the **README
prose**: the Go-rewrite table rows, the limiter section heading, and three
"Not built yet" entries. All corrected.

## What is NOT done, and why

- **No shared API-key store.** `MemoryApiKeyStore` is per-process; a key issued
  on one replica does not exist on the next. `TODO(guard-07)`. Deliberately
  absent rather than written wrongly.
- **No deployment has asked for a scope.** The gate is mounted and a route may
  declare `scopes`, but no deployment has, so in practice every verified caller
  is still forwarded. Turning it on is a per-entry configuration decision.
- **No new env variable.** The shipped binary wires an in-memory key store
  unconditionally (like the verifier), so no `RuntimeOptions` change and no
  `TestTheRuntimeReaderReadsExactlyTheseVariables` impact.
- **The `me` row in `account_scope.yml` is still red** (`scoping-bypassed`).
  That is a **pre-existing, documented core checker defect** around chi's
  `Use(` (the checker's `MIDDLEWARE` regex cannot read it), not introduced here.
  The three new api-keys rows are clean: 0 undeclared, 0 unreadable, 0 stale.

## Verification

- `./bin/prime` — **green** (gofmt, build, vet, `go test -v ./...`, and
  `api.gen.go` byte-identical to what `openapi/v1.yaml` generates).
- `tenancy-check .` — **green** (0 failures; the two warnings are the expected
  scanner limits for a Go service).
- `account-scope-check .` — 1 failure (the pre-existing `me` red, above); the
  three new rows counted.
- `go test ./...` — all packages ok.

## The successor's first move

If the shared store is the next packet: `ApiKeyStore` is the seam, and the
sibling packet already decided gateway owns its per-process state in Redis over
the RESP2 transport `internal/ratelimit` already speaks — so it is one shared
client with the limiter, not a fork. `internal/sessionredis` is the precedent.
