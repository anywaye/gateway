# REPORT-gateway-pantry-principal-01.md

Packet R2 — gateway mints the principal assertion for pantry's write routes
(seam-audit F2, `SEAM-AUDIT-01.md` §F2). Branch `worker/gateway-principal`.

## What was wrong

Pantry's write path verifies a gateway-signed principal assertion (RS256,
`aud` = pantry's origin, `sub` required). Gateway's minting mechanism was
complete and tested (`internal/httpapi/table.go`, `proxy.go`,
`assertion.go`) — but no shipped route table declared `principal` for
pantry, so gateway minted nothing (`nil` principal = mint nothing) and every
pantry write 401'd at the second hop with an empty `x-cafaye-principal`.

## The route entries as landed

The split is by path, because the table matches on path prefixes and
pantry's reads and writes share paths: `GET /v1/projects` (list) and `POST
/v1/projects` (register) differ by method, which no prefix can see. So the
gateway paths differ instead. `POST /v1/pantry-writes/projects` reaches
pantry as `POST /projects` (the matched prefix is stripped, the remainder
appended); longest-prefix match keeps `/v1/pantry-writes/...` on the write
entry and everything else under `/v1/pantry` on the read entry, with no
overlap (segment-boundary matching: `/v1/pantry` never claims
`/v1/pantry-writes`).

`charts/gateway/values.yaml` (ACTIVE — the launch artifact; verified with
`helm template`, ConfigMap value parses as JSON):
```json
{"/v1/pantry":{"baseUrl":"http://pantry:8080","public":true},"/v1/pantry-writes":{"baseUrl":"http://pantry:8080","principal":["sub"]}}
```
plus, in the same `env`:
```
ASSERTION_TTL_MS: "120000"
ASSERTION_SIGNING_KEY_FILE: "/etc/gateway/assertion/signing.pem"
```
The key file arrives on an `assertion-key` volume (`templates/deployment.yaml`)
mounted read-only from the `gateway-secrets` secret key `ASSERTION_SIGNING_KEY`
(new `secrets.assertionKeySecretName` / `assertionKeySecretKey` values, created
out of band like `REDIS_URL`). No secret, no pod — deliberate: a principal
entry with no key mints nothing, which would reopen this seam as a silent 401
at pantry rather than a refusal to boot.

`docker-compose.yml` (DOCUMENTED, still inactive — the dev stack ships neither
pantry nor key material, so the file's honest-default stance stands):
```
# ROUTE_TABLE: '{"/v1/pantry":{"baseUrl":"http://pantry:8080","public":true},"/v1/pantry-writes":{"baseUrl":"http://pantry:8080","principal":["sub"]}}'
# ASSERTION_SIGNING_KEY_FILE: "/etc/gateway/assertion/signing.pem"
# ASSERTION_TTL_MS: "120000"
```

`sub` only, no `github_id`: pantry treats `github_id` as optional metadata,
and a second claim would be a second credential surface nobody asked for.
No `token` on either entry: pantry authenticates the assertion, not a static
bearer, and a public entry carrying a token refuses to boot.

No other shipped table declares pantry (`grep pantry:8080` hits only these
two files plus docs/reports/test fixtures). The e2e/equivalence tables needed
no change: `internal/equivalence/scenarios.go:219` states no scenario declares
`principal`, and none exercises the write path.

## Origin-agreement evidence

Pantry's verifier demands `aud` == pantry's own origin. Gateway mints `aud`
from the route entry's own `BaseURL`, which validation has already reduced to
an origin — so both sides name the same string, `http://pantry:8080`:

- `internal/httpapi/proxy.go:363` — `AssertionSubject{Audience:
  route.BaseURL, Claims: route.Principal}`: the audience is the entry's base
  URL, never caller input, never a second spelling.
- `internal/httpapi/table.go:437` — `checkBaseURL` returns
  `originOf(parsed)`; `table.go:468-475` — `originOf` is
  `scheme://lowercased-host[:non-default-port]` (default ports dropped, so
  `http://pantry:80` and `http://pantry` cannot mint two audiences for one
  service).
- `internal/httpapi/assertion.go:293` — the envelope writes `"aud":
  subject.Audience` before declared claims, which cannot overwrite it
  (`checkClaimName` refuses `aud` in an entry).

The new test asserts `aud == "http://pantry:8080"` on a minted write-prefix
assertion, pinning the string both sides must agree on. Pantry's half
(`PANTRY_AUDIENCE == http://pantry:8080`) is the F1 packet's to set; this
packet guarantees what gateway sends.

## Tests

Tests-first: `internal/httpapi/pantry_shipped_table_test.go` was committed red
(commit `d77418b` — 0 write-prefix entries, no TTL/key vars in either file),
then the tables were edited to green. It reads both shipped files off disk
(active lines and commented examples alike) and asserts:

- `TestShippedPantryTablesMintSubOnlyOnTheWritePrefix` — exactly one
  non-public pantry entry with `principal == ["sub"]`; `/v1/pantry` stays
  public with no principal; end to end through `assertionFor`: the write
  prefix mints a signature-verified assertion carrying `sub`, omitting a
  caller-held `github_id`, bound to `aud == http://pantry:8080`; the read
  prefix mints nothing.
- `TestShippedPantryTablesKeepAssertionTTLAtOrUnderTheCeiling` — every
  `ASSERTION_TTL_MS` in either file is a positive integer ≤ 600000, and each
  file names `ASSERTION_SIGNING_KEY_FILE`.

`.dockerignore` gains `!docker-compose.yml` (with the reason stated in the
file): the test stage is `COPY . .` and the new test reads the compose file,
so without the negation `docker build --target test` would fail loud on "no
such file" while the host gate stayed green. `charts/` was never excluded.

## Gates

- `bin/prime` (both tiers): exit 0. 8 packages ok, 257 `--- PASS`, 0 `--- FAIL`
  (includes the 2 new tests / 4 new subtests). gofmt clean, `go vet` clean,
  toolchain go 1.26.1.
- `docker build --target test .`: exit 0. The new seam guard runs and passes
  in-image on both files (including `docker-compose.yml`, proving the
  `.dockerignore` negation), 0 failures suite-wide.
- `docker build .` (runtime): exit 0.
- `helm lint ./charts/gateway/`: 0 failed. `helm template` render checked:
  ConfigMap `ROUTE_TABLE` parses as JSON; Deployment carries the
  `assertion-key` volume, mount, and secret refs.
- Mechanism untouched: no change to `assertion.go`, TTL logic, signing, or
  any claim set — tables and configuration only. Identity and pantry
  untouched. No push; branch only.

## For the F1 packet

Gateway now sends `aud: "http://pantry:8080"`, `sub` set, RS256, 120s TTL,
`kid` = key thumbprint unless `ASSERTION_SIGNING_KEY_ID` is set. Pantry must
be wired with `PANTRY_AUDIENCE=http://pantry:8080` and the public half of this
deployment's signing key, handed out of band the way the service token was.
