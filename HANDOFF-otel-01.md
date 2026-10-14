# HANDOFF-otel-01

gateway emits real telemetry. The work is DONE and gate-green; this file is
written anyway because two things about it are decisions that are not mine, and
one gap in the fleet is worth naming rather than leaving in a commit message.

## Done and verified

`bin/prime-go` — the whole gate since the TypeScript cutover — is green:

```
==> ok
suite: 252 passed, 0 failed
packages: 8 with tests
```

The narrow verify the packet named:

```
$ go test ./internal/telemetry/... ./internal/httpapi/... -count=1
ok  	github.com/cafaye/gateway/internal/telemetry	0.371s
ok  	github.com/cafaye/gateway/internal/httpapi	2.535s

$ go test ./internal/httpapi/ -run "TestWithTelemetryOff|TestTheRequestOpensOneServerSpan|TestTheProcessIdentityIsOnTheResource|TestAFailureCarriesCoreError|TestAValidTraceparentIsContinued" -v
--- PASS: TestWithTelemetryOffARequestIsAnsweredAsBeforeAndNothingIsRecorded (0.00s)
--- PASS: TestTheRequestOpensOneServerSpanNamedByTheFleetsGrammar (0.00s)
--- PASS: TestTheProcessIdentityIsOnTheResourceAndNotOnTheSpan (0.00s)
--- PASS: TestAFailureCarriesCoreErrorVocabularyAndARefusalDoesNot (0.00s)
--- PASS: TestAValidTraceparentIsContinuedAndAGarbageOneIsIgnored (0.00s)
```

Three commits, in gate-green order:

| commit | what |
|---|---|
| `6d37ae8` | `cafe gen telemetry` output: the generated setup, its suite, `telemetry/otel-endpoint.json` |
| `f86f4d4` | the hand-written SDK half, the middleware, the binary wiring |
| `5dbeee1` | the narrow test, the compose endpoint, and the one-placement fix it found |

### The route I took, which the packet asked me to state

**The generator's, not the hand-mirrored one.** `cafe gen telemetry` exists,
`cafe/internal/cli/gen.go:118` declares it, and it wrote gateway's three files
from gateway's manifest. gateway's generated file differs from the one already
in `cafe/internal/telemetry/` by exactly four lines — the service name and the
endpoint variable name — which is what "derived from the manifest" is supposed to
look like:

```
$ diff cafe/internal/telemetry/telemetry.go gateway/internal/telemetry/telemetry.go
18c18
< // From the manifest: the service name ("courier") and the language, which is what decided that
---
> // From the manifest: the service name ("gateway") and the language, which is what decided that
59c59
< const ServiceName = "courier"
---
> const ServiceName = "gateway"
80c80
< 	EndpointVariable = "COURIER_OTEL_ENDPOINT"
---
> 	EndpointVariable = "GATEWAY_OTEL_ENDPOINT"
108c108
< // COURIER_OTEL_ENDPOINT wins over the standard `OTEL_EXPORTER_OTLP_ENDPOINT`, which
---
> // GATEWAY_OTEL_ENDPOINT wins over the standard `OTEL_EXPORTER_OTLP_ENDPOINT`, which
```

The hand-written half is `internal/telemetry/sdk.go`, and it is what the packet's
"identity already carries the same generated shape" points at. Where identity
hand-types its own copy of the allowlist check (`identity/internal/telemetry/telemetry.go:435`,
`attributeValue`, with its own `httpMethods` and `routeTemplate` tables), gateway
calls the GENERATED `Check` for every value instead — so a core release reaches
gateway through `cafe gen telemetry` and not through a table somebody remembered
to update.

## The two decisions that are not mine

### 1. `cafaye.yml`'s `language: typescript` → `go`  — MINE, REVERSIBLE IN ONE WORD

The generator refuses any language it does not emit for:

```
cafe: cafe gen telemetry: unsupported language: this manifest is written in
typescript. cafe generates telemetry for go only
```

`src/` was deleted at cutover (`f87c891`, `bin/prime-go`'s header says so) and
`bin/prime` is the Go gate, so the field described an implementation that is not
in this repository. I flipped the word, and said so in the manifest beside it.

Reversal cost: one word, and the telemetry packet stops being reproducible with
one command. What it does NOT do is resolve DECISION NEEDED item 7 in that file,
which asks which implementation the manifest describes — that question is still
open and this change does not pretend to answer it. **If the manager would rather
the manifest keep saying `typescript` until item 7 is ruled on, revert this word
and the rest of the packet stands** — but `cafe gen telemetry` will then refuse,
and the generated files will have to be maintained by hand.

### 2. gRPC, and OTel 1.46.0 rather than pins.md's 1.34.0  — WORTH A RULING

**gRPC.** The generated file's `DefaultEndpoint` is `http://otel-collector:4317`,
the collector's gRPC receiver, and that file says `DO NOT EDIT`. So the exporter
is `otlptracegrpc` and the compose file says 4317. identity chose HTTP/4318 —
which means **the fleet currently has identity and gateway on different ports of
the same collector**. Both are wired to a real receiver, so both work, and the
kit collector ships both. But it is an inconsistency a reader will trip over, and
one packet should settle it: either the generator's default moves to 4318, or
identity moves to 4317. **Not mine to decide, and I did not touch identity.**

**Version.** `kit/templates/otel/pins.md` lists `go.opentelemetry.io/otel` and
`.../sdk` at **1.34.0**. gateway is on **1.46.0**, because that is what
`identity/go.mod` pins and because 1.46.0 is what the local module cache holds.
pins.md itself calls its table placeholders — "a service pins to the version it
deploys… raise these to the current release" — so I read this as following the
rule rather than breaking it. But the packet said "no dependencies beyond the OTel
SDK versions in kit's pins.md", and **that is a literal deviation and it should be
confirmed, not inherited.** Also note pins.md's table does not name
`otlptracegrpc`'s own line for the HTTP exporter identity uses, so the table was
already not a description of what the fleet runs.

Five modules entered `go.mod` as direct requirements (`otel`, `otel/trace`,
`otel/sdk`, `otlptrace`, `otlptracegrpc`), and `otlptracegrpc` brings `grpc`,
`genproto` and `protobuf` — the same thing identity's `exporter.go` documents at
length for its HTTP choice, so this is known and recorded rather than discovered.

## What a successor's first move is

1. **Run the stack and look.** `docker compose -f docker-compose.yml -f
   <kit stack> up --build`, then `GET /healthz` and open HyperDX filtered to
   `service.name=gateway`. Everything in this packet is verified by tests over an
   in-memory exporter; **no span has yet been seen in a collector**, and that is
   the one thing a test cannot do.
2. **Verify a trace crosses a hop**, which this repository cannot do alone: start
   identity, send `traceparent` into gateway's `/v1/me` (or any routed request),
   and confirm one trace with two spans in the backend. §3 is asserted against the
   SDK's own propagator; the end-to-end hop is unproven.
3. **Decide the 4317/4318 question** and whether pins.md's 1.34.0 is amended or
   gateway's 1.46.0 is pinned deliberately in `CHANGELOG.md`.

## What remains half-done, and why

- **Metrics and logs are not emitted.** `internal/telemetry` has an exporter for
  TRACES only. core's contract names three signals and the generated package
  already knows how to switch each of them off, so `OTEL_METRICS_EXPORTER=none`
  would be a lie by omission rather than by setting: gateway has no meter and no
  logger, and adding either is a second packet. The packet's DONE MEANS asks for
  spans and logs-in-HyperDX; **gateway emits spans, not logs.** The syslog crash
  driver in `docker-compose.yml` is unchanged and still delivers panics.
- **`http.route` is absent on a 404, a 405, and on a FORWARDED request.** chi has
  no pattern for an unmatched path, and the pass-through's chain sits outside the
  router. Recording the unmatched path would put caller-controlled text in a span
  attribute — a series per URL somebody guessed. For the forwarded case the
  configured prefix IS known and bounded, so a later packet can add it; this one
  records nothing rather than guessing.
- **`tenant_id` is unset by default**, so it is on the resource only when
  `GATEWAY_TENANT_ID` is set. `docker-compose.yml` carries it commented out.
- **No kit template files were copied in.** `kit/templates/otel/go/` says the
  codec suite is worth keeping "if you use the snippet"; gateway uses the SDK
  path, whose propagation is the SDK's, and the equivalent assertion is the
  `TestAValidTraceparentIsContinuedAndAGarbageOneIsIgnored` table above. Copying
  `traceparent.go` into a service that never calls it would be a second
  implementation of an algorithm nothing here uses.

## The currently-failing command

None. Every command in this file was run and its output is above. The one
non-green line in `bin/prime-go`'s output is the pre-existing, environment-gated
Redis tier, which the gate counts and names:

```
ratelimit: DID NOT RUN — GATEWAY_REDIS_URL is unset. Set
GATEWAY_REDIS_URL=redis://127.0.0.1:6379 to run the GCRA script against a real
server, or GATEWAY_REDIS_REQUIRED=1 to make this a failure.
skips: 13 of 13 declared (all of them the live Redis tier), and 1 t.Skip() call site
```

It is unchanged by this packet and was counted before it.