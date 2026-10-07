# REPORT — gateway's first Helm chart, and a deployment that cannot forget Redis

**Packet:** gateway-w67-deployable. **Base commit:** `9b3d12e` (merge of
worker/gateway-w62-bindev). **Branch:** `worker/gateway-w67-deployable`.
**Outcome:** done — chart, Argo `Application`, compose declarations, CHANGELOG
and README landed; gate green; render recorded below.

## What the packet is for

Two launch blockers. **A6:** gateway had a `Dockerfile` and nothing that turns
the image into a running service — no chart, no `Application`, no hostname, no
readiness gate, no rollback. **B6:** `REDIS_URL` is load-bearing twice over
(the browser surface's session store, and the limiter's shared counters) and
appeared in no manifest a deploy reads — it was commented out in
`docker-compose.yml`, so a gateway deployed today serves `/healthz` and
`/readyz` and no sign-in. `TRUSTED_PROXIES` is the same class one layer down:
at its default `0` behind an ingress, every caller shares the proxy's peer
address and the launch rate-limits all users as one.

## What landed

| file | what it is |
|---|---|
| `charts/gateway/Chart.yaml` | chart metadata; `appVersion` moves with the image tag |
| `charts/gateway/values.yaml` | every value a generator must emit, with the reason at each line |
| `charts/gateway/templates/_helpers.tpl` | name/fullname/labels |
| `charts/gateway/templates/deployment.yaml` | Deployment: image, ports, `envFrom` ConfigMap, `REDIS_URL` `secretKeyRef`, probes, resources |
| `charts/gateway/templates/service.yaml` | ClusterIP Service |
| `charts/gateway/templates/ingress.yaml` | Traefik-class Ingress, TLS via cert-manager secret |
| `charts/gateway/templates/configmap.yaml` | the clear env, rendered not inlined |
| `deploy/argocd/gateway-application.yaml` | the pull-only loop: a commit changes the chart, Argo makes the box agree |
| `docker-compose.yml` | `REDIS_URL` and `TRUSTED_PROXIES` uncommented |
| `CHANGELOG.md`, `README.md` | what the chart is for and what it is not |

The chart is written **generated-shaped** as the reference `caf gen chart`
(packet L10) must reproduce: every value that belongs in a manifest is in
`values.yaml`, and nothing in the templates is a hand-typed constant a
generator could not emit. The CHANGELOG carries the table of
values.yaml → manifest field so L10 has a specification rather than a guess.

## The render, recorded exactly

`helm` v3.22.0 at `/opt/homebrew/bin/helm` (the path the packet names; the
`helm` on PATH is v4.3.0 and was not used). `kubectl` v1.33.9.

```sh
$ /opt/homebrew/bin/helm template gateway charts/gateway
# exit 0 — renders four documents:
#   configmap/gateway-env   service/gateway   deployment.apps/gateway
#   ingress.networking.k8s.io/gateway

$ /opt/homebrew/bin/helm lint charts/gateway
1 chart(s) linted, 0 chart(s) failed
```

`kubectl apply --dry-run=client -f -` against the rendered chart:

```
configmap/gateway-env created (dry run)
service/gateway created (dry run)
deployment.apps/gateway created (dry run)
ingress.networking.k8s.io/gateway created (dry run)
```

and against the Argo `Application`:

```
application.argoproj.io/gateway created (dry run)
```

**The caveat, stated rather than buried: there is no cluster on this machine**
(`kubectl config current-context` → not set; no k3s/k3d/kind/minikube). A
plain `kubectl apply --dry-run=client` fails here at *discovery*, not at
validation of these documents:

```
error: error validating "STDIN": error validating data: failed to download
openapi: Get "http://localhost:8080/openapi/v2?timeout=32s": dial tcp
[::1]:8080: connect: connection refused
```

So the dry-run was run against a minimal offline **discovery endpoint** (a
~90-line Python server, kept outside the tree) that serves `/api`, `/apis`,
the group-version resource lists for `v1`, `apps/v1`, `networking.k8s.io/v1`
and `argoproj.io/v1alpha1`, and a minimal protobuf `openapi.v2.Document`
(`swagger: "2.0"`, no definitions). What that proves: the documents decode,
default and are recognized by kubectl's RESTMapper, and the chart's structure
is valid. What it does **not** prove: field-level OpenAPI schema validation —
the fake endpoint serves no definitions, so the validator has no constraints
to check. On a real cluster the plain command is the stronger check and
should be re-run there; the command and its expected output are above.

## Decisions worth recording

- **`REDIS_URL` is a required `secretKeyRef`** (`secrets.redisUrlSecretName`,
  key `REDIS_URL`). No secret, no pod — a deployment cannot forget Redis.
  The secret is created out of band; the chart never renders a value. The
  comment at the line states both consequences: no browser surface (the four
  `/auth/*` routes decline — no sign-in) *and* an N× limit whose counters
  reset on every deploy.
- **The secret is named `gateway-secrets`, not `gateway-env`.** The first
  draft of this chart (previous attempt) used `gateway-env`, which is the
  ConfigMap's name. Two resources of different kinds sharing a name is legal
  in Kubernetes and confusing in every `kubectl get` that shows both.
- **Readiness is `/readyz`** — gateway's real, bounded, dependency-aware probe
  (`internal/httpapi/runtime.go`); liveness is `/healthz`. An Argo/rollout
  gate that reads `/healthz` accepts a container that cannot reach identity.
- **`TRUSTED_PROXIES` is `"1"` in the chart** (Traefik appends one hop) with
  the cost of a wrong one at the line: at `0` behind a proxy every caller
  shares one bucket; too high lets a caller mint a bucket per request by
  writing the trusted hop.
- **Locally, `TRUSTED_PROXIES` is `"0"`** — a thought-out zero, not a default
  nobody chose. The kit stack at the pinned ref runs **no ingress** in front
  of gateway (checked `templates/compose/docker-compose.yml` in the kit
  cache: postgres, nats, redis, otel-collector, tempo, loki, mimir, grafana —
  no Traefik), so nothing appends `X-Forwarded-For` and the socket peer is
  the right key. `REDIS_URL` is `redis://redis:6379`, kit's Redis on the
  `platform` network. Verified in the merged config:

  ```
  REDIS_URL: redis://redis:6379
  TRUSTED_PROXIES: "0"
  ```

- **The fail-open limiter was not touched.** `internal/ratelimit/limiter.go`
  argues it deliberately; the defect was that a deployment is not told what
  to set, and the chart is the telling.
- **The Argo `Application` points at the chart's own `values.yaml`** — one
  file, one source of truth. A deployment that needs to override (per-tenant
  host, route table) adds a `valueFiles` entry rather than editing the
  chart's defaults, so the chart stays the reference implementation.
- **No components the substrate excludes:** Argo core, no Dex, no SSO, no
  Redis HA, no Kamal, no `config/deploy.yml`.

## What I ruled out

- **Kamal / `config/deploy.yml` / `templates/kamal`** — the retiring path;
  the packet forbids adding to it.
- **Fixing the fail-open limiter** — a decision, not a defect.
- **Setting `GATEWAY_OTEL_ENDPOINT` in the chart** — it is read by
  `internal/telemetry`, not the runtime reader, and the in-cluster collector
  address belongs to the observability stack (L12). A guessed default is
  worse than the documented fallback (`http://otel-collector:4317`). Flagged
  as a gap below rather than invented.
- **Wiring the render into `bin/prime`** — the packet makes the render a
  separate, bounded command and the manager owns the gate. Recorded here
  instead.

## Known gaps (honest list)

1. **The image tag `0.1.0` does not exist yet.** `values.yaml` defaults
   `image.tag` to `Chart.yaml`'s `appVersion` (`0.1.0`), never `latest`; the
   first real release must push that tag. Until then `docker-compose.yml`'s
   `cafaye/gateway:dev` is the local image.
2. **In-cluster telemetry endpoint.** The chart does not set
   `GATEWAY_OTEL_ENDPOINT`; in the k3s cluster the default
   `http://otel-collector:4317` will not resolve from the `cafaye` namespace
   unless the observability stack names it so. L12's call.
3. **The chart render is not in CI.** It is a recorded, bounded command (this
   report). A `bin/prime-chart` or a CI job that runs the two commands
   against a real cluster would make the proof continuous; the manager owns
   the gate and that decision.
4. **The offline dry-run proves recognition, not schema** — see the caveat
   above. Re-run the plain command on a real cluster before the first
   deploy.

## The gate

```
$ ./bin/prime        # background, exit captured
== prime ok          # exit 0
```

`bin/prime` is now the Go tier alone (the TypeScript tier was deleted at
cutover, `src/` gone): gofmt clean, `go build`, `go vet`, `go test` green —
252 passed, 0 failed, 8 packages — and `internal/api/api.gen.go` byte-identical
to what `openapi/v1.yaml` generates. The 13 skips are the live Redis tier
(`GATEWAY_REDIS_URL` unset), counted and reported by the gate as designed.

## Successor's first move

Push the `0.1.0` image tag (or appVersion) when the first release cuts, then
re-run the plain `kubectl apply --dry-run=client` against a real cluster —
the offline endpoint here proves the documents parse, not that they satisfy
the schema. Then L10 (`caf gen chart`) has its specification: the
values.yaml → manifest table in `CHANGELOG.md` and the chart itself.
