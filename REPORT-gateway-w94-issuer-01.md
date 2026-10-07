# REPORT — the Ingress gets a certificate: the issuer annotation, and what else diverges

**Packet:** gateway-w94-issuer. **Base commit:** `c68faa8` (merge of
worker/gateway-w87-one-application). **Branch:** `worker/gateway-w94-issuer`.
**Outcome:** done — the issuer annotation landed through a value, the chart
test W67 recorded by hand now exists as `bin/chart-test`, the divergence
report is below, CHANGELOG and README-adjacent docs updated; gate green.

## What the packet is for

gateway's chart is the only hand-written chart in the fleet (W67). It turns
its Ingress on with `host: gateway.cafaye.com` and
`ingress.tls.secretName: gateway-tls`, but it emitted **no
`cert-manager.io/cluster-issuer` annotation** — measured:

```
$ grep -nE 'clusterIssuer|cluster-issuer|letsencrypt' charts/gateway/templates/ingress.yaml charts/gateway/values.yaml
# -> nothing
```

So `gateway-tls` was a secret nothing filled. That is launch item B7 ("no TLS
anywhere in the stack… real sign-in requires an HTTPS terminator"), and
gateway is the front door whose session cookie is `Secure` — without it the
browser surface cannot work at all. W67 wrote the chart before W83 landed the
ClusterIssuers; the generated charts are now ahead of it (`caf gen chart`
emits `ingress.clusterIssuer` and renders the annotation from it).

## What landed

| file | what it is |
|---|---|
| `charts/gateway/values.yaml` | `ingress.clusterIssuer: letsencrypt-prod`, beside `className`/`host`/`tls`, with the generator's rule at the line: rendered only when non-empty — empty means no cert-manager, a secret nothing writes |
| `charts/gateway/templates/ingress.yaml` | the `cert-manager.io/cluster-issuer` annotation, only when the value is non-empty and the operator has not set the same key in `ingress.annotations` (a duplicate annotation key is invalid YAML, so an explicit operator value wins) |
| `bin/chart-test` | **new.** The chart test W67 recorded by hand in `REPORT-gateway-chart-01.md` ("The render, recorded exactly") and this packet makes continuous. Deliberately not wired into `bin/prime`: the gate is static Go with a port-probe test, and a chart test needs `helm` — W67's report ruled the render "a separate, bounded command" and the manager owns the gate |
| `CHANGELOG.md` | the fix, and the divergences left for the manager |
| `REPORT-gateway-w94-issuer-01.md` | this report |

Everything hand-written was kept: `configmap.yaml` and `_helpers.tpl` are
untouched, and this is not a regenerate-the-chart packet.

## The proof, red then green

`bin/chart-test` asserts: (1) committed values render the Ingress with
`cert-manager.io/cluster-issuer: letsencrypt-prod` and the existing
`tls.secretName: gateway-tls`; (2) **the control that must go red** — with
`ingress.clusterIssuer: ""` the annotation is absent and the Ingress still
renders; (3) the operator `ingress.annotations` map still works and does not
collide; (4) `helm lint` passes.

Red on the unfixed chart (commit `0e2bcd4`, before the fix):

```
== 1. committed values — the Ingress carries the issuer annotation (B7)
FAIL - cert-manager.io/cluster-issuer: letsencrypt-prod is set — wanted: …
== 3. the operator annotations map still works, and does not collide
FAIL - the issuer annotation renders beside it — wanted: …
== chart test: 2 failure(s)        # exit 1
```

The control (check 2) passes pre-fix because there is no issuer logic to
bypass — its job is to catch a *hardcoded* annotation, which is the wrong fix.
Green after the fix (commit `4a82004`):

```
$ ./bin/chart-test
== chart test ok                  # exit 0
```

and the packet's own command, with the committed values and no `--set`:

```
$ helm template gateway ./charts/gateway | grep -B2 -A2 'cert-manager.io/cluster-issuer'
    # key is invalid YAML, so an explicit operator value wins.
    cert-manager.io/cluster-issuer: letsencrypt-prod
spec:
  ingressClassName: traefik
```

## The divergences, measured

Generator built at dispatch per the packet (`cd ../caf && mise exec -- go build
-o /tmp/caf-gen-w94 ./cmd/caf`), run in a scratch dir against gateway's
`cafaye.yml` — nothing written into gateway's tree. The generated chart has
seven files; gateway's has five. Full diff was read; the list is every place
they differ, with a verdict on whether it matters.

### The values keys

| # | gateway (hand-written) | generator | verdict |
|---|---|---|---|
| 1 | `secrets.redisUrlSecretName` + `secrets.redisUrlSecretKey` | `secretName: gateway-secrets` | **matters** — see below |
| 2 | `replicaCount: 1` | `replicas: 1` | matters — L10 drift, one word |
| 3 | `probes.liveness.*` + `probes.readiness.*` | `readinessProbe.*` only | matters — the generator's chart deploys gateway with **no liveness probe** |
| 4 | `ingress.tls.enabled` + `ingress.tls.secretName` | `ingress.tls: true`, `secretName: gateway-tls` hardcoded in the template | matters mildly — gateway's secret name is a value; the generator's is baked in |
| 5 | `ingress.annotations: {}` | — (no equivalent) | matters — operator extensibility the generator does not know about |
| 6 | `ingress.clusterIssuer` — **was missing**, now `letsencrypt-prod` | `clusterIssuer: ""` | **was the defect** — fixed; the defaults differ deliberately (gateway's is the launch issuer, the generator's is empty-by-default) |
| 7 | `env` → ConfigMap + `envFrom configMapRef` | `env` → Deployment `env:` entries | matters — same key, different mechanism (see #1) |
| 8 | `ingress.path` / `ingress.pathType` values | — | gateway hardcodes `/` / `Prefix` in the template, violating its own rule that "nothing in the templates is a hand-typed constant a generator could not emit" |
| 9 | — | `imagePullSecrets: gateway-ghcr` | **matters on the box** — see below |
| 10 | `image.repository: cafaye/gateway` | `image.repository: ghcr.io/cafaye/gateway` | **matters on the box** — see below |
| 11 | — | `targetRevision: master`, `namespace: gateway` | does not matter — these belong to the `Application`, which is kit's (W87); W88 stops the generator emitting it |
| 12 | `resources.limits.memory: 256Mi` | `512Mi` | does not matter — both are stated starting points |
| 13 | `service.port: 8080` | `service.port: 80` (Service) with `containerPort: 8080` from the language table | does not matter — gateway's is correct for this service (`PORT=8080`); the generator's 80 is its default, forwarded to the named `http` port |

**#1 is the packet's named divergence, and it is structural, not cosmetic.**
gateway's chart splits the environment in two: the clear env (eight keys) is
a ConfigMap the Deployment reads with `envFrom configMapRef`, and the one
secret value (`REDIS_URL`) is a **required `secretKeyRef`** — no secret, no
pod, so a deployment cannot forget Redis (W67's whole reason for the shape).
The generator reads the *whole* secret with `envFrom secretRef` and has no
ConfigMap at all. The two models cannot be reconciled by renaming a key: the
generator cannot reproduce gateway's chart as written, and that is L10's
specification gap to close, not gateway's to paper over.

**#9 and #10 matter on the box and the packet did not ask about them.**
`DEPLOYMENT.md`: charts ship from the private OCI registry (GHCR) with a
read-only pull secret on the box. The generated chart names that pull secret
(`imagePullSecrets: gateway-ghcr`) and points the image at
`ghcr.io/cafaye/gateway`. gateway's chart does neither: it names no pull
secret and its `image.repository` is `cafaye/gateway` — Docker Hub-shaped. A
pod scheduled on the box would try Docker Hub and fail to pull. Reported, not
fixed: the packet's scope is the Ingress, and the image registry is a
substrate decision (the `0.1.0` tag does not exist anywhere yet — W67's known
gap 1).

### The templates

| # | divergence | verdict |
|---|---|---|
| 14 | `_helpers.tpl` exists only in gateway's chart; the generator hardcodes `gateway` as every resource name | does not matter — gateway's release name *is* `gateway` (the Argo `Application`'s name), so the helper resolves to the same string; the helper is what keeps the chart reusable under another release name |
| 15 | `configmap.yaml` exists only in gateway's chart | does not matter — it is #1/#7, the deliberate ConfigMap split |
| 16 | `application.yaml` exists only in the generated chart | does not matter — gateway's copy was deleted in W87, correctly (kit owns the `Application`); W88 stops the generator emitting it |
| 17 | **no chart `README.md`** | **matters mildly** — the packet names it. The generated README documents the loop (push a values commit, Argo syncs, hand edits self-heal, rollback is `git revert`), the `helm push` to GHCR, the secrets and the `/readyz` contract. gateway's chart carries the same information in `values.yaml`'s header comments and the repository README — but the chart ships to GHCR and stands alone there; whoever pulls it gets no README |
| 18 | **no `fail`-when-enabled-without-host guard** | **matters** — the packet names it. The generator's Ingress opens with `{{- if not .Values.ingress.host }}{{- fail … }}{{- end }}`: an enabled Ingress with no host is a silent misroute, so the render refuses loudly. gateway's chart has no guard — an operator who clears `host` gets a broken Ingress instead of a failed render |
| 19 | tls block gated on `tls.enabled` alone | **matters mildly** — the generator gates on `tls AND clusterIssuer` ("TLS without an issuer is a secret nothing writes"). After this packet, gateway's chart with `clusterIssuer: ""` still renders the `tls` block naming `gateway-tls` — a secret nothing writes. The packet scoped the change to the annotation and its control asserts only that "the Ingress still renders" with an empty issuer, so this is reported, not changed |
| 20 | labels: gateway uses `_helpers.tpl` (`.Release.Service` → `Helm`, plus `app.kubernetes.io/version`); the generator hardcodes `app.kubernetes.io/managed-by: caf` | does not matter — cosmetic; both are valid label sets |
| 21 | `Chart.yaml`: gateway has a hand-written description and comments; the generator derives the description from the manifest and carries the `DO NOT EDIT` header | does not matter |

## Recommendations — for the manager, not implemented

1. **Keep the hand-written chart as the reference; feed this list to L10
   (`caf gen chart`) as the specification.** The chart encodes launch-specific
   decisions the generator cannot know (the ConfigMap split, the required
   `secretKeyRef`, the liveness probe, the host, the issuer default). The
   generator should learn the `secrets:` shape, the liveness probe and the
   `probes.*` naming — not the other way round.
2. **Cherry-pick the `fail` guard** (divergence 18) into `ingress.yaml`. It
   is one line and turns a silent misroute into a loud render failure. This
   packet did not add it because the packet scoped item 1 to the annotation.
3. **Decide the image repository and pull secret** (divergence 10/9). If
   the box pulls from GHCR, `image.repository` should be
   `ghcr.io/cafaye/gateway` and the chart should name `imagePullSecrets:
   gateway-ghcr` — both one-line changes when the first release cuts.
4. **Add a chart `README.md`** (divergence 17) — or explicitly accept the
   repository README as the chart's documentation and record that here.
5. **Decide the tls-block gating** (divergence 19): annotation-only (what
   this packet shipped) or the generator's stricter `tls AND issuer`.

## The gate

```
$ mise exec -- ./bin/prime        # background, exit captured
== prime ok                       # exit 0
```

gofmt clean, `go build`, `go vet`, `go test -count=1 -v ./...` — 8 packages,
all `ok` — and `internal/api/api.gen.go` byte-identical to what
`openapi/v1.yaml` generates. The chart tier is `./bin/chart-test`, green, as
a separate bounded command (above).

## Successor's first move

Whatever the manager decides from the recommendations: if the chart is
reconciled with the generator, re-run `bin/chart-test` after — its check 2
(the empty-issuer control) is the assertion that survives a regeneration,
because a regenerated template that hardcodes the annotation fails it. Then
parlor's chart ingress (`m93`) is the same defect one service over.
