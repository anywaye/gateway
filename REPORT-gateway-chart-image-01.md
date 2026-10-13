# REPORT — gateway's chart named an image with no registry host

Packet: `roll-c5-gw-image` (branch `roll/c5-gw-image`, worktree
`wt/roll-c5-gw-image`). One hour, four quarters. This is the completion report;
the packet is done, not handed on.

---

## 1. The measured failure, restated

A gateway pod on a Contabo box reached image-pull and failed forever:

```
Warning  Failed  spec.containers{gateway}: Failed to pull image "cafaye/gateway:0.1.0":
failed to pull and unpack image "docker.io/cafaye/gateway:0.1.0": ... pull access denied,
repository does not exist or may require authorization
```

`charts/gateway/values.yaml` said `image.repository: cafaye/gateway`, and
`charts/gateway/templates/deployment.yaml` renders
`"{{ .Values.image.repository }}:{{ .Values.image.tag }}"`. A repository value
with no registry host is resolved by containerd against Docker Hub, so the pod
asked for `docker.io/cafaye/gateway` — not ours.

## 2. The sweep — every `cafaye/gateway` without a host, classified

`grep -rn 'cafaye/gateway'` across the tree (excluding `.git`, `node_modules`),
minus the Go import path `github.com/cafaye/gateway/…` (the module path, correct)
and minus `REPORT-*.md`/`HANDOFF-*.md`/`CHANGELOG.md` (history):

| Hit | What it is | Action |
| --- | --- | --- |
| `charts/gateway/values.yaml:39` | **`image.repository: cafaye/gateway`** — the bug | **FIXED** → `ghcr.io/cafaye/gateway` |
| `docker-compose.yml:197` | `image: cafaye/gateway:dev`, beside a `build:` context | kept — a LOCAL tag `docker compose build` writes, never pulled. Identity's compose does the same (`cafaye/identity:dev`) |
| `Dockerfile:4,156` | comments showing `docker build -t cafaye/gateway:dev` | kept — local build example |
| `.github/workflows/ci.yml:497–535` | the `image` job creating `cafaye/gateway:dev` after `docker compose build` | kept — the local tag |
| `openapi/v1.yaml:268,281` | `info.license` naming "the cafaye/gateway repository" | kept — repo name, not an image |
| `cafaye.yml:183` | `url: git@github.com:cafaye/gateway.git` | kept — repo URL |
| `kit.ref:5` | prose about `git clone cafaye/gateway` | kept |
| `README.md:1522–1523` | `docker build -t cafaye/gateway:dev` / `docker run …` | kept — local |
| `CHANGELOG.md`, `REPORT-*.md` | history | kept |

**The chart was the only place the published name appeared without its host.**
Every remaining bare hit is a local, never-pulled tag or a non-image reference.

Sibling charts read read-only to confirm the convention, all at
`<svc>/chart/values.yaml` with the same shape:

```
identity:  repository: ghcr.io/cafaye/identity   tag: "0.1.0"
pantry:    repository: ghcr.io/cafaye/pantry     tag: "0.1.0"
parlor:    repository: ghcr.io/cafaye/parlor     tag: "0.1.0"
courier:   repository: ghcr.io/cafaye/courier    tag: "0.1.0"
```

and kit's `image.reusable.yml` derives the name from `ghcr.io/<github.repository>`
(never an input), while `publish.reusable.yml` reads `appVersion` from the chart
and passes it to the image build as the tag.

## 3. The fix

`charts/gateway/values.yaml`:

```diff
-  repository: cafaye/gateway
+  repository: ghcr.io/cafaye/gateway
```

The `tag` is unchanged (`"0.1.0"` = `Chart.yaml`'s `appVersion`; the tag
convention is a sibling's to own). The comment above the value now records the
measured pull failure and why the host is load-bearing, and that
`docker-compose.yml`'s `cafaye/gateway:dev` is the local image.

## 4. The check, and its red control

Two halves, because the repo has two places a chart fact can be checked:

**The gate (`bin/prime` → `bin/prime-go`).** A new step, "the chart names the
image the publish loop pushes", sits beside the publish-caller step. It:

1. derives the published path from `go.mod`'s module path —
   `github.com/cafaye/gateway` → `ghcr.io/cafaye/gateway` — rather than typing a
   literal, because kit's image workflow derives the name from the repository
   and a literal would be a second copy of a fact the repository already states;
2. fails if `image.repository` has no registry host, naming Docker Hub
   (`"cafaye/gateway" is docker.io/cafaye/gateway`), because a first segment
   with no `.`/`:` is a Docker Hub namespace and not a host;
3. fails if the value does not equal the derived published path.

**The chart-render step (`bin/chart-test`).** The repo already has a
`helm template` step, deliberately outside `bin/prime` (it needs `helm`). It
gains a section asserting the rendered Deployment's container image equals
`<published>:<appVersion>`, with a control that renders a hostless
`--set image.repository=cafaye/gateway` and checks the published path is absent.
This is the only place a template that ignored the value could be caught.

**Red control — the host stripped from `charts/gateway/values.yaml`:**

```
$ sed -i '' 's|repository: ghcr.io/cafaye/gateway|repository: cafaye/gateway|' charts/gateway/values.yaml
$ ./bin/prime-go ; echo "exit: $?"
...
==> the chart names the image the publish loop pushes
bin/prime-go: charts/gateway/values.yaml sets image.repository to "cafaye/gateway", which
  carries no registry host. containerd resolves a hostless value against
  Docker Hub — "cafaye/gateway" is docker.io/cafaye/gateway, not the image the
  publish workflow pushes — and the pod reaches image-pull and fails
  forever with 'pull access denied, repository does not exist'.
  The published path is ghcr.io/cafaye/gateway (ghcr.io/<github.repository>).
exit: 1

$ ./bin/chart-test ; echo "exit: $?"
== 4. the Deployment pulls the image the publish loop pushes
ok   - helm template renders the Deployment
FAIL - the container image is the published path at the chart's appVersion — wanted: image: "ghcr.io/cafaye/gateway:0.1.0"
...
== chart test: 1 failure(s)
exit: 1
```

Both reverted; `git status` clean after restore.

`gate.yml` declares the new step as the `chart-image` proof (7 of the schema's 8
slots), and the header's measured-output list and proof table are updated with
it.

## 5. Gate output

Command (the repo's stated gate):

```
$ ./bin/prime
...
==> the publish caller publishes the image and the chart
publish: .github/workflows/publish.yml calls kit's composed publish workflow with push: true, grants packages: write, and points at charts/gateway/ — whose Chart.yaml version 0.1.0 is the substrate's targetRevision 0.1.0
==> the chart names the image the publish loop pushes
chart image: charts/gateway/values.yaml sets image.repository to ghcr.io/cafaye/gateway, the image the publish workflow pushes
==> gofmt -l
...
ratelimit: DID NOT RUN — GATEWAY_REDIS_URL is unset. …
skips: 13 of 13 declared (all of them the live Redis tier), and 1 t.Skip() call site
==> the generated server matches the OpenAPI document
internal/api/api.gen.go regenerates byte-identically from openapi/v1.yaml, carries the v2.8.0 header, and its registrations are readable
suite: 265 passed, 0 failed
packages: 8 with tests
==> ok

== prime ok
exit: 0
```

And the gate declaration proves itself:

```
$ (cd cafaye/core && python3 harness/gate_check.py --prove --log-dir /tmp/… /Users/kaka/Code/any/moon/wt/roll-c5-gw-image)
OK …: 0 failure(s), 2 warning(s) — warnings do not move the exit code
exit: 0
```

The two warnings are the pre-existing `gate.requirement-unproven` ones on the
`go` and `network` requirements; the checker cannot run a bare `go` command and
says so. `bin/chart-test` also exits 0 on the committed values.

## 6. Commits

```
580f533 docs: record the chart image fix and the check that holds it
62d7459 gate: fail when the chart's image.repository loses the registry host
37b35a1 chart: image.repository carries the registry host (ghcr.io/cafaye/gateway)
```

Nothing pushed, nothing merged.

## 7. What I deliberately did NOT do

- **Did not change the image tag.** `image.tag` stays `"0.1.0"` = `Chart.yaml`'s
  `appVersion`; the appVersion/tag pairing is a sibling's convention to own.
- **Did not touch the local `cafaye/gateway:dev` tags** in `docker-compose.yml`,
  the `Dockerfile` comments, `ci.yml`'s `image` job, or the README's build
  example. They are local tags written by `docker compose build`, never pulled,
  and the sibling services' compose files use the same bare form.
- **Did not rewrite the README's stale CI section** (it still describes the
  deleted Bun jobs) or the `bin/prime` TypeScript-era prose — separate packets.
- **Did not correct `gate.yml`'s header line `suite: 252 passed`** to today's
  measured `265`. It is a pre-existing drift (no Go test was added by this
  packet) and unrelated to the chart; recorded here rather than edited.
- **Did not change the publish caller** (`publish.yml`) or the chart version.
- **Did not touch `cafaye/kit` or any other repo**, and spawned no agent.
