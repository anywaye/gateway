# REPORT — roll/c5-image-digest: a fixed image never reaches a box that already ran

**Worktrees:** this directory (`cafaye/gateway`, branch `roll/c5-image-digest`:
`718cd73` "the chart pins the image by sha256 …", then `443ac95` the
digest-correction commit, then the commit that lands this report) and
`~/Code/any/moon/wt/roll-c5-image-digest-kit` (`cafaye/kit`, same branch:
`6f4d5f0` "digest: publish pins the image by digest in the chart it pushes",
then `0732597` the gate assertions the successor added, §8).

**Status:** both halves committed. Gateway gate (`bin/prime`, which is
`bin/prime-go` now that `src/` is gone) green on the real tree; kit's focused
publish proof and its gate's `publish seam` check green; the red controls
proven red against the REAL gate binaries, not a stand-in — including the five
the successor added so the kit half is asserted and not merely reviewed (§8).

---

## 1. The seam

`ghcr.io/cafaye/gateway:0.1.0` is a **release constant that is overwritten on
every master push**: `publish.reusable.yml` reads `Chart.yaml`'s `appVersion`
and hands it to the image build, and `publish.yml` runs on `push: branches:
[master]`. A mutable release tag is `latest` with a better-sounding name.

The chart named the image by that tag (`repository:tag`), so a new build rendered
a **textually identical** Deployment. Argo CD's diff is textual: a refresh
reported `Synced` with no rollout, and `imagePullPolicy: IfNotPresent` re-served
the node's stale copy on every pod restart. Nothing in the pipeline could close
the gap — the defect applies to all four services.

The fix names the image by something that **cannot move**: the manifest digest.
The Deployment renders `repository@digest`, so a build is a textual diff Argo
will sync.

## 2. The evidence, as measured (live)

Quoted from the brief, and re-verified against the registry during this run:

```
                brief (registry): ghcr.io/cafaye/gateway:0.1.0 → sha256:c26470504877625458a0f2d2b56fcac4a8801db28f3068627d3394df5c237165
                brief (node):     ghcr.io/cafaye/gateway:0.1.0 → sha256:8e6059b0129c100614375e460cb447b48b4ed1e9a13ded5bd771f929585e79b6
```

Two different digests for one tag; the node six hours behind. Running
`docker buildx imagetools inspect` on the current registry here, the tag
**moved again** since the brief was written:

```
$ docker buildx imagetools inspect ghcr.io/cafaye/gateway:0.1.0
Name:      ghcr.io/cafaye/gateway:0.1.0
MediaType: application/vnd.oci.image.index.v1+json
Digest:    sha256:9edaa9ce56ad12add32c67632ca8d23c6642c265308a404c7152ca90f1f5e3b1
```

and the image's own `org.opencontainers.image.revision` label names the commit
each digest was built from:

```
c26470504877625458a0f2d2b56fcac4a8801db28f3068627d3394df5c237165 → revision d7d8a68   (the brief's registry image)
9edaa9ce56ad12add32c67632ca8d23c6642c265308a404c7152ca90f1f5e3b1 → revision f8a5caa   (what 0.1.0 resolves to now)
8e6059b0129c100614375e460cb447b48b4ed1e9a13ded5bd771f929585e79b6 → revision f3f6cad   (the node, from 2026-10-13T14:49Z)
```

So between the brief and this commit the tag moved a **second** time
(`d7d8a68 → f8a5caa`) and nothing but a manual re-resolve noticed. That is the
defect, demonstrated a second time in its own packet. It is why the fix is not
"bump the digest by hand every merge" (the brief already forbids that).

Re-verified by the successor's run, after the kit half was finished: the same
command still resolves `ghcr.io/cafaye/gateway:0.1.0` to
`sha256:9edaa9ce…e3b1`, so the committed `charts/gateway/values.yaml`
`image.digest` and the registry's tag agreed at the moment the gate in §4 ran.
That is the one live comparison the brief's DoD asks for, read off the
registry rather than copied from the chart.

## 3. What changed

### Gateway (this worktree)

| file | change |
|---|---|
| `charts/gateway/values.yaml` | `image.digest` added — `sha256:9edaa9ce…e3b1`, the digest `0.1.0` resolved to at commit time — with the measured evidence and the rule for who writes it. `image.tag` stays, equal to `appVersion`, as the operator-readable half. |
| `charts/gateway/templates/deployment.yaml` | the container image is `{{ .Values.image.repository }}@{{ .Values.image.digest }}`. `pullPolicy` unchanged (`IfNotPresent`) — the digest already names the bytes. |
| `bin/prime-go` | the chart check now also refuses an `image.digest` that is empty or not `sha256:<64 lowercase hex>`, the way it already refuses a hostless `image.repository`. |
| `bin/chart-test` (section 4) | renders the committed digest; proves a **changed** digest changes the rendered Deployment text (the case Argo's diff reads); refuses an absent digest *before* asserting on it; renders the empty/malformed shapes as the refusal describes. |
| `charts/gateway/Chart.yaml` | a comment recording that the tag is the human half and the digest is the reference. |
| `CHANGELOG.md` | the change and the evidence. |

### Kit (`roll-c5-image-digest-kit`)

| file | change |
|---|---|
| `chart.reusable.yml` | a new `image-digest` workflow-call input, and a `pin the image by digest` step that writes it into the chart's `values.yaml` as `image.digest` **before `helm package`** (a package is a tarball of the directory, so an edit afterwards pins nothing). It replaces a committed `digest:` line (refusing a file with two), inserts one for a chart that has not adopted the field, and notes-and-skips a chart with no `image:` block. A malformed digest is refused, not written. |
| `publish.reusable.yml` | the chart job now `needs: [resolve, image]` and passes `needs.image.outputs.digest` down. The chart **version** is untouched, so every Application's `targetRevision: 0.1.0` still resolves — the chart's **content** changes under a fixed tag and the diff fires. |
| `tests/publish_seam_check.sh` | section 3b + five red controls (successor, `0732597`): the digest output, the derived hand-off, the writing step located by what it does, ordered before `helm package`, refusing a malformed digest and skipping on empty. See §8. |
| `tests/validate.sh` | the `publish seam` check's label and comments name the digest assertions (the check itself is unchanged — single source of truth stays in `publish_seam_check.sh`). |
| `CHANGELOG.md` | the digest change, the residue, and the four controls. |

The `image.tag`/`appVersion` seam and the `image.repository` registry-host seam
are both untouched (see §5).

## 4. The proof

### Green, real tree

```
$ ./bin/prime-go
chart image: charts/gateway/values.yaml sets image.repository to ghcr.io/cafaye/gateway, the image the publish workflow pushes
chart image: charts/gateway/values.yaml pins image.digest sha256:9edaa9ce56ad12add32c67632ca8d23c6642c265308a404c7152ca90f1f5e3b1 — immutable, so a new build is a textual diff Argo rolls
…
suite: 272 passed, 0 failed
packages: 8 with tests
==> ok      (exit 0)

$ ./bin/chart-test
== 4. the Deployment pulls the image the publish loop pushes, NAMED BY DIGEST
ok   - values.yaml names image.digest sha256:9edaa9ce…e3b1
ok   - the container image is the published repository at the committed digest
ok   - the container image is NOT named by the mutable tag
ok   - a changed digest changes the rendered image (the diff Argo reads)
ok   - the committed digest is gone from the changed render
…
== chart test ok
```

The changed-digest assertion is the one that matters: the rendered Deployment
text differs, which is what Argo's diff reads and what it never saw before.

### The two digests compared (independent verification)

```
registry, now:  docker buildx imagetools inspect ghcr.io/cafaye/gateway:0.1.0 → sha256:9edaa9ce56ad12add32c67632ca8d23c6642c265308a404c7152ca90f1f5e3b1
chart, now:     charts/gateway/values.yaml image.digest                 → sha256:9edaa9ce56ad12add32c67632ca8d23c6642c265308a404c7152ca90f1f5e3b1
```

They match. The brief's independent check is "after publishing, compare the
registry tag's digest against the digest named by the pushed chart"; on the
**pushed** chart the two are equal by construction (the same image job's output
supplies both), and this commits the same equality for the checked-out chart.
The digest is a real, pullable artifact — `imagetools inspect
ghcr.io/cafaye/gateway@sha256:9edaa9ce…e3b1` resolves — not a literal.

### Red controls, against the real gates

The controls were not written for the report; they are `bin/prime-go`'s own
check and `bin/chart-test`'s own section, driven red on planted values and then
reverted:

```
# malformed digest (exactly the value the previous attempt had committed):
bin/prime-go: charts/gateway/values.yaml sets image.digest to "sha256:c26470504927…37165", which
  is not sha256:<64 hex> …                                                  exit 1

# empty digest:
bin/prime-go: charts/gateway/values.yaml sets no image.digest, and the Deployment renders
  its container image from exactly that value …                             exit 1

# absent digest, at the render level (bin/chart-test):
FAIL - values.yaml names no image.digest — the Deployment would render 'ghcr.io/cafaye/gateway@',
       a reference no registry answers                                              exit 1
```

A check that passes because the field is absent is worse than no check, so the
absence is refused **before** any assertion could match the broken render
(`image: "ghcr.io/cafaye/gateway@"`).

### Kit's own gate, after touching `publish.reusable.yml`

Both the static phase of `bash tests/validate.sh` and the focused publish proof
run green on the kit tree, and the publish seam check asserted **this** gateway
worktree's chart as one of the sibling checkouts beside kit:

```
$ bash tests/validate.sh --static-only        exit 0
PASS chart publish  (workflow_call, push defaults false, registry + chart == every service
                     Application repoURL, name/version not inputs, pull_request refused)
PASS publish seam   (local uses root-relative and resolving; caller/callee inputs agree both
                     ways; appVersion derived into the image tag; sha-<40> kept; sibling
                     charts agree with their Applications)
      publish seam: note: gateway: 3 sibling checkouts … carry a chart named 'gateway'
                     … every one is asserted, and the files are: …/roll-c5-image-digest/charts/gateway

$ bash tests/focused_publish.sh               exit 0
FOCUSED=publish  pass=1 … (same files the gate calls, all red controls red)
seam: 4 of 4 service Application(s) matched a sibling chart beside …; local uses root-relative
      and resolving; caller/callee inputs agree both ways; appVersion derived into the image tag
```

`publish.seam`'s appVersion refusal, the `targetRevision` agreement and the
root-relative `uses:` tripwire all still hold with the new `image-digest` input
added, in both directions.

**The successor extended this section's own check** — §8 — so the `publish
seam` summary above is the pre-extension one; it now ends "… sha-<40> kept;
image digest derived from the image job, written before helm package, refused
when malformed", with five more red controls.

### What the previous attempt left, and what was wrong with it

The worktree carried a committed gateway `718cd73` and a committed kit `6f4d5f0`.
Both were kept — the structure, the gate hooks and the kit workflow are correct.
One thing was **broken**: the digest committed in `charts/gateway/values.yaml`
was **65 hex characters**, one longer than the brief's `c264…37165`, so
`bin/prime-go`'s own new check refused it (exit 1) — the tree was committed
**red**, and `bin/chart-test` passed only because it read the digest without
validating its shape. This commit replaces it with the digest the registry
actually resolves `0.1.0` to now, and quotes the corrected values throughout.

## 5. The seams that must not move (unchanged)

- **`image.tag` == `appVersion`.** `0.1.0` in both `values.yaml` and
  `Chart.yaml`; kit's publish seam asserts the pair. `chart.reusable.yml` does
  not rewrite name or version.
- **`image.repository` carries the registry host.** `ghcr.io/cafaye/gateway`,
  asserted by `bin/prime-go` and `bin/chart-test` (the Docker Hub trap).
- **`targetRevision` == chart `version`.** `0.1.0`; untouched, so the
  Application resolves the same OCI tag.

## 6. The residual, stated

The chart's OCI tag `0.1.0` is **still overwritten on every push**. What changed
is that the chart's **content** now changes too (the digest inside it), so a
refresh of the Application produces a non-empty diff and Argo rolls the
Deployment. If Argo, under a fixed `targetRevision`, failed to notice a change
in the chart's OCI content, that would be the finding to report — it is not
papered over here. The chart's committed digest ages as the tag moves; the
publish run overwrites it with the digest it just built, which is why this is a
floor and not a field anyone hand-maintains.

## 7. The one Argo command a manager runs

After the kit and gateway changes are on master and the publish run has pushed
the new chart, force a hard refresh of the Application — this re-resolves the
OCI chart, and the changed content (the new `image.digest`) is what produces the
diff:

```sh
kubectl -n argocd patch application gateway --type merge \
  -p '{"metadata":{"annotations":{"argocd.argoproj.io/refresh":"hard"}}}'
```

Then confirm the box rolled to the digest the chart names:

```sh
kubectl -n cafaye get deploy gateway -o jsonpath='{.spec.template.spec.containers[0].image}{"\n"}'
# expect: ghcr.io/cafaye/gateway@sha256:<the digest in the pushed chart>
kubectl -n cafaye get pods -l app.kubernetes.io/name=gateway
```

Before the fix this first command reported `Synced` with no diff; after it, a
new ReplicaSet is created because the pod template's image string changed.

## 8. The kit half is asserted now, not merely reviewed (the successor's move)

The commit `6f4d5f0` added the `pin the image by digest` step and the
`needs.image.outputs.digest` hand-off, and **nothing in kit's gate looked at
either**: a later edit that deleted the step, moved it after `helm package` (a
package is a tarball of the directory, so that pins nothing), or dropped the
hand-off would have shipped green. That was this report's own §8, and `0732597`
closes it in `tests/publish_seam_check.sh`, in the file's existing idiom
(comments stripped before reading, facts derived rather than typed, one checker
program run by the real tree and by every fixture).

What is now asserted, and the red control that proves each assertion measures
something:

| assertion | red control |
|---|---|
| `image.reusable.yml` declares the `digest` workflow_call output the chart's `image.digest` derives from | **(i)** the output deleted — GitHub resolves `needs.image.outputs.digest` to empty rather than failing, so the chart pins its committed digest forever |
| `publish.reusable.yml`'s chart job passes `image-digest` as `needs.<job>.outputs.digest`, and `needs:` the image job | **(e)** the `image-digest: ${{ needs.image.outputs.digest }}` line deleted |
| `chart.reusable.yml` has a step that writes `values.yaml`'s `image.digest` | **(f)** that step deleted (through the YAML, so a comment cannot satisfy it) |
| that step sits **before** `helm package` | **(g)** the step moved after `helm package` — present, but pins nothing |
| that step refuses anything but `sha256:<64 hex>` and skips on an empty input | **(h)** its refusal weakened to `sha256:` |

Proven, with the transcript:

```
$ bash tests/publish_seam_check.sh <workflows> <apps> <fleet> <template>
…
seam: 4 of 4 service Application(s) matched a sibling chart beside …; local uses
      root-relative and resolving; caller/callee inputs agree both ways; appVersion
      derived into the image tag; sha-<40> kept; image digest derived from the image
      job, written before helm package, refused when malformed
publish seam: all nine red controls went red (unresolved path; literal tag; values
      pinning an unpublished tag; sha tag deleted; digest hand-off removed; pin step
      deleted; pin step reordered after pack; digest grammar weakened; digest output
      deleted)                                                              exit 0

$ bash tests/focused_publish.sh                                             exit 0
$ bash tests/validate.sh --only='publish seam'                              exit 0
note: FILTERED run -- 1 check(s) ran, 41 excluded by --only='publish seam'.
```

The five new controls are the packet's own rule — *a check that passes because
the field is absent is worse than no check* — applied to the half that was left
to review. The gateway half (`bin/prime-go`'s empty/malformed refusals plus
`bin/chart-test`'s render-level controls) is unchanged from §4.

**Kit's full gate ran, green.** `bash tests/validate.sh` with no filter, on the
final tree, exit 0 — `PASS: every check passed`, 8 checks skipped (named, never
hidden), 5 tiers run under a bound, none reached. So the kit half is not merely
"the focused proof passed"; the whole gate did. (A first full-gate invocation
was discarded rather than reported: the gate files were being edited while it
ran, and bash re-reading a shifting script printed a syntax error — the honest
move was to re-run it clean, which is the run quoted here.)
