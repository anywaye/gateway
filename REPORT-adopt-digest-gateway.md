# REPORT — adopt the image-digest pin in gateway's chart

**Repo:** `gateway`. **Branch:** `feat/digest-pin`. **Worktree:**
`/Users/kaka/Code/any/moon/wt/adopt-digest-gateway`. **Commit:**
`e601e6f` "digest: the image render is conditional — @digest when set, :tag
when not". **Gate:** green (`mise exec -- ./bin/prime`, exit 0, 276 passed,
0 failed). **Chart proof:** `./bin/chart-test`, 28 assertions green.

The brief is the fleet packet — one of seven repos "that never adopted the
template half". For `gateway` the premise is **stale**, and the first thing
this report has to do is say by how much, because it changes what the packet
is.

---

## 1. The finding that changes the packet: gateway already had the digest half

The brief says:

> The missing half is THIS repo: the Deployment template renders
> `{{ .Values.image.repository }}:{{ .Values.image.tag }}` and never reads
> `image.digest`, so even a digest-pinned chart renders an unchanged spec.

That is not the tree I was given. **Packet `roll-c5-image-digest` landed the
digest half in `gateway` and merged to master** (`73d1217 merge
roll-c5-image-digest`, commits `a8fc432`, `fb6b54f`; `REPORT-roll-c5-image-digest.md`).
At `HEAD^` the template already read:

```yaml
image: "{{ .Values.image.repository }}@{{ .Values.image.digest }}"
```

`values.yaml` already carried `image.digest`, `bin/prime-go` already refused an
empty or malformed one, and `bin/chart-test` section 4 already asserted the
digest render. So the *goal* — "a publish is a change Argo can SEE" — was
already bought for this repo: the composer writes a fresh digest, the template
renders it, Argo rolls. The live acceptance test would pass on `HEAD^`.

What `HEAD^` did **not** have, and what this packet is actually about, is the
**conditional**: `HEAD^` rendered `repository@digest` *unconditionally*. An
absent digest therefore rendered `repository@` — a reference no registry
answers — so the value could never be missing, not even on a chart that has not
published yet. Kit's step says out loud that this is a case it handles, in the
`INSERT` branch (§3 below): *"INSERT it, for a chart that has not adopted the
field yet."* Gateway could not receive that INSERT usefully, because the value
it would insert was only ever read as one arm.

So the delta this packet implements is exactly the delta the brief's items 1
and 3 ask for, and nothing more:

1. render `repository@digest` when a digest is present, `repository:tag` when
   it is not, and refuse a malformed one;
2. refresh the committed digest to the registry's current value;
3. assert **both** renders (and the refusal) in `bin/chart-test`.

The brief's framing ("never adopted the template half") is wrong for
`gateway`; its **change list is right**, and that is what I followed. Recorded
here so the manager is not surprised by a packet that looks smaller than its
siblings — gateway is not seven-of-seven behind, it is the one of the seven
that took the digest arm first and now takes the fallback.

---

## 2. The contract, quoted (`cafaye/kit/.github/workflows/chart.reusable.yml`)

The spec is kit's. The lines this packet followed, verbatim:

**§3, the digest seam — lines 58–76:**

> **3. THE IMAGE DIGEST — THE ONE THAT REACHES THE POD, AND THE ONE THAT WAS
> MEASURED MISSING.** … A DIGEST cannot move, so this workflow writes the
> digest of the image the compose run just built into the chart's
> `values.yaml` (`image.digest`) BEFORE `helm package`: the chart that lands in
> the OCI registry names the bytes the registry holds beside it, a new build is
> a textual diff Argo rolls, and the chart VERSION (seam 2) does not move — the
> substrate Application's targetRevision is untouched. The composer hands the
> digest down; see `publish.reusable.yml`, the only party that knows both ends.

**The step — "pin the image by digest", lines 290–302:**

> **WHO SUPPLIES THE VALUE:** the composer, from the image job's build output
> (`needs.image.outputs.digest`) — derived, never typed … An EMPTY input (a
> direct caller; or `push: false`, where nothing was pushed and there is no
> digest to read) skips this step and packages the chart as committed, which is
> what the committed digest in values.yaml is for.
>
> **IT REFUSES RATHER THAN WRITES A MALFORMED DIGEST:** a value that is not
> `sha256:<64 hex>` would render `repository@nonsense`, which looks like a pin
> and fails at image-pull with nothing naming this step.

**The refusal, exactly (lines 315–322):**

```sh
if ! printf '%s' "$IMAGE_DIGEST" | grep -qE '^sha256:[0-9a-f]{64}$'; then
  echo "chart: image-digest is '$IMAGE_DIGEST', not sha256:<64 hex>." >&2
  ...
  exit 1
fi
```

**The INSERT branch — the line that names the missing half (lines 348–351):**

```sh
else
  # INSERT it, for a chart that has not adopted the field yet: the
  # publish pins what the template can read, and a deployment that
  # does not render image.digest ignores a value it never reads.
  awk -v d="$IMAGE_DIGEST" '
    /^image:[[:space:]]*$/ { print; print "  digest: \"" d "\""; next }
    { print }
  ' "$values" >"$values.new"
```

This is why the fallback matters: kit will insert `image.digest` into a chart
that lacks it, and the chart must read it as one arm of a conditional rather
than interpolate `repository@` on the other.

**The contract section, verified: `publish.yml` does call the composer.** It is
`.github/workflows/publish.yml` in this repo:

```yaml
  publish:
    uses: cafaye/kit/.github/workflows/publish.reusable.yml@master
    with:
      push: true
      chart-dir: charts/gateway/
```

and the composer's `chart` job is where the digest is threaded
(`publish.reusable.yml:266–275`):

```yaml
    uses: ./.github/workflows/chart.reusable.yml
    with:
      ...
      image-digest: ${{ needs.image.outputs.digest }}
```

So `push: true` → image built → digest handed to `chart.reusable.yml` → written
into `charts/gateway/values.yaml` before `helm package`. **No workflow change
was needed**; the verification is the finding, and it holds.

---

## 3. The change

### `charts/gateway/templates/deployment.yaml`

The image line is now a three-way conditional. The `image:` comment was
rewritten to say why each arm exists (house voice; it names the measured
defect, the fallback, and the refusal):

```gotemplate
{{- $digest := .Values.image.digest | default "" }}
{{- if $digest }}
{{- if not (regexMatch "^sha256:[0-9a-f]{64}$" $digest) }}
{{- fail (printf "image.digest is %q, which is not sha256:<64 lowercase hex>. ..." $digest) }}
{{- end }}
image: "{{ .Values.image.repository }}@{{ $digest }}"
{{- else }}
image: "{{ .Values.image.repository }}:{{ .Values.image.tag }}"
{{- end }}
```

**The malformed behaviour is REFUSAL, and the reason is deliberate.** The brief
offers "absence-or-fail". I chose **fail**:

- *Absence is legitimate.* A chart that has not published, or a `push: false`
  direct render, has no digest — kit says so itself ("An EMPTY input … skips
  this step and packages the chart as committed"). That arm is the tag.
- *Malformation is never legitimate.* A non-empty value that is not
  `sha256:<64 hex>` is a pin that is not one. Rendering the tag for it would be
  a **silent** degradation to the mutable name — the exact class of defect this
  packet exists to close — and rendering the value would be
  `repository@nonsense`. Refusing the render and naming `image.digest` mirrors
  the kit step's own refusal (`chart.reusable.yml:315–322`) and `bin/prime-go`'s
  static refusal, which both already exist. A template cannot reject the value
  at the source, so it rejects the **render**.

### `charts/gateway/values.yaml`

The committed digest moves to the registry's current value and the `image:`
comment is updated around it:

```yaml
digest: "sha256:33f4773a2d10b3a2eaf046a5d80c5955a4743512845e68833f28735a889e164d"
```

**Verified against the registry, not pasted.** `docker buildx imagetools
inspect ghcr.io/cafaye/gateway:0.1.0` on this machine returned:

```
Name:      ghcr.io/cafaye/gateway:0.1.0
MediaType: application/vnd.oci.image.index.v1+json
Digest:    sha256:33f4773a2d10b3a2eaf046a5d80c5955a4743512845e68833f28735a889e164d
```

which is the brief's value exactly. The comment now says what writes the field
(`chart.reusable.yml`, from the image job's build output via
`publish.reusable.yml`), why it exists (a tag is mutable and was measured to
move; a digest cannot), and that this committed value is what a fresh clone and
a `push: false` run render. It also records that the **previous** committed
value (`sha256:9edaa9ce…`) had already been overwritten again between packets —
the defect restated by its own staleness.

### `bin/chart-test` (section 4)

Section 4 now asserts **both** renders and the refusal, plus the pre-existing
assertions (committed digest, changed digest, hostless control):

- committed digest → `image: "<published>@sha256:<committed>"`
- changed digest (`--set image.digest=sha256:<64 ones>`) → text changes
- **no digest (`--set image.digest=""`) → `image: "<published>:<appVersion>"`**,
  and NOT a bare `repository@`
- **malformed (`not-a-digest`, `sha256:abc`, a 64-char wrong-charset value) →
  the render FAILS and names `image.digest`** (three shapes, the three ways a
  digest goes wrong: not a digest, wrong length, wrong charset)

The section header, and the `note`, were rewritten to describe the two renders.

### `CHANGELOG.md`

One `### Changed` bullet under `[Unreleased]`, beside the `roll-c5-image-digest`
one, describing the conditional arm, the refusal, and the digest move.

### Nothing else

`image.repository`, `image.tag`, `pullPolicy`, `Chart.yaml`, `bin/prime-go`,
the workflows, and the Go app are untouched. `bin/prime-go`'s static refusal of
an empty/malformed committed digest stays: the committed value is the pin a
fresh clone renders, so it must be real, and the gate is the right place to say
so.

---

## 4. The two renders, as measured (and the refusal)

```
$ helm template gateway charts/gateway
          image: "ghcr.io/cafaye/gateway@sha256:33f4773a2d10b3a2eaf046a5d80c5955a4743512845e68833f28735a889e164d"

$ helm template gateway charts/gateway --set image.digest=""
          image: "ghcr.io/cafaye/gateway:0.1.0"

$ helm template gateway charts/gateway --set image.digest=nonsense
exit: 1
Error: execution error at (gateway/templates/deployment.yaml:57:14): image.digest is "nonsense", which is not sha256:<64 lowercase hex>. A malformed digest renders a reference no registry answers, so the chart refuses it the way the publish step does. Drop the key to render the committed tag, or set a real sha256 digest.
```

---

## 5. Red proofs (Q3)

Each mutation was planted in the real template, `./bin/chart-test` was run, and
the mutation was reverted with `git checkout`. The tree is clean after each.

**A — restore the pre-packet template (unconditional `repository@digest`).**
The fallback and every refusal assertion go red, because the empty digest
renders `repository@` and a malformed one renders `@not-a-digest`:

```
FAIL - no digest falls back to the committed tag — wanted: image: "ghcr.io/cafaye/gateway:0.1.0"
FAIL - no digest does NOT render a bare 'repository@' — unwanted: image: "ghcr.io/cafaye/gateway@"
FAIL - a malformed digest is refused — 'not-a-digest' rendered instead
FAIL - the refusal for 'not-a-digest' names image.digest
FAIL - a malformed digest is refused — 'sha256:abc' rendered instead
FAIL - the refusal for 'sha256:abc' names image.digest
FAIL - a malformed digest is refused — 'sha256:0000…z' rendered instead
FAIL - the refusal for 'sha256:0000…z' names image.digest
== chart test: 8 failure(s)
```

**B — break the digest arm (`@` → `:` in the digest render).** The render still
succeeds, so the assertions that the digest *names* the image go red:

```
FAIL - the container image is the published repository at the committed digest
FAIL - a changed digest changes the rendered image (the diff Argo reads)
FAIL - the control renders a hostless repository at the digest
== chart test: 3 failure(s)
```

**C — the fallback exists but does not use the committed tag (`:latest`).** The
tag-render assertion is the only one that catches it:

```
FAIL - no digest falls back to the committed tag — wanted: image: "ghcr.io/cafaye/gateway:0.1.0"
== chart test: 1 failure(s)
```

**A note on a fourth mutation that was rejected as a proof.** Setting the
regex to `{63}` makes *every* `helm template` fail, and `bin/chart-test`'s
`$(ingress_doc)` under `set -o pipefail` then aborts at section 1 before any
`bad` is recorded — exit 1, but with no assertion named. That is a red for the
wrong reason (the script dies at the first render, not at the digest
assertion), so it is recorded here and not counted as proof B.

---

## 6. Gate

```
$ mise exec -- ./bin/prime
...
suite: 276 passed, 0 failed
packages: 8 with tests
==> ok
== prime ok
exit: 0
```

Run on commit `e601e6f`, in the background, captured to
`/tmp/gate-adopt-digest-gateway.log` / `.exit`. The live-Redis tier reported
"13 of 13 declared skips" as `bin/prime-go` requires; the equivalence tier's
own gate handling is unchanged. `./bin/chart-test` (not in the gate — its
header says so, and the brief's item 4 forbids workflow changes) is green at 28
assertions and was run by hand as the chart proof.

No floor moved: the chart tests are a shell script, the Go suite is unchanged
at 276, and no counted test grew.

---

## 7. The live acceptance test

Manager pushes a trivial change → `publish.yml` runs → `publish.reusable.yml`
builds the image and hands `needs.image.outputs.digest` to
`chart.reusable.yml` → the `pin the image by digest` step **REPLACES** the
`digest:` line in `charts/gateway/values.yaml` (the REPLACE branch, since the
key is present) → `helm package` → `helm push` to
`oci://ghcr.io/cafaye/charts/gateway:0.1.0` → Argo's refresh sees a changed
rendered `image:` and rolls the Deployment, no human step. That is the first
unattended release, and gateway's template now reads both arms of the value the
composer writes.

**One honest caveat for the manager.** This packet *reverses* part of
`roll-c5-image-digest`'s deliberate choice. That packet accepted the
"I-render-`@`-and-refuse-absence-statically" design and, in
`bin/chart-test`'s own words, showed "an empty or malformed digest renders a
reference no registry answers". This packet replaces that loud broken render
with a fallback (absence) and a loud refusal (malformation), per the brief's
items 1 and 3 and per the fleet pattern the sibling worktrees
(`adopt-digest-website`) are implementing. If the manager would rather keep
`roll-c5-image-digest`'s no-fallback stance, the thing to revert is this commit
and the digest refresh should be split out — but then gateway is the only one
of the seven that does not follow the fleet's conditional template, and the
brief's "digest empty → `repository:tag`" assertion cannot exist.

---

## 8. Files touched

| File | Change |
|---|---|
| `charts/gateway/templates/deployment.yaml` | conditional image render; `fail` on malformed; comment rewritten |
| `charts/gateway/values.yaml` | committed digest → `sha256:33f4773a…`; `image:` comment updated |
| `bin/chart-test` | section 4: both renders + three malformed refusals; header/note rewritten |
| `CHANGELOG.md` | one `### Changed` bullet under `[Unreleased]` |
| `REPORT-adopt-digest-gateway.md` | this report |
