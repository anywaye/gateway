# REPORT — roll-c5-ci-tool-parity

**Packet:** gateway's Go suite runs in two CI jobs, and both were red on a
missing tool rather than on a defect. Fix both seams, and add a check that stops
the class recurring.

**Worker verdict:** both seams are closed in the trees; the class control is in
the gate and is proven non-vacuous; **the push-based independent verification is
NOT done, because the worker contract forbids pushing** (see §6). Everything
below that says "green" was measured locally, and I say where that stops.

---

## 1. The shape

Two jobs run gateway's Go tests, and each was missing a binary the other knew
about:

```
X ci (kit) / go     runtime_session_test.go: this test needs a real
                    `redis-server` on PATH and there is none ... executable
                    file not found in $PATH
X bin/prime         (exit code 127)     <- golangci-lint, never installed
```

Both are the same defect pointing the same way: **a step added a REQUIREMENT to
the gate, and the job that runs the gate was never taught to PROVIDE it.** One
was fixed in kit (the shared `go` job), one in gateway (its own `prime` job),
and the class is now caught by the gate itself.

Files touched:

| Repo | File | What |
|------|------|------|
| gateway | `.github/workflows/ci.yml` | `test-packages: redis-server` on the `ci (kit)` call; a pinned `golangci-lint` install in the `prime` job |
| gateway | `bin/prime-go` | new step: derive the tools the gate needs and assert CI installs them |
| kit | `.github/workflows/ci.reusable.yml` | new `test-packages` input + an install step before the `go` job's `test` |
| kit | `tests/validate.sh` | check that the `test-packages` seam is declared, opt-in, and installed *before* `test` |
| kit | `README.md` | the input documented in the workflow table and the adoption steps |

Commits, and **there are two kit variants — read §7.1 before acting**:

- gateway `a1fe4c5` — `ci: install redis-server and golangci-lint where the gate
  requires them, and fail naming the tool when absent` (this commit also bumps
  `kit.ref` to `fd383c9`; see §7.1)
- kit `fd383c9` — `ci: let a caller hand the Go job apt packages its tests exec`
  — **this is the variant on `kit@master`/`origin/master`**, pushed by the
  external manager, workflow-only
- kit `1f9804d` — `ci: a caller can name the apt packages its suite execs
  (test-packages)` — the branch `roll/c5-ci-tool-parity` in
  `/Users/kaka/Code/any/moon/wt/roll-c5-ci-tool-parity-kit`, which adds the
  README documentation and the `tests/validate.sh` durability check the pushed
  variant lacks (§7.1)

---

## 2. Seam one — kit's `go` job, and the general input behind it

`internal/httpapi/runtime_session_test.go` starts a real `redis-server` on a
free port by **executing the binary**, and `t.Fatalf`s when it is absent. That
refusal is deliberate (`startRedis`'s own header): the tier must not be able to
lie about having run, and "skip when Redis is missing" is the green-about-
nothing this repo keeps deleting. So the fix had to be "install the binary", not
"soften the test" — the brief's Do-NOT list says so and I agree with it.

kit gained the general seam the brief preferred over a bare `apt-get`:

```yaml
test-packages:
  description: >-
    Space-separated apt packages to install before the test step, for a suite
    that EXECS a binary the runner does not ship (e.g. 'redis-server') ...
  required: false
  type: string
  default: ''
```

and the Go job installs it immediately before `test`, gated on non-empty:

```yaml
- name: required test packages
  if: ${{ inputs.test-packages != '' }}
  env:
    KIT_TEST_PACKAGES: ${{ inputs.test-packages }}
  run: |
    set -euo pipefail
    sudo apt-get update -qq
    sudo apt-get install -y $KIT_TEST_PACKAGES
```

Three decisions worth naming, because they are the ones a reader would otherwise
have to guess:

- **The caller names the packages, because only the caller knows.** Deriving the
  list means kit reading a service's test source, which is the cross-repository
  reach this workflow deliberately does not do. The input is the boundary.
- **The value reaches the shell through `env:`, never `${{ }}` inside `run:`.**
  Interpolating an input into a script body is the template-injection surface
  zizmor flags; through `env:` it is data the shell expands. The shellcheck
  SC2086 suppression is deliberate word splitting — the value *is* a command
  line.
- **Honoured by the Go job only.** The defect was in the Go job; a second
  language that needs the same adds the identical step to its own job rather
  than growing a mechanism here. The input is named generically so that step
  needs no new input. This is the "small mechanism" the brief asked for; the
  README now says which job honours it, so nobody has to infer it.

`tests/validate.sh` grew one check so the seam cannot rot into "an input nothing
reads":

```
PASS test-packages  (declared, opt-in, installed before go test)
```

It asserts the input exists, defaults to `''`, is passed via `env:`, is actually
installed, and — the load-bearing half — the install is **before** the `test`
step. An install that runs after the suite it feeds helps nobody, and the
ordering is exactly the thing that quietly rots when someone reorders steps.

---

## 3. Seam two — gateway's `prime` job and the lint pin

`roll-c5-lint-parity` put `golangci-lint run` into `bin/prime-go`, which exits
`127` when the binary is absent (the refusal working as designed). CI's `prime`
job installed Go and redis-server and ran `bin/prime`, but never ran mise, so
the binary a local developer gets for free was absent and the step exited 127.

The job now installs it, and the **version is read out of `mise.toml`** rather
than typed:

```sh
version="$(sed -n 's/^"golangci-lint" *= *"\(.*\)"/\1/p' mise.toml)"
base="https://github.com/golangci/golangci-lint/releases/download/v${version}"
curl -sSfL "$base/golangci-lint-${version}-linux-${arch}.tar.gz" | tar -xz -C "$RUNNER_TEMP"
install -m 0755 ".../golangci-lint" "$HOME/.local/bin/golangci-lint"
```

A literal would have been a **third** copy of the number beside `mise.toml` and
kit's `golangci-lint-action` `version:`, and `bin/prime-go` already compares the
running binary against `mise.toml` — so a drifting literal would red every run
with a fix that lives in a file that is not wrong. The release archive is pinned
by version, never the installer script at a moving ref, so the linter version
still has exactly two homes. The follow-on `golangci-lint --version` plus
`bin/prime-go`'s own assertion is what proves the pin landed rather than
something adjacent.

---

## 4. The class control — in the gate, derived from the sources

The brief offered a choice: a shell-level check that fails on a `127` naming the
tool, or a test asserting the workflow's `prime` job declares the tools the gate
requires. I built the second, in `bin/prime-go`, because it fires **earlier and
in more places** than a runtime `127` wrapper:

- It runs in `bin/prime`, which is what CI's `prime` job runs — so it fails in
  the job the brief names.
- It runs **before** the `command -v golangci-lint` guard, so in a CI whose
  workflow lost the install it fails naming the tool rather than exiting 127 —
  the same message, one step earlier.
- It also runs locally, where the tools *are* present, so it reds the
  developer's run in the same commit that adds a requirement, instead of the
  job only CI runs.
- A buffered `127` wrapper would have cost the live log for every healthy run
  (the job currently streams `bin/prime`'s output); the static check costs
  nothing and gives the message sooner.

**The requirement set is derived, never listed.** Two sources, one per way a
tool reaches the gate:

- `command -v <tool>` in `bin/prime`/`bin/prime-go` — tools the gate refuses to
  run without. Today: `go`, `golangci-lint`.
- `exec.LookPath("<binary>")` in `cmd/`+`internal/` `*_test.go` — binaries the
  tests *exec*. Today: `redis-server`.

A hand-written list here would be the failure mode itself: the next tool added
to the gate would not be in it and the check would stay green about it. Reading
the same sources means `command -v foo` added tomorrow turns this step red until
`ci.yml` installs `foo`.

It checks the two jobs differently because they provide differently:

- **`prime`** must *install* every required tool. `go` is satisfied by
  `actions/setup-go`; everything else by an `install` on the same line as the
  tool name.
- **`ci (kit)`** must name the test binaries in a `test-packages` value, because
  kit's shared `go` job runs the same tests and never calls `bin/prime`.

Comments are stripped before the search, and that is load-bearing rather than
tidiness: the `prime` job's own header **names** `redis-server` while explaining
why the install exists, so a check reading raw text would find the name in the
prose and pass on a job that had lost the install. Finding the thing in the
sentence that describes it is the exact red herring `stripbaseurl`'s check hit
with its own header.

Green and red, measured (the red controls mutate a backup of `ci.yml` and
restore it; the check text is the real step, extracted by line range and run):

```
GREEN     CI tools: 'prime' installs go golangci-lint redis-server;
          'ci (kit)' passes redis-server to kit                        rc=0

RED 1     redis-server install line removed  (test binary)
          ::error::the CI 'prime' job does not install 'redis-server',
          which the Go tests exec ...                                  rc=1

RED 2     golangci-lint install line removed (gate tool)
          ::error::the CI 'prime' job does not install 'golangci-lint',
          which bin/prime-go refuses to run without (it exits 127) ... rc=1

RED 3     test-packages: redis-server -> test-packages: (empty)  (kit seam)
          ::error::the CI 'ci (kit)' job does not hand kit a
          'test-packages' value naming 'redis-server' ...              rc=1
```

Every red names the tool and the job, which is the whole point: the next person
does not have to rediscover which apt package to install.

---

## 5. What is verified, and how

**Gateway gate is green, measured.** `./bin/prime` on the merged tree, run in
this worktree with mise's tools on PATH:

```
suite: 272 passed, 0 failed
packages: 8 with tests
==> ok

== prime ok            exit: 0
```

The new step is in that run (`exit 0` includes it):
`CI tools: 'prime' installs go golangci-lint redis-server; 'ci (kit)' passes
redis-server to kit`.

**Kit gate is green for the new check, measured — on my branch, not on the
pushed variant.** A filtered run of kit's own gate against
`roll/c5-ci-tool-parity` (`1f9804d`, §7.1):

```
$ KIT_PYTHON=<main-tree .venv> bash tests/validate.sh --static-only --only=test-packages
PASS test-packages  (declared, opt-in, installed before go test)
PASS: every check passed.  (1 check ran, 37 excluded by --only)
```

The workflow also parses (YAML load, `test-packages` present with
`default: ""`), `bash -n tests/validate.sh` is clean, and shellcheck reports no
new findings.

**Red controls are proven red** — §4 and §1's mutations, each run and reverted.
The kit check's ordering assertion is separately proven: a copy of the workflow
with the `required test packages` marker moved after `test` fails with
`ordered after test`.

**What this does NOT verify:**

- The GitHub Actions runs themselves. I did not push (§6).
- The `curl | tar` release URL and the `linux-amd64`/`arm64` asset names were
  not fetched on a runner. They are the official golangci-lint release naming
  for a version-pinned archive; if a future release renames assets, the step
  fails loudly at `curl -f` rather than passing quietly.
- The kit `apt-get` step was not executed on a runner.

---

## 6. The independent verification the packet asked for — NOT DONE

The Definition of Done asks for a pushed branch with the two job verdicts pasted
into the commit message, and explicitly calls that "independent verification,
NOT a control you write". **I did not do it, and the reason is a direct
instruction conflict:** the quarterly contract appended to this brief says, in
bold, *"You commit; the manager merges and pushes. Do not merge and do not
push."* I followed the contract and left the push to the manager. So the
pushed-CI green is **outstanding**, and the packet should not be read as done
until it is run.

**Ordering is already part-satisfied:** gateway's `ci` job calls kit at
`@master`, and kit `master`/`origin/master` already carries the `test-packages`
seam (`fd383c9`, pushed by the external manager — see §7.1). So the kit side of
`ci (kit) / go` should install `redis-server` on gateway's next push. What
remains unverified is gateway's own branch, and the two verdicts the DoD asks to
be pasted in the commit message.

The manager's steps:

```sh
git -C /Users/kaka/Code/any/moon/wt/roll-c5-ci-tool-parity \
  push origin roll/c5-ci-tool-parity

# the two verdicts, pasted into the commit message per the DoD
gh run list --repo cafaye/gateway --branch roll/c5-ci-tool-parity --limit 1
gh run view --repo cafaye/gateway <run-id> \
  --json jobs --jq '.jobs[] | "\(.name) \(.conclusion)"'
```

Expect `ci (kit)` to show `go` green (install → build → lint → **test**) and
`bin/prime` to show the `golangci-lint` step green and `bin/prime` exit 0.

The two red controls can be re-proven in CI by deleting, in a throwaway branch,
(a) the `test-packages: redis-server` value and (b) the `golangci-lint` install
step; both must red the named job.

---

## 7. Residual notes and honest limits

### 7.1 There are two kit variants, and the one on `master` is thinner

While this packet was being worked, an external process (the manager) landed its
own `test-packages` seam directly on kit `master` and pushed it:

```
kit master == origin/master == fd383c9
  .github/workflows/ci.reusable.yml only — no README change, no tests/validate.sh
```

My branch `roll/c5-ci-tool-parity` (kit worktree, commit `1f9804d`) is **not** an
ancestor of that; it is the same seam plus three things the pushed variant does
not have:

1. **The input is documented** — the workflow table row and the adoption
   section (the brief: *"update the file that documents them in the same
   commit"*).
2. **The `tests/validate.sh` check** that the seam stays declared, opt-in, and
   installed *before* `test` — the durability the brief asked for, on the kit
   side.
3. **The value reaches the shell through `env:`**, not `${{ inputs.test-packages }}`
   interpolated inside `run:`. Interpolating a caller input into a script body is
   the template-injection surface zizmor flags and kit's own conventions avoid;
   `fd383c9` uses the interpolation. It is a caller's own value and the callers
   are trusted, so it is not a live hole today — it is the spelling kit's own
   lint-args guard exists to keep out of the shape.

Both variants work. **Recommendation:** if `fd383c9` is kept as the kit fix,
port items 1–3 onto it in a follow-up (or merge `roll/c5-ci-tool-parity`), so
the seam carries its documentation and its control. Gateway's `kit.ref` already
points at `fd383c9`, chosen by the external process, so gateway's local tooling
resolves the thinner variant regardless of which branch here is adopted.

### 7.2 A commit I did not author appeared under my changes

Gateway's `a1fe4c5` contains exactly the edits in this report, but its message
is not the one I wrote and its `Author`/date are the user's — something outside
this session committed (and later amended/re-hashed) the tree between my last
edit and my `git commit`, which then reported "nothing to commit". That same
process also committed kit `fd383c9` and edited `gateway/kit.ref`. Worth knowing
because if a second agent is also working this packet, the tree can move under
both of us; the hashes in §1 are the state at the time of writing.

### 7.3 Smaller notes

- **No `CHANGELOG.md` entry.** The prior packet in this stack
  (`roll-c5-lint-parity`) added none, and the AGENTS.md changelog rule is scoped
  to adding an endpoint. Flagged in case the manager wants one.
- **`test-packages` is currently a Go-job-only seam by design.** If a second
  language ever needs it, the step is copied into that job and — on my branch —
  `validate.sh`'s check grows to match, the same shape `required-tier` already
  has across the language jobs. I chose not to pre-copy it into eight jobs,
  because that mechanism would have been larger than the problem the brief
  described.
- **The gateway `prime` job's lint install is only exercised by a runner.**
  Locally the pin resolves through mise and `bin/prime-go` asserts the running
  version against `mise.toml`, so a mismatch is loud; but the `curl | tar`
  release URL and the `linux-amd64`/`arm64` asset names are unverified on a
  runner (see §5).
