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

Commits:

- gateway `843bd6e` — `ci: install redis-server and golangci-lint where the gate
  requires them, and fail naming the tool when absent`
- kit `1f9804d` — `ci: a caller can name the apt packages its suite execs
  (test-packages)`

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

**Kit gate is green for the new check, measured.** A filtered run of kit's own
gate against this branch:

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

**Ordering matters and is easy to get wrong:** gateway's `ci` job calls kit at
`@master`, so kit's change must be on `kit@master` before gateway's `ci (kit)`
job can go green. Merge kit first.

The manager's steps, in order:

```sh
# 1. kit first (its branch is the fix for ci (kit)/go)
git -C /Users/kaka/Code/any/moon/wt/roll-c5-ci-tool-parity-kit \
  push origin roll/c5-ci-tool-parity
#    ... merge to master (manager's call) ...

# 2. gateway
git -C /Users/kaka/Code/any/moon/wt/roll-c5-ci-tool-parity \
  push origin roll/c5-ci-tool-parity

# 3. the two verdicts, pasted into the commit message per the DoD
gh run list  --repo cafaye/gateway --branch roll/c5-ci-tool-parity --limit 1
gh run view  --repo cafaye/gateway <run-id> \
  --json jobs --jq '.jobs[] | "\(.name) \(.conclusion)"'
```

Expect `ci (kit)` to show `go` green (install → build → lint → **test**) and
`bin/prime` to show the `golangci-lint` step green and `bin/prime` exit 0.

The two red controls can be re-proven in CI by deleting, in a throwaway branch,
(a) the `test-packages: redis-server` value and (b) the `golangci-lint` install
step; both must red the named job.

---

## 7. Residual notes and honest limits

- **A commit I did not author appeared under my changes.** Gateway's commit
  `843bd6e` contains exactly the edits in this report, but its message is not
  the one I wrote and its `Author`/date are the user's — something outside this
  session committed the tree between my last edit and my `git commit`, which
  then reported "nothing to commit". Its message does not carry the pushed-CI
  verdicts the DoD wants; that is the manager's to amend when it runs §6. Kit's
  commit `1f9804d` is mine. Worth knowing because if a second agent is also
  working this packet, the tree may move under both of us.
- **`gateway/kit.ref` is not bumped.** It pins a kit commit for local tooling
  and the comment requires a ref that exists on `origin/master`; the kit fix is
  not pushed, so bumping it here would break other clones. It does not affect
  CI, which resolves kit at `@master`. `bin/dev pin` moves it once kit lands.
- **No `CHANGELOG.md` entry.** The prior packet in this stack
  (`roll-c5-lint-parity`) added none, and the AGENTS.md changelog rule is scoped
  to adding an endpoint. Flagged in case the manager wants one.
- **`test-packages` is currently a Go-job-only seam by design.** If a second
  language ever needs it, the step is copied into that job and `validate.sh`'s
  check grows to match — the same shape `required-tier` already has across the
  language jobs. I chose not to pre-copy it into eight jobs, because that
  mechanism would have been larger than the problem the brief described.
