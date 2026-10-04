#!/usr/bin/env bash
# The mutation evidence for REPORT-mvp-guard-principal-01.md.
#
# ## WHAT THIS IS FOR
#
# MD19 asks for four properties, "each needing a test that fails without it". A
# test that has only ever been observed passing has not been tested — it may be
# green because the code is right, or because the check never looked. This script
# settles that by making each property ABSENT, running the named test, and
# recording whether it went red.
#
# ## THE RULES IT FOLLOWS, AND ONE IT LEARNED THE HARD WAY
#
# A mutation asserted by exit status is not an assertion. So for every mutation:
#
#   1. `git diff` is printed after the edit, so the change that was made is
#      visible in the transcript rather than trusted.
#   2. The target line is re-read out of the file and printed, so a substitution
#      that silently failed to apply cannot be mistaken for a working one.
#   3. The expected test is run BY NAME against a named test FILE. A red is then
#      attributable to one assertion rather than to a neighbour.
#   4. The tree is put back by the **inverse substitution**, not by `git checkout`.
#      This is the rule the first draft of this script got wrong, and getting it
#      wrong cost a packet's uncommitted work: `git checkout -- <file>` is the
#      correct way to revert a mutation and is also the fastest way to destroy
#      every uncommitted edit in a file. Reverting by substitution cannot touch
#      anything the script did not change.
#   5. At the end, `git diff` must be EMPTY. A script that leaves a mutation
#      behind has not produced a proof, it has produced a broken tree.
#
# Every command is bounded by `timeout`. Nothing here runs for hours.
#
# ## USAGE
#
#     ./test/assertionMutations.sh
#
# Exits 0 only when every mutation was observed red on its named test AND the tree
# is clean at the end.
set -uo pipefail
cd "$(dirname "$0")/.."

PASS=0
FAIL=0

note() { printf '\n=====================================================\n=== %s\n' "$*"; }
ok()   { PASS=$((PASS + 1)); printf 'PROVED (green -> red): %s\n' "$*"; }
bad()  { FAIL=$((FAIL + 1)); printf 'NOT PROVED: %s\n' "$*"; }

# mutate <label> <source-file> <test-file> <old> <new> <test-name>
mutate() {
  local label="$1" src="$2" spec="$3" old="$4" new="$5" want="$6"
  note "$label"
  printf 'source: %s\ntest:   %s\ncase:   %s\n' "$src" "$spec" "$want"

  if ! python3 - "$src" "$old" "$new" <<'PY'
import sys
path, old, new = sys.argv[1], sys.argv[2], sys.argv[3]
body = open(path, encoding="utf-8").read()
if body.count(old) != 1:
    print(f"REFUSED: {path} contains {body.count(old)} copies of the target, expected exactly 1")
    sys.exit(3)
open(path, "w", encoding="utf-8").write(body.replace(old, new))
print("applied: 1 occurrence replaced")
PY
  then
    bad "$label — the mutation did not apply, so nothing was proved"
    return
  fi

  echo "--- git diff (the change, in the file) ---"
  git --no-pager diff -U1 -- "$src"
  echo "--- the mutated line, re-read from the file ---"
  grep -n -F -- "$new" "$src" || echo "!! NOT FOUND: the mutation is not in the file !!"

  local out
  out="$(timeout 180 bun test "$spec" -t "$want" 2>&1)"
  printf '%s\n' "$out" | grep -E '^\(fail\)|^ *[0-9]+ (pass|fail)$|^error:' | head -8

  if printf '%s' "$out" | grep -qE '^ [1-9][0-9]* fail$'; then
    ok "$label"
  else
    bad "$label — the named test stayed GREEN with the property absent"
    printf '%s\n' "$out" | tail -20
  fi

  # Reverted by substitution, for the reason in the header.
  python3 - "$src" "$new" "$old" <<'PY'
import sys
path, new, old = sys.argv[1], sys.argv[2], sys.argv[3]
body = open(path, encoding="utf-8").read()
if body.count(new) != 1:
    print(f"!! REFUSED TO REVERT: {path} contains {body.count(new)} copies of the mutation")
    sys.exit(3)
open(path, "w", encoding="utf-8").write(body.replace(new, old))
print("reverted")
PY
  echo "--- with the property back ---"
  timeout 180 bun test "$spec" -t "$want" 2>&1 | grep -E '^ *[0-9]+ (pass|fail)$'
}

# ---------------------------------------------------------------------------
# Property 1 — never on a public route. TWO gates, so TWO mutations. Removing
# either alone leaves the other holding the property up, and the surviving test
# would be green for the wrong reason — which is exactly what a reader of this
# script should not have to take on trust.
# ---------------------------------------------------------------------------

mutate \
  'property 1a — the boot refusal for a public entry that declares principal claims' \
  src/routes/table.ts src/routes/assertion.test.ts \
  '    if (open === true && principal !== undefined) {' \
  '    if (false && open === true && principal !== undefined) {' \
  'a public entry that declares principal claims refuses to boot'

mutate \
  'property 1b — the send-site check in assertionFor' \
  src/routes/proxy.ts src/routes/assertion.test.ts \
  '  if (route.public === true) return undefined;' \
  '  if (route.public === true && route.principal === undefined) return undefined;' \
  'the send site refuses on its own'

# ---------------------------------------------------------------------------
# Property 2 — not the caller's token, ever. The mutation is the exact refactor
# the property exists to stop: forward the inbound credential instead of signing.
# ---------------------------------------------------------------------------

mutate \
  'property 2 — forward the caller Authorization instead of signing an assertion' \
  src/routes/proxy.ts src/routes/assertion.test.ts \
  '  return assertion.mint(principal, { audience: route.baseUrl, claims: route.principal });' \
  '  return c.req.header("authorization")?.replace(/^bearer /i, "") ?? "";' \
  'the header is a different string, and not the caller'

# ---------------------------------------------------------------------------
# Property 3 — bound to the upstream, and short-lived. Two halves that fail
# independently, so two mutations.
# ---------------------------------------------------------------------------

mutate \
  'property 3a — the audience is the upstream origin' \
  src/routes/assertion.ts src/routes/assertion.test.ts \
  '    aud: subject.audience,' \
  '    aud: "https://everywhere.invalid",' \
  'the audience is the upstream it was minted for, and another one refuses it'

mutate \
  'property 3b — the window is real' \
  src/routes/assertion.ts src/routes/assertion.test.ts \
  '        .setExpirationTime(seconds + Math.floor(ttlMs / 1000))' \
  '        .setExpirationTime(seconds + 86_400)' \
  'it stops verifying once the window has passed'

# ---------------------------------------------------------------------------
# Property 4 — minimal claims. The mutation turns the declared set into the whole
# token, which is the one outcome the field exists to prevent. Note what it also
# breaks: `principal.claims` carries the caller's own `iss` and `aud`, so a
# wildcard spread placed AFTER the envelope overwrites gateway's audience too. That
# is not a second finding, it is the measurement of why the envelope is spread
# first — the mutation report showed it before anyone argued for the ordering.
# ---------------------------------------------------------------------------

mutate \
  'property 4 — minimal claims' \
  src/routes/assertion.ts src/routes/assertion.test.ts \
  '    ...declared(principal, subject.claims),' \
  '    ...principal.claims,' \
  'the declared names are there, in the token'

# ---------------------------------------------------------------------------
# The published key set. Not one of MD19's four, but the defect this packet found
# in itself, so it gets the same treatment: exporting the private key looks
# correct in every observable way, and only the field list catches it.
# ---------------------------------------------------------------------------

mutate \
  'the published JWK is the public half' \
  src/routes/assertion.ts src/routes/assertion.test.ts \
  '  const bare = await exportJWK(key.publicKey as never);' \
  '  const bare = await exportJWK(key.privateKey as never);' \
  'it carries no private parameter'

note 'the tree must be clean; a mutation left behind is a broken tree, not a proof'
if [ -n "$(git diff --stat)" ]; then
  git --no-pager diff --stat
  bad 'mutations were left in the working tree'
else
  ok 'working tree is clean — every mutation was reverted'
fi

printf '\n=====================================================\n=== %d proved, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]