#!/usr/bin/env bash
set -uo pipefail
cd "$(dirname "$0")/.."

PASS=0
FAIL=0

note() { printf '\n=====================================================\n=== %s\n' "$*"; }
ok()   { PASS=$((PASS + 1)); printf 'PROVED (green -> red): %s\n' "$*"; }
bad()  { FAIL=$((FAIL + 1)); printf 'NOT PROVED: %s\n' "$*"; }

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


mutate \
  'property 2 — forward the caller Authorization instead of signing an assertion' \
  src/routes/proxy.ts src/routes/assertion.test.ts \
  '  return assertion.mint(principal, { audience: route.baseUrl, claims: route.principal });' \
  '  return c.req.header("authorization")?.replace(/^bearer /i, "") ?? "";' \
  'the header is a different string, and not the caller'


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


mutate \
  'property 4 — minimal claims' \
  src/routes/assertion.ts src/routes/assertion.test.ts \
  '    ...declared(principal, subject.claims),' \
  '    ...principal.claims,' \
  'the declared names are there, in the token'


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