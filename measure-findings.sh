#!/usr/bin/env bash
set -uo pipefail
cd "$(dirname "$0")"

export PATH="$HOME/.local/share/mise/shims:$PATH"

SNAPSHOT="$(mktemp -d)"
trap 'rm -rf "$SNAPSHOT"' EXIT

FILES="internal/httpapi/bff.go internal/httpapi/httpapi.go internal/httpapi/problem.go"
for f in $FILES; do mkdir -p "$SNAPSHOT/$(dirname "$f")"; cp "$f" "$SNAPSHOT/$f"; done

restore() { for f in $FILES; do cp "$SNAPSHOT/$f" "$f"; done; }

differences() {
  local out
  out="$(go test -count=1 -v -run TestTheGoGatewayAnswersAsTheTypeScriptOneDoes ./internal/equivalence/ 2>&1)"
  local line
  line="$(printf '%s\n' "$out" | sed -n 's/.*comparisons, \([0-9]*\) differences.*/\1/p' | head -1)"
  if [ -z "$line" ]; then
    echo "DID-NOT-RUN"
    return
  fi
  echo "$line"
}

apply() {
  local file="$1" from="$2" to="$3"
  if ! grep -qF -- "$from" "$file"; then
    echo "MUTATION-DID-NOT-APPLY"
    return 1
  fi
  python3 -c '
import sys
path, frm, to = sys.argv[1], sys.argv[2], sys.argv[3]
body = open(path).read()
assert frm in body, "source text absent"
open(path, "w").write(body.replace(frm, to, 1))
' "$file" "$from" "$to" || return 1
  grep -qF -- "$to" "$file" || { echo "MUTATION-DID-NOT-APPLY"; return 1; }
}

printf '%-58s %10s %10s\n' "finding (§3)" "before" "after"
printf '%s\n' "--------------------------------------------------------------------------------"

after="$(differences)"
printf '%-58s %10s %10s\n' "the port as it stands" "n/a" "$after"

report() {
  local label="$1" file="$2" from="$3" to="$4"
  restore
  if ! apply "$file" "$from" "$to"; then
    printf '%-58s %10s %10s\n' "$label" "MUT-DID-NOT-APPLY" "$after"
    return
  fi
  local before
  before="$(differences)"
  printf '%-58s %10s %10s\n' "$label" "$before" "$after"
}

report "3.1 the problem envelope's field order" \
  internal/httpapi/problem.go \
  '	b.WriteString(`,"status":`)
	b.WriteString(strconv.Itoa(int(p.Status)))
	b.WriteString(`,"detail":`)
	writeJSONString(&b, p.Detail)' \
  '	b.WriteString(`,"code":`)
	writeJSONString(&b, string(p.Code))
	b.WriteString(`,"detail":`)
	writeJSONString(&b, p.Detail)
	b.WriteString(`,"status":`)
	b.WriteString(strconv.Itoa(int(p.Status)))'

report "3.2 writeRawJSON overwrites the content type" \
  internal/httpapi/httpapi.go \
  '	if w.Header().Get("Content-Type") == "" {
		w.Header().Set("Content-Type", "application/json")
	}
	w.WriteHeader(status)' \
  '	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)'

report "3.3 a BFF auto-registers an identity probe" \
  internal/httpapi/httpapi.go \
  'svc := &server{probes: options.Probes, bff: bff}' \
  'svc := &server{probes: append([]NamedProbe{{Name: "identity", Probe: bff.IdentityProbe()}}, options.Probes...), bff: bff}'

report "3.4 a doubled Sec-Fetch-Site is joined" \
  internal/httpapi/bff.go \
  '			if values := r.Header[name]; len(values) > 1 {
				r.Header[name] = values[:1]
			}' \
  '			if values := r.Header[name]; len(values) > 1 {
				r.Header[name] = []string{strings.Join(values, ", ")}
			}'

report "3.5 a non-revoking logout answers unusable" \
  internal/httpapi/bff.go \
  '		drain(answer)
		writeProblem(w, r, unreachable())' \
  '		drain(answer)
		writeProblem(w, r, unusable(b.target(identitySession), answer.StatusCode, nil, false))'

restore
echo
echo "restored. the port as it stands is back at: $(differences)"