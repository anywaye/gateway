#!/usr/bin/env bash
set -uo pipefail
cd "$(dirname "$0")/.."

PASS=0
FAIL=0

note() { printf '\n=====================================================\n=== %s\n' "$*"; }
ok()   { PASS=$((PASS + 1)); printf 'PROVED (green -> red): %s\n' "$*"; }
bad()  { FAIL=$((FAIL + 1)); printf 'NOT PROVED: %s\n' "$*"; }

mutate() {
  local label="$1" src="$2" want="$3" old="$4" new="$5"
  note "$label"
  printf 'source: %s\ncase:   %s\n' "$src" "$want"

  if ! python3 - "$src" "$old" "$new" <<'PY'
import sys
path, old, new = sys.argv[1], sys.argv[2], sys.argv[3]
body = open(path, encoding="utf-8").read()
if body.count(old) != 1:
    print(f"REFUSED: {path} contains {body.count(old)} copies of the target, expected exactly 1")
    sys.exit(1)
open(path, "w", encoding="utf-8").write(body.replace(old, new))
PY
  then
    bad "$label — the substitution did not apply, so nothing was proved"
    return
  fi

  printf -- '--- diff ---\n'
  git --no-pager diff -- "$src" | tail -n 12
  printf -- '--- the line now in the file ---\n'
  grep -n -F -- "$new" "$src" | head -3

  if timeout 300 go test ./internal/httpapi/ -count=1 -run "^${want}$" >/tmp/mutation.out 2>&1; then
    bad "$label — ${want} stayed GREEN with the property removed"
    tail -20 /tmp/mutation.out
  else
    ok "$label — ${want} went red"
    grep -E '^\s+(proxy|table|assertion)_test\.go' /tmp/mutation.out | head -4
  fi

  if ! python3 - "$src" "$new" "$old" <<'PY'
import sys
path, new, old = sys.argv[1], sys.argv[2], sys.argv[3]
body = open(path, encoding="utf-8").read()
if body.count(new) != 1:
    print(f"REFUSED: cannot revert, {path} contains {body.count(new)} copies of the mutated text")
    sys.exit(1)
open(path, "w", encoding="utf-8").write(body.replace(new, old))
PY
  then
    printf 'COULD NOT REVERT — the tree now holds a mutation and is NOT clean.\n'
    exit 1
  fi

  if timeout 300 go test ./internal/httpapi/ -count=1 -run "^${want}$" >/tmp/mutation.out 2>&1; then
    printf 'restored: %s is green again\n' "$want"
  else
    bad "$label — ${want} did not come back green, so the revert did not restore the property"
    tail -20 /tmp/mutation.out
    exit 1
  fi
}

mutate_pair() {
  local label="$1" src="$2" want="$3" old_a="$4" new_a="$5" old_b="$6" new_b="$7"
  note "$label"
  printf 'source: %s\ncase:   %s\nboth call sites, on purpose\n' "$src" "$want"

  if ! python3 - "$src" "$old_a" "$new_a" "$old_b" "$new_b" <<'PY'
import sys
path, old_a, new_a, old_b, new_b = sys.argv[1:6]
body = open(path, encoding="utf-8").read()
for old, new in ((old_a, new_a), (old_b, new_b)):
    if body.count(old) != 1:
        print(f"REFUSED: {path} contains {body.count(old)} copies of a target, expected exactly 1")
        sys.exit(1)
    body = body.replace(old, new)
open(path, "w", encoding="utf-8").write(body)
PY
  then
    bad "$label — the substitution did not apply, so nothing was proved"
    return
  fi

  printf -- '--- diff ---\n'
  git --no-pager diff -- "$src" | tail -n 20

  if timeout 300 go test ./internal/httpapi/ -count=1 -run "^${want}$" >/tmp/mutation.out 2>&1; then
    bad "$label — ${want} stayed GREEN with the property removed"
    tail -20 /tmp/mutation.out
  else
    ok "$label — ${want} went red"
    grep -E '^\s+(proxy|table|assertion)_test\.go' /tmp/mutation.out | head -4
  fi

  if ! python3 - "$src" "$new_a" "$old_a" "$new_b" "$old_b" <<'PY'
import sys
path, new_a, old_a, new_b, old_b = sys.argv[1:6]
body = open(path, encoding="utf-8").read()
for new, old in ((new_a, old_a), (new_b, old_b)):
    if body.count(new) != 1:
        print(f"REFUSED: cannot revert, {path} contains {body.count(new)} copies")
        sys.exit(1)
    body = body.replace(new, old)
open(path, "w", encoding="utf-8").write(body)
PY
  then
    printf 'COULD NOT REVERT — the tree now holds a mutation and is NOT clean.\n'
    exit 1
  fi

  if timeout 300 go test ./internal/httpapi/ -count=1 -run "^${want}$" >/tmp/mutation.out 2>&1; then
    printf 'restored: %s is green again\n' "$want"
  else
    bad "$label — ${want} did not come back green"
    tail -20 /tmp/mutation.out
    exit 1
  fi
}


mutate \
  'property 1: forward the caller Authorization as well as the service token' \
  internal/httpapi/proxy.go \
  TestTheCallersCredentialNeverReachesAnInternalService \
  '	if route.Token != "" {
		headers.Set("Authorization", "Bearer "+route.Token)
	}' \
  '	if route.Token != "" {
		headers.Set("Authorization", "Bearer "+route.Token)
	}
	if caller := r.Header.Get("Authorization"); caller != "" {
		headers.Set("Authorization", caller)
	}'

mutate \
  'property 1: an entry with no token gets one this process invented' \
  internal/httpapi/proxy.go \
  TestAnEntryWithNoTokenIsReachedWithNoAuthorizationAtAll \
  '	if route.Token != "" {
		headers.Set("Authorization", "Bearer "+route.Token)
	}' \
  '	if route.Token != "" {
		headers.Set("Authorization", "Bearer "+route.Token)
	} else {
		headers.Set("Authorization", "Bearer "+strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	}'


mutate \
  'property 2: rebuild becomes path.Clean, which normalises instead of reconstructing' \
  internal/httpapi/table.go \
  TestUpstreamPathRebuildsEverySegmentAndRefusesWhatItCannotExpress \
  '		segment, ok := decodeSegment(raw)
		if !ok || segment == "" || segment == "." || segment == ".." || strings.ContainsAny(segment, `/\`) {
			return "", false
		}' \
  '		segment, ok := decodeSegment(raw)
		if !ok {
			return "", false
		}
		segment = path.Clean("/" + segment)
		if segment == "/" {
			segment = ""
		}'

mutate \
  'property 2: an encoded separator inside a segment is joined instead of refused' \
  internal/httpapi/table.go \
  TestUpstreamPathRebuildsEverySegmentAndRefusesWhatItCannotExpress \
  'strings.ContainsAny(segment, `/\`)' \
  'strings.ContainsAny(segment, "\\")'

mutate \
  'property 2: a byte that is not text is passed through' \
  internal/httpapi/table.go \
  TestUpstreamPathRebuildsEverySegmentAndRefusesWhatItCannotExpress \
  '	if !utf8.ValidString(decoded) {
		return "", false
	}' \
  '	if false {
		return "", false
	}'


mutate \
  'property 3: the allowlist grows by one name' \
  internal/httpapi/proxy.go \
  TestTheRequestAllowlistIsExactlyTwoNames \
  'var ForwardedRequestHeaders = []string{"content-type", "accept"}' \
  'var ForwardedRequestHeaders = []string{"content-type", "accept", "x-forwarded-for"}'

mutate \
  'property 3: the response allowlist grows by one name' \
  internal/httpapi/proxy.go \
  TestTheResponseAllowlistIsExactlyOneName \
  'var ForwardedResponseHeaders = []string{"content-type"}' \
  'var ForwardedResponseHeaders = []string{"content-type", "set-cookie"}'

mutate \
  'property 3: the allowlist becomes a deny list' \
  internal/httpapi/proxy.go \
  TestOnlyContentTypeAndAcceptCrossToTheService \
  '	for _, name := range ForwardedRequestHeaders {
		if value, present := headerValue(r.Header, name); present {
			headers.Set(name, value)
		}
	}' \
  '	for name, values := range r.Header {
		switch http.CanonicalHeaderKey(name) {
		case "Authorization", "Cookie", "Proxy-Authorization", "X-Anywaye-Principal", "X-Forwarded-For", "X-Real-Ip", "X-Correlation-Id", "If-None-Match":
		default:
			headers[name] = values
		}
	}'


mutate \
  'property 4: CheckRedirect follows' \
  internal/httpapi/proxy.go \
  TestARedirectIsNeitherFollowedNorRelayed \
  '	CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	},' \
  '	CheckRedirect: func(*http.Request, []*http.Request) error {
		return nil
	},'

mutate \
  'property 4: the deadline is dropped, so a hung upstream hangs the handler' \
  internal/httpapi/proxy.go \
  TestAnUpstreamThatHangsIsA503AndNotAHungGateway \
  '	ctx, cancel := context.WithTimeout(r.Context(), p.timeout)
	defer cancel()' \
  '	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()'


mutate \
  'property 5: every upstream header is relayed instead of one' \
  internal/httpapi/proxy.go \
  TestTheRelayDropsSetCookieAndSetsNoStore \
  '	for _, name := range ForwardedResponseHeaders {
		if value, present := headerValue(response.header, name); present {
			w.Header().Set(name, value)
		}
	}' \
  '	for name, values := range response.header {
		w.Header()[name] = values
	}'

mutate \
  'property 6: no-store is not set' \
  internal/httpapi/proxy.go \
  TestAnUpstreamsOwnCacheControlIsOverriddenNotForwarded \
  '	w.Header().Set("Cache-Control", "no-store")' \
  '	if false {
		w.Header().Set("Cache-Control", "no-store")
	}'


mutate \
  'property 7: isRelayable becomes a range check that relays 5xx' \
  internal/httpapi/proxy.go \
  TestOnlyA2xxOrA4xxIsRelayed \
  'func IsRelayableStatus(status int) bool {
	return status < 300 || (status >= 400 && status < 500)
}' \
  'func IsRelayableStatus(status int) bool {
	return status < 500
}'

mutate \
  'property 7: 3xx crosses, which is a way out of the route table' \
  internal/httpapi/proxy.go \
  TestOnlyA2xxOrA4xxIsRelayed \
  'func IsRelayableStatus(status int) bool {
	return status < 300 || (status >= 400 && status < 500)
}' \
  'func IsRelayableStatus(status int) bool {
	return status < 400
}'


mutate_pair \
  'property 8: a malformed table is served rather than refused' \
  internal/httpapi/httpapi.go \
  TestABadRouteTableIsARefusalToConstructTheGateway \
  '	if o.Routes != nil {
		if _, err := ValidateRouteTable(o.Routes); err != nil {
			return err
		}
	}' \
  '	if o.Routes != nil && false {
		if _, err := ValidateRouteTable(o.Routes); err != nil {
			return err
		}
	}' \
  '	table, err := ValidateRouteTable(options.Routes)
	if err != nil {
		return nil, err
	}' \
  '	table, err := options.Routes, error(nil)
	if err != nil {
		return nil, err
	}'

mutate \
  'property 8: the public-plus-principal contradiction is resolved rather than refused' \
  internal/httpapi/table.go \
  TestABadRouteTableIsARefusalToConstructTheGateway \
  '		if target.Public && target.Principal != nil {' \
  '		if false {'


mutate \
  'MD19 1: an assertion is minted for a public entry' \
  internal/httpapi/proxy.go \
  TestAPublicEntryIsRefusedAnAssertionEvenByATableThatBootWouldHaveRefused \
  '	if route.Public {
		return "", nil
	}' \
  '	if route.Public && route.Principal == nil {
		return "", nil
	}'

mutate \
  'MD19 2: the assertion header carries the caller Authorization instead of a signature' \
  internal/httpapi/proxy.go \
  TestTheAssertionIsGatewaySignedAndNotTheCallersToken \
  '	if asserted != "" {
		headers.Set(AssertionHeader, asserted)
	}' \
  '	if asserted != "" {
		headers.Set(AssertionHeader, asserted)
	}
	if caller := r.Header.Get("Authorization"); caller != "" {
		headers.Set(AssertionHeader, caller)
	}'

mutate \
  'MD19 3: the audience is the caller token audience rather than the upstream origin' \
  internal/httpapi/assertion.go \
  TestTheAssertionIsBoundToTheUpstreamAndShortLived \
  '		"aud": subject.Audience,' \
  '		"aud": "https://gateway.localhost",'

mutate \
  'MD19 3: the lifetime ceiling is removed' \
  internal/httpapi/assertion.go \
  TestAnAssertionLifetimeNobodyMayExceedIsARefusalToBoot \
  '	if ttl > MaxAssertionTTL {' \
  '	if false {'

mutate \
  'MD19 4: the whole verified claim set is copied, which is the opposite of minimal' \
  internal/httpapi/assertion.go \
  TestTheAssertionCarriesOnlyTheDeclaredClaims \
  '	for name, value := range declaredClaims(principal, subject.Claims) {
		envelope[name] = value
	}' \
  '	for name, value := range principal.Claims {
		envelope[name] = value
	}'

mutate \
  'MD19 4: the reserved-name check is dropped, so an operator could choose the audience' \
  internal/httpapi/table.go \
  TestTheJSONASpellingAnOperatorGetsWrongIsAlsoARefusal \
  '	if isReservedClaim(name) {' \
  '	if false {'

mutate \
  'the published key carries the private half, which is what a JWK export of a private key object gives' \
  internal/httpapi/assertion.go \
  TestThePublishedJWKCarriesOnlyThePublicHalf \
  'type JSONWebKey struct {
	Kty string `json:"kty"`
	N   string `json:"n"`
	E   string `json:"e"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
}' \
  'type JSONWebKey struct {
	Kty   string `json:"kty"`
	N     string `json:"n"`
	E     string `json:"e"`
	Kid   string `json:"kid"`
	Alg   string `json:"alg"`
	Use   string `json:"use"`
	D     string `json:"d"`
	Primes []string `json:"p"`
}'


mutate \
  'the standing property: a private route stops refusing an anonymous caller' \
  internal/httpapi/gate.go \
  TestAnAnonymousCallerToAPrivateRouteGets401AndTheUpstreamIsNeverContacted \
  '		if err != nil || principal == nil {
			writeProblem(w, r, Problem{' \
  '		if err == nil && principal != nil {
			writeProblem(w, r, Problem{'

mutate \
  'the standing property: the gate is mounted on everything, not on /v1/*' \
  internal/httpapi/gate.go \
  TestAPublicRouteIsStillMountedAndTheProbesStillAnswerWithoutACredential \
  '		if !underRouteMount(path) {
			next.ServeHTTP(w, r)
			return
		}' \
  '		if false {
			next.ServeHTTP(w, r)
			return
		}'

mutate \
  "the standing property: MD18's public exception is dropped from the gate" \
  internal/httpapi/gate.go \
  TestAPublicRouteIsStillMountedAndTheProbesStillAnswerWithoutACredential \
  '		if IsPublicRoute(routes, path) {
			next.ServeHTTP(w, r)
			return
		}' \
  '		if false {
			next.ServeHTTP(w, r)
			return
		}'


mutate \
  'gateway owns its own route: the exclusion is dropped, so a /v1 entry proxies /v1/me away' \
  internal/httpapi/proxy.go \
  TestGatewayOwnsItsOwnRouteEvenUnderTheBroadestPrefix \
  '		if path == gatewayOwned {
			next.ServeHTTP(w, r)
			return
		}' \
  '		if false {
			next.ServeHTTP(w, r)
			return
		}'

note 'the tree must be clean; a mutation left behind is a broken tree, not a proof'
if [ -n "$(git status --porcelain -- internal src test)" ]; then
  git status --short -- internal src test
  FAIL=$((FAIL + 1))
  printf 'NOT PROVED: the working tree is not clean after the mutations.\n'
fi

printf '\n=====================================================\n'
printf 'proved: %d\nnot proved: %d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] || exit 1