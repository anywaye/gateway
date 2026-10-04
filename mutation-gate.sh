#!/usr/bin/env bash
# Mutation proof for gateway-go-bff-01.
#
#   ./mutation-gate.sh    apply each mutation, run the suite, revert
#
# A test that passes proves nothing about the thing it is testing unless you have
# seen it fail. So each mutation below breaks ONE property, the suite is run, the
# result is recorded, and the mutation is reverted. Every entry is verified to
# HAVE APPLIED by grepping the file for the mutated text before running — a
# mutation that silently failed to apply produces a passing recipe that proves
# nothing and is indistinguishable from a working one until somebody reads the
# diff.
set -uo pipefail
cd "$(dirname "$0")"

export PATH="$HOME/.local/share/mise/shims:$PATH"

PASSED=0
FAILED=0

# mutate <file> <old> <new> <label>
mutate() {
  local file="$1" from="$2" to="$3" label="$4"

  if ! grep -qF -- "$from" "$file"; then
    echo "  MUTATION DID NOT APPLY  $label"
    echo "    $from"
    echo "    is not in $file — this proves nothing and must not be counted as a pass"
    FAILED=$((FAILED + 1))
    return
  fi
  # Confirm the mutation is IN the file after the edit, not merely that the edit
  # exited zero.
  python3 - "$file" "$from" "$to" <<'PY'
import sys
path, frm, to = sys.argv[1], sys.argv[2], sys.argv[3]
body = open(path).read()
assert frm in body, "the source text is not in the file"
open(path, "w").write(body.replace(frm, to, 1))
PY
  if ! grep -qF -- "$to" "$file"; then
    echo "  MUTATION DID NOT APPLY  $label (the replace produced nothing)"
    FAILED=$((FAILED + 1))
    git checkout -- "$file"
    return
  fi

  # Confine the blast radius: the assertion names the property, so the run names
  # which one, but an unrelated compile error is not a pass either.
  local out
  out="$(go test -count=1 -run "$5" ./internal/... 2>&1)"
  if printf '%s' "$out" | grep -qE '^(FAIL|# )' ; then
    echo "  BIT   $label"
    PASSED=$((PASSED + 1))
    printf '%s\n' "$out" | grep -E '^(---|    bff_test|FAIL|# )' | head -4 | sed 's/^/      /'
  else
    echo "  DID NOT BITE  $label  — the suite stayed green, so the property is untested"
    FAILED=$((FAILED + 1))
  fi
  git checkout -- "$file"
}

# mutate2 <file> <from1> <to1> <from2> <to2> <label> <run-pattern>
#
# Two edits in one mutation, for a property that needs both halves broken to be
# observable: an ALLOWLIST is "the struct has only the two fields AND the reader
# only fills those two", and mutating either half alone leaves the property
# holding. Both are applied and both are verified before the suite runs.
mutate2() {
  local file="$1" from1="$2" to1="$3" from2="$4" to2="$5" label="$6"

  for pair in "$from1" "$from2"; do
    if ! grep -qF -- "$pair" "$file"; then
      echo "  MUTATION DID NOT APPLY  $label"
      echo "    $pair"
      echo "    is not in $file — this proves nothing and must not be counted as a pass"
      FAILED=$((FAILED + 1))
      return
    fi
  done
  python3 - "$file" "$from1" "$to1" "$from2" "$to2" <<'PY'
import sys
path, f1, t1, f2, t2 = sys.argv[1:6]
body = open(path).read()
assert f1 in body and f2 in body, "one of the two source texts is not in the file"
body = body.replace(f1, t1, 1).replace(f2, t2, 1)
open(path, "w").write(body)
PY
  if ! grep -qF -- "$to1" "$file" || ! grep -qF -- "$to2" "$file"; then
    echo "  MUTATION DID NOT APPLY  $label (the replace produced nothing)"
    FAILED=$((FAILED + 1))
    git checkout -- "$file"
    return
  fi

  local out
  out="$(go test -count=1 -run "$7" ./internal/... 2>&1)"
  if printf '%s' "$out" | grep -qE '^(FAIL|# )' ; then
    echo "  BIT   $label"
    PASSED=$((PASSED + 1))
    printf '%s\n' "$out" | grep -E '^(---|    bff_test|FAIL|# )' | head -4 | sed 's/^/      /'
  else
    echo "  DID NOT BITE  $label  — the suite stayed green, so the property is untested"
    FAILED=$((FAILED + 1))
  fi
  git checkout -- "$file"
}

echo "=== origin gate: accept same-site (a sibling subdomain) ==="
mutate internal/httpapi/bff.go \
  '!strings.EqualFold(strings.TrimSpace(site), "same-origin")' \
  '!strings.EqualFold(strings.TrimSpace(site), "same-site")' \
  'the gate accepts same-site' \
  'TestOnlySameOriginSecFetchSitePasses|TestACrossOriginPostIsRefused'

echo "=== origin gate: compare the whole Origin, not the host ==="
mutate internal/httpapi/bff.go \
  'if origin != "" && hostOf(origin) != r.Host {' \
  'if origin != "" && origin != "https://"+r.Host {' \
  'the gate compares origin by scheme too' \
  'TestOriginIsComparedByHostNotByScheme'

echo "=== origin gate: refuse a request that states neither header ==="
mutate internal/httpapi/bff.go \
  'return site != "" || origin != ""' \
  'return true' \
  'a request stating no origin is let through' \
  'TestARequestThatStatesNeitherHeaderIsRefused'

echo "=== origin gate: trust the friendlier of two disagreeing signals ==="
mutate internal/httpapi/bff.go \
  'if origin != "" && hostOf(origin) != r.Host {' \
  'if origin != "" && hostOf(origin) == r.Host {' \
  'disagreeing signals are resolved the wrong way' \
  'TestDisagreeingOriginSignalsAreRefused'

echo "=== cookie: drop the __Host- prefix ==="
mutate internal/httpapi/bff.go \
  'const SessionCookie = "__Host-bff-session"' \
  'const SessionCookie = "bff-session"' \
  'the __Host- prefix is gone' \
  'TestTheSessionCookieIsTheHostPrefixedContract'

echo "=== cookie: stop being HttpOnly ==="
mutate internal/httpapi/bff.go \
  'HttpOnly: true,' \
  'HttpOnly: false,' \
  'the cookie stops being HttpOnly' \
  'TestTheSessionCookieIsTheHostPrefixedContract'

echo "=== cookie: SameSite=Strict instead of Lax ==="
mutate internal/httpapi/bff.go \
  'SameSite: http.SameSiteLaxMode,' \
  'SameSite: http.SameSiteStrictMode,' \
  'the cookie is Strict' \
  'TestTheSessionCookieIsTheHostPrefixedContract'

echo "=== cookie: a clearing cookie that does not repeat the attributes ==="
mutate internal/httpapi/bff.go \
  'c := sessionCookie
	c.Value = ""
	c.Expires = time.Unix(0, 0).UTC()
	c.MaxAge = -1' \
  'c := sessionCookie
	c.Path = "/somewhere-else"
	c.Secure = false
	c.Value = ""
	c.Expires = time.Unix(0, 0).UTC()
	c.MaxAge = -1' \
  'the clearing cookie drops Path and Secure' \
  'TestClearingTheCookieRepeatsEveryAttribute'

echo "=== login: hand the browser identity's token ==="
mutate internal/httpapi/bff.go \
  'writeRawJSON(w, r, http.StatusOK, `{"expires_at":"`+isoMillis(session.ExpiresAt)+`"}`)' \
  'writeRawJSON(w, r, http.StatusOK, `{"expires_at":"`+isoMillis(session.ExpiresAt)+`","token":"`+session.Token+`"}`)' \
  'the login body carries the identity token' \
  'TestTheLoginBodyCarriesTheExpiryAndNothingElse|TestTheBrowserNeverReceivesTheIdentityToken'

echo "=== login: reuse the caller's session id (cookie fixation) ==="
mutate internal/httpapi/bff.go \
  'sessionID := uuid.NewString()' \
  'sessionID := submittedSessionID' \
  'the session id comes from the caller' \
  'TestEveryLoginMintsAFreshSessionId'

echo "=== login: store a session with an expiry in the past ==="
mutate internal/httpapi/bff.go \
  'if !shaped || !session.ExpiresAt.After(b.now()) {' \
  'if !shaped {' \
  'an already-expired session is accepted' \
  'TestASessionWithNoUsableExpiryIsRefusedAndNothingIsStored'

echo "=== login: a 423 collapses into the 401 ==="
mutate internal/httpapi/bff.go \
  'case http.StatusLocked:' \
  'case http.StatusLocked:
		writeProblem(w, r, Problem{Status: api.N401, Code: api.ProblemCodeUnauthorized, Detail: "email or password is not correct"})
		return' \
  'a lockout answers 401' \
  'TestALockedAccountIs423AndItsRetryAfterTravels'

echo "=== login: the Retry-After window is dropped ==="
mutate internal/httpapi/bff.go \
  'if isDigits(retry) {
			w.Header().Set("Retry-After", retry)
		}' \
  '' \
  'Retry-After is not carried' \
  'TestALockedAccountIs423AndItsRetryAfterTravels'

echo "=== login: any Retry-After is echoed ==="
mutate internal/httpapi/bff.go \
  'if isDigits(retry) {' \
  'if retry != "" {' \
  'a non-numeric Retry-After is echoed' \
  'TestALockedAccountIs423AndItsRetryAfterTravels'

echo "=== login: the 401 message varies by cause ==="
mutate internal/httpapi/bff.go \
  'case http.StatusUnauthorized:
		// ONE sentence for every refused credential.' \
  'case http.StatusUnauthorized:
		writeProblem(w, r, Problem{Status: api.N401, Code: api.ProblemCodeUnauthorized, Detail: readBody(t, answer)})
		return
		// ONE sentence for every refused credential.' \
  'the 401 detail is identity'\''s own body' \
  'TestTwoRefusalCausesProduceIdenticalResponses|TestTheTwoRefusalsAgreeOnStatusAndContentType'

echo "=== login: a refused credential still mints a session ==="
# The run pattern has to reach BOTH places the property is asserted: the 401's
# store is checked in `TestTwoRefusalCauses…` and the 423's in the lockout test.
# The first version of this mutation named only the lockout test and the suite
# stayed green — because the mutation it made was in the 401 branch. A recipe that
# only proves one of the two is a recipe that proves half a thing.
mutate internal/httpapi/bff.go \
  'writeProblem(w, r, Problem{
			Status: api.N401,
			Code:   api.ProblemCodeUnauthorized,
			Detail: "email or password is not correct",
		})' \
  '_ = b.sessions.Put(r.Context(), uuid.NewString(), session.Session{})
		writeProblem(w, r, Problem{
			Status: api.N401,
			Code:   api.ProblemCodeUnauthorized,
			Detail: "email or password is not correct",
		})' \
  'a refused login stores a record' \
  'TestALockedAccountIs423AndItsRetryAfterTravels|TestTwoRefusalCausesProduceIdenticalResponses'

echo "=== register: forward identity's whole user document ==="
# Both halves, and the reason is stated: an allowlist is "the type has only these
# fields" AND "the reader only fills these". Breaking one leaves it holding, which
# is what the first version of this mutation did — it added three omitempty fields
# the reader never fills, and the suite stayed green.
mutate2 internal/httpapi/bff.go \
  'func userOf(document any) (*user, bool) {' \
  'func userOf(document any) (any, bool) {' \
  '	return &user{ID: id, Email: email}, true' \
  '	whole := map[string]any{}
	for k, v := range object {
		whole[k] = v
	}
	return whole, true' \
  'the user document is a filter rather than an allowlist' \
  'TestRegisterReturnsTheAccountAndNoCookie'

echo "=== register: email before id (the byte comparison needs id first) ==="
mutate internal/httpapi/bff.go \
  'type user struct {
	ID    string `json:"id"`
	Email string `json:"email"`
}' \
  'type user struct {
	Email string `json:"email"`
	ID    string `json:"id"`
}' \
  'the user fields are in the wrong order' \
  'TestMeProxiesWithTheStoredTokenAndReturnsOnlyTheAccount|TestRegisterReturnsTheAccountAndNoCookie'

echo "=== register: registration mints a session too ==="
mutate internal/httpapi/bff.go \
  'writeJSON(w, r, http.StatusCreated, account)

	case http.StatusUnprocessableEntity:' \
  'setSessionCookie(w, uuid.NewString(), b.now().Add(time.Hour))
		writeJSON(w, r, http.StatusCreated, account)

	case http.StatusUnprocessableEntity:' \
  'a registration sets a cookie' \
  'TestRegisterReturnsTheAccountAndNoCookie'

echo "=== body: re-encode rather than forward verbatim ==="
mutate internal/httpapi/bff.go \
  'return string(raw), true' \
  'var again bytes.Buffer
		_ = json.Compact(&again, raw)
		return again.String(), true' \
  'the caller bytes are re-encoded' \
  'TestTheCallersBodyReachesIdentityVerbatim'

echo "=== body: the 4 KiB cap is off by one ==="
mutate internal/httpapi/bff.go \
  'if len(raw) > maxBodyBytes {' \
  'if len(raw) > maxBodyBytes+1 {' \
  'the cap accepts one byte too many' \
  'TestMalformedBodiesAreRefusedAndIdentityIsNeverAsked|TestABodyJustInsideTheCapIsForwarded'

echo "=== body: the cap is gone ==="
# BOTH bounds, because there are two and either one catches the common case. The
# first version of this recipe broke only the header's bound — and
# `httptest.NewRequest` always sets `Content-Length`, so the reader's bound caught
# it and the suite stayed green. Two honest bounds and one observable property is
# a fact about the TEST, and both have to go for the property to fail.
mutate2 internal/httpapi/bff.go \
  'if n, ok := parseContentLength(declared); ok && n > maxBodyBytes {' \
  'if n, ok := parseContentLength(declared); ok && n > 0 {' \
  '	if len(raw) > maxBodyBytes {' \
  '	if len(raw) > maxBodyBytes+8 {' \
  'the body cap is off by nine bytes' \
  'TestMalformedBodiesAreRefusedAndIdentityIsNeverAsked'

echo "=== me: an outage is treated as a revocation ==="
mutate internal/httpapi/bff.go \
  'log.Printf("gateway: identity call failed: %v", err)
		writeProblem(w, r, unreachable())
		return
	}

	switch answer.StatusCode {
	case http.StatusOK:' \
  'log.Printf("gateway: identity call failed: %v", err)
		clearSessionCookie(w)
		writeProblem(w, r, Problem{Status: api.N401, Code: api.ProblemCodeUnauthorized, Detail: "the session is no longer valid"})
		return
	}

	switch answer.StatusCode {
	case http.StatusOK:' \
  'an identity outage signs the browser out' \
  'TestAnIdentityOutageIs503AndTheSessionSurvivesIt'

echo "=== me: a withdrawal does not drop the record ==="
mutate internal/httpapi/bff.go \
  'if err := b.sessions.Delete(r.Context(), sessionID); err != nil {
			log.Printf("gateway: could not drop a withdrawn session: %v", err)
		}' \
  '' \
  'a withdrawn session stays in the store' \
  'TestAWithdrawnSessionIs401AndTheRecordIsDropped'

echo "=== me: a forgotten session does not clear the cookie ==="
mutate internal/httpapi/bff.go \
  'clearSessionCookie(w)
		writeProblem(w, r, Problem{
			Status: api.N401,
			Code:   api.ProblemCodeUnauthorized,
			Detail: "the session is no longer valid",
		})
		return
	}

	answer, err := b.call(r.Context(), http.MethodGet, identityMe' \
  'writeProblem(w, r, Problem{
			Status: api.N401,
			Code:   api.ProblemCodeUnauthorized,
			Detail: "the session is no longer valid",
		})
		return
	}

	answer, err := b.call(r.Context(), http.MethodGet, identityMe' \
  'a forgotten session keeps its cookie' \
  'TestAForgottenSessionIs401AndTheCookieIsCleared'

echo "=== logout: refusing to sign out when identity is down ==="
mutate internal/httpapi/bff.go \
  'answer, err := b.call(r.Context(), http.MethodDelete, identitySession, callOptions{token: session.Token})
	if err != nil {
		log.Printf("gateway: identity call failed: %v", err)
		writeProblem(w, r, unreachable())
		return
	}' \
  'answer, err := b.call(r.Context(), http.MethodDelete, identitySession, callOptions{token: session.Token})
	if err != nil {
		log.Printf("gateway: identity call failed: %v", err)
		w.WriteHeader(http.StatusNoContent)
		return
	}' \
  'signing out silently reports success when identity is down' \
  'TestSigningOutWhileIdentityIsDownStillSignsOutAndSays503'

echo "=== logout: the store is not emptied ==="
mutate internal/httpapi/bff.go \
  'if err := b.sessions.Delete(r.Context(), sessionID); err != nil {
		log.Printf("gateway: could not drop a session record: %v", err)
		writeProblem(w, r, unreachable())
		return
	}' \
  '' \
  'signing out leaves the record' \
  'TestSignOutRevokesLocallyAndUpstream'

echo "=== a store that is down answers 401 ==="
mutate internal/httpapi/bff.go \
  'log.Printf("gateway: could not read the session store: %v", err)
		writeProblem(w, r, unreachable())' \
  'log.Printf("gateway: could not read the session store: %v", err)
		writeProblem(w, r, Problem{Status: api.N401, Code: api.ProblemCodeUnauthorized, Detail: "the session is no longer valid"})' \
  'a down store answers 401' \
  'TestAStoreThatIsDownIs503Not401'

echo "=== a hung identity is not bounded ==="
mutate internal/httpapi/bff.go \
  'case <-bounded.Done():
		return nil, fmt.Errorf("%s did not answer within %s", what, timeout)' \
  'case <-make(chan struct{}):' \
  'the deadline does not bound a hung Doer' \
  'TestAHungIdentityIsBounded'

echo "=== a panic in identity takes the process down ==="
mutate internal/httpapi/bff.go \
  '		defer func() {
			if r := recover(); r != nil {
				answered <- outcome{err: fmt.Errorf("%s panicked: %v", what, r)}
			}
		}()' \
  '' \
  'a panicking Doer is not recovered' \
  'TestAPanickingIdentityIsA503AndNotADeadGateway'

echo "=== the refusal leaks the dependency's address ==="
mutate internal/httpapi/bff.go \
  'Detail: "the authentication service could not be reached"}' \
  'Detail: "the authentication service at "+b.identityURL+" could not be reached"}' \
  'the 503 names identity'"'"'s address' \
  'TestAnUnreachableIdentityIs503AndNamesNoHost'

echo "=== no browser surface: the four routes answer 501 ==="
mutate internal/httpapi/httpapi.go \
  'func notBuilt(w http.ResponseWriter, r *http.Request) {
	writeV0NotFound(w, r)
}' \
  'func notBuilt(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotImplemented)
}' \
  'a declined operation answers 501' \
  'TestWithoutABrowserSurfaceTheFourRoutesAre404'

echo "=== a configured identity is not probed ==="
mutate internal/httpapi/httpapi.go \
  'probes = append(probes, NamedProbe{Name: "identity", Probe: bff.IdentityProbe()})' \
  '_ = bff' \
  'identity is not a readiness probe' \
  'TestAConfiguredIdentityRegistersAProbeAndItIsFirst'

echo "=== a down dependency is reported as ready ==="
# NOT "the probe's error names the host". That mutation does not bite, and the
# reason is the property rather than a gap in it: `runProbe` collapses every
# non-nil error to the closed two-value `unavailable` and the error never reaches
# `/readyz`'s body at all, so there is no byte to change. The observable half of
# "the reason never reaches the caller" is therefore enforced by
# `TestADownDependencyIsUnavailableAndNamesNoReason` reading the body, and the only
# mutation available here is the one below — a probe that says `ok` for a
# dependency that is down.
mutate internal/httpapi/bff.go \
  'if answer.StatusCode != http.StatusOK {
			return fmt.Errorf("identity answered %d on %s", answer.StatusCode, identityHealthz)
		}' \
  'if answer.StatusCode != http.StatusOK {
			return nil
		}' \
  'a down dependency reports ok' \
  'TestADownDependencyIsUnavailableAndNamesNoReason'

echo "=== a doubled header answers the generator's 400 ==="
mutate internal/httpapi/httpapi.go \
  '		writeProblem(w, r, Problem{
			Status: api.N403,
			Code:   api.ProblemCodeForbidden,
			Detail: "this request is not from the same origin",
		})' \
  '		http.Error(w, err.Error(), http.StatusBadRequest)' \
  'a duplicated header is a text/plain 400' \
  'TestAHeaderSentTwiceIsTheOriginGatesAnswer'

echo
echo "mutation gate: $PASSED bit, $FAILED did not"
[ "$FAILED" -eq 0 ]