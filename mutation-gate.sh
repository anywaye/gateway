#!/usr/bin/env bash
set -uo pipefail
cd "$(dirname "$0")"

export PATH="$HOME/.local/share/mise/shims:$PATH"

PASSED=0
FAILED=0

SNAPSHOT="$(mktemp -d)"
trap 'rm -rf "$SNAPSHOT"' EXIT

restore_file() {
  local file="$1"
  if ! cmp -s "$file" "$SNAPSHOT/$file"; then
    cp "$SNAPSHOT/$file" "$file"
  fi
  if [ "$(cksum < "$file")" != "$(cat "$SNAPSHOT/$file.cksum")" ]; then
    echo "  RESTORE FAILED  $file — the snapshot and the file disagree after restoring" >&2
    FAILED=$((FAILED + 1))
    return 1
  fi
}

while IFS= read -r file; do
  mkdir -p "$SNAPSHOT/$(dirname "$file")"
  cp "$file" "$SNAPSHOT/$file"
  cksum < "$file" > "$SNAPSHOT/$file.cksum"
done < <(find cmd internal -name '*.go' -type f)
echo "snapshot: $(find "$SNAPSHOT" -name '*.cksum' | wc -l | tr -d ' ') file(s) under cmd/ and internal/, to be restored by copy"

mutate() {
  local file="$1" from="$2" to="$3" label="$4"

  if ! grep -qF -- "$from" "$file"; then
    echo "  MUTATION DID NOT APPLY  $label"
    echo "    $from"
    echo "    is not in $file — this proves nothing and must not be counted as a pass"
    FAILED=$((FAILED + 1))
    return
  fi
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
    restore_file "$file"
    return
  fi

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
  restore_file "$file"
}

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
    restore_file "$file"
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
  restore_file "$file"
}

echo "=== origin gate: accept same-site (a sibling subdomain) ==="
mutate internal/httpapi/bff.go \
  '!strings.EqualFold(site, "same-origin")' \
  '!strings.EqualFold(site, "same-site")' \
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

echo "=== a down dependency is reported as ready ==="
mutate internal/httpapi/bff.go \
  'if answer.StatusCode != http.StatusOK {
			return fmt.Errorf("identity answered %d on %s", answer.StatusCode, identityHealthz)
		}' \
  'if answer.StatusCode != http.StatusOK {
			return nil
		}' \
  'a down dependency reports ok' \
  'TestARegisteredIdentityProbeReportsByNameAndNeverByReason'

echo "=== a BFF auto-registers an identity probe (it must not) ==="
mutate internal/httpapi/httpapi.go \
  'svc := &server{probes: options.Probes, bff: bff}' \
  'svc := &server{probes: append([]NamedProbe{{Name: "identity", Probe: bff.IdentityProbe()}}, options.Probes...), bff: bff}' \
  'a BFF auto-registers an identity probe' \
  'TestABrowserSurfaceRegistersNoProbeAndTheReferenceAgrees'

echo "=== a logout identity could not revoke is answered unusable ==="
mutate internal/httpapi/bff.go \
  '		drain(answer)
		writeProblem(w, r, unreachable())' \
  '		drain(answer)
		writeProblem(w, r, unusable(b.target(identitySession), answer.StatusCode, nil, false))' \
  'a non-revoking logout answers unusable' \
  'TestANonRevokingLogoutIsUnreachableNotUnusable'

echo "=== the problem envelope is rendered in alphabetical order ==="
mutate internal/httpapi/problem.go \
  '	b.WriteString(`,"status":`)
	b.WriteString(strconv.Itoa(int(p.Status)))
	b.WriteString(`,"detail":`)
	writeJSONString(&b, p.Detail)' \
  '	b.WriteString(`,"code":`)
	writeJSONString(&b, string(p.Code))
	b.WriteString(`,"detail":`)
	writeJSONString(&b, p.Detail)
	b.WriteString(`,"status":`)
	b.WriteString(strconv.Itoa(int(p.Status)))' \
  'the envelope puts code before status' \
  'TestTheProblemEnvelopeIsTheReferencesFieldOrder|TestAValidationFailureKeepsFieldBeforeCodeAndIsLast'

echo "=== a problem document is served as application/json ==="
mutate internal/httpapi/httpapi.go \
  '	if w.Header().Get("Content-Type") == "" {
		w.Header().Set("Content-Type", "application/json")
	}
	w.WriteHeader(status)' \
  '	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)' \
  'writeRawJSON overwrites the problem content type' \
  'TestTheTwoRefusalsAgreeOnStatusAndContentType|TestTheProblemEnvelopeIsTheReferencesFieldOrder'

echo "=== a doubled header is joined rather than taking the first value ==="
echo "=== a doubled header is joined rather than taking the first value ==="
mutate internal/httpapi/bff.go \
  '			if values := r.Header[name]; len(values) > 1 {
				r.Header[name] = values[:1]
			}' \
  '			if values := r.Header[name]; len(values) > 1 {
				r.Header[name] = []string{strings.Join(values, ", ")}
			}' \
  'a doubled header is joined instead of collapsed' \
  'TestAHeaderSentTwiceTakesTheFirstValue'

echo "=== the generated router is allowed to refuse a doubled header ==="
mutate internal/httpapi/httpapi.go \
  '	router.Use(collapseRepeatedHeaders)' \
  '' \
  'the duplicate-header collapse is not installed' \
  'TestAHeaderSentTwiceTakesTheFirstValue|TestTheParameterRefusalIsUnreachableForTheDeclaredHeaders'

echo
echo "mutation gate: $PASSED bit, $FAILED did not"
[ "$FAILED" -eq 0 ]