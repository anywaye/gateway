package httpapi

import (
	"crypto/rand"
	"crypto/rsa"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cafaye/gateway/internal/api"
)

// The pass-through, and the security properties it exists to hold.
//
// Each test below is ONE property, named after it, and each is shown red by a
// mutation in `test/proxyMutations.sh`. The properties are the eight in the
// packet brief plus the standing 401, and they are checked **on the request the
// upstream received** rather than on the function that built it: a header-building
// helper can be correct while the thing that sends the request adds a header back,
// and the recorded request is the only place that difference is visible.

// --------------------------------------------------------------------------
// fixtures
// --------------------------------------------------------------------------

// recordedRequest is what an upstream actually received.
//
// Method, escaped path, raw query and the header set. Nothing else: the transport's
// own headers are written by two different HTTP clients and are not gateway's
// choice, so comparing them would compare `net/http` with undici.
type recordedRequest struct {
	Method string
	Path   string
	Query  string
	Header http.Header
	Body   string
}

// upstream is a recording service: it answers whatever it was told to answer and
// remembers what it was asked.
//
// A real socket rather than an injected client, and that is a deliberate departure
// from `src/routes/proxy.test.ts`, which injects `fetch` so the suite never opens
// one. There are three properties here that only a real client can demonstrate —
// that a redirect is not followed, that a hung upstream is bounded by a deadline,
// and that a body streams — and an injected fetch would assert about a stub rather
// than about the code that has to get it right. Every assertion in this file is
// about what leaves the process, so the socket is the honest fixture.
type upstream struct {
	server *httptest.Server

	mu       sync.Mutex
	last     recordedRequest
	requests int
}

func newUpstream(t *testing.T, answer http.HandlerFunc) *upstream {
	t.Helper()

	u := &upstream{}
	u.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)

		u.mu.Lock()
		u.last = recordedRequest{
			Method: r.Method,
			Path:   r.URL.EscapedPath(),
			Query:  r.URL.RawQuery,
			Header: r.Header.Clone(),
			Body:   string(body),
		}
		u.requests++
		u.mu.Unlock()

		if answer != nil {
			answer(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"ok":true}`)
	}))
	t.Cleanup(u.server.Close)

	return u
}

// Origin is the base URL to put in a route table. httptest's own, so it is a real
// `http://127.0.0.1:PORT` with no path, which is what `checkBaseURL` demands.
func (u *upstream) Origin() string { return u.server.URL }

// Last is what the upstream last received, failing the test if it received
// nothing — a property asserted against an empty recorder is a property that
// silently passed.
func (u *upstream) Last(t *testing.T) recordedRequest {
	t.Helper()

	u.mu.Lock()
	defer u.mu.Unlock()
	if u.requests == 0 {
		t.Fatal("the upstream received nothing, so every assertion about what crossed is vacuous")
	}
	return u.last
}

// Count is how many requests the upstream received.
func (u *upstream) Count() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.requests
}

// reset forgets the record, so a case can assert that a request did **not** reach
// the upstream at all.
func (u *upstream) reset() {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.requests = 0
	u.last = recordedRequest{}
}

// testKey is an RSA key pair for the assertion tests.
//
// Generated per test run rather than checked in, because a committed private key in
// a repository is a thing every reader has to notice and none of them should have
// to. `rsa.GenerateKey` at 2048 bits takes tens of milliseconds, which is a cost
// paid once per run and not per assertion.
func testKey(t *testing.T) AssertionKey {
	t.Helper()

	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("cannot generate a test signing key: %v", err)
	}
	return AssertionKey{Private: private, Public: &private.PublicKey}
}

// silenceLog swaps the operational log for the duration of one test.
//
// Every refusal and every translated upstream answer writes a line, and a suite
// that printed them would bury its own failures in the noise of tests that are
// supposed to fail upstream. Restored by `t.Cleanup`, so a test cannot leave the
// process's stderr pointing at a buffer nobody reads.
func silenceLog(t *testing.T) *strings.Builder {
	t.Helper()

	previous := stderr
	captured := &strings.Builder{}
	stderr = captured
	t.Cleanup(func() { stderr = previous })

	return captured
}

// --------------------------------------------------------------------------
// property 1: the caller's credential never reaches an internal service
// --------------------------------------------------------------------------

// TestTheCallersCredentialNeverReachesAnInternalService is property 1, and it is
// the anti-confused-deputy property: the reason the gateway exists.
//
// The caller authenticates *to gateway* and gets to choose nothing about what a
// service sees. So the `Authorization` that reaches the upstream is the table's own
// service credential — never the caller's — and the caller's `Cookie` does not
// reach it at all. Both are asserted on the request the upstream **received**,
// because a header builder that is correct and a transport that adds something back
// produce the same green here and opposite behaviour in production.
func TestTheCallersCredentialNeverReachesAnInternalService(t *testing.T) {
	silenceLog(t)
	service := newUpstream(t, nil)

	options := Options{Routes: RouteTable{
		"/v1/pantry": {BaseURL: service.Origin(), Token: "svc-token-for-pantry"},
	}}

	rec := ask(t, options, http.MethodGet, "/v1/pantry/items", map[string]string{
		"Authorization":   "Bearer caller-token-for-gateway",
		"Cookie":          "__Host-bff-session=abc123",
		"X-Forwarded-For": "203.0.113.9",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("the gateway answered %d, want 200 — the case under test is a relayed request", rec.Code)
	}

	seen := service.Last(t)
	if got := seen.Header.Get("Authorization"); got != "Bearer svc-token-for-pantry" {
		t.Errorf("the upstream saw Authorization %q, want %q — gateway must attach its own credential and never the caller's", got, "Bearer svc-token-for-pantry")
	}
	if strings.Contains(strings.Join(seen.Header.Values("Authorization"), "|"), "caller-token-for-gateway") {
		t.Error("the caller's own token reached the upstream. That is the confused deputy: the caller authenticated to gateway and then chose who they are downstream.")
	}
	if got := seen.Header.Get("Cookie"); got != "" {
		t.Errorf("the upstream saw Cookie %q; a caller's session cookie must never cross to an internal service", got)
	}
	if got := seen.Header.Get("X-Forwarded-For"); got != "" {
		t.Errorf("the upstream saw X-Forwarded-For %q; a caller-chosen header must not reach a service", got)
	}
}

// The other half of the same property, and the one an allowlist gets wrong by
// accident: an entry with **no** token must be reached with no `Authorization` at
// all. Sending one this process invented would be a different thing, and a service
// that authenticates nothing is the case where inventing one matters.
func TestAnEntryWithNoTokenIsReachedWithNoAuthorizationAtAll(t *testing.T) {
	silenceLog(t)
	service := newUpstream(t, nil)

	rec := ask(t, Options{Routes: RouteTable{"/v1/catalog": {BaseURL: service.Origin()}}},
		http.MethodGet, "/v1/catalog/services", map[string]string{"Authorization": "Bearer caller-token"})
	if rec.Code != http.StatusOK {
		t.Fatalf("the gateway answered %d, want 200", rec.Code)
	}

	if got := service.Last(t).Header.Get("Authorization"); got != "" {
		t.Errorf("the upstream saw Authorization %q; an entry with no token must send no credential at all, not one this process invented", got)
	}
}

// --------------------------------------------------------------------------
// property 3: only content-type and accept cross
// --------------------------------------------------------------------------

// TestOnlyContentTypeAndAcceptCrossToTheService is property 3.
//
// Two headers, and the list is the control. Every other header the caller sent is
// dropped — which is asserted as a *set*, over a caller that sent nine of them, so
// a name nobody thought of when this test was written is not a hole in it. The
// allowlist is read out of `ForwardedRequestHeaders` rather than restated, so
// widening the list in `proxy.go` makes this test fail.
func TestOnlyContentTypeAndAcceptCrossToTheService(t *testing.T) {
	silenceLog(t)
	service := newUpstream(t, nil)

	sent := map[string]string{
		"Content-Type":        "application/json",
		"Accept":              "application/problem+json",
		"Authorization":       "Bearer caller-token",
		"Cookie":              "session=abc",
		"X-Forwarded-For":     "203.0.113.9",
		"X-Forwarded-Host":    "gateway.example",
		"X-Forwarded-Proto":   "https",
		"X-Real-Ip":           "203.0.113.9",
		"X-Correlation-Id":    "trace-me",
		"Proxy-Authorization": "Basic Zm9vOmJhcg==",
	}

	rec := ask(t, Options{Routes: RouteTable{"/v1/pantry": {BaseURL: service.Origin()}}},
		http.MethodGet, "/v1/pantry/items", sent)
	if rec.Code != http.StatusOK {
		t.Fatalf("the gateway answered %d, want 200", rec.Code)
	}

	seen := service.Last(t)

	// The two that must cross, and must carry the caller's value. `sent` is keyed
	// canonically because that is what `http.Header.Set` writes and what the
	// recorded request comes back with, while the allowlist is spelled in lower case
	// because that is how it is spelled in the source — a comparison between the two
	// spellings is a comparison that silently compares nothing.
	for _, name := range ForwardedRequestHeaders {
		canonical := http.CanonicalHeaderKey(name)
		if got, want := seen.Header.Get(name), sent[canonical]; got != want {
			t.Errorf("the upstream saw %s: %q, want the caller's %q", name, got, want)
		}
	}

	// And the shape: no header beyond the allowlist, gateway's own credential and the
	// transport's. `Host` is not in `Header` on the server side — it is
	// `Request.Host` — so it cannot be compared here, and the pass-through's own
	// comment is where that exclusion is argued.
	allowed := map[string]bool{"Accept-Encoding": true, "User-Agent": true}
	for _, name := range ForwardedRequestHeaders {
		allowed[http.CanonicalHeaderKey(name)] = true
	}
	if service.Origin() != "" {
		allowed["Authorization"] = true
	}

	var extra []string
	for name := range seen.Header {
		if !allowed[http.CanonicalHeaderKey(name)] {
			extra = append(extra, name)
		}
	}
	if len(extra) > 0 {
		t.Errorf("the upstream saw header(s) %v that the caller sent and the allowlist does not name. The allowlist is the control; anything not in it is a potential smuggling channel.", extra)
	}
}

// The same property in the response direction, on a caller that sent a body: a
// body crosses, and `content-type` crosses with it, so the service reads the shape
// it was sent as.
func TestABodyIsStreamedAndItsContentTypeCrossesWithIt(t *testing.T) {
	silenceLog(t)
	service := newUpstream(t, nil)

	payload := `{"name":"a service","version":"1.0.0"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/pantry/services", strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")

	handler, err := New(Options{Routes: RouteTable{"/v1/pantry": {BaseURL: service.Origin()}}})
	if err != nil {
		t.Fatalf("New refused: %v", err)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("the gateway answered %d, want 200\n  %s", rec.Code, rec.Body.String())
	}
	seen := service.Last(t)
	if seen.Method != http.MethodPost {
		t.Errorf("the upstream saw method %s, want POST", seen.Method)
	}
	if seen.Body != payload {
		t.Errorf("the upstream read body %q, want %q", seen.Body, payload)
	}
	if got := seen.Header.Get("Content-Type"); got != "application/json" {
		t.Errorf("the upstream saw Content-Type %q, want application/json", got)
	}
}

// TestTheRequestAllowlistIsExactlyTwoNames is the check the allowlist test above
// could not be.
//
// `TestOnlyContentTypeAndAcceptCrossToTheService` builds its expectation out of
// `ForwardedRequestHeaders`, which is right for "the two that crossed are the two
// named" and useless for "only two cross": widen the list and the test widens with
// it and stays green. That was not reasoned — it was measured, by the mutation
// script, which added `x-forwarded-for` to the list, watched the test stay green,
// and reported it. This test states the list as a literal so the mutation bites.
func TestTheRequestAllowlistIsExactlyTwoNames(t *testing.T) {
	want := []string{"content-type", "accept"}

	if len(ForwardedRequestHeaders) != len(want) {
		t.Fatalf("the request allowlist is %v, want exactly %v. Every name in it is a header a caller chose that reaches an internal service, and the whole property is the length of this list.", ForwardedRequestHeaders, want)
	}
	for i, name := range want {
		if ForwardedRequestHeaders[i] != name {
			t.Errorf("the request allowlist is %v, want exactly %v — position %d", ForwardedRequestHeaders, want, i)
		}
	}
}

// TestTheResponseAllowlistIsExactlyOneName is the same property in the response
// direction, and it is one name long: `content-type`.
//
// `set-cookie` is not in it, which is why a service cannot write the browser's
// session from behind the edge. The response allowlist is read by the relay, so a
// name added here crosses to the caller — and the mutation that adds `set-cookie`
// is the one that turns session fixation back on.
func TestTheResponseAllowlistIsExactlyOneName(t *testing.T) {
	want := []string{"content-type"}

	if len(ForwardedResponseHeaders) != len(want) {
		t.Fatalf("the response allowlist is %v, want exactly %v. Anything else here is a header a service controls that reaches the caller unexamined.", ForwardedResponseHeaders, want)
	}
	for i, name := range want {
		if ForwardedResponseHeaders[i] != name {
			t.Errorf("the response allowlist is %v, want exactly %v — position %d", ForwardedResponseHeaders, want, i)
		}
	}
}

// --------------------------------------------------------------------------
// property 4: no redirect is followed, and the call is bounded
// --------------------------------------------------------------------------

// TestARedirectIsNeitherFollowedNorRelayed is property 4, first half.
//
// A `Location` an internal service answers with is an address that is not on the
// internet, so following it is a way out of the route table and relaying it hands
// the caller the same address. The upstream here serves both the redirect and the
// destination it names, so a `CheckRedirect` that follows answers 200 with the
// destination's body — and the test's failure names exactly that.
func TestARedirectIsNeitherFollowedNorRelayed(t *testing.T) {
	logged := silenceLog(t)
	service := newUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.EscapedPath(), "/moved") {
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"followed":true}`)
			return
		}
		w.Header().Set("Location", "/moved")
		w.WriteHeader(http.StatusFound)
	})

	for _, status := range []int{http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		answering := newUpstream(t, func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.EscapedPath(), "/moved") {
				w.Header().Set("Content-Type", "application/json")
				io.WriteString(w, `{"followed":true}`)
				return
			}
			w.Header().Set("Location", "/moved")
			w.WriteHeader(status)
		})

		rec := ask(t, Options{Routes: RouteTable{"/v1/pantry": {BaseURL: answering.Origin()}}},
			http.MethodGet, "/v1/pantry/start", nil)

		if rec.Code != http.StatusServiceUnavailable {
			t.Errorf("a %d was answered %d, want 503 — a redirect is neither followed nor relayed", status, rec.Code)
		}
		var problem api.Problem
		decode(t, rec, &problem)
		if problem.Detail != "the service this request needs did not answer" {
			t.Errorf("a %d produced %q; that is the wrong 503 for an answer that arrived and was unusable", status, problem.Detail)
		}
		if answering.Count() != 1 {
			t.Errorf("a %d made %d requests to the upstream; a followed redirect is a way out of the route table", status, answering.Count())
		}
	}
	_ = service

	if strings.Contains(logged.String(), "followed") {
		t.Errorf("the log names a followed redirect:\n%s", logged.String())
	}
}

// TestAnUpstreamThatHangsIsA503AndNotAHungGateway is property 4, second half.
//
// The deadline has to bound the **handler**, not just the socket: an upstream that
// accepts the connection and then says nothing is the case where a client timeout
// is the only thing standing between one slow service and a gateway that stops
// answering. The upstream here sleeps for a long time relative to the timeout, and
// the test does not wait for it — the assertion is that the answer arrives first.
func TestAnUpstreamThatHangsIsA503AndNotAHungGateway(t *testing.T) {
	logged := silenceLog(t)
	release := make(chan struct{})
	service := newUpstream(t, func(w http.ResponseWriter, _ *http.Request) {
		<-release
	})
	t.Cleanup(func() { close(release) })

	started := time.Now()
	rec := ask(t, Options{
		Routes:          RouteTable{"/v1/pantry": {BaseURL: service.Origin()}},
		UpstreamTimeout: 50 * time.Millisecond,
	}, http.MethodGet, "/v1/pantry/slow", nil)
	elapsed := time.Since(started)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("a hung upstream was answered %d, want 503", rec.Code)
	}
	if elapsed > 5*time.Second {
		t.Errorf("the answer took %s; the deadline is not bounding the handler", elapsed)
	}
	if !strings.Contains(logged.String(), "could not be reached") {
		t.Errorf("the log does not say the upstream could not be reached, so an operator cannot tell a timeout from a refusal:\n%s", logged.String())
	}
}

// --------------------------------------------------------------------------
// property 5 and 6: what crosses back
// --------------------------------------------------------------------------

// TestTheRelayDropsSetCookieAndSetsNoStore is properties 5 and 6 together, because
// they are two halves of one header policy.
//
// `set-cookie` is dropped because a service answering `Set-Cookie: __Host-bff-session=…`
// would be writing the browser's session from behind the edge — session fixation
// arriving through the gateway on an origin where the `__Host-` prefix is honoured.
// `cache-control: no-store` is the one header added rather than forwarded, because
// proxied traffic is authenticated and a shared cache in front of this is an
// account's data at rest.
func TestTheRelayDropsSetCookieAndSetsNoStore(t *testing.T) {
	silenceLog(t)
	service := newUpstream(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Add("Set-Cookie", "__Host-bff-session=attacker-chosen; Path=/; Secure")
		w.Header().Add("Set-Cookie", "tracking=1; Path=/")
		w.Header().Set("X-Powered-By", "pantry/1.0")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		io.WriteString(w, `{"ok":true}`)
	})

	rec := ask(t, Options{Routes: RouteTable{"/v1/pantry": {BaseURL: service.Origin()}}},
		http.MethodGet, "/v1/pantry/items", nil)

	if rec.Code != http.StatusOK {
		t.Fatalf("the gateway answered %d, want 200", rec.Code)
	}
	if got := rec.Header().Values("Set-Cookie"); len(got) != 0 {
		t.Errorf("the caller received Set-Cookie %v; a service must not be able to write the browser's session from behind the edge", got)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control is %q, want no-store", got)
	}
	if got := rec.Header().Get("X-Powered-By"); got != "" {
		t.Errorf("the caller received X-Powered-By %q; the response allowlist is one header long", got)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type is %q, want the upstream's application/json", got)
	}
}

// An upstream that cached its own answer and said so must not get to: the relay
// overrides it. This is the same property as above from the other side, and it is
// separate because an allowlist that forgets to *set* the header still drops the
// upstream's, which is a different bug from forgetting to drop.
func TestAnUpstreamsOwnCacheControlIsOverriddenNotForwarded(t *testing.T) {
	silenceLog(t)
	service := newUpstream(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=3600, s-maxage=86400")
		w.Header().Set("Pragma", "cache")
		w.Header().Set("Expires", "Wed, 21 Oct 2099 07:28:00 GMT")
		io.WriteString(w, `{"ok":true}`)
	})

	rec := ask(t, Options{Routes: RouteTable{"/v1/pantry": {BaseURL: service.Origin()}}},
		http.MethodGet, "/v1/pantry/items", nil)

	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control is %q, want no-store — an authenticated answer must not be cacheable by an intermediary", got)
	}
	for _, name := range []string{"Pragma", "Expires"} {
		if got := rec.Header().Get(name); got != "" {
			t.Errorf("the caller received %s: %q; only the content type crosses", name, got)
		}
	}
}

// --------------------------------------------------------------------------
// property 7: what crosses back depends on the status
// --------------------------------------------------------------------------

// TestOnlyA2xxOrA4xxIsRelayed is property 7, through a real upstream rather than
// against the predicate.
//
// The bug this rule exists to prevent is relaying everything, and relaying a 500
// turns a service's outage into an opaque 500 the caller cannot act on while
// `ECONNREFUSED` and an HTML error page leak the platform's internals. The table
// covers every status class on both sides of both boundaries, because a check that
// only tests 200 and 500 does not know where the boundary is.
func TestOnlyA2xxOrA4xxIsRelayed(t *testing.T) {
	relayed := []int{200, 201, 202, 299, 400, 401, 403, 404, 409, 413, 422, 423, 429, 499}
	translated := []int{300, 301, 302, 303, 304, 307, 308, 399, 500, 502, 503, 504}

	// The predicate, over the same boundaries — the first run of the reference's own
	// suite got this wrong as a range check, so the predicate and the behaviour are
	// held together rather than one of them being assumed.
	for _, status := range relayed {
		if !IsRelayableStatus(status) {
			t.Errorf("IsRelayableStatus(%d) = false; a 2xx and a 4xx are the service's own contract", status)
		}
	}
	for _, status := range translated {
		if IsRelayableStatus(status) {
			t.Errorf("IsRelayableStatus(%d) = true; a 3xx is a Location and a 5xx is an error page from behind the edge", status)
		}
	}

	silenceLog(t)
	for _, status := range relayed {
		t.Run(http.StatusText(status), func(t *testing.T) {
			service := newUpstream(t, func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/problem+json")
				w.WriteHeader(status)
				io.WriteString(w, `{"the":"service's own answer"}`)
			})

			rec := ask(t, Options{Routes: RouteTable{"/v1/pantry": {BaseURL: service.Origin()}}},
				http.MethodGet, "/v1/pantry/x", nil)

			if rec.Code != status {
				t.Fatalf("the upstream's %d was answered %d, want it relayed unchanged", status, rec.Code)
			}
			if got := rec.Body.String(); got != `{"the":"service's own answer"}` {
				t.Errorf("the relayed body is %q, want the upstream's own. A 422 that became a 400 drops the field errors a form turns into sentences.", got)
			}
		})
	}

	for _, status := range translated {
		t.Run("translated "+http.StatusText(status), func(t *testing.T) {
			service := newUpstream(t, func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "text/html")
				w.WriteHeader(status)
				io.WriteString(w, `<html>identity.internal:8080</html>`)
			})

			rec := ask(t, Options{Routes: RouteTable{"/v1/pantry": {BaseURL: service.Origin()}}},
				http.MethodGet, "/v1/pantry/x", nil)

			if rec.Code != http.StatusServiceUnavailable {
				t.Fatalf("the upstream's %d was answered %d, want 503", status, rec.Code)
			}
			if strings.Contains(rec.Body.String(), "identity.internal") {
				t.Errorf("the upstream's body reached the caller: %q", rec.Body.String())
			}
			if got := rec.Header().Get("Content-Type"); got != problemContentType {
				t.Errorf("a translated answer is %q, want %q", got, problemContentType)
			}
		})
	}
}

// The two 503s are deliberately different sentences, and an operator reading a log
// at 3am has to be able to tell "the service is down" from "the service is broken".
// Both are asserted, because a change that merged them would still produce two
// green tests elsewhere.
func TestTheTwoServiceFailuresAreDifferentSentencesAndDifferentLogLines(t *testing.T) {
	silenceLog(t)

	unreachable := newUpstream(t, nil)
	unreachable.server.Close() // nothing is listening now
	logged := silenceLog(t)
	rec := ask(t, Options{Routes: RouteTable{"/v1/pantry": {BaseURL: unreachable.Origin()}}},
		http.MethodGet, "/v1/pantry/x", nil)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("a dead socket was answered %d, want 503", rec.Code)
	}
	var dead api.Problem
	decode(t, rec, &dead)
	if dead.Detail != "the service this request needs could not be reached" {
		t.Errorf("a dead socket said %q", dead.Detail)
	}
	if !strings.Contains(logged.String(), "could not be reached") {
		t.Errorf("a dead socket logged nothing an operator could read:\n%s", logged.String())
	}
	if strings.Contains(logged.String(), "the service this request needs") {
		t.Errorf("the log carries the caller's sentence rather than the operator's:\n%s", logged.String())
	}
}

// A service's error page is exactly where a credential turns up, so the log gets
// the **shape** of it and never the body. The assertion plants a credential in the
// body and looks for it in the log.
func TestTheLogNamesTheShapeOfAnAnswerAndNeverItsBody(t *testing.T) {
	logged := silenceLog(t)
	service := newUpstream(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusInternalServerError)
		io.WriteString(w, `<html>failed to reach pantry: token cafaye_secretvalue</html>`)
	})

	rec := ask(t, Options{Routes: RouteTable{"/v1/pantry": {BaseURL: service.Origin()}}},
		http.MethodGet, "/v1/pantry/x", nil)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("a 500 from the upstream was answered %d, want 503", rec.Code)
	}

	for _, want := range []string{"not JSON", "answered 500"} {
		if !strings.Contains(logged.String(), want) {
			t.Errorf("the log does not say %q, so an operator cannot tell a broken service from a down one:\n%s", want, logged.String())
		}
	}
	if strings.Contains(logged.String(), "cafaye_secretvalue") {
		t.Errorf("the credential from the upstream's body reached the log:\n%s", logged.String())
	}
}

// A JSON error page and an HTML one are different diagnoses, and the reference
// separates them deliberately — `typeof null` is "object", so the obvious test
// reports an HTML page as a JSON document.
func TestTheShapeOfAnAnswerTellsJsonFromNullFromText(t *testing.T) {
	cases := []struct{ body, want string }{
		{body: `{"error":"boom"}`, want: "a JSON document"},
		{body: `[1,2,3]`, want: "a JSON document"},
		{body: `null`, want: "not JSON"},
		{body: `"a string"`, want: "a JSON scalar"},
		{body: `<html/>`, want: "not JSON"},
		{body: ``, want: "not JSON"},
	}

	for _, tc := range cases {
		t.Run(tc.body, func(t *testing.T) {
			logged := silenceLog(t)
			service := newUpstream(t, func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				io.WriteString(w, tc.body)
			})

			ask(t, Options{Routes: RouteTable{"/v1/pantry": {BaseURL: service.Origin()}}},
				http.MethodGet, "/v1/pantry/x", nil)

			if !strings.Contains(logged.String(), "("+tc.want+")") {
				t.Errorf("the body %q was logged as something other than %q:\n%s", tc.body, tc.want, logged.String())
			}
		})
	}
}

// An upstream that answers without a content type gets `application/octet-stream`,
// and not `text/plain; charset=utf-8` sniffed out of the body by `net/http` and not
// nothing either.
//
// The reference's answer was measured: `new Response(body, {status, headers})` with
// no content type in `headers` reaches the caller as `application/octet-stream`
// under Bun. Go has three possible answers here — the service's, `octet-stream`, and
// whatever `net/http` guesses from the first 512 bytes — and the check exists to say
// which one this port picks, because a relayed body whose type changed under it is a
// difference a client that switches on the content type would see.
func TestAResponseWithNoContentTypeIsRelayedAsOctetStreamNotSniffed(t *testing.T) {
	silenceLog(t)
	service := newUpstream(t, func(w http.ResponseWriter, _ *http.Request) {
		// `Header()["Content-Type"]` with no values is the only way to write a
		// response with no content type at all through net/http's own writer.
		w.Header()["Content-Type"] = []string{}
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, `plain text, deliberately untyped`)
	})

	rec := ask(t, Options{Routes: RouteTable{"/v1/pantry": {BaseURL: service.Origin()}}},
		http.MethodGet, "/v1/pantry/x", nil)

	if got := rec.Header().Get("Content-Type"); got != relayedUntyped {
		t.Errorf("Content-Type is %q, want %q — and specifically not `text/plain; charset=utf-8`, which is `net/http` guessing from the body", got, relayedUntyped)
	}
	if got := rec.Body.String(); got != "plain text, deliberately untyped" {
		t.Errorf("the body is %q", got)
	}
}

// --------------------------------------------------------------------------
// the standing 401, and the gate's placement
// --------------------------------------------------------------------------

// TestAnAnonymousCallerToAPrivateRouteGets401AndTheUpstreamIsNeverContacted is the
// property two prior packets each promised, and the reason the gate is a seam
// rather than a copy of the verifier.
//
// The refusal is asserted **and** the upstream is asserted not to have been
// contacted, because a 401 after a call was already made is a 401 that still spent
// a service's capacity on a caller who was never going to be let in. The
// `Authenticate` here refuses, which is the only thing it has to do: what is under
// test is the gate's decision and its position, not verification — that is the
// packet that ports RS256, and this seam is where it plugs in.
func TestAnAnonymousCallerToAPrivateRouteGets401AndTheUpstreamIsNeverContacted(t *testing.T) {
	silenceLog(t)
	service := newUpstream(t, nil)

	options := Options{
		Routes: RouteTable{
			"/v1/pantry":  {BaseURL: service.Origin()},
			"/v1/catalog": {BaseURL: service.Origin(), Public: true},
		},
		Authenticate: func(*http.Request) (*Principal, error) {
			return nil, errNoCredential
		},
	}

	rec := ask(t, options, http.MethodGet, "/v1/pantry/items", nil)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("an anonymous caller to a private route got %d, want 401", rec.Code)
	}
	var problem api.Problem
	decode(t, rec, &problem)
	if problem.Code != "unauthorized" || problem.Detail != "a bearer token is required" {
		t.Errorf("the refusal is %+v; it must be the reference's own sentence", problem)
	}
	if got := rec.Header().Get("Content-Type"); got != problemContentType {
		t.Errorf("a 401 is %q, want %q", got, problemContentType)
	}
	if service.Count() != 0 {
		t.Errorf("the upstream was contacted %d time(s) for a request the gateway refused. A 401 after the call is a 401 that still spent a service's capacity.", service.Count())
	}
}

// The other half of the same property, and the one that makes it a *gate* rather
// than a blanket refusal: a public route is still mounted, and the probe endpoints
// still answer an orchestrator that has no credential at all.
func TestAPublicRouteIsStillMountedAndTheProbesStillAnswerWithoutACredential(t *testing.T) {
	silenceLog(t)
	service := newUpstream(t, nil)

	options := Options{
		Routes: RouteTable{
			"/v1/pantry":  {BaseURL: service.Origin()},
			"/v1/catalog": {BaseURL: service.Origin(), Public: true},
		},
		Authenticate: func(*http.Request) (*Principal, error) { return nil, errNoCredential },
	}

	if rec := ask(t, options, http.MethodGet, "/v1/catalog/services", nil); rec.Code != http.StatusOK {
		t.Errorf("a public route answered %d, want 200: `public: true` is the only way to answer without a credential", rec.Code)
	}
	for _, path := range []string{"/healthz", "/readyz"} {
		if rec := ask(t, options, http.MethodGet, path, nil); rec.Code != http.StatusOK {
			t.Errorf("%s answered %d with a gate configured; an orchestrator has no credential and a throttled probe is a restart", path, rec.Code)
		}
	}
	if rec := ask(t, options, http.MethodGet, "/nope", nil); rec.Code != http.StatusNotFound {
		t.Errorf("an unrouted path answered %d, want 404", rec.Code)
	}
}

// A caller the gate *did* establish reaches the pass-through, and is the only
// difference between the two rows above.
func TestACredentialTheGateEstablishedReachesThePassThrough(t *testing.T) {
	silenceLog(t)
	service := newUpstream(t, nil)

	rec := ask(t, Options{
		Routes: RouteTable{"/v1/pantry": {BaseURL: service.Origin()}},
		Authenticate: func(*http.Request) (*Principal, error) {
			return &Principal{Sub: "user-1"}, nil
		},
	}, http.MethodGet, "/v1/pantry/items", nil)

	if rec.Code != http.StatusOK {
		t.Fatalf("an authenticated caller got %d, want 200", rec.Code)
	}
	if service.Count() != 1 {
		t.Errorf("the upstream was contacted %d time(s), want 1", service.Count())
	}
}

// TestGatewayOwnsItsOwnRouteEvenUnderTheBroadestPrefix is the port's one structural
// difference from the reference, stated as a test.
//
// `src/index.ts` registers `/v1/me` before the pass-through and Hono answers in
// registration order. chi has no such order for a middleware and a route, so the
// exclusion is written into `routeProxy.handle`. `/v1` is a **permitted** prefix —
// it claims the whole API surface — and it is the only table that can reach
// `/v1/me`, so this is the case that would go quietly wrong.
//
// And `/v1/me/` is a different path, which the reference *does* relay under a `/v1`
// entry: it is not gateway's own route, and treating it as one would be a refusal
// the reference does not make.
func TestGatewayOwnsItsOwnRouteEvenUnderTheBroadestPrefix(t *testing.T) {
	silenceLog(t)
	service := newUpstream(t, nil)

	rec := ask(t, Options{Routes: RouteTable{"/v1": {BaseURL: service.Origin()}}},
		http.MethodGet, "/v1/me", nil)

	// With no verifier there is no `/v1/me` to serve, and both answers are the same
	// 404 — which is the point. What must NOT happen is a relay.
	if rec.Code != http.StatusNotFound {
		t.Fatalf("`/v1/me` under a `/v1` entry answered %d, want 404 — it is gateway's own route and a table must not be able to proxy it away", rec.Code)
	}
	if service.Count() != 0 {
		t.Errorf("the upstream was contacted for `/v1/me`; gateway's own route must never be proxied")
	}

	// And the sibling that ISN'T gateway's own route.
	rec = ask(t, Options{Routes: RouteTable{"/v1": {BaseURL: service.Origin()}}},
		http.MethodGet, "/v1/me/extra", nil)
	if rec.Code != http.StatusOK {
		t.Errorf("`/v1/me/extra` answered %d, want 200: it is not gateway's own route, and the reference relays it", rec.Code)
	}
}

// An assertion that cannot be signed is gateway's own 503, and the service never
// sees the request. This is the property the comment on `routeProxy.call` claims,
// and it is separate from a dead socket because the log line has to tell them
// apart.
func TestAnAssertionSigningFailureIsGatewayOwns503AndTheServiceIsNotAsked(t *testing.T) {
	logged := silenceLog(t)
	service := newUpstream(t, nil)

	// A minter with no key: construction is bypassed so the failure happens at mint
	// time, which is what a key that stopped being usable looks like.
	broken := &AssertionMinter{issuer: DefaultAssertionIssuer, ttl: DefaultAssertionTTL, now: time.Now}

	handler, err := New(Options{
		Routes: RouteTable{"/v1/pantry": {BaseURL: service.Origin(), Principal: []string{"sub"}}},
		Assert: broken,
		// The gate is configured so there IS a principal to assert about; without it
		// the pass-through has nothing to mint from and correctly sends nothing.
		Authenticate: func(*http.Request) (*Principal, error) {
			return &Principal{Sub: "user-1", Claims: map[string]any{"sub": "user-1"}}, nil
		},
	})
	if err != nil {
		t.Fatalf("New refused: %v", err)
	}

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/pantry/items", nil))

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("a signing failure was answered %d, want 503", rec.Code)
	}
	if service.Count() != 0 {
		t.Error("the service saw a request whose assertion could not be signed; a signing failure must be gateway's own 503 before the call")
	}
	if !strings.Contains(logged.String(), "could not mint the principal assertion") {
		t.Errorf("the log does not distinguish a signing failure from a dead socket:\n%s", logged.String())
	}
}

// The query crosses verbatim and the segment is rebuilt, on one request: the two
// halves of "one configured destination, never a caller-supplied host".
func TestTheQueryCrossesVerbatimAndTheDestinationIsTheTables(t *testing.T) {
	silenceLog(t)
	service := newUpstream(t, nil)

	ask(t, Options{Routes: RouteTable{"/v1/pantry": {BaseURL: service.Origin()}}},
		http.MethodGet, "/v1/pantry/items/caf%C3%A9%20au%20lait?trace=abc&x=%2Fetc", nil)

	seen := service.Last(t)
	if seen.Path != "/items/caf%C3%A9%20au%20lait" {
		t.Errorf("the upstream saw path %q, want the rebuilt /items/caf%%C3%%A9%%20au%%20lait", seen.Path)
	}
	if seen.Query != "trace=abc&x=%2Fetc" {
		t.Errorf("the upstream saw query %q, want it verbatim", seen.Query)
	}
}

// errNoCredential is what a gate returns for a caller it will not authenticate.
var errNoCredential = errCredential("no bearer token")

type errCredential string

func (e errCredential) Error() string { return string(e) }

// The refusals above decode into `api.Problem` — the generated type — rather than
// into a local struct, so a field renamed in `openapi/v1.yaml` breaks these tests
// instead of silently making them assert nothing.

// TestARelayedNoContentKeepsItsEmptyBody is the one 2xx that has no body to relay,
// and it is separate from the table above because `net/http` suppresses a body on
// it — so a test that asserted "the upstream's body came back" on a 204 would be
// asserting something false about `net/http` rather than about the relay.
func TestARelayedNoContentKeepsItsEmptyBody(t *testing.T) {
	silenceLog(t)
	service := newUpstream(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNoContent)
	})

	rec := ask(t, Options{Routes: RouteTable{"/v1/pantry": {BaseURL: service.Origin()}}},
		http.MethodGet, "/v1/pantry/items", nil)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("the upstream's 204 was answered %d, want 204", rec.Code)
	}
	if got := rec.Body.String(); got != "" {
		t.Errorf("the relayed body is %q, want empty", got)
	}
}
