package httpapi

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/anywaye/gateway/internal/api"
	"github.com/anywaye/gateway/internal/auth"
	"github.com/anywaye/gateway/internal/ratelimit"
)



type recordedRequest struct {
	Method string
	Path   string
	Query  string
	Header http.Header
	Body   string
}

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

func (u *upstream) Origin() string { return u.server.URL }

func (u *upstream) Last(t *testing.T) recordedRequest {
	t.Helper()

	u.mu.Lock()
	defer u.mu.Unlock()
	if u.requests == 0 {
		t.Fatal("the upstream received nothing, so every assertion about what crossed is vacuous")
	}
	return u.last
}

func (u *upstream) Count() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.requests
}

func testKey(t *testing.T) AssertionKey {
	t.Helper()

	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("cannot generate a test signing key: %v", err)
	}
	return AssertionKey{Private: private, Public: &private.PublicKey}
}

func silenceLog(t *testing.T) *strings.Builder {
	t.Helper()

	previous := stderr
	captured := &strings.Builder{}
	stderr = captured
	t.Cleanup(func() { stderr = previous })

	return captured
}


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

	for _, name := range ForwardedRequestHeaders {
		canonical := http.CanonicalHeaderKey(name)
		if got, want := seen.Header.Get(name), sent[canonical]; got != want {
			t.Errorf("the upstream saw %s: %q, want the caller's %q", name, got, want)
		}
	}

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

func TestABodyIsStreamedAndItsContentTypeCrossesWithIt(t *testing.T) {
	silenceLog(t)
	service := newUpstream(t, nil)

	payload := `{"name":"a service","version":"1.0.0"}`
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/pantry/services", strings.NewReader(payload))
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


func TestOnlyA2xxOrA4xxIsRelayed(t *testing.T) {
	relayed := []int{200, 201, 202, 299, 400, 401, 403, 404, 409, 413, 422, 423, 429, 499}
	translated := []int{300, 301, 302, 303, 304, 307, 308, 399, 500, 502, 503, 504}

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

func TestTheTwoServiceFailuresAreDifferentSentencesAndDifferentLogLines(t *testing.T) {
	silenceLog(t)

	unreachable := newUpstream(t, nil)
	unreachable.server.Close()
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

func TestTheLogNamesTheShapeOfAnAnswerAndNeverItsBody(t *testing.T) {
	logged := silenceLog(t)
	service := newUpstream(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusInternalServerError)
		io.WriteString(w, `<html>failed to reach pantry: token anywaye_secretvalue</html>`)
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
	if strings.Contains(logged.String(), "anywaye_secretvalue") {
		t.Errorf("the credential from the upstream's body reached the log:\n%s", logged.String())
	}
}

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

func TestAResponseWithNoContentTypeIsRelayedAsOctetStreamNotSniffed(t *testing.T) {
	silenceLog(t)
	service := newUpstream(t, func(w http.ResponseWriter, _ *http.Request) {
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

func TestARequestTheAuthGateRefusedIsNotCounted(t *testing.T) {
	silenceLog(t)
	service := newUpstream(t, nil)
	store := newCountingStore(t)

	options := Options{
		Routes: RouteTable{
			"/v1/pantry":  {BaseURL: service.Origin()},
			"/v1/catalog": {BaseURL: service.Origin(), Public: true},
		},
		Authenticate: func(*http.Request) (*Principal, error) { return nil, errNoCredential },
		Limiter:      countingLimiter(t, store),
	}

	rec := ask(t, options, http.MethodGet, "/v1/pantry/items", nil)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("an anonymous caller to a private route got %d, want 401. This test is about what the limiter recorded for it, so it needs the refusal to have happened.", rec.Code)
	}
	if got := store.count(); got != 0 {
		t.Errorf("the limiter recorded %d hit(s) for a request the auth gate refused. A refused request must be counted against nothing: counted, a flood of forged tokens spends the shared anonymous bucket for every legitimate anonymous caller.", got)
	}
	if got := rec.Header().Get("RateLimit-Remaining"); got != "" {
		t.Errorf("a 401 carries RateLimit-Remaining: %q, so it announces an allowance this request did not spend. A caller told about a bucket it was not counted against is being told a lie about its own limit.", got)
	}
}

func TestARequestTheAuthGateAcceptedIsCounted(t *testing.T) {
	silenceLog(t)
	service := newUpstream(t, nil)
	store := newCountingStore(t)

	options := Options{
		Routes: RouteTable{"/v1/pantry": {BaseURL: service.Origin()}},
		Authenticate: func(*http.Request) (*Principal, error) {
			return &Principal{Sub: "acct_1"}, nil
		},
		Limiter: countingLimiter(t, store),
	}

	rec := ask(t, options, http.MethodGet, "/v1/pantry/items", nil)

	if rec.Code != http.StatusOK {
		t.Fatalf("an authenticated caller to a private route got %d, want 200 from the upstream.", rec.Code)
	}
	if got := store.count(); got != 1 {
		t.Errorf("the limiter recorded %d hit(s) for an authenticated routed request, want 1. This is the other half of the refusal test above: without it, a gateway whose limiter never runs on forwarded traffic passes both.", got)
	}
	if got := rec.Header().Get("RateLimit-Remaining"); got == "" {
		t.Error("a forwarded request answered no RateLimit-Remaining, so the limiter ran but announced nothing. A limiter that counts silently is one a client cannot pace itself against.")
	}
}

func TestADoubledHeaderIsReducedBeforeTheGatesOnAForwardedRequest(t *testing.T) {
	silenceLog(t)
	service := newUpstream(t, nil)

	h := build(t, func(*http.Request) (*http.Response, error) {
		return answer(http.StatusCreated, `{"id":"11111111-2222-3333-4444-555555555555","email":"a@example.test"}`).Response, nil
	})
	handler, err := New(Options{
		BFF:    bffOf(h),
		Routes: RouteTable{"/v1/catalog": {BaseURL: service.Origin(), Public: true}},
	})
	if err != nil {
		t.Fatalf("New refused a gateway with both a browser surface and a route table: %v", err)
	}

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/v1/catalog/items", nil)
	req.Header.Add("Origin", "https://gateway.test")
	req.Header.Add("Origin", "https://elsewhere.test")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if got := len(req.Header["Origin"]); got != 1 {
		t.Fatalf("Origin still carries %d value(s) when the request reached the gateway's own gates. `collapseRepeatedHeaders` runs outermost precisely so a gate never decides about a value the gateway then throws away, and on a routed path it reaches those gates only through the chain `everyRequest` builds.", got)
	}
	if got := req.Header.Get("Origin"); got != "https://gateway.test" {
		t.Errorf("Origin is %q after the reduction, want the FIRST value %q. The reference takes the first value of a doubled header — refusing one would look stricter and be a divergence.", got, "https://gateway.test")
	}

	if rec.Code != http.StatusOK {
		t.Errorf("a doubled Origin on a public routed path answered %d, want the upstream's 200. The reduction takes the first value, so this request is same-origin and must be forwarded.", rec.Code)
	}
	if service.Count() != 1 {
		t.Errorf("the upstream saw %d request(s), want 1. Without this the assertions above could be read on a gateway that never forwarded at all.", service.Count())
	}
}

func bffOf(h *harness) *BffOptions {
	return &BffOptions{
		IdentityURL: "http://identity.test",
		Sessions:    h.sessions,
		Now:         func() time.Time { return h.now },
		Doer: doerFunc(func(r *http.Request) (*http.Response, error) {
			return answer(http.StatusCreated, `{"id":"11111111-2222-3333-4444-555555555555","email":"a@example.test"}`).Response, nil
		}),
	}
}

func newCountingStore(t *testing.T) *countingStore {
	t.Helper()
	inner, err := ratelimit.NewMemoryStore(0)
	if err != nil {
		t.Fatalf("building an inner store: %v", err)
	}
	return &countingStore{inner: inner}
}

type countingStore struct {
	inner ratelimit.Store
	hits  int
}

func (s *countingStore) Hit(key string, request ratelimit.Request) (ratelimit.Verdict, error) {
	s.hits++
	return s.inner.Hit(key, request)
}

func (s *countingStore) count() int { return s.hits }

func countingLimiter(t *testing.T, store ratelimit.Store) RateLimiter {
	t.Helper()
	limiter, err := ratelimit.NewLimiter(ratelimit.Options{
		Store:  store,
		Exempt: isProbePath,
	}, RateLimitRefuser)
	if err != nil {
		t.Fatalf("building a limiter over the counting store: %v", err)
	}
	return limiter
}

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

func TestGatewayOwnsItsOwnRouteEvenUnderTheBroadestPrefix(t *testing.T) {
	silenceLog(t)
	service := newUpstream(t, nil)

	rec := ask(t, Options{Routes: RouteTable{"/v1": {BaseURL: service.Origin()}}},
		http.MethodGet, "/v1/me", nil)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("`/v1/me` under a `/v1` entry answered %d, want 404 — it is gateway's own route and a table must not be able to proxy it away", rec.Code)
	}
	if service.Count() != 0 {
		t.Errorf("the upstream was contacted for `/v1/me`; gateway's own route must never be proxied")
	}

	rec = ask(t, Options{Routes: RouteTable{"/v1": {BaseURL: service.Origin()}}},
		http.MethodGet, "/v1/me/extra", nil)
	if rec.Code != http.StatusOK {
		t.Errorf("`/v1/me/extra` answered %d, want 200: it is not gateway's own route, and the reference relays it", rec.Code)
	}
}

func TestAnAssertionSigningFailureIsGatewayOwns503AndTheServiceIsNotAsked(t *testing.T) {
	logged := silenceLog(t)
	service := newUpstream(t, nil)

	broken := &AssertionMinter{issuer: DefaultAssertionIssuer, ttl: DefaultAssertionTTL, now: time.Now}

	handler, err := New(Options{
		Routes: RouteTable{"/v1/pantry": {BaseURL: service.Origin(), Principal: []string{"sub"}}},
		Assert: broken,
		Authenticate: func(*http.Request) (*Principal, error) {
			return &Principal{Sub: "user-1", Claims: auth.ClaimsFrom(map[string]any{"sub": "user-1"})}, nil
		},
	})
	if err != nil {
		t.Fatalf("New refused: %v", err)
	}

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/v1/pantry/items", nil))

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

var errNoCredential = errCredential("no bearer token")

type errCredential string

func (e errCredential) Error() string { return string(e) }


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
