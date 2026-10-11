package httpapi

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A bad vhost table is a refusal to construct the gateway, and the message names
// the hostname — the same rule the path table follows, because a name that routes
// nowhere answers 404 for a backend that exists and nothing about that failure
// points at configuration.
func TestABadVHostTableIsARefusalToConstructTheGateway(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name     string
		document string
		want     string
	}{
		{"empty object routes nothing", `{}`, "at least one hostname"},
		{"not JSON at all", `auth.cafaye.test`, "VHOST_TABLE must be a JSON object"},
		{"not an object", `["auth.cafaye.test"]`, "VHOST_TABLE must be a JSON object"},
		{"entry not an object", `{"auth.cafaye.test": "http://x"}`, "must be an object with a baseUrl"},
		{"scheme is not a hostname", `{"https://auth.cafaye.test": {"baseUrl": "http://127.0.0.1:9"}}`, "bare hostname"},
		{"port is not a hostname", `{"auth.cafaye.test:443": {"baseUrl": "http://127.0.0.1:9"}}`, "bare hostname"},
		{"uppercase is not said plainly", `{"Auth.cafaye.test": {"baseUrl": "http://127.0.0.1:9"}}`, "lowercase"},
		{"wildcard is a second matching language", `{"*.cafaye.test": {"baseUrl": "http://127.0.0.1:9"}}`, "bare hostname"},
		{"empty base", `{"auth.cafaye.test": {"baseUrl": ""}}`, "baseUrl must be a non-empty string"},
		{"base with a path swallows the call", `{"auth.cafaye.test": {"baseUrl": "http://127.0.0.1:9/oidc"}}`, "no path"},
		{"base with credentials logs a password", `{"auth.cafaye.test": {"baseUrl": "http://user:pass@127.0.0.1:9"}}`, "must not carry credentials"},
		{"empty token is not no token", `{"auth.cafaye.test": {"baseUrl": "http://127.0.0.1:9", "token": ""}}`, "non-empty string"},
		{"token with a newline is header injection", "{\"auth.cafaye.test\": {\"baseUrl\": \"http://127.0.0.1:9\", \"token\": \"a\\nb\"}}", "whitespace or control"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			table, err := ParseVHostTable(tc.document)
			if err == nil {
				t.Fatalf("ParseVHostTable(%q) = %v, want a refusal naming %q", tc.document, table, tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("ParseVHostTable(%q) error = %q, want it to name %q", tc.document, err, tc.want)
			}
			if _, err := New(Options{VHosts: VHostTable{"auth.cafaye.test": {BaseURL: "http://127.0.0.1:9\n"}}}); err == nil {
				t.Fatal("New with an unvalidatable vhost table constructed a gateway; validation must refuse before assembly")
			}
		})
	}
}

// An unset split is a gateway whose routing is the path table alone — not a
// refusal, because a deployment that has not decided names mean different
// backends is a deployment like every one that shipped before this file existed.
func TestAnUnsetVHostTableIsThePathTableAlone(t *testing.T) {
	t.Parallel()

	for _, document := range []string{"", "   ", "\n\t "} {
		table, err := ParseVHostTable(document)
		if err != nil {
			t.Fatalf("ParseVHostTable(%q) = %v, want no table and no error", document, err)
		}
		if table != nil {
			t.Fatalf("ParseVHostTable(%q) = %v, want nil", document, table)
		}
	}
	if gate := vhostGate(nil, 0, nil); gate != nil {
		t.Fatal("vhostGate(nil, …) is a middleware; a gate that cannot refuse is not a gate and the honest spelling of none is the absence")
	}
}

// The Host header is matched case-insensitively with any port stripped, because
// that is what a browser sends: `Auth.cafaye.test:443` is the same name as
// `auth.cafaye.test`, and a split that missed it would route TLS traffic by no
// rule a reader could find.
func TestEffectiveHostIsCaseInsensitiveAndPortless(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct{ host, want string }{
		{"auth.cafaye.test", "auth.cafaye.test"},
		{"Auth.Cafaye.Test", "auth.cafaye.test"},
		{"auth.cafaye.test:443", "auth.cafaye.test"},
		{"AUTH.CAFAYE.TEST:19090", "auth.cafaye.test"},
		{"127.0.0.1:19090", "127.0.0.1"},
	} {
		r := httptest.NewRequest(http.MethodGet, "https://ignored/.well-known/openid-configuration", nil)
		r.Host = tc.host
		if got := effectiveHost(r); got != tc.want {
			t.Errorf("effectiveHost(%q) = %q, want %q", tc.host, got, tc.want)
		}
	}
}

// Gateway's own paths are never proxied away, whatever Host arrived: the probes
// stay answerable through `api.cafaye.test` (readyz green on the API name is one
// of the loop's proofs), and the browser surface and gateway's own routes are
// answered here for the reason routeProxy.handle names its exclusion.
func TestGatewayOwnPathsAreNeverVhostProxied(t *testing.T) {
	t.Parallel()

	backend := newUpstream(t, nil)
	handler, err := New(Options{VHosts: VHostTable{"api.cafaye.test": {BaseURL: backend.Origin()}}})
	if err != nil {
		t.Fatalf("New = %v, want a gateway", err)
	}

	// The probes answer 200 from gateway itself.
	for _, path := range []string{"/healthz", "/readyz"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Host = "api.cafaye.test"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("GET %s through api.cafaye.test = %d, want 200 from gateway itself", path, rec.Code)
		}
	}

	// `/v1/me` is gateway's own route too: without a verifier it declines with
	// the router's 404 rather than 200, and the assertion that matters is the
	// same — the backend never sees it.
	req := httptest.NewRequest(http.MethodGet, "/v1/me", nil)
	req.Host = "api.cafaye.test"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("GET /v1/me through api.cafaye.test = %d, want the router's 404 (no verifier configured)", rec.Code)
	}

	backend.mu.Lock()
	requests := backend.requests
	backend.mu.Unlock()
	if requests != 0 {
		t.Fatalf("the backend received %d requests for gateway-owned paths; none may cross", requests)
	}
}

// A hostname the table does not name falls through to the path table and then the
// router — which is what keeps the split additive: unknown names behave exactly
// as before this file existed.
func TestAnUnknownHostnameFallsThroughToTheRouter(t *testing.T) {
	t.Parallel()

	backend := newUpstream(t, nil)
	handler, err := New(Options{VHosts: VHostTable{"auth.cafaye.test": {BaseURL: backend.Origin()}}})
	if err != nil {
		t.Fatalf("New = %v, want a gateway", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	req.Host = "unknown.cafaye.test"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("GET through an unknown hostname = %d, want the router's 404", rec.Code)
	}
}

// The named hostname proxies the whole path to its backend: status and body
// cross, the query crosses, the caller's credential does not, and gateway's
// service token does.
func TestANamedHostnameProxiesTheWholePathToItsBackend(t *testing.T) {
	t.Parallel()

	backend := newUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"issuer":"https://auth.cafaye.test"}`)
	})
	handler, err := New(Options{VHosts: VHostTable{"auth.cafaye.test": {BaseURL: backend.Origin(), Token: "service-token"}}})
	if err != nil {
		t.Fatalf("New = %v, want a gateway", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration?pretty=true", nil)
	req.Host = "auth.cafaye.test"
	req.Header.Set("Authorization", "Bearer caller-credential")
	req.Header.Set("Cookie", "session=caller-cookie")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET discovery through auth.cafaye.test = %d, want 200", rec.Code)
	}
	if body := rec.Body.String(); !strings.Contains(body, "https://auth.cafaye.test") {
		t.Fatalf("discovery body = %q, want the backend's answer to cross", body)
	}

	got := backend.Last(t)
	if got.Path != "/.well-known/openid-configuration" {
		t.Errorf("backend path = %q, want the full path, not a prefix remainder", got.Path)
	}
	if got.Query != "pretty=true" {
		t.Errorf("backend query = %q, want it to cross", got.Query)
	}
	if auth := got.Header.Get("Authorization"); auth != "Bearer service-token" {
		t.Errorf("backend Authorization = %q, want gateway's service token and nothing of the caller's", auth)
	}
	if cookie := got.Header.Get("Cookie"); cookie != "" {
		t.Errorf("backend Cookie = %q, want nothing: the caller's cookie never crosses", cookie)
	}
	if host := got.Header.Get("Host"); strings.Contains(host, "cafaye.test") {
		t.Errorf("backend Host = %q, want the backend's own: the caller's Host never crosses", host)
	}
}

// A traversal through a named hostname is not expressible: an encoded separator
// inside a segment survives URL normalisation (it is one segment, not three) and
// `UpstreamPath` refuses it, so the request falls through to the router's 404
// rather than reaching the backend in any spelling. A plain `%2e%2e` segment, by
// contrast, resolves the way the URL parser resolves it — `/%2e%2e/secret` is
// `/secret` on the same backend, which escaped nothing.
func TestATraversalThroughANamedHostnameReachesNoBackend(t *testing.T) {
	t.Parallel()

	backend := newUpstream(t, nil)
	handler, err := New(Options{VHosts: VHostTable{"auth.cafaye.test": {BaseURL: backend.Origin()}}})
	if err != nil {
		t.Fatalf("New = %v, want a gateway", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/a%2f..%2f..%2fsecret", nil)
	req.Host = "auth.cafaye.test"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("GET /a%%2f..%%2f..%%2fsecret through auth.cafaye.test = %d, want 404", rec.Code)
	}

	backend.mu.Lock()
	defer backend.mu.Unlock()
	if backend.requests != 0 {
		t.Fatal("the backend received a traversal; a rebuilt path must make it inexpressible")
	}
}

// The split changes nothing about the API surface: with both tables configured,
// a /v1 path on the API name is still answered by the path table's backend, and
// the OIDC face on the auth name by the vhost's.
func TestTheVhostSplitLeavesThePathTableAlone(t *testing.T) {
	t.Parallel()

	api := newUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"surface":"api"}`)
	})
	auth := newUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"surface":"auth"}`)
	})
	handler, err := New(Options{
		Routes: RouteTable{"/v1": {BaseURL: api.Origin()}},
		VHosts: VHostTable{
			"api.cafaye.test":  {BaseURL: api.Origin()},
			"auth.cafaye.test": {BaseURL: auth.Origin()},
		},
	})
	if err != nil {
		t.Fatalf("New = %v, want a gateway", err)
	}

	apiReq := httptest.NewRequest(http.MethodGet, "/v1/pantry/items", nil)
	apiReq.Host = "api.cafaye.test"
	apiRec := httptest.NewRecorder()
	handler.ServeHTTP(apiRec, apiReq)
	if apiRec.Body.String() != `{"surface":"api"}` {
		t.Fatalf("GET /v1/pantry/items through api.cafaye.test = %q, want the path table's backend", apiRec.Body.String())
	}

	authReq := httptest.NewRequest(http.MethodGet, "/oidc/authorize", nil)
	authReq.Host = "auth.cafaye.test"
	authRec := httptest.NewRecorder()
	handler.ServeHTTP(authRec, authReq)
	if authRec.Body.String() != `{"surface":"auth"}` {
		t.Fatalf("GET /oidc/authorize through auth.cafaye.test = %q, want the vhost's backend", authRec.Body.String())
	}
}
