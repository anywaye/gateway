package httpapi

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestABadVHostTableIsARefusalToConstructTheGateway(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name     string
		document string
		want     string
	}{
		{"empty object routes nothing", `{}`, "at least one hostname"},
		{"not JSON at all", `auth.anywaye.test`, "VHOST_TABLE must be a JSON object"},
		{"not an object", `["auth.anywaye.test"]`, "VHOST_TABLE must be a JSON object"},
		{"entry not an object", `{"auth.anywaye.test": "http://x"}`, "must be an object with a baseUrl"},
		{"scheme is not a hostname", `{"https://auth.anywaye.test": {"baseUrl": "http://127.0.0.1:9"}}`, "bare hostname"},
		{"port is not a hostname", `{"auth.anywaye.test:443": {"baseUrl": "http://127.0.0.1:9"}}`, "bare hostname"},
		{"uppercase is not said plainly", `{"Auth.anywaye.test": {"baseUrl": "http://127.0.0.1:9"}}`, "lowercase"},
		{"wildcard is a second matching language", `{"*.anywaye.test": {"baseUrl": "http://127.0.0.1:9"}}`, "bare hostname"},
		{"empty base", `{"auth.anywaye.test": {"baseUrl": ""}}`, "baseUrl must be a non-empty string"},
		{"base with a path swallows the call", `{"auth.anywaye.test": {"baseUrl": "http://127.0.0.1:9/oidc"}}`, "no path"},
		{"base with credentials logs a password", `{"auth.anywaye.test": {"baseUrl": "http://user:pass@127.0.0.1:9"}}`, "must not carry credentials"},
		{"empty token is not no token", `{"auth.anywaye.test": {"baseUrl": "http://127.0.0.1:9", "token": ""}}`, "non-empty string"},
		{"token with a newline is header injection", "{\"auth.anywaye.test\": {\"baseUrl\": \"http://127.0.0.1:9\", \"token\": \"a\\nb\"}}", "whitespace or control"},
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
			if _, err := New(Options{VHosts: VHostTable{"auth.anywaye.test": {BaseURL: "http://127.0.0.1:9\n"}}}); err == nil {
				t.Fatal("New with an unvalidatable vhost table constructed a gateway; validation must refuse before assembly")
			}
		})
	}
}

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

func TestEffectiveHostIsCaseInsensitiveAndPortless(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct{ host, want string }{
		{"auth.anywaye.test", "auth.anywaye.test"},
		{"Auth.Anywaye.Test", "auth.anywaye.test"},
		{"auth.anywaye.test:443", "auth.anywaye.test"},
		{"AUTH.ANYWAYE.TEST:19090", "auth.anywaye.test"},
		{"127.0.0.1:19090", "127.0.0.1"},
	} {
		r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "https://ignored/.well-known/openid-configuration", nil)
		r.Host = tc.host
		if got := effectiveHost(r); got != tc.want {
			t.Errorf("effectiveHost(%q) = %q, want %q", tc.host, got, tc.want)
		}
	}
}

func TestGatewayOwnPathsAreNeverVhostProxied(t *testing.T) {
	t.Parallel()

	backend := newUpstream(t, nil)
	handler, err := New(Options{VHosts: VHostTable{"api.anywaye.test": {BaseURL: backend.Origin()}}})
	if err != nil {
		t.Fatalf("New = %v, want a gateway", err)
	}

	for _, path := range []string{"/healthz", "/readyz"} {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, path, nil)
		req.Host = "api.anywaye.test"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("GET %s through api.anywaye.test = %d, want 200 from gateway itself", path, rec.Code)
		}
	}

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/v1/me", nil)
	req.Host = "api.anywaye.test"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("GET /v1/me through api.anywaye.test = %d, want the router's 404 (no verifier configured)", rec.Code)
	}

	backend.mu.Lock()
	requests := backend.requests
	backend.mu.Unlock()
	if requests != 0 {
		t.Fatalf("the backend received %d requests for gateway-owned paths; none may cross", requests)
	}
}

func TestAnUnknownHostnameFallsThroughToTheRouter(t *testing.T) {
	t.Parallel()

	backend := newUpstream(t, nil)
	handler, err := New(Options{VHosts: VHostTable{"auth.anywaye.test": {BaseURL: backend.Origin()}}})
	if err != nil {
		t.Fatalf("New = %v, want a gateway", err)
	}

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/.well-known/openid-configuration", nil)
	req.Host = "unknown.anywaye.test"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("GET through an unknown hostname = %d, want the router's 404", rec.Code)
	}
}

func TestANamedHostnameProxiesTheWholePathToItsBackend(t *testing.T) {
	t.Parallel()

	backend := newUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"issuer":"https://auth.anywaye.test"}`)
	})
	handler, err := New(Options{VHosts: VHostTable{"auth.anywaye.test": {BaseURL: backend.Origin(), Token: "service-token"}}})
	if err != nil {
		t.Fatalf("New = %v, want a gateway", err)
	}

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/.well-known/openid-configuration?pretty=true", nil)
	req.Host = "auth.anywaye.test"
	req.Header.Set("Authorization", "Bearer caller-credential")
	req.Header.Set("Cookie", "session=caller-cookie")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET discovery through auth.anywaye.test = %d, want 200", rec.Code)
	}
	if body := rec.Body.String(); !strings.Contains(body, "https://auth.anywaye.test") {
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
	if host := got.Header.Get("Host"); strings.Contains(host, "anywaye.test") {
		t.Errorf("backend Host = %q, want the backend's own: the caller's Host never crosses", host)
	}
}

func TestATraversalThroughANamedHostnameReachesNoBackend(t *testing.T) {
	t.Parallel()

	backend := newUpstream(t, nil)
	handler, err := New(Options{VHosts: VHostTable{"auth.anywaye.test": {BaseURL: backend.Origin()}}})
	if err != nil {
		t.Fatalf("New = %v, want a gateway", err)
	}

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/a%2f..%2f..%2fsecret", nil)
	req.Host = "auth.anywaye.test"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("GET /a%%2f..%%2f..%%2fsecret through auth.anywaye.test = %d, want 404", rec.Code)
	}

	backend.mu.Lock()
	defer backend.mu.Unlock()
	if backend.requests != 0 {
		t.Fatal("the backend received a traversal; a rebuilt path must make it inexpressible")
	}
}

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
			"api.anywaye.test":  {BaseURL: api.Origin()},
			"auth.anywaye.test": {BaseURL: auth.Origin()},
		},
	})
	if err != nil {
		t.Fatalf("New = %v, want a gateway", err)
	}

	apiReq := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/v1/pantry/items", nil)
	apiReq.Host = "api.anywaye.test"
	apiRec := httptest.NewRecorder()
	handler.ServeHTTP(apiRec, apiReq)
	if apiRec.Body.String() != `{"surface":"api"}` {
		t.Fatalf("GET /v1/pantry/items through api.anywaye.test = %q, want the path table's backend", apiRec.Body.String())
	}

	authReq := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/oidc/authorize", nil)
	authReq.Host = "auth.anywaye.test"
	authRec := httptest.NewRecorder()
	handler.ServeHTTP(authRec, authReq)
	if authRec.Body.String() != `{"surface":"auth"}` {
		t.Fatalf("GET /oidc/authorize through auth.anywaye.test = %q, want the vhost's backend", authRec.Body.String())
	}
}
