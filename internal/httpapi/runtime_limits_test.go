package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/anywaye/gateway/internal/testkeys"
)

func limitPolicy(t *testing.T, w http.Header) (name, quota, window string) {
	t.Helper()

	value := w.Get("RateLimit-Policy")
	if value == "" {
		t.Fatal("no RateLimit-Policy header on an answered request; the limiter did not run")
	}

	parts := strings.Split(value, ";")
	name = strings.Trim(strings.TrimSpace(parts[0]), `"`)
	for _, param := range parts[1:] {
		key, val, _ := strings.Cut(param, "=")
		switch strings.TrimSpace(key) {
		case "q":
			quota = val
		case "w":
			window = val
		}
	}
	return name, quota, window
}

func gatewayFromEnv(t *testing.T, extra map[string]string) (Options, http.Handler) {
	t.Helper()

	config, err := RuntimeOptions(mapEnv(extra))
	if err != nil {
		t.Fatalf("RuntimeOptions refused the environment: %v", err)
	}
	t.Cleanup(config.CloseResources)

	handler, err := New(config.Options)
	if err != nil {
		t.Fatalf("New refused the configuration RuntimeOptions built: %v", err)
	}
	return config.Options, handler
}

func authenticatedGateway(t *testing.T) (http.Handler, string) {
	t.Helper()

	fixture := newJWKSFixture(t)
	options, _ := gatewayFromEnv(t, map[string]string{
		"IDENTITY_JWKS_URL": fixture.URL,
		"IDENTITY_ISSUER":   testkeys.Issuer,
		"GATEWAY_CLIENT_ID": testkeys.Audience,
	})

	verifier, err := authVerifierFor(t, fixture)
	if err != nil {
		t.Fatalf("building a verifier for the fixture's key set: %v", err)
	}
	options.Verifier = verifier

	handler, err := New(options)
	if err != nil {
		t.Fatalf("New refused the configuration with a fixture verifier: %v", err)
	}
	return handler, tokenValid(t, fixture)
}

func TestEveryShippedRouteDrawsItsOwnNamedAllowance(t *testing.T) {
	_, gateway := gatewayFromEnv(t, nil)
	secured, token := authenticatedGateway(t)

	for _, tc := range []struct {
		path   string
		policy string
		quota  string
		authed bool
	}{
		{"/auth/login", "gateway-auth-login", "10", false},
		{"/auth/register", "gateway-auth-register", "5", false},
		{"/auth/logout", "gateway-auth-logout", "30", false},
		{"/auth/me", "gateway-auth", "60", false},
		{"/v1/pantry/items", "gateway-api", "600", true},
		{"/v1/api-keys", "gateway-api-keys", "60", true},
		{"/somewhere-else", "gateway-api", "600", false},
	} {
		t.Run(tc.path, func(t *testing.T) {
			handler := gateway
			if tc.authed {
				handler = secured
			}

			req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, tc.path, nil)
			if tc.authed {
				req.Header.Set("Authorization", bearer(token))
			}

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			name, quota, _ := limitPolicy(t, rec.Header())
			if name != tc.policy {
				t.Errorf("%q drew policy %q, want %q", tc.path, name, tc.policy)
			}
			if quota != tc.quota {
				t.Errorf("%q drew q=%s, want q=%s", tc.path, quota, tc.quota)
			}
		})
	}
}

func TestLoginIsNotAnsweredUnderTheDefaultAllowance(t *testing.T) {
	_, handler := gatewayFromEnv(t, nil)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/auth/login", nil))
	name, quota, window := limitPolicy(t, rec.Header())

	if name == "gateway-api" {
		t.Fatal("/auth/login is answered under gateway-api, which is the gap this port closed")
	}
	if name != "gateway-auth-login" {
		t.Fatalf("/auth/login drew policy %q, want gateway-auth-login", name)
	}
	if quota != "10" {
		t.Errorf("/auth/login announced q=%s, want q=10", quota)
	}
	if window != "60" {
		t.Errorf("/auth/login announced w=%s, want w=60", window)
	}
	if got := rec.Header().Get("RateLimit-Limit"); got != "10" {
		t.Errorf("RateLimit-Limit is %q on /auth/login, want 10; the un-prefixed trio is what deployed clients read", got)
	}
}

func TestTheLoginAllowanceIsEnforcedAndNotJustAnnounced(t *testing.T) {
	_, handler := gatewayFromEnv(t, nil)

	for _, tc := range []struct {
		path  string
		allow int
	}{
		{"/auth/login", 10},
		{"/auth/register", 5},
	} {
		t.Run(tc.path, func(t *testing.T) {
			for i := 1; i <= tc.allow; i++ {
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, tc.path, nil))

				if rec.Code == http.StatusTooManyRequests {
					t.Fatalf("request %d of %d was already refused; the allowance is %d, so this test is counting from the wrong number", i, tc.allow, tc.allow)
				}
			}

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, tc.path, nil))

			if rec.Code != http.StatusTooManyRequests {
				t.Fatalf("request %d of %d was answered %d, want 429; the allowance is being announced and not enforced", tc.allow+1, tc.allow, rec.Code)
			}
			if got := rec.Header().Get("Content-Type"); got != "application/problem+json" {
				t.Errorf("Content-Type is %q on the 429, want application/problem+json", got)
			}
			if rec.Header().Get("Retry-After") == "" {
				t.Error("no Retry-After on the 429; a client told to come straight back is a hot loop against a bucket that cannot open yet")
			}
		})
	}
}

func TestExhaustingOneAuthBudgetLeavesTheOtherSpendingItsOwn(t *testing.T) {
	_, handler := gatewayFromEnv(t, nil)

	for i := 0; i < 5; i++ {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/auth/register", nil))
		if rec.Code == http.StatusTooManyRequests {
			t.Fatalf("registration was refused at request %d of 5", i+1)
		}
	}

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/auth/login", nil))

	if rec.Code == http.StatusTooManyRequests {
		t.Error("exhausting the registration budget refused a login; the two share a bucket and a caller could burn one to deny the other")
	}
	if name, _, _ := limitPolicy(t, rec.Header()); name != "gateway-auth-login" {
		t.Errorf("the login request after registration was spent drew policy %q, want gateway-auth-login", name)
	}
}

func TestARouteThatMerelySharesANameDoesNotInheritItsAllowance(t *testing.T) {
	_, handler := gatewayFromEnv(t, nil)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/auth/loginfoo", nil))
	name, quota, _ := limitPolicy(t, rec.Header())

	if name == "gateway-auth-logout" {
		t.Fatalf("/auth/loginfoo drew the logout allowance; a prefix must end at a segment boundary or every new route under /auth inherits a budget by name")
	}
	if name != "gateway-auth" {
		t.Errorf("/auth/loginfoo drew policy %q, want gateway-auth", name)
	}
	if quota != "60" {
		t.Errorf("/auth/loginfoo drew q=%s, want q=60", quota)
	}
}

func TestTheProbePathsAreStillNeverCounted(t *testing.T) {
	_, handler := gatewayFromEnv(t, nil)

	for path := range ProbePaths {
		t.Run(path, func(t *testing.T) {
			for i := 0; i < 5; i++ {
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, path, nil))

				if rec.Code == http.StatusTooManyRequests {
					t.Fatalf("%s was throttled on request %d; a throttled probe is an orchestrator that cannot see a healthy process", path, i+1)
				}
				if got := rec.Header().Get("RateLimit-Policy"); got != "" {
					t.Errorf("%s announced a policy %q; an exempt path should announce nothing rather than a limit it does not enforce", path, got)
				}
			}
		})
	}
}

func TestTheConstructorAllowanceDoesNotOverrideAnEntryTheTableNames(t *testing.T) {
	_, handler := gatewayFromEnv(t, map[string]string{
		"RATE_LIMIT_REQUESTS":  "7",
		"RATE_LIMIT_WINDOW_MS": "30000",
	})

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/auth/login", nil))

	if name, quota, window := limitPolicy(t, rec.Header()); name != "gateway-auth-login" || quota != "10" || window != "60" {
		t.Errorf("/auth/login drew %s;q=%s;w=%s, want gateway-auth-login;q=10;w=60; a route the table names must not inherit RATE_LIMIT_REQUESTS", name, quota, window)
	}
}
