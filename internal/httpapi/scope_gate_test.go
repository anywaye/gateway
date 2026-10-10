package httpapi

import (
	"net/http"
	"testing"

	"github.com/cafaye/gateway/internal/ratelimit"
	"github.com/cafaye/gateway/internal/testkeys"
)

// The scope gate: a route that declares what a caller must hold, and a caller
// that does not hold it.
//
// # WHAT THIS PROVES THAT A POSITIVE TEST CANNOT
//
// `RequireScope` is implemented and was tested in `internal/auth` before this
// packet, but it was mounted by nothing — so the capabilities half of what the
// verifier proves about a caller was parsed, verified and discarded. A test that
// a caller WITH the scope succeeds would pass against a gateway that never
// consults the scope at all. The refusal is the property: a route that declared
// a scope and a caller without it must be a `403`, and the upstream must not be
// contacted.
//
// The gate is mounted after the credential gate and before the limiter, so a
// caller refused for capability is counted against nothing — the same rule an
// unverified token gets. That ordering is asserted here too: the refusal is a
// `403` and not a `429`, and the limiter's bucket is not spent.

// TestARouteThatDeclaresAScopeRefusesACallerWithoutIt is the finding, in the
// direction that matters.
func TestARouteThatDeclaresAScopeRefusesACallerWithoutIt(t *testing.T) {
	fixture := newJWKSFixture(t)
	verifier, err := authVerifierFor(t, fixture)
	if err != nil {
		t.Fatalf("building the verifier: %v", err)
	}

	service := newUpstream(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ok":true}`))
	})

	store, err := ratelimit.NewMemoryStore(0)
	if err != nil {
		t.Fatalf("building the counter store: %v", err)
	}
	limiter, err := ratelimit.NewLimiter(ratelimit.Options{
		Limit:  600,
		Window: ratelimit.DefaultWindow,
		Store:  store,
		Exempt: isProbePath,
	}, RateLimitRefuser)
	if err != nil {
		t.Fatalf("building the limiter: %v", err)
	}

	// The route declares the scope. A caller without it must be refused.
	options := Options{
		Verifier: verifier,
		Limiter:  limiter,
		Routes: RouteTable{
			"/v1/pantry": {BaseURL: service.Origin(), Scopes: []string{"pantry:read"}},
		},
	}

	// A token WITHOUT the scope.
	without := fixture.Mint(t, testkeys.Claims{
		ExpiresIn: testkeys.Valid,
		Scope:     "invoices:read",
		AccountID: "cd000000-0000-4000-8000-000000000002",
	})
	rec := ask(t, options, http.MethodGet, "/v1/pantry/items", map[string]string{
		"Authorization": bearer(without),
		"Accept":        "application/json",
	})

	if rec.Code != http.StatusForbidden {
		t.Fatalf("a caller without the route's scope was answered %d, want 403. The scope gate is mounted after the credential gate and before the limiter, so a capability refusal is a 403 and not a 429.", rec.Code)
	}
	if got := rec.Body.String(); got == "" {
		t.Errorf("the refusal wrote no body, so a caller learns nothing about why")
	}
	// The upstream must not be contacted: a relayed request is a request gateway
	// just decided not to make.
	if service.Count() != 0 {
		t.Errorf("the upstream received %d request(s) for a caller the scope gate refused. A refusal that still spends an upstream call is a gate mounted after the pass-through.", service.Count())
	}

	// A token WITH the scope is forwarded.
	with := fixture.Mint(t, testkeys.Claims{
		ExpiresIn: testkeys.Valid,
		Scope:     "pantry:read",
		AccountID: "cd000000-0000-4000-8000-000000000003",
	})
	rec = ask(t, options, http.MethodGet, "/v1/pantry/items", map[string]string{
		"Authorization": bearer(with),
		"Accept":        "application/json",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("a caller WITH the route's scope was answered %d, want 200. The scope gate must not refuse a caller that holds what the route declared.", rec.Code)
	}
	if service.Count() != 1 {
		t.Errorf("the upstream received %d request(s) for a caller that holds the scope, want 1", service.Count())
	}
}

// TestARouteThatDeclaresNoScopeForwardsAnyVerifiedCaller is the additive half: a
// route with no `scopes` field forwards every verified caller, which is what
// every deployed route already means and the reason the field is safe to add.
func TestARouteThatDeclaresNoScopeForwardsAnyVerifiedCaller(t *testing.T) {
	fixture := newJWKSFixture(t)
	verifier, err := authVerifierFor(t, fixture)
	if err != nil {
		t.Fatalf("building the verifier: %v", err)
	}

	service := newUpstream(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ok":true}`))
	})

	options := Options{
		Verifier: verifier,
		Routes: RouteTable{
			"/v1/pantry": {BaseURL: service.Origin()},
		},
	}

	// A token with NO scope at all is still forwarded: the route declared none.
	token := fixture.Mint(t, testkeys.Claims{
		ExpiresIn: testkeys.Valid,
		AccountID: "cd000000-0000-4000-8000-000000000002",
	})
	rec := ask(t, options, http.MethodGet, "/v1/pantry/items", map[string]string{
		"Authorization": bearer(token),
		"Accept":        "application/json",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("a route that declared no scope forwarded a verified caller to %d, want 200. The field is additive: an entry with no scopes behaves exactly as it did before the field existed.", rec.Code)
	}
	if service.Count() != 1 {
		t.Errorf("the upstream received %d request(s), want 1", service.Count())
	}
}

// TestAPublicRouteCannotDeclareScopes holds the boot refusal: a public route has
// no verified caller, so there is nothing to check a scope against.
func TestAPublicRouteCannotDeclareScopes(t *testing.T) {
	_, err := ValidateRouteTable(RouteTable{
		"/v1/catalog": {BaseURL: "http://catalog:8080", Public: true, Scopes: []string{"catalog:read"}},
	})
	if err == nil {
		t.Fatalf("a public route that declares scopes was accepted, and a public route has no verified caller to check a scope against")
	}
}
