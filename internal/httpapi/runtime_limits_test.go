// The per-route allowance table, as the SHIPPED BINARY enforces it.
//
// `internal/ratelimit/limits_test.go` holds the table and the resolution rule. This
// file exists because that table is data, and data nothing reads is the exact shape
// the audit found: `Options.Policy` and `Options.Resolve` were already on the
// limiter, nothing set them, and `/auth/login` was served at 600/min. Everything
// here goes through `RuntimeOptions` and `New` -- the path `cmd/gateway` takes --
// because a test that built the resolver itself would have kept passing after the
// wiring was removed.
//
// The assertions name the POLICY, not just "a limit was applied". "Some limit was
// applied" passes with the table absent, and the table being absent is the bug.
package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cafaye/gateway/internal/testkeys"
)

// limitPolicy is the `RateLimit-Policy` value as a gateway builds it: the policy
// name as a structured-field String, then `q` and `w`.
//
// The name is PARSED rather than the whole header compared, so a failure says which
// half went wrong: "drew policy gateway-api, want gateway-auth-login" is a finding,
// and "header was not `"gateway-auth-login";q=10;w=60`" is a rerun.
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

// gatewayFromEnv is the shipped assembly: read the environment, build the router.
//
// There is no `Limiter` constructed by hand anywhere in this file, because a
// hand-built one is a test that cannot tell a wired gateway from an unwired one.
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

// The AUTHENTICATED gateway, and the two reasons it is a separate helper. Both were
// found by running the assertion, not by reading the code.
//
// # ONE: THE LIMITER IS MOUNTED AFTER THE CREDENTIAL GATE, AND THAT IS THE DESIGN
//
// `httpapi.go` mounts the verifier on `/v1/` and the limiter after it, so an
// ANONYMOUS `/v1` request is answered 401 with no `RateLimit-*` header on it at
// all. That is `limiter.go`'s own stated reason: a request refused by the auth gate
// is never counted, because a token that does not verify must not become a
// rate-limit key.
//
// The consequence for this file is worth spelling out. Asserting a `/v1` allowance
// needs a token that verifies, and reading `RateLimit-Policy` off an anonymous
// `/v1` request finds no header and reads as "the table does not apply to `/v1`",
// which is the opposite of what is true.
//
// # TWO: NO TOKEN THIS REPOSITORY CAN MINT VERIFIES AGAINST THE RUNTIME
//
// `testkeys` anchors every `exp` at `testkeys.Clock` (2026-01-02) and
// `RuntimeOptions` builds the verifier on the real clock with no way to inject one.
// A token minted by `testkeys` for a RuntimeOptions-built gateway is therefore
// expired by construction and always answers 401. `authVerifierFor` in
// `fixture_test.go` sidesteps this by injecting the fixed clock, which a gateway
// built from the environment has no way to do.
//
// So the VERIFIER is swapped and nothing else is. The limiter used below is the one
// `RuntimeOptions` built from the shipped table -- the thing under test, enforced
// for real by `TestTheLoginAllowanceIsEnforcedAndNotJustAnnounced` -- and only the
// credential check is replaced, so that a token can exist. Building the limiter here
// instead would be the test that keeps passing after the wiring is removed, which is
// the exact shape of the gap this packet closed.
//
// For whoever owns the fixtures: a clock injectable through the environment would
// remove the need for this seam entirely. That is a change to `RuntimeOptions`,
// whose variable list is asserted by `TestTheRuntimeReaderReadsExactlyTheseVariables`,
// and it is not this packet's to make.
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

// EVERY SHIPPED ENTRY, BY NAME, THROUGH THE RUNTIME.
//
// The order is the reference's, and the row that matters most is the first: a
// gateway that resolved `/auth/login` to `gateway-api` would be 60x more
// permissive on the most attacked surface it serves, and it would still announce
// `q=600` and look configured.
//
// `/v1` needs the token `authenticatedGateway` mints; `/auth` and unrecognized
// paths do not, because the credential gate is mounted on `/v1/` only. Nothing
// asserts the STATUS here -- which route a path resolves to is the route table's
// business and is tested there -- because a `404` from an unmounted route still
// says which allowance was drawn, which is the whole question here.
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

// THE ASSERTION THAT KILLS THE ACTUAL GAP, in one test.
//
// `/auth/login` must not be answered under the default allowance. Both facts are
// asserted separately on purpose: a gateway that announced `gateway-auth-login`
// while enforcing `q=600` is the failure a header-only check cannot see, and a
// gateway that enforced 10 while announcing `gateway-api` is the one a caller
// cannot self-diagnose.
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

// THE NUMBERS ARE ENFORCED, NOT ANNOUNCED. This is the test a header assertion
// cannot replace.
//
// Ten requests are admitted and the eleventh is refused on `/auth/login`, five and
// the sixth on `/auth/register`. Under the pre-port wiring all of them were
// admitted and every response carried `q=600`, so this is the assertion that
// distinguishes a table that is WIRED from a table that is merely PRESENT, and it
// is why the quota is asserted by exhausting it rather than only by reading it back.
//
// Every request comes from the same peer, so every request shares one bucket: the
// counter is keyed on the strongest identity the request has, and an anonymous
// request's strongest identity is its address.
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

// The two are SEPARATE BUCKETS, and this is the property that makes the four auth
// entries worth having.
//
// Login and register share a prefix family and are two entries precisely so they are
// two policies. A caller who has burned the registration budget must not be able to
// lock out every legitimate sign-up from that address, and a caller brute-forcing
// logins must not be spending the registration allowance while they do it.
// Exhausting one must leave the other admitting.
//
// The counter key leads with the policy name, so this is a property of the key and
// not of the counting.
func TestExhaustingOneAuthBudgetLeavesTheOtherSpendingItsOwn(t *testing.T) {
	_, handler := gatewayFromEnv(t, nil)

	for i := 0; i < 5; i++ {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/auth/register", nil))
		if rec.Code == http.StatusTooManyRequests {
			t.Fatalf("registration was refused at request %d of 5", i+1)
		}
	}

	// Registration is spent. Login is a different policy and is untouched.
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/auth/login", nil))

	if rec.Code == http.StatusTooManyRequests {
		t.Error("exhausting the registration budget refused a login; the two share a bucket and a caller could burn one to deny the other")
	}
	if name, _, _ := limitPolicy(t, rec.Header()); name != "gateway-auth-login" {
		t.Errorf("the login request after registration was spent drew policy %q, want gateway-auth-login", name)
	}
}

// The boundary rule, through the runtime, in the PERMISSIVE direction, which is
// the direction that is a bug.
//
// `/auth/loginfoo` shares a name with `/auth/logout` and is not under it. It draws
// the auth-adjacent entry, and a matcher using a raw string prefix would hand it the
// 30/min logout budget. The assertion names the policy, so the failure says which
// entry answered rather than only that something was wrong.
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

// The probes are exempt, and that exemption is the only thing standing between the
// table and a restart loop.
//
// `Options.Exempt` was already wired; this asserts the table did not quietly take
// over from it. An orchestrator polling `/readyz` is metered at 60/min on the
// auth-adjacent default if the exemption is lost, and a throttled probe is an
// orchestrator that cannot see a healthy process.
//
// NO STATUS IS ASSERTED, and that is deliberate rather than lazy. This gateway is
// built with no identity to ask, so `/readyz` correctly answers `503` and `/healthz`
// correctly answers `200`. The property under test is that neither is ever a `429`,
// and asserting `200` on `/readyz` would be asserting something about dependency
// reachability that has nothing to do with rate limiting. The paths are read from
// `ProbePaths` rather than typed here, so a probe added later fails this test
// rather than quietly ceasing to be covered.
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

// The window is per ENTRY, and the limiter's constructor values still govern
// anything no entry claims.
//
// `RATE_LIMIT_REQUESTS` and `RATE_LIMIT_WINDOW_MS` set the limiter's fallback, and
// the reference's `rateLimit.ts` keeps them as the allowance for a policy the table
// does not name. The shipped table names every policy it enforces, so these are the
// fallback for a table that has been replaced -- and the point of the case is that
// the per-route table did not make them inert.
//
// The `/auth/login` assertion is the load-bearing half. Setting `RATE_LIMIT_REQUESTS`
// must NOT widen `/auth/login` back to the constructor's number, or the pre-port bug
// arrives through a different door: a table that is wired but overridden by an
// environment variable that still works.
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
