package httpapi

// The identity-public drift check and the forwarding behavior it protects.
//
// Identity's public /v1 surface is identity's declaration, not gateway's: every
// operation in identity's openapi/v1.yaml that carries `security: []`. Gateway
// holds a compiled copy of that list (identitypublic.go) and TWO checks keep
// the copy honest:
//
//   - TestIdentityPublicMatchesIdentityDeclaration compares the compiled list
//     against testdata/identity-public.txt, which is extracted mechanically
//     from identity's spec (the provenance and the command are in the file).
//     When identity opens a new public route and this repository has not
//     refreshed, this test goes red.
//   - TestIdentityPublicDriftFixtureIsDetected proves the comparison above is
//     not a check that passes by reading one side: run against a fixture with
//     one invented extra route, it must name exactly that route.
//
// The behavior half below is what the list is FOR: every declared public
// operation is forwarded to identity with no credential, and nothing identity
// did not declare public is opened by it.

import (
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// identityPublicFixture reads one drift-check fixture: one `METHOD /v1/path`
// per line, `#` comments and blank lines ignored.
func identityPublicFixture(t *testing.T, name string) []string {
	t.Helper()

	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("cannot read the identity-public fixture %s: %v", name, err)
	}

	var out []string
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out
}

// TestIdentityPublicMatchesIdentityDeclaration is the control that keeps the
// signup hole closed: the compiled list must equal identity's declaration,
// entry for entry, in both directions.
func TestIdentityPublicMatchesIdentityDeclaration(t *testing.T) {
	declared := identityPublicFixture(t, "identity-public.txt")

	missing, extra := compareIdentityPublicRoutes(declared)
	if len(missing) != 0 {
		t.Errorf("identity declares %d public route(s) gateway does not treat as public: %q. Refresh identitypublic.go from testdata/identity-public.txt (see its header)", len(missing), missing)
	}
	if len(extra) != 0 {
		t.Errorf("gateway treats %d route(s) as identity-public that identity does not declare public: %q. Gateway must not open what identity did not declare", len(extra), extra)
	}
}

// TestIdentityPublicDriftFixtureIsDetected is the RED control for the check
// above: a fixture where identity gained a public route and gateway did not
// must be reported, naming the route. If this passes without naming it, the
// comparison reads one repository and is not a check.
func TestIdentityPublicDriftFixtureIsDetected(t *testing.T) {
	declared := identityPublicFixture(t, "identity-public.extra.txt")

	missing, extra := compareIdentityPublicRoutes(declared)
	if !reflect.DeepEqual(missing, []string{"POST /v1/password-resets/expired-purge"}) {
		t.Errorf("the drift fixture's new route was reported as %q, want exactly [POST /v1/password-resets/expired-purge]. A check that cannot name the new route cannot keep this closed", missing)
	}
	if len(extra) != 0 {
		t.Errorf("the drift fixture reported gateway-only routes %q, want none", extra)
	}
}

// TestIdentityPublicOperationsAreForwardedWithoutACredential is the packet's
// floor and its whole public surface: every operation identity marks
// `security: []` crosses gateway to identity with no token, and identity's
// answer — not a 401 — comes back.
func TestIdentityPublicOperationsAreForwardedWithoutACredential(t *testing.T) {
	silenceLog(t)
	identity := newUpstream(t, nil)

	options := Options{
		IdentityBaseURL: identity.Origin(),
		Authenticate:    func(*http.Request) (*Principal, error) { return nil, errNoCredential },
	}

	// The 15 operations from testdata/identity-public.txt, with concrete
	// values for the template segments. `{token}` and `{provider}` each stand
	// for exactly one segment here, which is the whole of what they match.
	for _, tc := range []struct{ method, path string }{
		{http.MethodPost, "/v1/users"},
		{http.MethodPost, "/v1/signup-timestamp"},
		{http.MethodPost, "/v1/session"},
		{http.MethodPost, "/v1/session/mfa"},
		{http.MethodPost, "/v1/password-resets"},
		{http.MethodPost, "/v1/password-resets/confirm"},
		{http.MethodPost, "/v1/email-verifications"},
		{http.MethodPost, "/v1/email-verifications/confirm"},
		{http.MethodPost, "/v1/email-changes/current-address"},
		{http.MethodPost, "/v1/email-changes/new-address"},
		{http.MethodPost, "/v1/agents"},
		{http.MethodGet, "/v1/agents/claim/abc123"},
		{http.MethodPost, "/v1/session-links/redeem"},
		{http.MethodGet, "/v1/auth/oauth/google"},
		{http.MethodGet, "/v1/auth/oauth/google/callback?code=abc&state=def"},
	} {
		rec := ask(t, options, tc.method, tc.path, nil)
		if rec.Code != http.StatusOK {
			t.Errorf("%s %s answered %d, want 200 from identity: a public identity operation must cross gateway with no credential", tc.method, tc.path, rec.Code)
		}
	}

	if got := identity.Count(); got != 15 {
		t.Errorf("identity saw %d request(s), want 15: every public operation above must have been forwarded", got)
	}
	last := identity.Last(t)
	if last.Path != "/v1/auth/oauth/google/callback" {
		t.Errorf("identity last saw path %q, want the full callback path: the fallback forwards the caller's path, not a stripped one", last.Path)
	}
	if last.Query != "code=abc&state=def" {
		t.Errorf("identity last saw query %q, want the caller's query string verbatim", last.Query)
	}
}

// TestIdentityPrivateOperationsStillRefuseWithoutACredential is the packet's
// ceiling: nothing identity did not declare public is opened by the fallback.
// The three named paths are the brief's green control; the rest are the
// near-misses that a path-only or method-blind matcher would open by mistake.
func TestIdentityPrivateOperationsStillRefuseWithoutACredential(t *testing.T) {
	silenceLog(t)
	identity := newUpstream(t, nil)

	options := Options{
		IdentityBaseURL: identity.Origin(),
		Authenticate:    func(*http.Request) (*Principal, error) { return nil, errNoCredential },
	}

	for _, tc := range []struct{ method, path string }{
		// The brief's control, verbatim.
		{http.MethodGet, "/v1/me"},
		{http.MethodGet, "/v1/accounts"},
		{http.MethodGet, "/v1/introspections"},
		// Same path, different method: the declaration is per operation.
		{http.MethodDelete, "/v1/session"},
		{http.MethodPost, "/v1/session-links"},
		{http.MethodPost, "/v1/auth/oauth/google"},
		{http.MethodPost, "/v1/auth/oauth/google/callback"},
		// Template near-misses: a missing or an extra segment is not the route.
		{http.MethodGet, "/v1/agents/claim"},
		{http.MethodGet, "/v1/agents/claim/abc123/extra"},
		{http.MethodGet, "/v1/auth/oauth"},
		{http.MethodGet, "/v1/auth/oauth/google/callback/extra"},
		// Authenticated identity operations, for contrast.
		{http.MethodGet, "/v1/sessions"},
		{http.MethodPost, "/v1/invitations/accept"},
	} {
		if rec := ask(t, options, tc.method, tc.path, nil); rec.Code != http.StatusUnauthorized {
			t.Errorf("%s %s answered %d, want 401: identity did not declare this operation public and gateway must not open it", tc.method, tc.path, rec.Code)
		}
	}

	if got := identity.Count(); got != 0 {
		t.Errorf("identity saw %d request(s), want 0: a refused caller must never cost identity a call", got)
	}
}
