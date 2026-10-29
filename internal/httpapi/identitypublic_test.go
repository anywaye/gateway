package httpapi


import (
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

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

func TestIdentityPublicOperationsAreForwardedWithoutACredential(t *testing.T) {
	silenceLog(t)
	identity := newUpstream(t, nil)

	options := Options{
		IdentityBaseURL: identity.Origin(),
		Authenticate:    func(*http.Request) (*Principal, error) { return nil, errNoCredential },
	}

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

func TestIdentityPrivateOperationsStillRefuseWithoutACredential(t *testing.T) {
	silenceLog(t)
	identity := newUpstream(t, nil)

	options := Options{
		IdentityBaseURL: identity.Origin(),
		Authenticate:    func(*http.Request) (*Principal, error) { return nil, errNoCredential },
	}

	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/v1/me"},
		{http.MethodGet, "/v1/accounts"},
		{http.MethodGet, "/v1/introspections"},
		{http.MethodDelete, "/v1/session"},
		{http.MethodPost, "/v1/session-links"},
		{http.MethodPost, "/v1/auth/oauth/google"},
		{http.MethodPost, "/v1/auth/oauth/google/callback"},
		{http.MethodGet, "/v1/agents/claim"},
		{http.MethodGet, "/v1/agents/claim/abc123/extra"},
		{http.MethodGet, "/v1/auth/oauth"},
		{http.MethodGet, "/v1/auth/oauth/google/callback/extra"},
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
