package httpapi

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/anywaye/gateway/internal/auth"
	"github.com/anywaye/gateway/internal/ratelimit"
	"github.com/anywaye/gateway/internal/testkeys"
)

func newJWKSFixture(t *testing.T) *testkeys.Fixture {
	t.Helper()
	return testkeys.NewFixture(t).Serve(t)
}

func tokenValid(t *testing.T, f *testkeys.Fixture) string {
	return f.Mint(t, testkeys.Claims{
		ExpiresIn: testkeys.Valid,
		Scope:     "invoices:read invoices:write",
		AccountID: "cd000000-0000-4000-8000-000000000002",
	})
}

func authVerifierFor(t *testing.T, f *testkeys.Fixture) (*auth.Verifier, error) {
	t.Helper()

	return auth.New(auth.Options{
		Issuer:   testkeys.Issuer,
		Audience: testkeys.Audience,
		JWKSURL:  f.URL,
		Now:      func() time.Time { return testkeys.Clock },
	})
}

func askWithVerifier(t *testing.T, options Options, method, path string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()

	if options.Limiter == nil {
		store, err := ratelimit.NewMemoryStore(0)
		if err != nil {
			t.Fatalf("building a memory store for a single request: %v", err)
		}
		limiter, err := ratelimit.NewLimiter(ratelimit.Options{
			Limit:  600,
			Window: ratelimit.DefaultWindow,
			Store:  store,
			Exempt: isProbePath,
		}, RateLimitRefuser)
		if err != nil {
			t.Fatalf("building a limiter for a single request: %v", err)
		}
		options.Limiter = limiter
	}

	return ask(t, options, method, path, headers)
}

func bearer(token string) string {
	return "Bearer " + strings.TrimSpace(token)
}
