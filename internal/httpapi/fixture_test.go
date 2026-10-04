// The glue between `internal/testkeys` and this package's tests.
//
// One file rather than helpers spread through `httpapi_test.go` because the same
// two shapes are wanted by every test that needs a credential — a verifier pointed
// at a live key set, and a request carrying a token — and a fixture spelled three
// different ways across three tests is a fixture whose differences are accidental.
package httpapi

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cafaye/gateway/internal/auth"
	"github.com/cafaye/gateway/internal/ratelimit"
	"github.com/cafaye/gateway/internal/testkeys"
)

// newJWKSFixture is a served key set and a token that verifies against it.
//
// The two values a test wants together — the server and a token — are returned as a
// pair rather than as two calls, because a test that built a token from one fixture
// and pointed the verifier at another would get a `401` for a reason that is not the
// one under test.
func newJWKSFixture(t *testing.T) *testkeys.Fixture {
	t.Helper()
	return testkeys.NewFixture(t).Serve(t)
}

// tokenValid is the claims a test gets when it wants a token that verifies: an
// `exp` an hour out, a scope, and an `account_id`.
//
// A FUNCTION rather than a variable, so a test running in parallel cannot reassign a
// token another test is about to send: the fixture mints from its own key, so a shared
// variable would be a token signed by one server presented to another.
//
// The `exp` matters. A token with NO `exp` is valid forever, which is a real and
// different claim — the reference verifies it, and so does this port — but it is not
// the shape identity issues, so the fixture's "valid" token is not it.
func tokenValid(t *testing.T, f *testkeys.Fixture) string {
	return f.Mint(t, testkeys.Claims{
		ExpiresIn: testkeys.Valid,
		Scope:     "invoices:read invoices:write",
		AccountID: "cd000000-0000-4000-8000-000000000002",
	})
}

// authVerifierFor builds a verifier pointed at the fixture's live key set.
//
// The clock is injected at a fixed instant one hour after the epoch so the cache TTL
// is testable without sleeping and so a token's `exp` — minted relative to the wall
// clock by `testkeys` — is comfortably in the future. That mismatch is the one
// honest wrinkle: the fixture mints with `time.Now` and the verifier reads with a
// fixed clock, so a test that wants an EXPIRED token has to mint one against the same
// fixed instant, which `expiredAt` is for.
func authVerifierFor(t *testing.T, f *testkeys.Fixture) (*auth.Verifier, error) {
	t.Helper()

	// The issuer, the audience and the clock are the fixture's OWN constants, so a
	// test that mints a token and a test that verifies it cannot disagree about which
	// of the three they are. Three lines rather than a `testkeys` helper, because a
	// fixture package that imported `internal/auth` could not be imported by
	// `internal/auth`'s own tests — an import cycle Go rejects in a test build.
	return auth.New(auth.Options{
		Issuer:   testkeys.Issuer,
		Audience: testkeys.Audience,
		JWKSURL:  f.URL,
		Now:      func() time.Time { return testkeys.Clock },
	})
}

// askWithVerifier is `ask` plus the two fields this packet added, so a test does not
// have to assemble an `Options` by hand to make one request.
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

// bearer is the header value for a token, spelled once.
//
// `Bearer <token>` with the capital B the reference's own tests use, because the
// scheme is case-INsensitive and a test that happened to use `bearer` would prove the
// case-insensitivity on every request it made instead of on the one that means to.
func bearer(token string) string {
	return "Bearer " + strings.TrimSpace(token)
}
