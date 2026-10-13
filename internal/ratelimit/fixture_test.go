// Shared fixtures for this package's tests.
//
// One file because three tests want the same three things — a store, a limiter and a
// refusal writer — and a helper spelled three ways across three tests is a helper
// whose differences are accidental.
package ratelimit

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"runtime"
	"testing"
	"time"

	"github.com/cafaye/gateway/internal/auth"
)

// newTestStore is a memory store for a single test.
//
// The memory backend rather than a fake `Store` because most of these tests are about
// the limiter's WIRING and a fake store would let them pass while the store was
// wrong. The tests that are about the store's own arithmetic are in `store_test.go`
// and drive `count` directly.
func newTestStore(t *testing.T) Store {
	t.Helper()

	store, err := NewMemoryStore(0)
	if err != nil {
		t.Fatalf("NewMemoryStore refused the default configuration: %v", err)
	}
	return store
}

// refuseInTest records the refusals a limiter writes, and writes a problem-shaped
// body so a test can assert on the status.
//
// It is NOT `internal/httpapi`'s writer, and that is deliberate: this package must be
// testable without importing the package that renders the envelope, because the
// dependency runs one way and a test that reversed it would be a cycle. What is
// checked here is that the limiter ASKS for the right status, code and detail — the
// rendering of them is `internal/httpapi`'s business and is checked there.
func refuseInTest(w http.ResponseWriter, r *http.Request, status int, code, detail string) {
	w.Header().Set("X-Refusal-Code", code)
	w.Header().Set("X-Refusal-Detail", detail)
	w.WriteHeader(status)
	_, _ = w.Write([]byte(`{"code":"` + code + `","detail":"` + detail + `"}`))
}

// recorded is one refusal a test collected.
type recorded struct {
	Status int
	Code   string
	Detail string
	Path   string
}

// recorder is a limiter's refusal writer that keeps what it was asked for.
type recorder struct{ refusals []recorded }

func (rec *recorder) refuse(w http.ResponseWriter, r *http.Request, status int, code, detail string) {
	rec.refusals = append(rec.refusals, recorded{Status: status, Code: code, Detail: detail, Path: r.URL.Path})
	refuseInTest(w, r, status, code, detail)
}

// fixedClock is a clock a test moves, which is how a window boundary is crossed
// without sleeping.
type fixedClock struct{ now time.Time }

func (c *fixedClock) Now() time.Time { return c.now }

// claimSet parses a JSON object into an `auth.Claims`, for the tests about what a
// bucket falls back to.
//
// A PARSE rather than a hand-built `auth.Claims`, because `Claims`'s fields are
// unexported and a test that could set them directly would be testing a
// representation rather than a payload — and the payload is what a token carries.
func claimSet(t *testing.T, document string) auth.Claims {
	t.Helper()

	var claims auth.Claims
	if err := json.Unmarshal([]byte(document), &claims); err != nil {
		t.Fatalf("parsing the claim document %s: %v", document, err)
	}
	return claims
}

// withPrincipal attaches a verified principal to a request, which is how a handler
// sees one in production and how `KeySourceOf` reads one here.
func withPrincipal(r *http.Request, principal *auth.Principal) *http.Request {
	return auth.WithPrincipalForTest(r, principal)
}

// strptr is a string pointer, for the one field of `auth.Principal` that is optional.
func strptr(value string) *string { return &value }

// ask drives one request at a limiter and returns the recorder's answer.
func ask(t *testing.T, limiter *Limiter, method, path string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequest(method, path, nil)
	for name, value := range headers {
		req.Header.Set(name, value)
	}
	req.RemoteAddr = "198.51.100.7:41234"

	rec := httptest.NewRecorder()
	limiter.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	})).ServeHTTP(rec, req)
	return rec
}

// runtimeYield is the gap a read-then-write limiter has and a one-step limiter does
// not. It exists only so `twoStepStore` can be written at all: a two-step store with
// no yield between its steps and a mutex in each is indistinguishable from a one-step
// store, which is precisely the point `limiter_test.go` proves by contrast.
func runtimeYield() { runtime.Gosched() }

// isProbePathForTest is `internal/httpapi`'s `isProbePath`, inlined.
//
// The exemption is a set gateway decides and this package consumes, so a test here
// builds it from the same set rather than importing the package that owns it — which
// would be a cycle in a test build, and would also mean this package's tests could not
// say what the exemption IS.
func isProbePathForTest(path string) bool {
	switch path {
	case "/healthz", "/readyz":
		return true
	}
	return false
}
