package ratelimit

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"runtime"
	"testing"
	"time"

	"github.com/anywaye/gateway/internal/auth"
)

func newTestStore(t *testing.T) Store {
	t.Helper()

	store, err := NewMemoryStore(0)
	if err != nil {
		t.Fatalf("NewMemoryStore refused the default configuration: %v", err)
	}
	return store
}

func refuseInTest(w http.ResponseWriter, r *http.Request, status int, code, detail string) {
	w.Header().Set("X-Refusal-Code", code)
	w.Header().Set("X-Refusal-Detail", detail)
	w.WriteHeader(status)
	_, _ = w.Write([]byte(`{"code":"` + code + `","detail":"` + detail + `"}`))
}

type recorded struct {
	Status int
	Code   string
	Detail string
	Path   string
}

type recorder struct{ refusals []recorded }

func (rec *recorder) refuse(w http.ResponseWriter, r *http.Request, status int, code, detail string) {
	rec.refusals = append(rec.refusals, recorded{Status: status, Code: code, Detail: detail, Path: r.URL.Path})
	refuseInTest(w, r, status, code, detail)
}

type fixedClock struct{ now time.Time }

func (c *fixedClock) Now() time.Time { return c.now }

func claimSet(t *testing.T, document string) auth.Claims {
	t.Helper()

	var claims auth.Claims
	if err := json.Unmarshal([]byte(document), &claims); err != nil {
		t.Fatalf("parsing the claim document %s: %v", document, err)
	}
	return claims
}

func withPrincipal(r *http.Request, principal *auth.Principal) *http.Request {
	return auth.WithPrincipalForTest(r, principal)
}

func strptr(value string) *string { return &value }

func ask(t *testing.T, limiter *Limiter, method, path string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequestWithContext(context.Background(), method, path, nil)
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

func runtimeYield() { runtime.Gosched() }

func isProbePathForTest(path string) bool {
	switch path {
	case "/healthz", "/readyz":
		return true
	}
	return false
}
