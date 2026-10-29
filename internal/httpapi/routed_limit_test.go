
package httpapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/anywaye/gateway/internal/ratelimit"
)

var (
	routedLimitAt = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	routedLimit   = 3
)

func routedLimiter(t *testing.T, store ratelimit.Store) RateLimiter {
	t.Helper()

	limiter, err := ratelimit.NewLimiter(ratelimit.Options{
		Limit:  routedLimit,
		Window: time.Minute,
		Store:  store,
		Now:    func() time.Time { return routedLimitAt },
		Exempt: isProbePath,
	}, RateLimitRefuser)
	if err != nil {
		t.Fatalf("building a limiter over the store: %v", err)
	}
	return limiter
}

func routedMemoryStore(t *testing.T) ratelimit.Store {
	t.Helper()

	store, err := ratelimit.NewMemoryStore(0)
	if err != nil {
		t.Fatalf("building an in-memory counter store: %v", err)
	}
	return store
}

func spendTheAllowanceOnAnUnroutedPath(t *testing.T, options Options) {
	t.Helper()

	for i := 0; i < routedLimit; i++ {
		rec := ask(t, options, http.MethodGet, "/v1/nothing-here", map[string]string{"Accept": "application/json"})
		if rec.Code != http.StatusNotFound {
			t.Fatalf("spending the allowance, request %d: an unrouted path answered %d, want 404. The spending has to happen somewhere the route table does not claim, or the request under test is spending its own allowance and the fixture is wrong.", i+1, rec.Code)
		}
		if got, want := rec.Header().Get("RateLimit-Remaining"), remainingAfter(i+1); got != want {
			t.Fatalf("spending the allowance, request %d: RateLimit-Remaining is %q, want %q. The announced remainder is how the refusal below is shown to be the SAME bucket rather than a fresh one — and a limiter mounted in two places spends twice what it announces.", i+1, got, want)
		}
	}
}

func remainingAfter(n int) string {
	switch n {
	case 1:
		return "2"
	case 2:
		return "1"
	case 3:
		return "0"
	default:
		return ""
	}
}

func TestRoutedTrafficIsCountedAndARoutedRefusalNeverReachesTheService(t *testing.T) {
	logged := silenceLog(t)
	service := newUpstream(t, nil)

	options := Options{
		Routes:  RouteTable{"/v1/pantry": {BaseURL: service.Origin()}},
		Limiter: routedLimiter(t, routedMemoryStore(t)),
	}
	spendTheAllowanceOnAnUnroutedPath(t, options)

	rec := ask(t, options, http.MethodGet, "/v1/pantry/items", map[string]string{"Accept": "application/json"})

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("a routed request whose bucket was spent by %d unrouted requests answered %d, want 429. The limiter is mounted around the pass-through (`everyRequest`), so a path the route table claims is answered by the chain the limiter is in — read `everyRequest` before changing the mount.", routedLimit, rec.Code)
	}

	if got, want := rec.Header().Get("RateLimit-Remaining"), "0"; got != want {
		t.Errorf("the refusal announced RateLimit-Remaining: %q, want %q. The refusal agrees, so a difference here is this request being counted a different number of times than the ones above spent — the signature of a limiter mounted in both places.", got, want)
	}

	for _, name := range append([]string{"Retry-After"}, ratelimit.RateLimitHeaders...) {
		if rec.Header().Get(name) == "" {
			t.Errorf("the refusal announced no %s. A client reads these to pace itself, and a 429 without them is a client that cannot tell a second from a two-hundredth attempt.", name)
		}
	}

	if got := service.Count(); got != 0 {
		t.Errorf("the upstream was contacted %d time(s) for a request the gateway refused. A refusal that still spends a service's capacity is a limiter mounted after the pass-through rather than in front of it.", got)
	}

	t.Logf("ROUTED TRAFFIC IS COUNTED: %d unrouted requests spent the allowance, the routed request was refused %d with the whole announced family, and the upstream was never contacted. The limiter's line, if any: %s", routedLimit, rec.Code, strings.TrimSpace(logged.String()))
}

func TestAnUnreachableCounterStoreServesRoutedTrafficUncountedAndIsNamedInReadiness(t *testing.T) {
	var limiterLog strings.Builder
	previousLogf := ratelimit.Logf
	ratelimit.Logf = func(format string, args ...any) {
		fmt.Fprintf(&limiterLog, format, args...)
	}
	t.Cleanup(func() { ratelimit.Logf = previousLogf })
	silenceLog(t)
	service := newUpstream(t, nil)

	store := ratelimit.Store(unreachableCounterStore{})

	options := Options{
		Probes:  []NamedProbe{{Name: "redis", Probe: storeProbe(store)}},
		Routes:  RouteTable{"/v1/pantry": {BaseURL: service.Origin()}},
		Limiter: routedLimiter(t, store),
	}

	for i := 1; i <= routedLimit+1; i++ {
		rec := ask(t, options, http.MethodGet, "/v1/pantry/items", map[string]string{"Accept": "application/json"})

		if rec.Code != http.StatusOK {
			t.Fatalf("request %d against an unreachable counter store answered %d, want 200 from the upstream. For as long as the store is unreachable gateway applies no limit; failing closed would hand a counter-store outage to every caller as a 429.", i, rec.Code)
		}
		for _, name := range append([]string{"Retry-After"}, ratelimit.RateLimitHeaders...) {
			if value := rec.Header().Get(name); value != "" {
				t.Errorf("request %d carried %s: %q on a request that was not counted. A client told its allowance and then never refused is worse than a client told nothing.", i, name, value)
			}
		}
		if body := rec.Body.String(); strings.Contains(body, secretNeverReached) || strings.Contains(body, hostNeverReached) {
			t.Errorf("request %d carried the store's own failure to the caller: %s", i, body)
		}
	}

	rec := ask(t, options, http.MethodGet, "/readyz", nil)
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("/readyz answered %d with an unreachable counter store, want 503. A limiter that is silently applying no limit is otherwise indistinguishable from one at its allowance.", rec.Code)
	}
	var deps struct {
		Deps map[string]string `json:"deps"`
	}
	decode(t, rec, &deps)
	if got := deps.Deps["redis"]; got != "unavailable" {
		t.Errorf("/readyz reports deps.redis = %q, want \"unavailable\". A dependency that is down has to be named, or readiness is a green about a gateway that is not limiting anything.", got)
	}
	if body := rec.Body.String(); strings.Contains(body, secretNeverReached) || strings.Contains(body, hostNeverReached) {
		t.Errorf("/readyz carried the store's own failure: %s. A readiness body is served to an unauthenticated caller, so its detail is a map of the deployment.", body)
	}

	if !strings.Contains(limiterLog.String(), "rate-limit store is unavailable") {
		t.Errorf("the gateway logged %q while serving against an unreachable counter store; want a line naming the rate-limit store being unavailable. A fail-open nobody can see is an outage nobody can diagnose.", limiterLog.String())
	}
}

const (
	secretNeverReached = "hunter2"
	hostNeverReached   = "10.0.3.9"
)

type unreachableCounterStore struct{}

func (unreachableCounterStore) Hit(_ string, _ ratelimit.Request) (ratelimit.Verdict, error) {
	return ratelimit.Verdict{}, errors.New(
		"dial tcp " + hostNeverReached + ":6379: connect: connection refused (REDIS_URL=redis://:" + secretNeverReached + "@redis.internal)")
}

func storeProbe(store ratelimit.Store) Probe {
	return func(context.Context) error {
		_, err := store.Hit("", ratelimit.Request{})
		return err
	}
}
