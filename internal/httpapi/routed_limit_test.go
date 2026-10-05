// Routed traffic and the limiter, as two properties of THIS service.
//
// # WHY THIS FILE EXISTS AND WHAT IT REPLACED
//
// Both properties below were properties of the *equivalence* harness — the tier
// that stood a second implementation up and compared the two byte for byte. That
// tier is gone, and the properties were not, so they moved here rather than
// disappearing with it. A property that only a comparison could see is a property
// that dies with the comparison; a property the service can be *asked* about is a
// property that outlives whatever it was first written next to.
//
// What moved, and what did not:
//
//   - `TestTheGoSideCountsRoutedTraffic` moved. It stood up the reference to ask
//     the same burst of both, and the half of it that was "the reference also
//     answered 429" is gone with the reference. The half that remains is stronger
//     for its absence: the assertion is now about what THIS gateway does with a
//     bucket spent elsewhere, with no second implementation to agree with.
//   - The `counterStoreDown` scenario moved. Its refusal-vs-served distinction is
//     a property of this service's mount and of `ratelimit`'s fail-open, and both
//     are things a reader can check without a second gateway.
//
// # WHY THE ALLOWANCE IS THREE AND THE CLOCK IS FROZEN
//
// Both are fixtures, and both are load-bearing rather than tidy. GCRA spends the
// allowance continuously, so with the clock frozen the third request lands exactly
// on the threshold and the fourth is refused — which means the crossing is a
// function of the request count alone and a test can state it exactly. An
// allowance of one refuses on the second request and never reaches the boundary,
// so it would assert a refusal without ever asserting the crossing.

package httpapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/cafaye/gateway/internal/ratelimit"
)

// The frozen instant both tests below read, and the allowance they spend.
//
// A fixed clock because `RateLimit-Reset` and `Retry-After` are both functions of
// it: on a live clock these assertions would be about two `time.Now()` calls a few
// milliseconds apart, which fail on arithmetic nobody is reading.
var (
	routedLimitAt = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	routedLimit   = 3
)

// routedLimiter is a limiter at the frozen clock and the allowance above, over
// `store`, with the two probe paths exempt.
//
// The exemption is read from `ProbePaths` rather than typed, for the reason
// `equivalence`'s own `exemptProbes` gave: "these two are the only operations with
// no `429`" is a claim about that set, and a copy of it here would be a list free
// to drift from the one the exemption is keyed on.
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

// spendTheAllowanceOnAnUnroutedPath takes the bucket to zero without ever asking
// the route table, so the request that follows is answered by the pass-through
// against an allowance it did not spend.
//
// One bucket per identity rather than per path, which is the whole point: the
// allowance a routed request draws is the one an unrouted request spent, and a
// limiter that counted them separately would let a caller buy N times the limit
// by spreading a burst across paths.
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

// remainingAfter is what the limiter must announce once `n` requests of an
// allowance of three have been served at a frozen clock: two, then one, then
// zero. Written out rather than computed, because a computed remainder is this
// test agreeing with the implementation it is checking.
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

// Routed traffic is counted, and a routed refusal never reaches the service.
//
// The mount order is the property: the limiter is mounted around the pass-through
// (`New`, `everyRequest`), so a path the route table claims is counted before it
// is forwarded. The defect this replaced was a limiter that was a chi `Use` inside
// the router while the pass-through wrapped the router from outside — every
// routed request was relayed with no rate-limit accounting at all, and the
// gateway answered `200` with no `RateLimit-*` header on a bucket that was
// already empty.
//
// So the assertion is asked in the order that defect would fail: spend the
// allowance where nothing is forwarded, then ask a path the table DOES claim.
// A gateway that does not count routed traffic serves that last request, and the
// upstream sees it.
func TestRoutedTrafficIsCountedAndARoutedRefusalNeverReachesTheService(t *testing.T) {
	logged := silenceLog(t)
	service := newUpstream(t, nil)

	options := Options{
		Routes:  RouteTable{"/v1/pantry": {BaseURL: service.Origin()}},
		Limiter: routedLimiter(t, routedMemoryStore(t)),
	}
	spendTheAllowanceOnAnUnroutedPath(t, options)

	rec := ask(t, options, http.MethodGet, "/v1/pantry/items", map[string]string{"Accept": "application/json"})

	// The refusal, and not "no headers". A `200` with headers on it is a limiter
	// working and something else refusing, which is a different defect and would
	// pass a bare status check in the other direction.
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("a routed request whose bucket was spent by %d unrouted requests answered %d, want 429. The limiter is mounted around the pass-through (`everyRequest`), so a path the route table claims is answered by the chain the limiter is in — read `everyRequest` before changing the mount.", routedLimit, rec.Code)
	}

	// The announced remainder, which is the half a status cannot see. A gateway
	// that counted this request TWICE would refuse here exactly as a correct one
	// does and differ only in this number.
	if got, want := rec.Header().Get("RateLimit-Remaining"), "0"; got != want {
		t.Errorf("the refusal announced RateLimit-Remaining: %q, want %q. The refusal agrees, so a difference here is this request being counted a different number of times than the ones above spent — the signature of a limiter mounted in both places.", got, want)
	}

	// And the whole announced family, read off the limiter's own list rather than
	// typed: a refusal that omits `Retry-After`, or carries a stale
	// `RateLimit-Reset`, tells a client something different from one that does not.
	for _, name := range append([]string{"Retry-After"}, ratelimit.RateLimitHeaders...) {
		if rec.Header().Get(name) == "" {
			t.Errorf("the refusal announced no %s. A client reads these to pace itself, and a 429 without them is a client that cannot tell a second from a two-hundredth attempt.", name)
		}
	}

	// And the consequence rather than the arithmetic: a relayed request is an
	// upstream call this gateway just decided not to make.
	if got := service.Count(); got != 0 {
		t.Errorf("the upstream was contacted %d time(s) for a request the gateway refused. A refusal that still spends a service's capacity is a limiter mounted after the pass-through rather than in front of it.", got)
	}

	// Printed rather than only asserted, because a property that is visible only on
	// a passing run is one that gets lost the first time somebody filters output.
	t.Logf("ROUTED TRAFFIC IS COUNTED: %d unrouted requests spent the allowance, the routed request was refused %d with the whole announced family, and the upstream was never contacted. The limiter's line, if any: %s", routedLimit, rec.Code, strings.TrimSpace(logged.String()))
}

// A counter store that cannot be reached is served, uncounted, and named in
// readiness — and the reason reaches neither the caller nor `/readyz`.
//
// This is the `counterStoreDown` decision, kept because the decision is a property
// of this service and not of any comparison: `ratelimit` fails OPEN, which is
// named in its own source and is the right direction for an edge, and the three
// consequences are all things a deployment can observe.
//
//   - SERVED. A store that cannot answer has told us nothing about whether this
//     caller has spent anything, and guessing "no" keeps the edge serving.
//     Failing closed would hand a Redis outage to every caller as a 429.
//   - UNANNOUNCED. No `RateLimit-*` header at all: a client told its allowance and
//     then never refused is worse than a client told nothing.
//   - VISIBLE. `/readyz` names `redis` as unavailable, because a limiter that is
//     silently applying no limit is otherwise indistinguishable from one at its
//     allowance — and readiness is the only place an operator can see it.
//
// It is asked on a ROUTED path deliberately. The same request against a path the
// router answers would look identical if the limiter were never reached at all,
// which is exactly what the counting test above rules out.
func TestAnUnreachableCounterStoreServesRoutedTrafficUncountedAndIsNamedInReadiness(t *testing.T) {
	// TWO sinks, and the second one is the point.
	//
	// `silenceLog` swaps this package's `stderr`, which is what the PROXY writes
	// to. The line this test asserts on is not the proxy's: the fail-open is
	// logged by the LIMITER, through `ratelimit.Logf`. Capturing only `stderr`
	// leaves the assertion reading an empty builder and failing on a gateway
	// that did log the line — which is what happened the first time this file
	// was run, and is why the sink is named here rather than left implicit.
	//
	// `ratelimit/limiter_test.go` already asserts this same line from inside the
	// limiter. This holds it from inside the GATEWAY, because the gateway is
	// where an operator is looking when a rate limit stops being applied.
	var limiterLog strings.Builder
	previousLogf := ratelimit.Logf
	ratelimit.Logf = func(format string, args ...any) {
		fmt.Fprintf(&limiterLog, format, args...)
	}
	t.Cleanup(func() { ratelimit.Logf = previousLogf })
	// The proxy's own stderr still has to be silenced, or a failing run prints a
	// copy of the fail-open reason to the console on every request.
	silenceLog(t)
	service := newUpstream(t, nil)

	// The shape `redis.go` produces when the connection is refused, and nothing
	// else: `Hit` returns an error and the limiter's own decision is what happens
	// next. A store that answered "allowed" would be testing the store rather than
	// the fail-open path.
	//
	// The message carries a host, a port and a credential on purpose, so the
	// assertions below can prove none of them reach a caller.
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

	// READINESS, and by name rather than by count: the store is unreachable rather
	// than absent, and the only thing that tells an operator the difference is
	// this endpoint.
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

	// And to the log, which is where the reason belongs. `ratelimit`'s own test
	// holds the same property at the limiter; this holds that the GATEWAY logs it,
	// because the gateway is where an operator is looking.
	if !strings.Contains(limiterLog.String(), "rate-limit store is unavailable") {
		t.Errorf("the gateway logged %q while serving against an unreachable counter store; want a line naming the rate-limit store being unavailable. A fail-open nobody can see is an outage nobody can diagnose.", limiterLog.String())
	}
}

// The two facts a caller must never learn from the store's failure, named rather
// than read out of the message string — so an assertion names a value it declared
// instead of whatever an implementation happened to format.
const (
	secretNeverReached = "hunter2"
	hostNeverReached   = "10.0.3.9"
)

// unreachableCounterStore is a counter store that cannot be reached.
type unreachableCounterStore struct{}

func (unreachableCounterStore) Hit(_ string, _ ratelimit.Request) (ratelimit.Verdict, error) {
	return ratelimit.Verdict{}, errors.New(
		"dial tcp " + hostNeverReached + ":6379: connect: connection refused (REDIS_URL=redis://:" + secretNeverReached + "@redis.internal)")
}

// storeProbe is the readiness probe for a store, and it produces the SAME error
// from the store rather than from a second literal of the message. Two copies of a
// string is two things to change, and the assertions above name parts of it.
func storeProbe(store ratelimit.Store) Probe {
	return func(context.Context) error {
		_, err := store.Hit("", ratelimit.Request{})
		return err
	}
}
