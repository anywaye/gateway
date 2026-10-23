// The two limiter scenarios' configuration: the allowance, the clock, and the two
// stores.
//
// This file is separate from `scenarios.go` because it is the ONE thing these two
// scenarios need that the other eleven do not — a counter store a test can make
// misbehave — and because the numbers below are this package's own fixtures. They
// were once checked against the TypeScript reference's, by reading the other
// language's literal out of its source; that check is gone with the reference and
// what is left is `TestTheClockTheLimiterReadsIsTheOneTheFixtureClaims`, which
// asserts the constant against the instant every comment here names.
//
// # THE CLOCK IS FROZEN, AND THE REASON IS THE HEADERS
//
// `RateLimit-Reset` and `Retry-After` are both derived from the clock the limiter
// reads. Ask the same refusal on a live clock and every number in it moves between
// two reads of `time.Now()`, so a failure says something about the fixture rather
// than about the gateway. Frozen, every number below is exact and the refusal is a
// function of the request count alone.
//
// # THE ALLOWANCE IS THREE, AND WHY NOT ONE
//
// GCRA spends the allowance continuously, so with the clock frozen the third
// request lands exactly on the threshold and the fourth is refused — `count` in
// `internal/ratelimit/store.go` is strictly greater-than, which is what lets a
// burst of exactly `limit` through. A limit of one refuses on the second request
// and never reaches the boundary at all, so it would give a refusal without the
// crossing.
package equivalence

import (
	"context"
	"errors"
	"time"

	"github.com/anywaye/gateway/internal/httpapi"
	"github.com/anywaye/gateway/internal/ratelimit"
)

// The instant this package's limiter reads. 2026-01-01T00:00:00Z, whole seconds
// so no rounding question can be blamed on the fixture. It was the same literal
// the TypeScript reference declared as `FIXED_NOW_MS` — equal by reading that
// file, so a drifted constant showed up as a difference in `X-RateLimit-Reset`
// that read like a port defect. With the reference gone that class of drift has
// nowhere to hide, so `TestTheClockTheLimiterReadsIsTheOneTheFixtureClaims`
// holds the constant to the instant every comment here claims instead.
const (
	equivalenceNowMillis int64 = 1_767_225_600_000

	// Three per minute, which was the reference's `limiterTable` too. See the file
	// comment for why three and not one.
	equivalenceLimit  = 3
	equivalenceWindow = time.Minute
)

// equivalenceNow is the frozen clock, as `ratelimit.Options.Now` wants it.
func equivalenceNow() time.Time { return time.UnixMilli(equivalenceNowMillis) }

// limiterFor builds the limiter one limiter scenario runs with.
func limiterFor(scenario string) (httpapi.RateLimiter, error) {
	store, err := storeFor(scenario)
	if err != nil {
		return nil, err
	}

	return ratelimit.NewLimiter(ratelimit.Options{
		Limit:  equivalenceLimit,
		Window: equivalenceWindow,
		Store:  store,
		Now:    equivalenceNow,
		Exempt: exemptProbes,
		Policy: func(string) string { return ratelimit.DefaultPolicy },
	}, httpapi.RateLimitRefuser)
}

// storeFor is the one place the two scenarios' stores are told apart.
//
// A working in-memory store rather than a scripted set of verdicts, because what
// the refusal case compares is the limiter's own arithmetic crossing a threshold,
// and a store that hands back a canned "not allowed" would compare the harness's
// fixture rather than the port.
func storeFor(scenario string) (ratelimit.Store, error) {
	switch scenario {
	case ScenarioLimitsExhausted:
		return ratelimit.NewMemoryStore(0)

	case ScenarioCounterStoreDown:
		// The shape `redis.go` produces when the connection is refused, and
		// nothing else: `Hit` returns an error and the limiter's own decision is
		// what happens next. A store that answered "allowed" instead would test
		// the store rather than the fail-open path.
		return unreachableStore{}, nil

	default:
		return nil, errors.New("equivalence: no limiter store for scenario " + scenario)
	}
}

// unreachableStore is a counter store that cannot be reached.
//
// The error names a host, a port and a credential, which is the point: the
// comparison has to be able to prove the reason reaches neither a response body
// nor `/readyz`. `ratelimit.failedOpen` says in its own comment that the message
// goes to the log and the caller gets a request with nothing on it, and this is
// the store that makes that checkable.
type unreachableStore struct{}

func (unreachableStore) Hit(_ string, _ ratelimit.Request) (ratelimit.Verdict, error) {
	return ratelimit.Verdict{}, errors.New(
		"dial tcp 10.0.3.9:6379: connect: connection refused (REDIS_URL=redis://:hunter2@redis.internal)")
}

// The values inside `unreachableStore`'s error and the `redis` probe's, named
// rather than read out of the message string — so a check asserts against a value
// it declared rather than against whatever an implementation happened to format.
//
// A bare credential in a log is a credential, and a host tells a reader where the
// counter store is supposed to be, which is the topology an unauthenticated caller
// has no business learning.
const (
	theSecretBothSidesMustNotLeak = "hunter2"
	theHostBothSidesMustNotLeak   = "10.0.3.9"
)

// thePartsOfTheReasonNeitherSideMayEcho is the whole set, and it is a slice of a
// package-level constant rather than a literal at each use, because a check that
// names the parts in two places and the reason in a third is three lists.
var thePartsOfTheReasonNeitherSideMayEcho = []string{
	theSecretBothSidesMustNotLeak,
	theHostBothSidesMustNotLeak,
	"redis.internal",
	"REDIS_URL",
	"connection refused",
}

// probeFor is the `redis` probe a limiter scenario registers.
//
// The store being unreachable is not the same fact as the store being absent, and
// the only thing that tells an operator the difference is `/readyz`. The healthy
// side is `alwaysOK` and the broken side is a throw carrying the same credential,
// so the degraded case can also prove the reason does not reach the readiness
// body — the same property `probesDegraded` holds for identity and aperture.
func probeFor(scenario string) httpapi.Probe {
	if scenario == ScenarioCounterStoreDown {
		return func(context.Context) error {
			// The SAME error the store returns, produced from the store rather than
			// from a second literal of the message. Two copies of a string is two
			// things to change, and the leak check below names parts of it — so if
			// they drift, the check is asserting against a message that is no longer
			// the one being produced.
			_, cause := unreachableStore{}.Hit("", ratelimit.Request{})
			return cause
		}
	}
	return alwaysOK
}

// exemptProbes is the limiter's exemption list, and it reads the service's own set
// rather than naming the two paths.
//
// The same reason `internal/httpapi` exports `ProbePaths`: "these two are the only
// operations with no `429`" is a claim about this set, and a copy of it here would
// be a list that can drift from the one the exemption is really keyed on.
func exemptProbes(path string) bool {
	_, exempt := httpapi.ProbePaths[path]
	return exempt
}
