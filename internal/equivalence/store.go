package equivalence

import (
	"context"
	"errors"
	"time"

	"github.com/anywaye/gateway/internal/httpapi"
	"github.com/anywaye/gateway/internal/ratelimit"
)

const (
	equivalenceNowMillis int64 = 1_767_225_600_000

	equivalenceLimit  = 3
	equivalenceWindow = time.Minute
)

func equivalenceNow() time.Time { return time.UnixMilli(equivalenceNowMillis) }

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

func storeFor(scenario string) (ratelimit.Store, error) {
	switch scenario {
	case ScenarioLimitsExhausted:
		return ratelimit.NewMemoryStore(0)

	case ScenarioCounterStoreDown:
		return unreachableStore{}, nil

	default:
		return nil, errors.New("equivalence: no limiter store for scenario " + scenario)
	}
}

type unreachableStore struct{}

func (unreachableStore) Hit(_ string, _ ratelimit.Request) (ratelimit.Verdict, error) {
	return ratelimit.Verdict{}, errors.New(
		"dial tcp 10.0.3.9:6379: connect: connection refused (REDIS_URL=redis://:hunter2@redis.internal)")
}

const (
	theSecretBothSidesMustNotLeak = "hunter2"
	theHostBothSidesMustNotLeak   = "10.0.3.9"
)

var thePartsOfTheReasonNeitherSideMayEcho = []string{
	theSecretBothSidesMustNotLeak,
	theHostBothSidesMustNotLeak,
	"redis.internal",
	"REDIS_URL",
	"connection refused",
}

func probeFor(scenario string) httpapi.Probe {
	if scenario == ScenarioCounterStoreDown {
		return func(context.Context) error {
			_, cause := unreachableStore{}.Hit("", ratelimit.Request{})
			return cause
		}
	}
	return alwaysOK
}

func exemptProbes(path string) bool {
	_, exempt := httpapi.ProbePaths[path]
	return exempt
}
