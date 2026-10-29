package ratelimit

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

type brokenStore struct{ calls int }

func (b *brokenStore) Hit(string, Request) (Verdict, error) {
	b.calls++
	return Verdict{}, errors.New("dial tcp 10.0.0.5:6379: connect: connection refused (password=hunter2)")
}

type countingStore struct {
	mu      sync.Mutex
	keys    []string
	verdict Verdict
}

func (c *countingStore) Hit(key string, _ Request) (Verdict, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.keys = append(c.keys, key)
	return c.verdict, nil
}

func (c *countingStore) seen() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.keys...)
}

func TestRedisDownFailsOpenAndABrokenConfigurationFailsClosed(t *testing.T) {
	t.Run("an unreachable counter store serves the request uncounted", func(t *testing.T) {
		store := &brokenStore{}
		rec := &recorder{}
		limiter, err := NewLimiter(Options{Store: store}, rec.refuse)
		if err != nil {
			t.Fatalf("NewLimiter refused a valid configuration: %v", err)
		}

		got := ask(t, limiter, http.MethodGet, "/v1/me", nil)

		if got.Code != http.StatusOK {
			t.Errorf("a request against an unreachable counter store was answered %d, want 200. The alternative — failing closed — hands an outage in the counter store to every caller as a 429, which is the same class of mistake as restarting the process on a dependency blip and much harder to notice.", got.Code)
		}
		if len(rec.refusals) != 0 {
			t.Errorf("the limiter wrote %d refusal(s) against an unreachable store: %+v", len(rec.refusals), rec.refusals)
		}
		if store.calls == 0 {
			t.Error("the limiter did not even ask the store. A fail-open that never tries is a limiter that is off, and the two look identical from here.")
		}

		for _, name := range RateLimitHeaders {
			if value := got.Header().Get(name); value != "" {
				t.Errorf("%s is %q on a request that was not counted. A client told its allowance and then never refused is worse than a client told nothing.", name, value)
			}
		}
		if got := got.Header().Get("Retry-After"); got != "" {
			t.Errorf("Retry-After is %q on a request that was not counted", got)
		}
	})

	t.Run("and the reason goes to the log, not to the caller", func(t *testing.T) {
		var logged strings.Builder
		previous := Logf
		Logf = func(format string, args ...any) { fmt.Fprintf(&logged, format, args...) }
		t.Cleanup(func() { Logf = previous })

		limiter, err := NewLimiter(Options{Store: &brokenStore{}}, refuseInTest)
		if err != nil {
			t.Fatalf("NewLimiter refused a valid configuration: %v", err)
		}
		rec := ask(t, limiter, http.MethodGet, "/v1/me", nil)

		if !strings.Contains(logged.String(), "rate-limit store is unavailable") {
			t.Errorf("the log line is %q, want one naming the rate-limit store being unavailable. A fail-open nobody can see is an outage nobody can diagnose.", logged.String())
		}
		if strings.Contains(rec.Body.String(), "hunter2") || strings.Contains(rec.Body.String(), "10.0.0.5") {
			t.Errorf("the response body carries an internal fact: %s", rec.Body.String())
		}
		if strings.Contains(logged.String(), "hunter2") != strings.Contains(logged.String(), "connection refused") {
			t.Error("the log line dropped the underlying reason. An error string that does not carry the cause is an error string nobody can act on.")
		}
	})

	t.Run("a broken configuration is a refusal to build", func(t *testing.T) {
		for _, tc := range []struct {
			name    string
			options Options
			want    string
		}{
			{
				name:    "no store",
				options: Options{},
				want:    "Store",
			},
			{
				name:    "a negative limit",
				options: Options{Store: newTestStore(t), Limit: -1},
				want:    "limit",
			},
			{
				name:    "a window too short to divide",
				options: Options{Store: newTestStore(t), Limit: 10, Window: time.Microsecond},
				want:    "windowMs",
			},
			{
				name:    "a negative trusted-proxy count",
				options: Options{Store: newTestStore(t), TrustedProxies: -1},
				want:    "trustedProxies",
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				_, err := NewLimiter(tc.options, refuseInTest)
				if err == nil {
					t.Fatalf("NewLimiter accepted %s", tc.name)
				}
				if !errors.Is(err, ErrNotConfigured) {
					t.Errorf("the refusal is %v, which is not ErrNotConfigured — a caller cannot tell its own mistake from a defect in this package", err)
				}
				if !strings.Contains(err.Error(), tc.want) {
					t.Errorf("the refusal %q does not name %q, and a message that does not name the field is a message the operator has to guess about", err, tc.want)
				}
			})
		}
	})

	t.Run("a policy name that cannot be a structured-field key is refused per request", func(t *testing.T) {
		rec := &recorder{}
		limiter, err := NewLimiter(Options{
			Store:  newTestStore(t),
			Policy: func(string) string { return `gateway"api;w=999999` },
		}, rec.refuse)
		if err != nil {
			t.Fatalf("NewLimiter refused a valid configuration: %v", err)
		}

		got := ask(t, limiter, http.MethodGet, "/v1/me", nil)
		if got.Code != http.StatusOK {
			t.Errorf("a request carrying an unserialisable policy name was answered %d, want 200 — the name is gateway's own configuration and the middleware fails open on it, the same way it does for an unreachable store", got.Code)
		}
		for _, name := range RateLimitHeaders {
			if value := got.Header().Get(name); value != "" {
				t.Errorf("%s is %q on a request whose policy name cannot be serialized. A header carrying a second field item that a client reads as a second policy is the failure this check exists to prevent.", name, value)
			}
		}
	})
}

func TestOneAtomicStepAdmitsExactlyTheLimitUnderABurst(t *testing.T) {
	t.Run("the memory store", func(t *testing.T) {
		store, err := NewMemoryStore(0)
		if err != nil {
			t.Fatalf("NewMemoryStore: %v", err)
		}

		const limit, burst = 50, 200
		request := Request{Limit: limit, Window: time.Minute, Now: time.Unix(1_790_000_000, 0)}

		var wg sync.WaitGroup
		admitted := make([]bool, burst)
		wg.Add(burst)
		for i := range burst {
			go func() {
				defer wg.Done()
				verdict, err := store.Hit("one-bucket", request)
				if err != nil {
					t.Errorf("Hit: %v", err)
					return
				}
				admitted[i] = verdict.Allowed
			}()
		}
		wg.Wait()

		if got := countTrue(admitted); got != limit {
			t.Errorf("a burst of %d at a limit of %d admitted %d. A read-then-write limiter admits N times the limit under a burst, and a burst is exactly what an edge receives.", burst, limit, got)
		}
	})

	t.Run("a store that counts in two steps admits the whole burst", func(t *testing.T) {
		store := &twoStepStore{used: map[string]int{}}
		const limit, burst = 50, 200
		request := Request{Limit: limit, Window: time.Minute, Now: time.Unix(1_790_000_000, 0)}

		admitted := make([]bool, burst)
		var wg sync.WaitGroup
		wg.Add(burst)
		for i := range burst {
			go func() {
				defer wg.Done()
				verdict, err := store.Hit("one-bucket", request)
				if err != nil {
					t.Errorf("Hit: %v", err)
					return
				}
				admitted[i] = verdict.Allowed
			}()
		}
		wg.Wait()

		got := countTrue(admitted)
		if got == limit {
			t.Errorf("the two-step store admitted exactly %d under a concurrent burst, which means this test cannot tell one step from two. The reference's GCRA Lua exists precisely because this shape is the failure.", limit)
		}
		if got < burst {
			t.Errorf("the two-step store admitted %d of %d; every caller reads the count before any of them writes it, so the number should be the whole burst", got, burst)
		}
		t.Logf("measured: a two-step store admits %d of %d at a limit of %d; the one-step store admits %d", got, burst, limit, limit)
	})
}

type twoStepStore struct {
	mu   sync.Mutex
	used map[string]int
}

func (s *twoStepStore) Hit(key string, request Request) (Verdict, error) {
	s.mu.Lock()
	used := s.used[key]
	s.mu.Unlock()

	runtimeYield()

	s.mu.Lock()
	defer s.mu.Unlock()
	if used >= request.Limit {
		return Verdict{Allowed: false}, nil
	}
	s.used[key] = used + 1
	return Verdict{Allowed: true}, nil
}

func countTrue(values []bool) int {
	total := 0
	for _, value := range values {
		if value {
			total++
		}
	}
	return total
}

func TestEveryRateLimitFieldIsAnnouncedOnEveryAnsweredRequest(t *testing.T) {
	store := &countingStore{verdict: Verdict{
		Allowed:   true,
		Remaining: 598,
		ResetAt:   time.Unix(1_790_000_030, 0),
		RetryAt:   time.Unix(1_790_000_000, 0),
	}}
	clock := &fixedClock{now: time.Unix(1_790_000_000, 0)}

	limiter, err := NewLimiter(Options{
		Store:  store,
		Limit:  600,
		Window: time.Minute,
		Now:    clock.Now,
	}, refuseInTest)
	if err != nil {
		t.Fatalf("NewLimiter refused a valid configuration: %v", err)
	}

	t.Run("on an allowed request", func(t *testing.T) {
		got := ask(t, limiter, http.MethodGet, "/v1/me", nil)

		want := map[string]string{
			"RateLimit-Policy":      `"gateway-api";q=600;w=60`,
			"RateLimit":             `"gateway-api";r=598;t=30`,
			"RateLimit-Limit":       "600",
			"RateLimit-Remaining":   "598",
			"RateLimit-Reset":       "30",
			"X-RateLimit-Limit":     "600",
			"X-RateLimit-Remaining": "598",
			"X-RateLimit-Reset": "1790000030000",
		}

		if len(RateLimitHeaders) != len(want) {
			t.Errorf("RateLimitHeaders names %d fields and this table names %d. `RATE_LIMIT_HEADERS` in the reference exists so that something outside this file can name them all without spelling them from memory — the two drifting is the failure.", len(RateLimitHeaders), len(want))
		}
		for _, name := range RateLimitHeaders {
			if got.Header().Get(name) != want[name] {
				t.Errorf("%s is %q, want %q", name, got.Header().Get(name), want[name])
			}
		}
		if got := got.Header().Get("Retry-After"); got != "" {
			t.Errorf("Retry-After is %q on an ALLOWED request. It is not part of the allowance — it is an instruction, set only on a refusal, and RFC 9110 defines it rather than the draft these come from.", got)
		}
	})

	t.Run("on a refusal", func(t *testing.T) {
		store.verdict = Verdict{
			Allowed:   false,
			Remaining: 0,
			ResetAt:   clock.now.Add(30 * time.Second),
			RetryAt: clock.now.Add(4200 * time.Millisecond),
		}
		rec := &recorder{}

		refusing, err := NewLimiter(Options{
			Store:  store,
			Limit:  600,
			Window: time.Minute,
			Now:    clock.Now,
		}, rec.refuse)
		if err != nil {
			t.Fatalf("NewLimiter refused a valid configuration: %v", err)
		}

		got := ask(t, refusing, http.MethodGet, "/v1/me", nil)

		if got.Code != http.StatusTooManyRequests {
			t.Fatalf("a refused request was answered %d, want 429", got.Code)
		}
		for _, name := range RateLimitHeaders {
			if got.Header().Get(name) == "" {
				t.Errorf("%s is absent from the 429. §6 of the draft lets a server return these regardless of status code, so a client being throttled learns its budget only from the absence.", name)
			}
		}

		if got := got.Header().Get("Retry-After"); got != "5" {
			t.Errorf("Retry-After is %q, want \"5\" — a retry 4200ms away is 5 seconds, because the arithmetic ceils", got)
		}
		store.verdict.RetryAt = clock.now
		immediately := ask(t, refusing, http.MethodGet, "/v1/me", nil)
		if got := immediately.Header().Get("Retry-After"); got != "1" {
			t.Errorf("Retry-After is %q for a retry due NOW, want \"1\" — Retry-After: 0 tells a client to come back immediately, which is a hot loop against a bucket that cannot open", got)
		}

		if len(rec.refusals) != 2 {
			t.Fatalf("the limiter wrote %d refusals across two refused requests", len(rec.refusals))
		}
		refusal := rec.refusals[0]
		if refusal.Status != http.StatusTooManyRequests || refusal.Code != "rate_limited" {
			t.Errorf("the refusal is %+v, want 429 rate_limited", refusal)
		}
		if refusal.Detail != "too many requests for this window" {
			t.Errorf("the refusal's detail is %q, want the fixed sentence", refusal.Detail)
		}
	})
}

func TestTheTwoProbePathsAreNeverCounted(t *testing.T) {
	store := &countingStore{verdict: Verdict{Allowed: true, Remaining: 0}}
	clock := &fixedClock{now: time.Unix(1_790_000_000, 0)}

	limiter, err := NewLimiter(Options{
		Store:  store,
		Limit:  1,
		Window: time.Minute,
		Now:    clock.Now,
		Exempt: isProbePathForTest,
	}, refuseInTest)
	if err != nil {
		t.Fatalf("NewLimiter refused a valid configuration: %v", err)
	}

	for _, path := range []string{"/healthz", "/readyz"} {
		for i := 0; i < 5; i++ {
			got := ask(t, limiter, http.MethodGet, path, nil)
			if got.Code != http.StatusOK {
				t.Errorf("%s request %d was answered %d at a limit of 1, want 200 — a throttled probe is an orchestrator that cannot see a healthy process", path, i, got.Code)
			}
			if len(got.Header()) > 0 && got.Header().Get("RateLimit-Limit") != "" {
				t.Errorf("%s carries RateLimit headers at request %d; a probe is not counted, so it is not told about an allowance", path, i)
			}
		}
	}
	if len(store.seen()) != 0 {
		t.Errorf("the store saw %d request(s) for the probe paths: %v", len(store.seen()), store.seen())
	}

	if got := ask(t, limiter, http.MethodGet, "/v1/me", nil); got.Code != http.StatusOK {
		t.Fatalf("a non-exempt request was answered %d", got.Code)
	}
	if len(store.seen()) != 1 {
		t.Errorf("the store saw %d request(s) for one non-exempt request", len(store.seen()))
	}
}
