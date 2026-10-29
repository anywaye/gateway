package ratelimit

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"math"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// Options is the limiter's configuration, validated at construction.
//
// `RATE_LIMIT_REQUESTS=0` has to be a refusal to boot rather than a surprise on
// the first request of the week, and that is checked in `NewLimiter` rather than
// per request. `src/middleware/rateLimit.ts` (removed at cutover) validates the same three numbers in
// the same place and says why.
type Options struct {
	Limit int

	Window time.Duration

	Store Store

	TrustedProxies int

	Policy func(path string) string

	Resolve func(policy string) (limit int, window time.Duration, ok bool)

	Now func() time.Time

	Exempt func(path string) bool
}

// DefaultWindow is the shipped window, and it is `DEFAULT_LIMIT_TABLE` in
// `src/middleware/limits.ts` (removed at cutover).
const DefaultWindow = 60 * time.Second

// DefaultPolicy is the shipped policy name, and it is the `gateway-api` the
// README's endpoint table prints on every `/v1` row.
const DefaultPolicy = "gateway-api"

// DefaultLimit is the shipped allowance.
const DefaultLimit = 600

// Refuser writes a rate-limit refusal. `internal/httpapi` supplies it, so the
// problem-document envelope stays in the package that owns it — the same
// one-directional dependency `internal/auth` has.
type Refuser func(w http.ResponseWriter, r *http.Request, status int, code, detail string)

// Limiter is the built middleware.
type Limiter struct {
	store          Store
	trustedProxies int
	policy         func(string) string
	resolve        func(string) (int, time.Duration, bool)
	now            func() time.Time
	exempt         func(string) bool
	defaultLimit   int
	defaultWindow  time.Duration
	refuse         Refuser

	mu     sync.Mutex
	limits map[string]allowance
}

type allowance struct {
	Limit  int
	Window time.Duration
	Policy string
}

// NewLimiter builds the limiter, or refuses the configuration.
//
// Every refusal is `ErrNotConfigured`-wrapped, so a caller can tell its own
// mistake from a defect in this package. The three numbers are the reference's
// three: `limit`, `windowMs` and `trustedProxies`.
func NewLimiter(options Options, refuse Refuser) (*Limiter, error) {
	if refuse == nil {
		return nil, fmt.Errorf("%w: a limiter needs a Refuser, or it cannot write a 429", ErrNotConfigured)
	}
	if options.Store == nil {
		return nil, fmt.Errorf("%w: a limiter needs a Store; build one with no store means applying no limit, which is expressed by not mounting a limiter at all", ErrNotConfigured)
	}

	limit := options.Limit
	if limit == 0 {
		limit = DefaultLimit
	}
	if limit < 1 {
		return nil, fmt.Errorf("%w: limit must be an integer >= 1, got %d", ErrNotConfigured, limit)
	}

	window := options.Window
	if window == 0 {
		window = DefaultWindow
	}
	if window < time.Millisecond {
		return nil, fmt.Errorf("%w: windowMs must be at least 1ms, got %v — an interval that truncates to zero is a limiter that cannot count", ErrNotConfigured, window)
	}

	if options.TrustedProxies < 0 {
		return nil, fmt.Errorf("%w: trustedProxies must be an integer >= 0, got %d", ErrNotConfigured, options.TrustedProxies)
	}

	policy := options.Policy
	if policy == nil {
		policy = func(string) string { return DefaultPolicy }
	}
	now := options.Now
	if now == nil {
		now = time.Now
	}
	exempt := options.Exempt
	if exempt == nil {
		exempt = func(string) bool { return false }
	}

	return &Limiter{
		store:          options.Store,
		trustedProxies: options.TrustedProxies,
		policy:         policy,
		resolve:        options.Resolve,
		now:            now,
		exempt:         exempt,
		defaultLimit:   limit,
		defaultWindow:  window,
		refuse:         refuse,
		limits:         make(map[string]allowance),
	}, nil
}

func (l *Limiter) allow(name string) (allowance, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if known, ok := l.limits[name]; ok {
		return known, nil
	}

	checked := allowance{Limit: l.defaultLimit, Window: l.defaultWindow, Policy: name}
	if l.resolve != nil {
		if limit, window, ok := l.resolve(name); ok {
			if limit < 1 {
				return allowance{}, fmt.Errorf("%w: policy %s: limit must be an integer >= 1, got %d", ErrNotConfigured, name, limit)
			}
			if window < time.Millisecond {
				return allowance{}, fmt.Errorf("%w: policy %s: windowMs must be at least 1ms, got %v", ErrNotConfigured, name, window)
			}
			checked.Limit, checked.Window = limit, window
		}
	}

	if err := assertStructuredKey(name); err != nil {
		return allowance{}, err
	}

	l.limits[name] = checked
	return checked, nil
}

func assertStructuredKey(value string) error {
	if value == "" || len(value) > 64 {
		return fmt.Errorf("%w: policy must be a structured-field key, got %q", ErrNotConfigured, value)
	}
	for i, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
		case r == '*':
			if i != 0 {
				return fmt.Errorf("%w: policy must be a structured-field key, got %q", ErrNotConfigured, value)
			}
		case (r >= '0' && r <= '9') || r == '_' || r == '-' || r == '.':
			if i == 0 {
				return fmt.Errorf("%w: policy must be a structured-field key, got %q", ErrNotConfigured, value)
			}
		default:
			return fmt.Errorf("%w: policy must be a structured-field key, got %q", ErrNotConfigured, value)
		}
	}
	return nil
}

// Wrap is the middleware.
//
// `store.Hit` is the whole decision: it counts and answers in one atomic step, so
// a burst of N concurrent requests admits exactly `limit` of them rather than N.
// There is no read here before the write, and that is the property the burst test
// exists to hold in place.
func (l *Limiter) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		at := l.now()
		if l.exempt(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		active, err := l.allow(l.policy(r.URL.Path))
		if err != nil {
			l.failedOpen(r, err)
			next.ServeHTTP(w, r)
			return
		}

		key := CounterKey(active.Policy, Key(KeySourceOf(r, l.trustedProxies)))

		verdict, err := l.store.Hit(key, Request{Limit: active.Limit, Window: active.Window, Now: at})
		if err != nil {
			l.failedOpen(r, err)
			next.ServeHTTP(w, r)
			return
		}

		l.announce(w, active, verdict, at)

		if !verdict.Allowed {
			w.Header().Set("Retry-After", strconv.FormatInt(secondsUntil(at, verdict.RetryAt, true), 10))
			l.refuse(w, r, http.StatusTooManyRequests, "rate_limited", "too many requests for this window")
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (l *Limiter) failedOpen(r *http.Request, cause error) {
	Logf("gateway: the rate-limit store is unavailable; this request is not counted (%s %s): %v", r.Method, r.URL.Path, cause)
}

func (l *Limiter) announce(w http.ResponseWriter, active allowance, verdict Verdict, at time.Time) {
	windowSeconds := int64(math.Ceil(active.Window.Seconds()))
	effective := secondsUntil(at, verdict.ResetAt, false)
	resetAtMillis := verdict.ResetAt.UnixMilli()

	w.Header().Set("RateLimit-Policy", fmt.Sprintf("%q;q=%d;w=%d", active.Policy, active.Limit, windowSeconds))
	w.Header().Set("RateLimit", fmt.Sprintf("%q;r=%s;t=%d", active.Policy, number(verdict.Remaining), effective))
	w.Header().Set("RateLimit-Limit", strconv.Itoa(active.Limit))
	w.Header().Set("RateLimit-Remaining", number(verdict.Remaining))
	w.Header().Set("RateLimit-Reset", strconv.FormatInt(effective, 10))
	w.Header().Set("X-RateLimit-Limit", strconv.Itoa(active.Limit))
	w.Header().Set("X-RateLimit-Remaining", number(verdict.Remaining))
	w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(resetAtMillis, 10))
}

// RateLimitHeaders is every field `announce` sets, by name.
//
// Exported rather than kept private because something outside this file has to name
// them all and must not spell them from memory: `openapi/v1.yaml` puts each one on
// the `429`, and a rate-limit header family the document and the middleware name
// differently is a client reading `RateLimit-Remaining` from a header nobody
// documented. `internal/equivalence` compared this list against the headers the
// reference actually sends.
//
// `Retry-After` is deliberately not here. It is not part of the allowance — it is
// an instruction, set only on a refusal, and RFC 9110 defines it rather than the
// draft these come from.
var RateLimitHeaders = []string{
	"RateLimit-Policy",
	"RateLimit",
	"RateLimit-Limit",
	"RateLimit-Remaining",
	"RateLimit-Reset",
	"X-RateLimit-Limit",
	"X-RateLimit-Remaining",
	"X-RateLimit-Reset",
}

func secondsUntil(at, until time.Time, atLeastOne bool) int64 {
	seconds := int64(math.Ceil(until.Sub(at).Seconds()))
	if seconds < 0 {
		seconds = 0
	}
	if atLeastOne && seconds < 1 {
		seconds = 1
	}
	return seconds
}

func number(value float64) string {
	if value == math.Trunc(value) {
		return strconv.FormatInt(int64(value), 10)
	}
	return strconv.FormatFloat(value, 'f', -1, 64)
}

// CounterKey is the counter key: the policy, then a digest of the caller's
// identity.
//
// The policy leads it, so two policies never share a bucket by accident and a
// caller who exhausts `/auth/login` cannot spend the `/v1` allowance.
//
// The identity is DIGESTED rather than pasted in, and that is not tidiness.
// `Key` produces whatever the verified identity contains: an `account_id` claim is
// whatever identity chose to put there, an IPv6 address can carry a `%zone`, and a
// bucket name becomes a Redis key. The store's charset check exists to stop
// anything unsafe landing in one — and a key that trips it THROWS, the middleware
// fails open, and the limiter is silently off in exactly the deployment that needs
// it. Hashing makes that impossible by construction rather than by a charset
// nobody remembers, and it has the side benefit the rate-limit draft's privacy
// section asks for: a `KEYS gateway:rl:*` scan no longer yields a list of the
// accounts hitting the edge.
//
// 32 hex characters of SHA-256 is 128 bits against a keyspace of accounts, and the
// key is an input to a bucket, not a secret: a collision would merge two callers'
// allowances, not expose either.
func CounterKey(policy, identity string) string {
	digest := sha256.Sum256([]byte(identity))
	return policy + ":" + hex.EncodeToString(digest[:])[:32]
}

// Logf is where a limiter's own log lines go.
//
// A variable rather than a direct `log.Printf`, and the reason is the same one
// `probe.go` gives for its timeout: a test asserts on what this package reported
// and needs to see it, and a package that hardcodes its logger cannot be observed
// by the test that exists to observe it. `internal/httpapi` sets it once at
// startup; nothing here reads it otherwise.
var Logf = func(format string, args ...any) {
	log.Printf(format, args...)
}
