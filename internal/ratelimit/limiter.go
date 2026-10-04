// The rate-limit middleware.
//
// Everything about *which* bucket a request belongs to is `key.go`, and everything
// about *how* a bucket is counted is `store.go` behind `Store`. What is left here
// is the part only this file can decide:
//
//   - the policy, which is half the key and the name in `RateLimit-Policy`,
//   - what a client is told — RFC 9651's `RateLimit-Policy` and `RateLimit`, the
//     `RateLimit-Limit`/`-Remaining`/`-Reset` trio every deployed client already
//     reads, and `Retry-After` on a refusal,
//   - and what happens when the counter store is unreachable.
//
// # IT IS MOUNTED AFTER AUTHENTICATION, ON PURPOSE
//
// The key is the strongest identity the request has, and the strongest identity is
// only known once a token has been verified or a key has been looked up. The cost
// of that ordering is stated rather than hidden: a request refused by the auth gate
// is never counted, because a token that does not verify must not become a
// rate-limit key, and a rejected credential is cheap to reject — the algorithm is
// read off the header before any key is fetched.
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
// per request. `src/middleware/rateLimit.ts` validates the same three numbers in
// the same place and says why.
type Options struct {
	// Requests allowed per window. An integer >= 1.
	Limit int

	// Window length. Zero means the reference's default of 60s; see
	// `DefaultWindow`.
	Window time.Duration

	// Where buckets are counted. Required — a limiter with no store applies no
	// limit, and `internal/httpapi` expresses that by not mounting one at all,
	// which is a shape a reader can see rather than a nil the limiter invents.
	Store Store

	// How many proxies stand in front of gateway, which is how much of
	// `X-Forwarded-For` may be believed. Zero — the default — believes none of it.
	// See `ClientIP`.
	TrustedProxies int

	// The policy in force for a path, and the numbers it stands for.
	//
	// A function of the PATH rather than of the request, and that is a narrowing
	// the port is explicit about: the reference reads `policy(c)` per request
	// because a per-route table is resolved from the path, and with only the
	// default table ported there is exactly one answer. The `Resolve` hook below is
	// how the per-route packet gets at the same numbers without this type
	// changing shape.
	Policy func(path string) string

	// The numbers a policy name stands for, when a route carries its own.
	//
	// A name the table does not carry falls back to the allowance above rather
	// than failing, so a typo in a table costs the default allowance and nothing
	// else. This is `resolve` in `rateLimit.ts` and the fallback is its documented
	// behaviour.
	Resolve func(policy string) (limit int, window time.Duration, ok bool)

	// Clock, injected so a test can cross a window boundary without sleeping.
	Now func() time.Time

	// Paths that are never throttled. Required to be non-nil-safe: nil means
	// nothing is exempt, and `internal/httpapi` passes `ProbePaths`.
	Exempt func(path string) bool
}

// DefaultWindow is the shipped window, and it is `DEFAULT_LIMIT_TABLE` in
// `src/middleware/limits.ts`.
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

	// Policy name -> that policy's own numbers, memoised.
	//
	// The reference memoises the same map and for the same reason: a policy is
	// read PER REQUEST, so validating the name once per request is validating it
	// on every request, and the map also means a name's numbers are decided once
	// rather than re-resolved per request.
	//
	// The lock is because Go reads this from every goroutine and the reference's
	// single loop did not have to. `sync.Map` was the other candidate and a plain
	// mutex is the honest one: the map holds one entry per distinct policy name,
	// which is a handful, and a `sync.Map` optimises for a case this does not have.
	mu     sync.Mutex
	limits map[string]allowance
}

// allowance is a policy name and the numbers it stands for.
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
		// One millisecond, not one nanosecond: `count` divides the window by the
		// limit to get the interval, and an interval that truncates to zero is a
		// division by zero on every request. A window shorter than a millisecond
		// cannot express "600 per second" and is not a rate anybody asked for.
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

// allow is the policy name's numbers, resolved once and remembered.
//
// The name is VALIDATED here rather than escaped and truncated, and the reference
// says why: a name that cannot be serialised into a structured field is a
// configuration mistake to surface, and the one way it could be *not* surfaced is
// a header carrying a second field item that a client reads as a second policy.
//
// That is RFC 9651 §3.1.1.3's key grammar: `lcalpha / DIGIT / "_" / "-" / "." /
// "*"`, opening on a letter or `*`, at most 64 characters.
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
			// Only legal as the FIRST character, and the loop below enforces that
			// by rejecting it anywhere else.
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
			// A policy name that cannot be a structured-field key is gateway's own
			// configuration being wrong, and the middleware's answer is the same
			// as `createJwtVerifier`'s: refuse the request rather than serve it
			// with headers nobody can parse. The reason goes to the log.
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
			// A whole second at minimum. `Retry-After: 0` tells a client to come
			// back immediately, and a client that obeys it is a hot loop against a
			// bucket that cannot open for another few hundred milliseconds.
			w.Header().Set("Retry-After", strconv.FormatInt(secondsUntil(at, verdict.RetryAt, true), 10))
			l.refuse(w, r, http.StatusTooManyRequests, "rate_limited", "too many requests for this window")
			return
		}

		next.ServeHTTP(w, r)
	})
}

// failedOpen is a counter store that is not there.
//
// # FAILS OPEN, AND THE COST IS NAMED RATHER THAN HIDDEN
//
// For as long as Redis is unreachable, gateway applies no limit at all. The
// alternative — failing closed — hands an outage in the counter store to every
// caller as a 429, which is the same class of mistake as restarting the process on
// a dependency blip, and much harder to notice. A store that cannot answer has
// told us nothing about whether the caller has spent anything, and guessing "no" is
// guessing in the direction that keeps the edge serving.
//
// The headers are left off rather than guessed at, because a client told
// `RateLimit-Limit: 600` and then never refused is worse than a client told
// nothing. The store is a registered readiness probe, so `/readyz` says so.
//
// The message can name a host, a port and a bucket; the caller gets a request with
// no rate-limit headers on it and no idea why, and the log is where that goes.
func (l *Limiter) failedOpen(r *http.Request, cause error) {
	Logf("gateway: the rate-limit store is unavailable; this request is not counted (%s %s): %v", r.Method, r.URL.Path, cause)
}

// announce is the header family, on every answered request.
//
// Two shapes, because clients in the field read two shapes and a gateway that
// sends only one of them throttles nobody. There is no RFC for these fields yet;
// the citation is the IETF HTTPAPI working group's Standards Track draft,
// `draft-ietf-httpapi-ratelimit-headers-11` (Polli, Martinez Ruiz, Miller; 23 May
// 2026), which builds on **RFC 9651** (Structured Field Values for HTTP) — not
// RFC 9331, which is L4S/ECN and has nothing to do with rate limiting.
//
//   - §3 `RateLimit-Policy` — the quota policy, as a List of Items: the policy
//     name as a String, `q` for the quota, `w` for the window in seconds.
//     RateLimit-Policy: "gateway-api";q=600;w=60
//   - §4 `RateLimit` — the quota currently available under that policy: `r` for the
//     available quota and, per §4.1.2, `t` for the *effective window*, "the number
//     of seconds within which the client can use no more than the available quota".
//     That is a countdown to the replenishment, not a copy of `w`: the draft's own
//     examples show it moving. Sending the window here would tell a client its
//     remaining quota lasts twice as long as it does.
//     RateLimit: "gateway-api";r=12;t=44
//   - The un-prefixed `RateLimit-Limit`, `RateLimit-Remaining` and
//     `RateLimit-Reset` trio, which the same draft dropped in -08 and which
//     deployed clients and proxies still parse. `RateLimit-Reset` counts down in
//     seconds, like `t`, so the two agree by construction.
//   - This repository's own `X-RateLimit-*`, which is what gateway sent before the
//     draft existed: same numbers, and `X-RateLimit-Reset` as an absolute epoch
//     instant, because a client that wants a wall-clock deadline should not have to
//     reconstruct one from a delta.
//
// §6 lets a server return these regardless of status code, so they go on the 429 as
// well; §7 makes `Retry-After` take precedence when both are present, and that is
// the order they are meant to be read in.
//
// # THE NUMBERS ARE FORMATTED LIKE JAVASCRIPT, DELIBERATELY
//
// `remaining` is a whole number of quota units in the reference because `Verdict`
// there is typed as numbers coming out of Lua's integer arithmetic, and Go's
// `%.0f` of a float64 is what a client reads either way. `internal/equivalence`
// compares these header VALUES byte for byte, and `strconv.FormatFloat(v, 'f',
// -1, 64)` is `String(v)` in JavaScript for every value a limiter can produce.
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
// documented. `internal/equivalence` compares this list against the headers the
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

// secondsUntil is `Math.max(0, Math.ceil((until - at) / 1000))`, and `atLeastOne`
// is the `Math.max(1, …)` the `Retry-After` line adds.
//
// `Ceil` and not a truncation, and that is the reference's arithmetic: a reset 400
// milliseconds away is `t=1`, not `t=0`, because `RateLimit-Reset` counts in whole
// seconds and rounding down would tell a client its budget is back before it is.
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

// number is `String(n)` for a whole quota count.
//
// `%.0f` rounds; a quota count is always a whole number by construction — it is
// `limit - ceil(used)` — so there is nothing to round and this is exact.
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
