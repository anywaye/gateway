// Where the rate-limit counters live.
//
// The limiter itself (`limiter.go`) decides *which* bucket a request belongs to
// and what to say about it; this file decides how that bucket is counted, and
// there are two answers because there are two deployments:
//
//	memory  one process, lost on restart. Correct for a single instance.
//	redis   shared by every replica and across restarts (`redis.go`).
//
// Both sit behind `Store`, and the parity table in `parity_test.go` runs one
// behaviour table through both, so the abstraction is proven rather than asserted.
// `internal/httpapi` picks between them from `REDIS_URL`.
package ratelimit

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

// ErrNotConfigured is a configuration this package cannot serve. The same
// sentinel `internal/auth` and `internal/httpapi` use, and for the same reason:
// `errors.Is` is the whole reason it is a sentinel and not only a message.
var ErrNotConfigured = errors.New("ratelimit: invalid configuration")

// Verdict is what one request did to its bucket.
//
// `ResetAt` and `RetryAt` are two different instants, and conflating them is how
// a client backs off for the wrong amount:
//
//	ResetAt  when this caller is back to its *full* allowance.
//	RetryAt  when *this* request — the one that was refused — is admitted.
//
// On an admitted request `RetryAt` is at or before `now`: it is already admitted.
// On a refusal it is in the future, and it is what `Retry-After` says.
type Verdict struct {
	Allowed bool

	// Quota units left after this request. Never negative.
	Remaining float64

	// When the whole allowance is back.
	ResetAt time.Time

	// When this exact request would next be admitted.
	RetryAt time.Time
}

// Request is what one request did to its bucket, and the allowance it spent it
// against.
type Request struct {
	// Quota units per window. A whole number >= 1.
	Limit int

	// Window length. At least one millisecond, because a zero interval is a
	// division by zero in `count` and a limiter that panics is a limiter that
	// answers nothing.
	Window time.Duration

	// The instant this request arrived, from the limiter's clock so a test can
	// move time without sleeping.
	Now time.Time
}

// Store is one bucket, counted and read in a single step.
//
// The shape of this interface IS the atomicity guarantee. There is deliberately
// no `Peek` to call before `Hit`, so an implementation cannot read a count,
// release a lock, and write a stale one back — and read-then-write is exactly
// what admits N times the limit under a burst: every replica reads "4 used,
// limit 5" and all five of them write "5 used". The burst tests are what hold
// this in place.
//
// Implementations RETURN AN ERROR when their storage is unreachable. Turning
// that into a response is the middleware's decision and not the store's: a store
// that caught its own failure and answered "no" would turn a dependency outage
// into a platform-wide 429.
type Store interface {
	Hit(key string, request Request) (Verdict, error)
}

// count is GCRA — a smooth sliding window, in one number per bucket.
//
// Ported verbatim from `count()` in `src/middleware/rateLimitStore.ts`, including
// the two comments that explain why the arithmetic is what it is:
//
//   - A caller is thought of as owing `tat - now` of time. Each request adds
//     `windowMs / limit` to the debt; time passing repays it continuously rather
//     than in a lump at an edge. A request is admitted when the debt it would
//     leave is no more than one whole window.
//   - A fixed window cannot say that. It hands out `limit` per aligned bucket of
//     time, so `limit` requests one millisecond before the edge plus `limit` one
//     millisecond after it is 2x the allowance inside two milliseconds.
//
// ONE DIFFERENCE FROM THE SOURCE, and it is a difference of SPELLING only: the
// debt is a `time.Time` here and a `number` of milliseconds there, so `tat` is
// `time.UnixMilli(0)` rather than `0` and every comparison is `time.Time`'s
// rather than `<` on a float. The Redis Lua below has to do the same arithmetic
// on integers because Lua has no integer milliseconds type either, and the parity
// test is what proves the two agree request for request.
func count(tat, now time.Time, request Request) (time.Time, Verdict) {
	interval := request.Window / time.Duration(request.Limit)
	next := now
	if tat.After(now) {
		next = tat
	}
	next = next.Add(interval)
	delay := next.Sub(now)

	// Strictly greater, so a caller sitting exactly on the threshold is admitted:
	// that is what lets a burst of exactly `limit` land.
	if delay > request.Window {
		// Nothing is written. A refused request must not deepen the debt, or a
		// caller that keeps hammering while throttled locks itself out for as long
		// as it keeps trying.
		return tat, Verdict{
			Allowed:   false,
			Remaining: 0,
			ResetAt:   tat,
			RetryAt:   next.Add(-request.Window),
		}
	}

	used := float64(next.Sub(now)) / float64(interval)
	remaining := float64(request.Limit) - ceil(used)
	if remaining < 0 {
		remaining = 0
	}

	return next, Verdict{
		Allowed:   true,
		Remaining: remaining,
		// The whole allowance is back once the debt has been repaid in full, which
		// is at `next`. Before this request it stood at `tat`, so one request costs
		// exactly one interval of that.
		ResetAt: next,
		// Already admitted at `now`, so this is at or before it. Only the refusal
		// branch above produces a future value, and that is the `Retry-After`.
		RetryAt: next.Add(-interval).Add(-request.Window),
	}
}

// ceil is `Math.ceil` for the one value it is applied to.
//
// `math.Ceil` is the function and this is the alias, and it exists so the two
// places that round an allowance down to a whole number — this one and the Redis
// script's `math.ceil` — can be read as the same operation by someone comparing
// the two implementations.
func ceil(value float64) float64 {
	if value <= 0 {
		return 0
	}
	whole := float64(int64(value))
	if whole == value {
		return whole
	}
	return whole + 1
}

// DefaultMaxClients is how many settled buckets the memory store holds before it
// sweeps.
const DefaultMaxClients = 100_000

// MemoryStore counts buckets in one process.
//
// # SINGLE-INSTANCE ONLY, and said so here, in the README and in the compose file
// rather than in a line nobody reads: a caller gets `limit` per window from
// *each* replica, so N replicas is an N-times limit, and every bucket is lost on
// restart. The parity test pins the difference by showing two of these disagreeing
// where two Redis-backed ones share one bucket.
//
// # THE LOCK IS HELD ACROSS THE WHOLE UPDATE
//
// That is the atomicity argument, and it is `jwt.ts`'s argument in another
// language: "Everything between the read and the write in `count` is synchronous,
// and that is the whole atomicity argument — a JavaScript turn cannot be
// interleaved." Go's mutex is the same property spelled with a lock, and firing
// 200 concurrent `Hit`s at a limit of 50 still admits exactly 50.
type MemoryStore struct {
	mu         sync.Mutex
	buckets    map[string]time.Time
	maxClients int
}

// NewMemoryStore builds the in-memory store.
func NewMemoryStore(maxClients int) (*MemoryStore, error) {
	if maxClients == 0 {
		maxClients = DefaultMaxClients
	}
	if maxClients < 1 {
		return nil, fmt.Errorf("%w: maxClients must be an integer >= 1, got %d", ErrNotConfigured, maxClients)
	}
	return &MemoryStore{buckets: make(map[string]time.Time), maxClients: maxClients}, nil
}

// Hit counts one request against one bucket.
//
// # THERE IS NO CLOCK OPTION HERE, AND THAT IS DELIBERATE
//
// `Request.Now` is the only clock this store reads. A second one at construction
// would be a second answer to "what time is it" in the same process, and the two
// could disagree — a bucket aged by the constructor's clock and a request stamped
// by the caller's is a limiter whose arithmetic depends on which of two clocks
// reached it first.
func (s *MemoryStore) Hit(key string, request Request) (Verdict, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.buckets) >= s.maxClients {
		s.sweepSettledLocked(request.Now)
	}

	tat, _ := s.buckets[key]
	next, verdict := count(tat, request.Now, request)
	if verdict.Allowed {
		s.buckets[key] = next
	}
	return verdict, nil
}

// Size is how many buckets are held right now. v0 introspection, deliberately off
// the interface, and the parity test is its only caller.
func (s *MemoryStore) Size() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.buckets)
}

// sweepSettledLocked drops buckets whose debt has already been repaid.
//
// A bucket at `tat <= now` owes nothing, so forgetting it hands the caller
// exactly the allowance they had already earned — no more and no less, which is
// why this is safe. A bucket still in debt is NEVER swept: evicting one would hand
// that caller a fresh allowance for the price of one extra request, which is the
// self-DoS a rate limiter exists to prevent.
//
// `maxClients` bounds SETTLED state, not admitted traffic: a bucket that still
// owes quota is never swept, so the map can hold `maxClients` plus every caller
// active in the current window. That is stated in the README rather than
// defended against, because the alternative — evicting a caller in debt — is the
// failure this limiter is for.
func (s *MemoryStore) sweepSettledLocked(at time.Time) {
	for key, tat := range s.buckets {
		if !tat.After(at) {
			delete(s.buckets, key)
		}
	}
}
