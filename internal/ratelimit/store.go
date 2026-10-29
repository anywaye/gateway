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

	Remaining float64

	ResetAt time.Time

	RetryAt time.Time
}

// Request is what one request did to its bucket, and the allowance it spent it
// against.
type Request struct {
	Limit int

	Window time.Duration

	Now time.Time
}

func (r Request) nowMs() float64 { return float64(r.Now.UnixMilli()) }

func (r Request) windowMs() float64 { return float64(r.Window.Milliseconds()) }

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

func count(tat, now float64, request Request) (float64, Verdict) {
	windowMs := request.windowMs()
	interval := windowMs / float64(request.Limit)
	next := now
	if tat > now {
		next = tat
	}
	next = next + interval
	delay := next - now

	if delay > windowMs {
		return tat, Verdict{
			Allowed:   false,
			Remaining: 0,
			ResetAt:   at(tat),
			RetryAt:   at(next - windowMs),
		}
	}

	used := ceil((next - now) / interval)
	remaining := float64(request.Limit) - used
	if remaining < 0 {
		remaining = 0
	}

	return next, Verdict{
		Allowed:   true,
		Remaining: remaining,
		ResetAt: at(next),
		RetryAt: at(next - interval - windowMs),
	}
}

func at(ms float64) time.Time { return time.UnixMilli(int64(ms)) }

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
	buckets    map[string]float64
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
	return &MemoryStore{buckets: make(map[string]float64), maxClients: maxClients}, nil
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

	now := request.nowMs()
	if len(s.buckets) >= s.maxClients {
		s.sweepSettledLocked(now)
	}

	next, verdict := count(s.buckets[key], now, request)
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

func (s *MemoryStore) sweepSettledLocked(at float64) {
	for key, tat := range s.buckets {
		if tat <= at {
			delete(s.buckets, key)
		}
	}
}
