// Package sessiontest is the in-memory session store the suite and the
// equivalence check stand in with.
//
// # THIS IS NOT THE SERVICE'S SESSION STORE
//
// `internal/httpapi` ships NO session store. `Options.BFF.Sessions` is a
// `SessionStore`, and the only implementations of it in this module live in test
// files or in this package — which is why this package exists as its own module
// path rather than as a `_test.go` inside `httpapi`: `internal/equivalence` is a
// separate package and needs one too, and a `_test.go` is invisible across a
// package boundary.
//
// That visibility is the point, so it is ENFORCED rather than asserted in a
// comment. `TestNoProductionFileImportsTheSessionDouble` reads every non-test
// source file under `cmd/` and `internal/` and fails on any import of this
// package. So "the Go service ships no session store" is a property a reader can
// check by running one test, not a promise in a header that a later packet could
// quietly break by adding one import.
//
// # WHY THERE IS NO IMPLEMENTATION, IN ONE PARAGRAPH
//
// `src/bff/session.ts` has one: a `Map` in one process, marked
// `TODO(guard-06)`/`TODO(guard-07)` for Redis. Porting it would have copied the
// worse of two designs into the language that makes the better one easier to
// write. The better one is `identity/internal/sessions/store.go` — it is handed a
// `TokenDigest` and has no code path that can produce a raw credential, and its
// `ErrNotFound` is one error for "no such token, a revoked token, an expired
// token, and a token belonging to a deleted user". But it is keyed by
// `token_digest` and resolves a *token* to a session, which is the OPPOSITE
// direction from what this service needs (`SessionStore.Get` is handed the
// browser's opaque id and must return the token), Go's `internal/` rule forbids
// the import across modules, and no identity endpoint performs the inverse
// lookup. The `internal/session` package comment has the measurement; this is the
// consequence of it.
//
// So the store is a fixture, it says so on every type, and the interface it
// stands in for is the thing the next packet implements.
package sessiontest

import (
	"context"
	"sync"
	"time"

	"github.com/cafaye/gateway/internal/session"
)

// New is a map-backed `SessionStore`, per process, expired records dropped on the
// way out rather than in a background sweep.
//
// A record read once is never read again, so the read that has to notice is the
// only one — the same reasoning `memorySessionStore` gives, kept because a fixture
// that swept differently from the thing it stands in for would make the tests
// prove something other than what they claim.
func New(now func() time.Time) *Store {
	if now == nil {
		now = time.Now
	}
	return &Store{now: now, held: map[string]session.Session{}}
}

// Store is the double. Every method takes the mutex, because the suite drives the
// handler from several goroutines and `go test -race` is part of the gate — a
// fixture that raced would make a failure in the service indistinguishable from a
// failure in the thing being tested.
type Store struct {
	mu   sync.Mutex
	now  func() time.Time
	held map[string]session.Session
}

var _ session.SessionStore = (*Store)(nil)

// Get is the live session, or nil. Absent and expired are the same answer.
func (s *Store) Get(_ context.Context, sessionID string) (*session.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	record, held := s.held[sessionID]
	if !held {
		return nil, nil
	}
	if !record.ExpiresAt.After(s.now()) {
		delete(s.held, sessionID)
		return nil, nil
	}
	return &record, nil
}

// Put stores a session under an id.
func (s *Store) Put(_ context.Context, sessionID string, record session.Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.held[sessionID] = record
	return nil
}

// Delete drops one. Deleting an id that is not there succeeds.
func (s *Store) Delete(_ context.Context, sessionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.held, sessionID)
	return nil
}

// Size is how many records are held, expired ones included.
//
// Fixture-only and deliberately not on `SessionStore`: the interface is what every
// backend owes the service, and this is what this one can cheaply answer.
func (s *Store) Size() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return len(s.held)
}

// Held returns the session ids in the store, so a test can prove the id in the
// cookie is the one the record is under — which is the property that makes the
// cookie a pointer rather than a decoration.
func (s *Store) Held() []string {
	s.mu.Lock()
	defer s.mu.Unlock()

	ids := make([]string, 0, len(s.held))
	for id := range s.held {
		ids = append(ids, id)
	}
	return ids
}

// Fail makes every method return an error, so a test can stand in for a store
// that is down.
//
// Not a flag on `New`, because a store that can be told to fail is a store whose
// tests can forget to test the failure — and "the store is unavailable" has to
// reach the caller as a `503` rather than as a `401`, which is the whole reason it
// is here.
type Fail struct{}

func (Fail) Get(context.Context, string) (*session.Session, error) {
	return nil, errStoreDown
}

func (Fail) Put(context.Context, string, session.Session) error { return errStoreDown }

func (Fail) Delete(context.Context, string) error { return errStoreDown }

var errStoreDown = errorString("sessiontest: the session store is down")

type errorString string

func (e errorString) Error() string { return string(e) }
