package sessiontest

import (
	"context"
	"sync"
	"time"

	"github.com/anywaye/gateway/internal/session"
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
