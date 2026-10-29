package session

import (
	"context"
	"time"
)

// Session is one live browser session.
//
// `ExpiresAt` is the token's own expiry, taken from what identity said rather
// than from a TTL this package invented: identity decides how long a session is
// good for, and a second clock here would be a second answer to that question.
type Session struct {
	Token string

	ExpiresAt time.Time
}

// SessionStore is the contract every session backend implements.
//
// THREE METHODS AND NOTHING ELSE, deliberately, ported from
// `src/bff/session.ts` (removed at cutover) and not one more. A `Size`, a `List` and a `Count` are
// all things a caller could want and none of them anything the BFF needs, and
// every one of them added here is a method the Redis implementation has to grow.
//
// Absent and expired are the SAME answer, and that is not a simplification: a
// backend that returned an expired record would be handing out a session it
// knows is dead, and a backend that distinguished them would be telling a caller
// which of the two happened.
type SessionStore interface {
	Get(ctx context.Context, sessionID string) (*Session, error)

	Put(ctx context.Context, sessionID string, session Session) error

	Delete(ctx context.Context, sessionID string) error
}
