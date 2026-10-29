package sessionredis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/anywaye/gateway/internal/ratelimit"
	"github.com/anywaye/gateway/internal/session"
)

const namespace = "gateway:sess"

// Commands is the whole Redis surface this store needs: one command at a time.
//
// Deliberately not `ratelimit.Commands`, which is the limiter's two methods
// (`Eval`, `Ping`). Widening that interface would have put `Do` on the limiter's
// contract and grown its test double for the sake of a caller the limiter does not
// have; declaring the one method this store needs is smaller and leaves the
// limiter's shape alone.
//
// `ratelimit.Value` rather than `any` because Go matches interface methods on
// exact type identity, and `Connection.Do` answers `ratelimit.Value`.
type Commands interface {
	Do(ctx context.Context, args ...string) (ratelimit.Value, error)
}

// Connecter is the lazy client `NewLazy` takes: it opens a socket on first use.
//
// Declared HERE rather than widening `ratelimit.LazyRedis` with a `Do` method
// because the limiter does not need one, and a method added to `LazyRedis` for the
// benefit of a different package is a method every other `*LazyRedis` user has
// been given. Two constructors — this one and `New` over an already-open
// transport — is the smaller change, and it leaves `internal/ratelimit` untouched.
type Connecter interface {
	Connect() (*ratelimit.Connection, error)
}

// ErrNotConfigured is a refusal to build rather than a store that misbehaves.
//
// Same error the limiter's construction refusals use, so `RuntimeOptions` reports
// one kind of "this deployment is not configured" rather than two.
var ErrNotConfigured = errors.New("sessionredis: not configured")

// RedisStore keeps sessions in Redis.
//
// Expiry is the VALUE's job, not Redis's: `record.expiresAt` is compared against
// the injected clock on every read, exactly as `memorySessionStore` compares
// `expiresAt <= now()`. The `PX` on `SET` is a backstop that keeps the keyspace
// from growing without bound, and it is never the source of truth — a store whose
// only expiry mechanism is a TTL has moved the answer to "when does this session
// end" from identity to Redis, and identity is the thing that mints the token and
// says when it dies.
type RedisStore struct {
	commands Commands
	now      func() time.Time
}

var _ session.SessionStore = (*RedisStore)(nil)

// New builds the store over an already-constructed client.
//
// `now` is the clock expiry is judged against, and it is injected so a test can
// age a session without sleeping: the `<=` boundary is the whole of the parity
// with the reference, and a boundary that can only be reached by waiting is a
// boundary nobody tests.
func New(commands Commands, now func() time.Time) (*RedisStore, error) {
	if commands == nil {
		return nil, fmt.Errorf("%w: a session store needs a Redis client", ErrNotConfigured)
	}
	if now == nil {
		return nil, fmt.Errorf("%w: New needs a clock", ErrNotConfigured)
	}
	return &RedisStore{commands: commands, now: now}, nil
}

// NewLazy is the constructor a binary uses: the client dials on first use, so
// building a store opens nothing.
//
// That matters for the shape of the failure. A gateway configured with a
// `REDIS_URL` that is down still STARTS, and `/readyz` names `redis` as
// unavailable — the same contract the limiter already has. A store that dialed at
// construction would instead make a Redis outage a gateway that will not boot,
// which is the "a dependency outage is not a restart" rule applied to the wrong
// thing: a browser session being unavailable should be a `503` on the four `/auth`
// routes, not a process that an orchestrator takes out of rotation.
func NewLazy(connecter Connecter, now func() time.Time) (*RedisStore, error) {
	if connecter == nil {
		return nil, fmt.Errorf("%w: a session store needs a Redis client", ErrNotConfigured)
	}
	if now == nil {
		return nil, fmt.Errorf("%w: NewLazy needs a clock", ErrNotConfigured)
	}
	return &RedisStore{
		commands: &lazyCommands{connecter: connecter},
		now:      now,
	}, nil
}

type lazyCommands struct{ connecter Connecter }

func (l *lazyCommands) Do(ctx context.Context, args ...string) (ratelimit.Value, error) {
	connection, err := l.connecter.Connect()
	if err != nil {
		return nil, err
	}
	return connection.Do(ctx, args...)
}

type record struct {
	Token     string `json:"token"`
	ExpiresAt int64  `json:"expires_at"`
}

// KeyFor is the Redis key one session id lives under.
//
// Off the interface, like the limiter's: what a backend can cheaply answer about
// itself is not what every backend owes gateway. It is also the assertion's
// observation point — a test reads the key off the transport rather than
// rebuilding it here, because a test that re-derives the production expression
// passes on a broken namespace.
func (s *RedisStore) KeyFor(sessionID string) string { return namespace + ":" + sessionID }

// Get is the live session, or nil. Absent and expired are the SAME answer.
//
// # AN ID THAT IS NOT ONE GATEWAY MINTED IS ABSENT, NOT AN ERROR
//
// `Get` is handed the `__Host-bff-session` COOKIE, so unlike every other id in
// this repository it is caller input. The cookie is a canonical lowercase v4 UUID
// because that is what `uuid.NewString()` mints, and anything else was not minted
// here and therefore cannot be in the store: absent is the whole truth about it.
//
// Answering an error instead would send a caller who pasted junk into their own
// cookie to a `503`, which says "we cannot tell whether you are signed in" for an
// id that was never a possibility. The reference answers `401` here, because
// `sessions.get(junk)` is `undefined` in a `Map` and the cookie value is never
// what makes it defined.
//
// This is also the property that keeps caller bytes out of a Redis key: an id
// that fails the shape check never reaches `KeyFor`, so there is nothing to
// escape the namespace with. The reference needs no such rule — a `Map` cannot be
// escaped by a crafted key — and that is exactly why the hazard only appears when
// the map becomes a shared store.
func (s *RedisStore) Get(ctx context.Context, sessionID string) (*session.Session, error) {
	if !isMintedID(sessionID) {
		return nil, nil
	}

	key := s.KeyFor(sessionID)
	reply, err := s.commands.Do(ctx, "GET", key)
	if err != nil {
		return nil, fmt.Errorf("sessionredis: GET %s: %w", key, err)
	}
	if reply == nil {
		return nil, nil
	}

	payload, ok := reply.(string)
	if !ok {
		return nil, fmt.Errorf("sessionredis: GET %s answered %T", key, reply)
	}

	stored, err := decodeRecord(payload)
	if err != nil {
		return nil, fmt.Errorf("sessionredis: GET %s: %w", key, err)
	}

	expiresAt := time.UnixMilli(stored.ExpiresAt).UTC()
	if !expiresAt.After(s.now()) {
		_, _ = s.commands.Do(ctx, "DEL", key)
		return nil, nil
	}

	return &session.Session{Token: stored.Token, ExpiresAt: expiresAt}, nil
}

// Put stores a session under an id gateway minted.
//
// ONE `SET`, and the expiry goes on the same command rather than as a follow-up:
// a `SET` followed by an `EXPIRE` leaves a window in which the record exists with
// no TTL, which is a leaked key on exactly the deployment this store exists for.
func (s *RedisStore) Put(ctx context.Context, sessionID string, held session.Session) error {
	if !isMintedID(sessionID) {
		return fmt.Errorf("%w: Put was handed %q, which is not a session id this service mints", ErrNotConfigured, sessionID)
	}

	payload, err := json.Marshal(record{
		Token:     held.Token,
		ExpiresAt: held.ExpiresAt.UnixMilli(),
	})
	if err != nil {
		return fmt.Errorf("sessionredis: encoding a session: %w", err)
	}

	key := s.KeyFor(sessionID)
	ttl := held.ExpiresAt.Sub(s.now()).Milliseconds()
	if ttl < 1 {
		ttl = 1
	}

	reply, err := s.commands.Do(ctx, "SET", key, string(payload), "PX", strconv.FormatInt(ttl, 10))
	if err != nil {
		return fmt.Errorf("sessionredis: SET %s: %w", key, err)
	}
	if status, ok := reply.(string); !ok || !strings.EqualFold(status, "OK") {
		return fmt.Errorf("sessionredis: SET %s answered %s", key, describe(reply))
	}
	return nil
}

// Delete drops one. Deleting an id that is not there succeeds, so a client
// retrying a sign-out is not told it did the wrong thing.
//
// An id that is not minted returns success without a round trip, for the same
// reason `Get` treats one as absent: it was never ours, so there is nothing to
// delete and nothing to report.
func (s *RedisStore) Delete(ctx context.Context, sessionID string) error {
	if !isMintedID(sessionID) {
		return nil
	}

	key := s.KeyFor(sessionID)
	reply, err := s.commands.Do(ctx, "DEL", key)
	if err != nil {
		return fmt.Errorf("sessionredis: DEL %s: %w", key, err)
	}
	if _, ok := reply.(int); !ok {
		return fmt.Errorf("sessionredis: DEL %s answered %s", key, describe(reply))
	}
	return nil
}

func isMintedID(sessionID string) bool {
	if len(sessionID) != 36 {
		return false
	}
	for i := 0; i < len(sessionID); i++ {
		c := sessionID[i]
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
				return false
			}
		}
	}
	return true
}

func decodeRecord(payload string) (record, error) {
	var out record
	if err := json.Unmarshal([]byte(payload), &out); err != nil {
		return record{}, fmt.Errorf("the stored session is not readable: %w", err)
	}
	if out.Token == "" {
		return record{}, errors.New("the stored session carries no credential")
	}
	return out, nil
}

func describe(value ratelimit.Value) string {
	switch typed := value.(type) {
	case nil:
		return "null"
	case string:
		return fmt.Sprintf("a %d-byte string", len(typed))
	case int:
		return strconv.Itoa(typed)
	case []ratelimit.Value:
		return fmt.Sprintf("an array of %d", len(typed))
	default:
		return fmt.Sprintf("%T", typed)
	}
}
