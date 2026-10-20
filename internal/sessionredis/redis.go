// Package sessionredis is the session store the Go service ships.
//
// # WHY THIS EXISTS, AND WHY IT IS NOT A REUSE
//
// `internal/session` records why the store could not be identity's, and that
// record was checked rather than inherited — see `REPORT-gateway-session-store-01`
// and `CHANGELOG.md`. Both halves hold: identity's `sessions` table has no column
// for the presented value (it is keyed on `token_digest`, `ByToken` is its only
// read and takes a token), and Go's `internal/` rule forbids the import. So the
// one route that was never going to be right — reusing the service that mints
// credentials as the service that remembers them in the clear — stays closed, and
// gateway owns its sessions.
//
// The rejected alternative is the reference's own store: a `Map` in one process,
// which signs a browser out on the next restart and on whichever replica it did
// not sign in to. That is the *degraded* shape, and a Go gateway serving it would
// be less capable than the TypeScript one while looking identical in a diff.
//
// # ONE CLIENT, NOT A SECOND PROTOCOL
//
// The transport is `internal/ratelimit`'s, and this package does not have a RESP2
// encoder of its own: `Commands` is one method, `Do`, and `*ratelimit.LazyRedis`
// satisfies it. `RuntimeOptions` already builds that client for the limiter and
// hands the SAME one here, so a deployment has one socket to Redis rather than
// two, one command-in-flight lock rather than two, and one implementation of RESP2
// rather than two implementations that will disagree.
//
// Forking `resp.go` is the specific thing this packet was warned about, and the
// cost is not the forty lines: it is that the next reply-shape defect has two
// places to be fixed and one of them is the one nobody tests.
//
// # THE STORE HOLDS THE TOKEN IN THE CLEAR, AND THAT IS THE REFERENCE'S POSTURE
//
// `SessionStore.Get` must return the identity token so the BFF can put it in a
// `Bearer` header for `/v1/me`. A store that held a digest could not answer, so
// this one stores the credential. That is a different posture from identity's,
// which never stores a presented value and could not if it wanted to — and it is
// named here rather than glossed, because "the sessions are in Redis" reads as
// harmless in a threat model and is not: a Redis that is readable by the wrong
// principal is a credential store that has leaked.
package sessionredis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/cafaye/gateway/internal/ratelimit"
	"github.com/cafaye/gateway/internal/session"
)

// namespace is gateway's own session prefix.
//
// Same rule as the limiter's `gateway:rl`: a store's prefix is ADDED to this
// rather than replacing it, because a key outside gateway's namespace is a key
// nobody can find again, and a namespace an operator can configure away is a
// namespace that silently stops holding sessions. There is deliberately no
// operator-settable prefix — one namespace is one thing to reason about, and a
// second knob here is a second answer to "which keys are mine".
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

// lazyCommands dials per call and holds nothing.
//
// The dial itself is single-flight in `LazyRedis.Connect` — it holds its lock
// across the connect, which is the same mechanism `internal/auth` uses for the
// JWKS fetch — so this is one socket per call, not one socket per call.
type lazyCommands struct{ connecter Connecter }

func (l *lazyCommands) Do(ctx context.Context, args ...string) (ratelimit.Value, error) {
	connection, err := l.connecter.Connect()
	if err != nil {
		return nil, err
	}
	return connection.Do(ctx, args...)
}

// record is the stored shape.
//
// Two fields and no more, and the expiry is epoch MILLISECONDS so that what goes
// into the key and what comes back out are the same kind of number. `Token` is the
// credential and is never logged, rendered in an error, or included in any
// message this package writes — the errors below name the KEY, which is gateway's
// own uuid and not a secret.
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
		// A shape this store did not write. Reporting it as ABSENT would sign a
		// signed-in browser out because a byte changed somewhere, and reporting it
		// as a session would be worse. `503` is "we cannot tell", which is what it
		// is — and `NewBff` already maps a store error to that.
		return nil, fmt.Errorf("sessionredis: GET %s answered %T", key, reply)
	}

	stored, err := decodeRecord(payload)
	if err != nil {
		return nil, fmt.Errorf("sessionredis: GET %s: %w", key, err)
	}

	expiresAt := time.UnixMilli(stored.ExpiresAt).UTC()
	if !expiresAt.After(s.now()) {
		// Dropped on the way out rather than in a background sweep: a record read
		// once is never read again, so this is the only read that has to notice.
		// The reference does the same thing, and the DEL is best-effort — a failed
		// delete must not turn "this session is gone" into "we cannot tell",
		// because the record is gone either way and the TTL will take it.
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
	// Not the cookie's asymmetry from `Get`: here the id is GATEWAY's, minted by
	// `login` one line above the call. An id that is not a minted UUID is a defect
	// in this repository rather than a stranger at the door, and refusing to build
	// the key is what keeps that from being a write to somewhere unexpected.
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

	// Clamped at one millisecond rather than refused. `login` already refuses an
	// already-expired session, so this is unreachable from the handler — and a
	// store that refused an expired `put` would be a store with a second answer to
	// "what does an expired session mean" than the reference has, where storing it
	// and reading it back as absent is the whole behavior. `PX 0` is an error to
	// Redis, so the clamp is what makes "store it anyway" expressible.
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
		// The write did not report success and the caller is about to be handed a
		// cookie for a record that may not be there. `login` answers 503 rather
		// than 200 for exactly this, and it is the only thing that makes that
		// branch reachable.
		//
		// `describe`, NOT `render`, and this is a correction the tests forced: the
		// limiter can safely quote a bulk string because everything it stores is a
		// count, and the value here is a credential. A Redis that answered a `SET`
		// with something else might have echoed the payload back, and quoting that
		// into an error would put a live identity token in a log line.
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
	// Any integer is fine, including the `0` for a key that was already gone.
	// Anything else means the connection answered something this client does not
	// understand, and reporting that as a successful sign-out would be the
	// permissive direction on an answer nobody defined.
	if _, ok := reply.(int); !ok {
		return fmt.Errorf("sessionredis: DEL %s answered %s", key, describe(reply))
	}
	return nil
}

// isMintedID is the shape `uuid.NewString()` produces: a canonical lowercase
// 8-4-4-4-12 hex UUID, 36 characters, nothing else.
//
// Constrained to THAT rather than to a UUID-ish charset on purpose. `login` mints
// the only ids that ever reach this package, and the check is not "does this look
// like an id" — it is "could this have come out of `uuid.NewString()`". Anything
// looser would let a cookie value reach `KeyFor`, and the value of the assertion
// is that a caller cannot put bytes in a key.
//
// It is a parser rather than a regexp because it is 36 fixed positions and a
// regexp for a fixed shape is a regexp nobody reads.
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
		// A session with no credential is a cookie that authenticates nobody, and
		// the only two answers here are "signed in" and "cannot tell".
		return record{}, errors.New("the stored session carries no credential")
	}
	return out, nil
}

// describe is the answer from Redis, by SHAPE and never by contents.
//
// "the command answered" followed by nothing is not a message anybody can act on,
// so the limiter's `render` quotes it — and quoting is exactly what cannot be done
// here. Everything the limiter stores is a count, so a bulk string is safe to
// print; a `GET`'s answer and a `SET`'s payload are the identity token, so a
// dependency that echoed either back would put a live credential in a log line
// through the error path that exists to be readable.
//
// So a bulk string is described by its length, and a number is printed because a
// number cannot be a credential. `TestTheErrorMessagesNeverCarryTheToken` holds
// this: it answers a `SET` with the token itself and requires the message to
// survive.
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
