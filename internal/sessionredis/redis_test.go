package sessionredis

import (
	"context"
	"encoding/json"
	"errors"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cafaye/gateway/internal/ratelimit"
	"github.com/cafaye/gateway/internal/session"
)

// The store, over a fake Redis.
//
// The fake is a key/value SERVER and not a second copy of the store: it keeps
// strings, hands back what was written, and records the arguments. Expiry is
// deliberately NOT the fake's job — the store judges expiry against its own clock
// on every read, and a fake that dropped keys on a TTL would be testing Redis's
// behavior while naming it the store's.
//
// And the key is read off the TRANSPORT here rather than rebuilt from
// `KeyFor`: `KeyFor` is the production expression, so a test that repeats it
// passes on a broken namespace.

const minted = "3f2b1c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d"

// fakeRedis is `GET`, `SET` and `DEL` over a map, plus the calls it saw.
type fakeRedis struct {
	mu      sync.Mutex
	values  map[string]string
	calls   [][]string
	answers map[string]func() (ratelimit.Value, error)
	fail    error
}

func newFakeRedis() *fakeRedis {
	return &fakeRedis{values: map[string]string{}, answers: map[string]func() (ratelimit.Value, error){}}
}

func (f *fakeRedis) Do(_ context.Context, args ...string) (ratelimit.Value, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, args)

	if f.fail != nil {
		return nil, f.fail
	}
	if answer, ok := f.answers[args[0]]; ok {
		return answer()
	}

	switch args[0] {
	case "GET":
		value, held := f.values[args[1]]
		if !held {
			// `$-1`: a nil bulk string, which is what an absent key is.
			return nil, nil
		}
		return value, nil
	case "SET":
		f.values[args[1]] = args[2]
		return "OK", nil
	case "DEL":
		_, held := f.values[args[1]]
		delete(f.values, args[1])
		if held {
			return 1, nil
		}
		return 0, nil
	default:
		return nil, errors.New("fakeRedis: no such command " + args[0])
	}
}

func (f *fakeRedis) seen() [][]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([][]string(nil), f.calls...)
}

// stored is the value the fake is holding, read back through `encoding/json` so
// the assertion is about the bytes Redis would hand to another client rather than
// about a Go struct this package happens to use.
func (f *fakeRedis) stored(key string) (record, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	payload, held := f.values[key]
	if !held {
		return record{}, false
	}
	var out record
	if err := json.Unmarshal([]byte(payload), &out); err != nil {
		return record{}, false
	}
	return out, true
}

type fixedClock struct{ at time.Time }

func (c fixedClock) now() time.Time { return c.at }

// TestARoundTripThroughRedisPutsTheSessionUnderGatewaySess is the happy path,
// read off the transport.
func TestARoundTripThroughRedisPutsTheSessionUnderGatewaySess(t *testing.T) {
	fake := newFakeRedis()
	store, err := New(fake, time.Now)
	if err != nil {
		t.Fatalf("New refused a working client: %v", err)
	}

	expires := time.Now().Add(time.Hour).UTC().Truncate(time.Millisecond)
	if err := store.Put(context.Background(), minted, aSession("a-token", expires)); err != nil {
		t.Fatalf("Put: %v", err)
	}

	got, err := store.Get(context.Background(), minted)
	if err != nil || got == nil {
		t.Fatalf("Get after Put: %v, %v; want the session back", got, err)
	}
	if got.Token != "a-token" {
		t.Errorf("the session came back with token %q, want %q", got.Token, "a-token")
	}
	if !got.ExpiresAt.Equal(expires) {
		t.Errorf("the expiry came back as %s, want %s. It is identity's expiry, not a TTL this store chose", got.ExpiresAt, expires)
	}

	calls := fake.seen()
	if len(calls) != 2 || calls[0][0] != "SET" || calls[1][0] != "GET" {
		t.Fatalf("the store issued %v, want one SET then one GET", calls)
	}
	if key := calls[0][1]; key != "gateway:sess:"+minted {
		t.Errorf("the session lives under %q, want gateway:sess:<id>. A caller who can choose the tail of that key can read and delete other sessions", key)
	}
	// `SET key value PX ttl` — one command, because a SET followed by an EXPIRE
	// leaves a window in which the record exists with no TTL.
	if want := []string{"SET", "gateway:sess:" + minted, calls[0][2], "PX", calls[0][4]}; strings.Join(calls[0], " ") != strings.Join(want, " ") {
		t.Errorf("the store issued %v, want SET <key> <payload> PX <ttl>", calls[0])
	}
}

// TestAnAbsentSessionIsNilAndNotAnError is the one answer for two cases.
func TestAnAbsentSessionIsNilAndNotAnError(t *testing.T) {
	store, err := New(newFakeRedis(), time.Now)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	got, err := store.Get(context.Background(), minted)
	if err != nil {
		t.Errorf("Get on an absent id returned %v. Absent is an answer, not a failure, and an error here is a 503 on every caller who has simply never signed in", err)
	}
	if got != nil {
		t.Errorf("Get on an absent id returned %+v, want nil", got)
	}
}

// TestTheExpiryBoundaryIsInclusive is the row a careless port gets wrong.
//
// The reference is `expiresAt <= now()`: a session whose expiry is the current
// instant is ALREADY expired. `<` here would keep a session alive for one more
// read, which is a session outliving the token that authorizes it.
func TestTheExpiryBoundaryIsInclusive(t *testing.T) {
	// Each row carries an OFFSET from the subtest's fixed clock rather than an
	// absolute instant. The table literal is built before the loop, so a
	// `time.Now()` written here is a different instant from the `now` each subtest
	// fixes inside itself — and on a loaded machine the gap between the two is more
	// than the millisecond the third row is made of, which flips the boundary and
	// fails the case for a reason that tracks the machine and not the code.
	for _, tc := range []struct {
		name     string
		offset   time.Duration
		wantLive bool
	}{
		{"a millisecond before now", -time.Millisecond, false},
		{"exactly now", 0, false},
		{"a millisecond after now", time.Millisecond, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := newFakeRedis()
			// The clock is FIXED, so "exactly now" is exactly true rather than a
			// race against the wall clock — which is the difference between testing
			// this boundary and testing it once per run.
			now := time.Now()
			// Anchored to THAT clock, so every row is measured against the same
			// instant the store uses and no row spends the next row's margin.
			expires := now.Add(tc.offset)
			store, err := New(fake, func() time.Time { return now })
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			if err := store.Put(context.Background(), minted, aSession("t", expires)); err != nil {
				t.Fatalf("Put: %v", err)
			}
			fake.mu.Lock()
			fake.calls = nil
			fake.mu.Unlock()

			got, err := store.Get(context.Background(), minted)
			if err != nil {
				t.Fatalf("Get: %v", err)
			}
			if live := got != nil; live != tc.wantLive {
				t.Errorf("a session expiring %s is live=%v, want %v", tc.name, live, tc.wantLive)
			}

			if !tc.wantLive {
				// Dropped on the way out, as `memorySessionStore` does — the read is
				// the only one that has to notice.
				calls := fake.seen()
				if len(calls) != 2 || calls[1][0] != "DEL" {
					t.Errorf("reading an expired session issued %v, want GET then DEL. The record is never read again, so the read is the only place the sweep can happen", calls)
				}
				if _, held := fake.stored("gateway:sess:" + minted); held {
					t.Errorf("the expired record is still in the fake after the read")
				}
			}
		})
	}
}

// TestAnAlreadyExpiredSessionIsStoredAndReadsBackAsAbsent is the row where being
// MORE correct-looking is wrong.
//
// `login` refuses an already-expired session before it calls `Put`, so this is
// unreachable from the handler. A store that REFUSED it would have a second
// answer to "what does an expired session mean" than the reference, and the
// reference's answer is store-it-and-read-it-as-absent. `PX 0` is an error to
// Redis, which is why the TTL is clamped rather than passed through.
func TestAnAlreadyExpiredSessionIsStoredAndReadsBackAsAbsent(t *testing.T) {
	fake := newFakeRedis()
	now := time.Now()
	store, err := New(fake, fixedClock{at: now}.now)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if err := store.Put(context.Background(), minted, aSession("t", now.Add(-time.Hour))); err != nil {
		t.Fatalf("Put refused an already-expired session: %v. The reference stores it, and refusing here invents an answer the reference does not have", err)
	}

	calls := fake.seen()
	if len(calls) != 1 || calls[0][3] != "PX" || calls[0][4] != "1" {
		t.Errorf("the store issued %v, want SET with a clamped PX of 1 — a negative PX is an error to Redis, so this is how 'store it anyway' stays expressible", calls)
	}

	got, err := store.Get(context.Background(), minted)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != nil {
		t.Errorf("a session stored already-expired came back live: %+v", got)
	}
}

// TestCallerSuppliedBytesNeverReachAKey is the property this port adds, and it
// is the reason the id is parsed rather than trusted.
//
// `Get` and `Delete` are handed the COOKIE. The reference has no such hazard — a
// `Map` cannot be escaped by a crafted key — and that is exactly why the hazard
// only appears when the map becomes a shared store.
func TestCallerSuppliedBytesNeverReachAKey(t *testing.T) {
	for _, junk := range []string{
		"",
		"../../config",
		"gateway:sess:3f2b1c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d",
		"not-a-uuid",
		"3F2B1C4D-5E6F-4A7B-8C9D-0E1F2A3B4C5D", // uppercase: not what `uuid.NewString()` mints
		"3f2b1c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5",
		"3f2b1c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d ",
	} {
		t.Run(strings.ReplaceAll(junk, "/", "_"), func(t *testing.T) {
			fake := newFakeRedis()
			store, err := New(fake, time.Now)
			if err != nil {
				t.Fatalf("New: %v", err)
			}

			got, err := store.Get(context.Background(), junk)
			if err != nil || got != nil {
				t.Errorf("Get(%q) = %+v, %v; want absent with no error. A caller who pasted junk into their own cookie is a stranger answering 401, not an outage", junk, got, err)
			}
			if err := store.Delete(context.Background(), junk); err != nil {
				t.Errorf("Delete(%q) = %v; want success — there is nothing of ours to delete", junk, err)
			}

			if calls := fake.seen(); len(calls) != 0 {
				t.Errorf("an id that could not have been minted by login issued %v. Caller bytes reached a Redis key", calls)
			}
		})
	}
}

// TestPutRefusesAnIdGatewayDidNotMint is the asymmetry, stated.
//
// On `Get` a bad id is a stranger. On `Put` it is a DEFECT — `login` mints the id
// one line above the call — so it is refused rather than quietly stored somewhere
// the writer did not intend.
func TestPutRefusesAnIdGatewayDidNotMint(t *testing.T) {
	fake := newFakeRedis()
	store, err := New(fake, time.Now)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := store.Put(context.Background(), "chosen-by-the-caller", aSession("t", time.Now().Add(time.Hour))); err == nil {
		t.Errorf("Put accepted an id this service could not have minted")
	}
	if calls := fake.seen(); len(calls) != 0 {
		t.Errorf("a refused Put still issued %v", calls)
	}
}

// TestDeleteOfAnAbsentSessionSucceeds, because a client retrying a sign-out must
// not be told it did the wrong thing.
func TestDeleteOfAnAbsentSessionSucceeds(t *testing.T) {
	fake := newFakeRedis()
	now := time.Now()
	store, err := New(fake, fixedClock{at: now}.now)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := store.Put(context.Background(), minted, aSession("t", now.Add(time.Hour))); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := store.Delete(context.Background(), minted); err != nil {
		t.Errorf("Delete: %v", err)
	}
	if err := store.Delete(context.Background(), minted); err != nil {
		t.Errorf("the second Delete = %v, want success. A retried sign-out is not an error", err)
	}
	if got, _ := fake.stored("gateway:sess:" + minted); got != (record{}) {
		t.Errorf("the record is still in Redis after a Delete: %+v", got)
	}
}

// TestAWriteThatDidNotReportSuccessIsAnError, because `login` is about to hand the
// browser a cookie for a record that may not be there.
func TestAWriteThatDidNotReportSuccessIsAnError(t *testing.T) {
	fake := newFakeRedis()
	fake.answers["SET"] = func() (ratelimit.Value, error) { return "QUEUED", nil }
	store, err := New(fake, time.Now)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := store.Put(context.Background(), minted, aSession("t", time.Now().Add(time.Hour))); err == nil {
		t.Errorf("Put accepted a SET that answered %q. Answering 200 would hand the caller a cookie for a record that is not there", "QUEUED")
	}
}

// TestAStoredSessionThatIsNotReadableIsNotAnAbsence.
//
// Three ways the answer can be wrong, and all three must be errors rather than a
// silent "signed out": a value this store did not write, a JSON string that does
// not decode, and a record carrying no credential. Reporting any of them as absent
// signs a live browser out over a byte; reporting the first as a session would be
// worse.
func TestAStoredSessionThatIsNotReadableIsNotAnAbsence(t *testing.T) {
	for _, tc := range []struct {
		name   string
		answer func() (ratelimit.Value, error)
	}{
		{"a number", func() (ratelimit.Value, error) { return 7, nil }},
		{"unparseable bytes", func() (ratelimit.Value, error) { return "{not json", nil }},
		{"no credential", func() (ratelimit.Value, error) { return `{"token":"","expires_at":4102444800000}`, nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := newFakeRedis()
			fake.answers["GET"] = tc.answer
			store, err := New(fake, time.Now)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			got, err := store.Get(context.Background(), minted)
			if err == nil {
				t.Errorf("Get = %+v, want an error. This is 503 — we cannot tell — and reporting it as absent signs a signed-in browser out", got)
			}
		})
	}
}

// TestAnUnreachableStoreIsAnErrorOnEveryMethod, so it reaches the caller as the
// 503 it is rather than as a 401.
func TestAnUnreachableStoreIsAnErrorOnEveryMethod(t *testing.T) {
	fake := newFakeRedis()
	fake.fail = errors.New("connection refused")
	store, err := New(fake, time.Now)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	now := time.Now()
	expires := now.Add(time.Hour)
	if _, err := store.Get(context.Background(), minted); err == nil {
		t.Errorf("Get through an unreachable store returned no error")
	}
	if err := store.Put(context.Background(), minted, aSession("t", expires)); err == nil {
		t.Errorf("Put through an unreachable store returned no error")
	}
	if err := store.Delete(context.Background(), minted); err == nil {
		t.Errorf("Delete through an unreachable store returned no error")
	}
}

// TestTheErrorMessagesNeverCarryTheToken. A dependency's answer is where a
// credential turns up, so `render` quotes the STATUS and nothing else.
func TestTheErrorMessagesNeverCarryTheToken(t *testing.T) {
	const token = "identity-token-that-must-not-be-logged"
	fake := newFakeRedis()
	fake.answers["SET"] = func() (ratelimit.Value, error) { return token, nil }
	store, err := New(fake, time.Now)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	err = store.Put(context.Background(), minted, aSession(token, time.Now().Add(time.Hour)))
	if err == nil {
		t.Fatalf("Put accepted an answer that was not OK")
	}
	if strings.Contains(err.Error(), token) {
		t.Errorf("the error carries the credential: %v", err)
	}
	// Readable is still the requirement: "answered something" with no shape is the
	// failure mode a credential-safe renderer walks into, by refusing to say
	// anything at all.
	if !strings.Contains(err.Error(), "answered") {
		t.Errorf("the error does not say what Redis answered: %v", err)
	}
}

// TestConstructionRefuses rather than returning a store that cannot work.
func TestConstructionRefuses(t *testing.T) {
	if _, err := New(nil, time.Now); !errors.Is(err, ErrNotConfigured) {
		t.Errorf("New(nil, clock) = %v, want a refusal. A store with no client is a store whose every call is a nil dereference", err)
	}
	if _, err := New(newFakeRedis(), nil); !errors.Is(err, ErrNotConfigured) {
		t.Errorf("New(client, nil) = %v, want a refusal. Expiry is judged against this clock, so no clock is no expiry", err)
	}
}

// TestTheShippedBinaryLinksThisStore is the INVERSE of
// `internal/sessiontest`'s guard, and the two are a pair.
//
// That one asserts the fixture is not in the binary. This asserts the real store
// IS — because the failure this packet exists to fix was a gateway that could not
// serve its browser surface, and the shape of that failure is a package that is
// absent rather than one that is broken. A guard that only ever says "no" cannot
// notice that the "yes" stopped happening.
func TestTheShippedBinaryLinksThisStore(t *testing.T) {
	module, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("cannot resolve the module root: %v", err)
	}

	list := exec.CommandContext(context.Background(), "go", "list", "-deps", "./cmd/...")
	list.Dir = module
	out, err := list.CombinedOutput()
	if err != nil {
		t.Fatalf("`go list -deps ./cmd/...` failed, so this check cannot answer: %v\n%s", err, out)
	}

	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if strings.HasSuffix(strings.TrimSpace(line), "/internal/sessionredis") {
			return
		}
	}
	t.Errorf("the binary does not link internal/sessionredis, so the Go service still ships no session store and /auth/* still answers 404 on a configured deployment. `RuntimeOptions` has to build this store when both IDENTITY_URL and REDIS_URL are set")
}

// aSession is the record a test stores. NOT named `session`: that is the imported
// package, and a package-level declaration may not share a file block with an
// import of that name.
func aSession(token string, expires time.Time) session.Session {
	return session.Session{Token: token, ExpiresAt: expires.UTC()}
}
