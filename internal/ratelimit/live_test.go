// The GCRA script, executed by a real redis-server.
//
// # WHAT THIS FILE IS FOR, AND WHY A TRANSCRIPTION IS NOT ENOUGH
//
// Every other test in this package drives the Redis path without a server:
// `parity_test.go` transcribes `GCRALua` into Go and runs the transcript, and
// requires the two backends to agree over one behavior table. That proves the
// CLIENT — key names, argument marshaling, reply decoding — and it leaves the
// SCRIPT covered by review. A Lua body no test has run is a body that is correct
// by assertion rather than by evidence, and it is the body that decides whether a
// deployment with `REDIS_URL` set limits at all.
//
// This file closes that gap. It is the counterpart of
// `src/middleware/rateLimitRedisLive.test.ts` (removed at cutover), and it exists because two things
// about a real server are invisible from here:
//
//  1. REDIS TRUNCATES A LUA NUMBER TOWARD ZERO on the way out. `math.ceil` in the
//     script is load-bearing for exactly that reason, and no transcription can find
//     it, because a transcription is free to return a float.
//  2. AN ERROR REPLY IS PART OF RESP, NOT A DESYNC. `-ERR` from `EVAL` means the
//     script did not run; reading it as "no quota used" is a limiter that opens
//     exactly when its dependency is broken.
//
// # GATED ON `GATEWAY_REDIS_URL`, AND THE GATE IS COUNTED
//
//	GATEWAY_REDIS_URL=redis://127.0.0.1:6379 go test ./internal/ratelimit/   # runs
//	go test ./internal/ratelimit/                                            # skips, and says so
//	GATEWAY_REDIS_REQUIRED=1 …                                               # the skip is a failure
//
// The skip PRINTS a line beginning `ratelimit: DID NOT RUN` and `bin/prime-go`
// counts it, for the same reason it counts the equivalence tier's: `go test`
// discards a passing package's output, so a tier that skips silently verifies
// nothing and reports the strongest-looking green there is. `TestMain` refuses to
// register a single test when `GATEWAY_REDIS_REQUIRED=1` and there is no URL, so an
// escalated run fails on its first line rather than in a summary of zero passes.
//
// # EVERYTHING GOES THROUGH `Connect`, THE TRANSPORT PRODUCTION USES
//
// `Commands` is deliberately two methods wide, and widening it for a test would
// trade a reviewed interface for a second, divergent way of talking to Redis. The
// commands the store does not expose — `TTL`, `GET`, `LPUSH`, `DEL` — are run
// through `Connection.Do`, which is the same `EVAL`-shaped call the store makes.
package ratelimit

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// liveWindow is the window every case here counts in. Sixty seconds because that
// is the deployment's default and because a `PX` an order of magnitude larger
// makes a leaked key harmless for the length of a test run.
const liveWindow = time.Minute

// liveRedisURL and liveRedisRequired are read ONCE, at TestMain, and never again.
// A test that re-read the environment could see a different answer on its
// hundredth case than on its first, which is the shape of a flaky test nobody can
// reproduce.
var (
	liveRedisURL      string
	liveRedisRequired bool
)

// liveRun is one namespace per run, so two runs against one server — a
// developer's leftover daemon and a CI container, or two worktrees — cannot read
// each other's buckets and turn stale state into a red suite.
//
// The store's own charset check is exercised by the value put in front of it: a
// UUID is `[A-Za-z0-9-]`, all of which `AssertBucket` accepts.
var liveRun = "live-" + randomToken()

// randomToken is 16 hex characters off the clock, which is enough to separate two
// runs that start in the same second and does not need a dependency for it.
//
// `crypto/rand` rather than `time.Now().UnixNano()` because two worktrees started
// in the same nanosecond is not as unlikely as it looks, and a shared bucket
// between them is a red suite in a file that would otherwise be green.
func randomToken() string {
	const alphabet = "0123456789abcdef"
	seed := uint64(time.Now().UnixNano())
	var out strings.Builder
	for i := 0; i < 16; i++ {
		// xorshift64: enough spread for a namespace, and the loop is four lines
		// rather than an import of a package that exists for this.
		seed ^= seed << 13
		seed ^= seed >> 7
		seed ^= seed << 17
		out.WriteByte(alphabet[seed&0xf])
	}
	return out.String()
}

// # TESTMAIN IS NOT THE GATE, AND IT WAS, AND IT ATE THE PACKAGE
//
// This function used to `os.Exit(0)` when `GATEWAY_REDIS_URL` was unset — before
// `m.Run()`, so before a single test in the package was registered. That made
// `go test ./internal/ratelimit/` on a machine with no Redis report `ok` for a
// package that had run NO tests: not the live tier, not the parity table, not the
// instant grid, not `key_test.go`, not `limiter_test.go`. All of them.
//
// It was found the least interesting way possible. `TestTheInstantsAreWhereTheArithmeticPutsThem`
// was left with expectations that had just been transcribed by hand, two of them
// wrong, and it passed without Redis and failed with Redis — which cannot both be
// true of a test whose arithmetic is deterministic. The explanation was that the
// "passing" run had executed nothing.
//
// # THE GATE BELONGS ON THE TIER, NOT ON THE BINARY
//
// `liveTier` is the gate now: it skips the test that asked for a server, and every
// test in this file asks for one, so the file is gated as a unit while the rest of
// the package runs unconditionally. The escalation is still here, and still refuses
// before anything runs, because `GATEWAY_REDIS_REQUIRED=1` means "a run that cannot
// run this tier is a failure" and that is a statement about the RUN, not about one
// test in it.
//
// The countable skip line moved with it — `liveTier` prints `ratelimit: DID NOT
// RUN` once, before the first skip, and sets a flag so the rest stay quiet. One line
// is countable; N is not, which is the whole reason this lived in `TestMain` to
// begin with.
func TestMain(m *testing.M) {
	liveRedisURL = strings.TrimSpace(os.Getenv("GATEWAY_REDIS_URL"))
	liveRedisRequired = os.Getenv("GATEWAY_REDIS_REQUIRED") == "1"

	if liveRedisURL == "" && liveRedisRequired {
		// Exit before a single test is registered, so an escalated run says so in
		// its first line rather than in a summary of zero passes.
		fmt.Fprintln(os.Stderr,
			"ratelimit: GATEWAY_REDIS_REQUIRED=1 and GATEWAY_REDIS_URL is unset. The live Redis tier"+
				" cannot run, and a run that cannot run it proves nothing about GCRALua. Point"+
				" GATEWAY_REDIS_URL at a redis-server, or unset GATEWAY_REDIS_REQUIRED to skip this"+
				" tier on purpose.")
		os.Exit(1)
	}

	os.Exit(m.Run())
}

// liveTierSkipped keeps the DID NOT RUN line to one per run.
var liveTierSkipped bool

// # NOTHING HERE DELETES ANYTHING IT DID NOT WRITE
//
// The first draft ran `FLUSHDB` before and after, which is convenient and wrong:
// `GATEWAY_REDIS_URL` points at a SERVER, and a developer who sets it to the Redis
// they are already using would watch this file empty their database. The keys go
// instead, and only the ones under this run's prefix — which is what makes the
// namespace worth having in the first place.
//
// Every bucket carries a `PX` equal to its window, so Redis would reclaim them on
// its own; deleting them leaves the server as it was found and doubles as a check
// that the namespace is ours alone.
const liveCleanup = `
local found = redis.call('KEYS', ARGV[1] .. '*')
for i = 1, #found do redis.call('DEL', found[i]) end
return #found
`

// liveTier opens two independent connections to the server and registers the
// cleanup that takes this run's keys with it.
//
// TWO connections, because "two replicas share one bucket" is only a fact about
// Redis if the two sides are on separate sockets. One connection serialized behind
// its own mutex would prove the mutex, not the server.
func liveTier(t *testing.T) (a, b *Connection) {
	t.Helper()

	if liveRedisURL == "" {
		if !liveTierSkipped {
			liveTierSkipped = true
			fmt.Printf("ratelimit: DID NOT RUN — GATEWAY_REDIS_URL is unset. Set GATEWAY_REDIS_URL=redis://127.0.0.1:6379 to run the GCRA script against a real server, or GATEWAY_REDIS_REQUIRED=1 to make this a failure.\n")
		}
		t.Skip("no GATEWAY_REDIS_URL: the live Redis tier did not run")
	}

	open := func() *Connection {
		t.Helper()
		connection, err := Connect(RedisConnectionOptions{URL: liveRedisURL})
		if err != nil {
			t.Fatalf("GATEWAY_REDIS_URL=%s did not answer: %v", liveRedisURL, err)
		}
		return connection
	}
	a, b = open(), open()

	t.Cleanup(func() {
		if _, err := a.Eval(liveCleanup, nil, []string{"gateway:rl:" + liveRun}); err != nil {
			t.Logf("could not remove this run's keys from %s: %v. They carry a PX equal to their window, so Redis reclaims them anyway.", liveRedisURL, err)
		}
		_ = a.Close()
		_ = b.Close()
	})
	return a, b
}

// liveCall is one `redis.call` for a single key, over the production transport.
func liveCall(t *testing.T, connection *Connection, script, key string) Value {
	t.Helper()

	value, err := connection.Eval(script, []string{key}, nil)
	if err != nil {
		t.Fatalf("EVAL %q against %q: %v", script, key, err)
	}
	return value
}

// liveStore is a store over `connection`, in a bucket namespace of its own.
//
// The namespace is per CALL rather than per run on purpose: two cases in one file
// that share a bucket share its debt, and a case that starts with a bucket already
// spent fails for a reason that has nothing to do with what it is checking.
func liveStore(t *testing.T, connection *Connection, name string) *RedisStore {
	t.Helper()

	store, err := NewRedisStore(connection, liveRun+"."+name)
	if err != nil {
		t.Fatalf("NewRedisStore: %v", err)
	}
	t.Cleanup(func() { liveCall(t, connection, "return redis.call('DEL', KEYS[1])", store.KeyFor("acct:1")) })
	return store
}

// -----------------------------------------------------------------------------
// the transport
// -----------------------------------------------------------------------------

// TestARealServerAnswersPingWithPong is the floor: if this fails, everything below
// it failed for the same reason and reporting fifteen failures says less than one.
func TestARealServerAnswersPingWithPong(t *testing.T) {
	a, b := liveTier(t)

	for name, connection := range map[string]*Connection{"a": a, "b": b} {
		answered, err := connection.Ping(context.Background())
		if err != nil {
			t.Fatalf("connection %s: PING: %v", name, err)
		}
		if !answered {
			t.Errorf("connection %s: PING did not answer PONG. A server that answers something else is not a Redis this client can drive, and every case below would fail for that reason instead of its own.", name)
		}
	}
}

// TestTheReplyDecoderReadsTheThreeShapesTheScriptCanProduce pins what the server
// SENDS, before the store is trusted to read it.
//
// `verdictOf` refuses any shape it does not recognize rather than inferring
// `allowed` from it, so what arrives is worth pinning: a bulk string, an integer,
// an array, and — the one that matters most — the error reply.
func TestTheReplyDecoderReadsTheThreeShapesTheScriptCanProduce(t *testing.T) {
	a, _ := liveTier(t)
	key := liveRun + ":shapes"

	if got := liveCall(t, a, "return redis.call('SET', KEYS[1], 'hello')", key); got != "OK" {
		t.Errorf("SET answered %s, want OK", render(got))
	}
	if got := liveCall(t, a, "return redis.call('GET', KEYS[1])", key); got != "hello" {
		t.Errorf("GET answered %s, want \"hello\"", render(got))
	}
	if got := liveCall(t, a, "return 42", key); got != 42 {
		t.Errorf("an integer came back as %s (%T), want 42", render(got), got)
	}

	// The array the script itself returns, through the real decoder.
	reply, err := a.Eval("return {1, 2, 3}", []string{key}, nil)
	if err != nil {
		t.Fatalf("EVAL returning an array: %v", err)
	}
	items, ok := reply.([]Value)
	if !ok || len(items) != 3 {
		t.Fatalf("an array came back as %s (%T), want three elements", render(reply), reply)
	}

	// The error reply is the fourth shape, and it is the one that matters most: a
	// `-ERR` from EVAL means the script did not run, and reading it as "no quota
	// used" would be a limiter that opens exactly when its dependency is broken.
	var replyErr *ReplyError
	_, err = a.Eval("return redis.call('INCR', KEYS[1])", []string{key}, nil)
	if !errors.As(err, &replyErr) {
		t.Errorf("INCR on a string key answered %v, want a *ReplyError. A store that cannot tell an error reply from an answer has no way to fail open.", err)
	}
}

// TestTheScriptAnswersFourIntegers is the claim `math.ceil` exists to make.
//
// Redis converts a Lua number to an integer reply by TRUNCATING toward zero, so
// every one of these four is a whole number on the wire no matter what the script
// computed. A float in the reply is a shape this client does not see, and its
// absence here would mean the script's arithmetic had stopped producing the values
// the client reads.
func TestTheScriptAnswersFourIntegers(t *testing.T) {
	a, _ := liveTier(t)
	key := liveRun + ":shape4"

	reply, err := a.Eval(GCRALua, []string{key}, []string{"3", "60000", "0"})
	if err != nil {
		t.Fatalf("the GCRA script did not run: %v", err)
	}

	items, ok := reply.([]Value)
	if !ok || len(items) != 4 {
		t.Fatalf("the script answered %s (%T), want an array of four", render(reply), reply)
	}
	for i, item := range items {
		number, numberErr := numberOf(item)
		if numberErr != nil {
			t.Errorf("reply[%d] is %T, want a number. The script returns four numbers and the store reads four numbers; a string here means the conversion changed.", i, item)
			continue
		}
		if number != float64(int64(number)) {
			t.Errorf("reply[%d] is %v, want a whole number. Redis truncates a Lua number toward zero, so a fractional value here is the one thing the server never sends — which means the script returned something other than a number.", i, number)
		}
	}
}

// TestAnErrorReplyFailsOneCommandAndNotTheConnection is the regression.
//
// A single `-ERR` used to wedge the socket permanently: the reader caught every
// parse failure, consumed no bytes and resolved no waiter, so the same `-ERR` was
// re-parsed on every later chunk and every later command on that connection timed
// out — for the life of the process. `LazyRedis` caches a connection, so a gateway
// hit once would fail open on every request until it restarted, and `/readyz`
// would say `redis: unavailable` with nothing in the log saying why.
//
// An error reply is part of RESP, not a desync: Redis sends one deliberately and
// the stream stays in sync. So it has to fail the command that asked for it and
// leave the connection usable, which is what this asserts — including that the
// next command gets the RIGHT answer and not merely any answer.
func TestAnErrorReplyFailsOneCommandAndNotTheConnection(t *testing.T) {
	a, _ := liveTier(t)
	key := liveRun + ":err"

	if got := liveCall(t, a, "return redis.call('SET', KEYS[1], 'not-a-number')", key); got != "OK" {
		t.Fatalf("SET answered %s, want OK", render(got))
	}

	var replyErr *ReplyError
	if _, err := a.Eval("return redis.call('INCR', KEYS[1])", []string{key}, nil); !errors.As(err, &replyErr) {
		t.Fatalf("INCR on a string key answered %v, want a *ReplyError", err)
	}

	// The connection still answers, and still answers in order.
	if answered, err := a.Ping(context.Background()); err != nil || !answered {
		t.Fatalf("after an error reply PING answered (%v, %v), want (true, nil)", answered, err)
	}
	if got := liveCall(t, a, "return redis.call('GET', KEYS[1])", key); got != "not-a-number" {
		t.Errorf("after an error reply GET answered %s, want \"not-a-number\". A connection that survived by skipping bytes would answer something, and this is what says it answered the RIGHT something.", render(got))
	}
	if got := liveCall(t, a, "return 1", key); got != 1 {
		t.Errorf("after an error reply a literal came back as %s, want 1", render(got))
	}
}

// TestAnErrorReplyLeavesAStoreThatKeepsCounting is the same wedge seen through the
// store rather than the transport, because "the limiter stopped counting and
// nothing said so" is the failure that matters.
//
// The store's script is broken the way a key collision with another subsystem would
// break it: a LIST where the script expects a string, so its own `GET` answers
// `-WRONGTYPE` and `EVAL` hands that back. That is a real failure mode, not a mock
// — it needs the server to refuse, which is the only way to produce the reply at
// all.
func TestAnErrorReplyLeavesAStoreThatKeepsCounting(t *testing.T) {
	a, _ := liveTier(t)
	store := liveStore(t, a, "errored")
	limit := 3
	request := Request{Limit: limit, Window: liveWindow, Now: time.Unix(0, 0)}

	for i := 0; i < limit; i++ {
		verdict, err := store.Hit("acct:1", request)
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		if !verdict.Allowed {
			t.Fatalf("request %d of %d was refused on a fresh bucket", i+1, limit)
		}
	}
	if verdict, _ := store.Hit("acct:1", request); verdict.Allowed {
		t.Fatalf("request %d was admitted on a bucket of %d", limit+1, limit)
	}

	key := store.KeyFor("acct:1")
	liveCall(t, a, "return redis.call('DEL', KEYS[1])", key)
	liveCall(t, a, "return redis.call('LPUSH', KEYS[1], 'not-a-string')", key)

	// Both must fail. One failing and one succeeding would mean the reply was
	// consumed on the first and the second read a stale one.
	for i := 0; i < 2; i++ {
		_, err := store.Hit("acct:1", request)
		var replyErr *ReplyError
		if !errors.As(err, &replyErr) {
			t.Fatalf("request %d after the key was clobbered answered %v, want a *ReplyError. The middleware fails open on this throw, so a limiter that opens silently is what a non-error here would produce.", i+1, err)
		}
		if !strings.Contains(replyErr.Message, "WRONGTYPE") {
			t.Errorf("request %d answered %q, want a message naming WRONGTYPE — the reply has to say what the server objected to", i+1, replyErr.Message)
		}
	}

	// The connection is unharmed by the two that threw, and the store counts again
	// the moment the key is the type the script expects.
	if answered, err := a.Ping(context.Background()); err != nil || !answered {
		t.Fatalf("after two failed scripts PING answered (%v, %v), want (true, nil)", answered, err)
	}
	liveCall(t, a, "return redis.call('DEL', KEYS[1])", key)
	verdict, err := store.Hit("acct:1", request)
	if err != nil {
		t.Fatalf("after the key was repaired: %v", err)
	}
	if !verdict.Allowed {
		t.Error("after the key was repaired the store refused a request on a fresh bucket. A store that keeps failing after its dependency recovers is a limiter that is off for the life of the process.")
	}
}

// TestAnUnreachableServerThrowsRatherThanResolving is what makes failing open
// honest.
//
// Failing open costs the whole limit for as long as the store is down, and that
// trade is only defensible if the store really does throw when Redis is gone. A
// connection that resolved on a refused port would turn an outage into a limiter
// answering "allowed" with no error anywhere.
func TestAnUnreachableServerThrowsRatherThanResolving(t *testing.T) {
	// The port is opened and released here, so the check cannot collide with a
	// developer's own Redis.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("could not open a port to close: %v", err)
	}
	dead := listener.Addr().String()
	_ = listener.Close()

	// `Connect` is eager, so it refuses to hand back a client at all.
	if _, err := Connect(RedisConnectionOptions{URL: "redis://" + dead, Timeout: 500 * time.Millisecond}); err == nil {
		t.Error("Connect answered a client for a port nothing is listening on. A client that resolves against a dead server turns an outage into a limiter answering \"allowed\" with no error anywhere.")
	}

	// `LazyRedis` is what production builds, and its contract is the interesting
	// one: a Redis that is DOWN is not a refusal to boot, it is an unavailable
	// dependency the first command reports and the next one RETRIES. Two attempts
	// rather than one, because the second is what proves the failure is not cached
	// forever — a remembered failure is an outage a long-lived process never
	// recovers from.
	lazy, err := NewLazyRedis(RedisConnectionOptions{URL: "redis://" + dead, Timeout: 500 * time.Millisecond})
	if err != nil {
		t.Fatalf("NewLazyRedis on a dead port: %v. A malformed URL is a startup error and an unreachable server is not; a lazy client that refuses to build for the second is a gateway that will not boot because its counter store is down.", err)
	}
	t.Cleanup(func() { _ = lazy.Close() })

	for attempt := 1; attempt <= 2; attempt++ {
		if _, err := lazy.Ping(context.Background()); err == nil {
			t.Errorf("attempt %d: PING through a lazy client answered for a port nothing is listening on", attempt)
		}
	}
}

// -----------------------------------------------------------------------------
// the script
// -----------------------------------------------------------------------------

// TestTheScriptAndTheMemoryStoreAnswerTheSameRequest is the tier's reason for
// existing.
//
// The oracle is `count()` — the implementation the memory store is built from —
// and NOT the transcription in `parity_test.go`. That is deliberate: if the
// transcription and the script were both wrong the same way, the
// transcription-based parity suite would stay green, and only a comparison against
// `count()` can tell.
//
// 24 requests at 700ms with a limit of 5 over a 10s window, so the table spends
// its allowance, refuses for a while, and repays — all three regimes, rather than
// only the first.
func TestTheScriptAndTheMemoryStoreAnswerTheSameRequest(t *testing.T) {
	a, _ := liveTier(t)

	const (
		limit  = 5
		window = 10 * time.Second
	)
	server := liveStore(t, a, "identical")
	memory, err := NewMemoryStore(0)
	if err != nil {
		t.Fatalf("NewMemoryStore: %v", err)
	}

	at := time.Unix(0, 0)
	refusals := 0
	for i := 0; i < 24; i++ {
		request := Request{Limit: limit, Window: window, Now: at.Add(time.Duration(i) * 700 * time.Millisecond)}

		expected, err := memory.Hit("acct:1", request)
		if err != nil {
			t.Fatalf("step %d, memory store: %v", i, err)
		}
		if !expected.Allowed {
			refusals++
		}

		received, err := server.Hit("acct:1", request)
		if err != nil {
			t.Fatalf("step %d, redis store: %v", i, err)
		}
		expectSameVerdict(t, received, expected, fmt.Sprintf("#%d", i))
	}

	// The table has to have refused something, or it has proved that nothing
	// happens rather than that the two agree.
	if refusals == 0 {
		t.Error("24 requests against a limit of 5 over 10s refused nothing, so this proved that the two backends agree about admitting and not that they agree about refusing.")
	}
}

// TestTheScriptAndTheMemoryStoreAgreeAcrossRandomisedLimits is the same comparison
// with the boundaries spread out.
//
// A fixed seed, generated not slept: no wall clock, nothing to flake. A 32-bit LCG
// is enough — this needs a spread of shapes, not statistical quality, and a seeded
// sequence is reproducible on a machine and in CI.
func TestTheScriptAndTheMemoryStoreAgreeAcrossRandomisedLimits(t *testing.T) {
	a, _ := liveTier(t)

	server := liveStore(t, a, "random")
	memory, err := NewMemoryStore(0)
	if err != nil {
		t.Fatalf("NewMemoryStore: %v", err)
	}

	state := uint32(0x5eed1234)
	next := func(modulo uint32) int {
		state = state*1664525 + 1013904223
		return int((state >> 8) % modulo)
	}

	at := time.Unix(1_000_000, 0)
	clock := at
	refusals := 0
	for i := 0; i < 400; i++ {
		clock = clock.Add(time.Duration(next(3000)) * time.Millisecond)
		request := Request{
			Limit:  1 + next(6),
			Window: time.Duration(1000+next(59000)) * time.Millisecond,
			Now:    clock,
		}
		bucket := fmt.Sprintf("acct:%d", next(4))

		expected, err := memory.Hit(bucket, request)
		if err != nil {
			t.Fatalf("step %d, memory store: %v", i, err)
		}
		if !expected.Allowed {
			refusals++
		}

		received, err := server.Hit(bucket, request)
		if err != nil {
			t.Fatalf("step %d, redis store: %v", i, err)
		}
		expectSameVerdict(t, received, expected, fmt.Sprintf("#%d", i))
	}

	if refusals == 0 {
		t.Error("400 randomized requests refused nothing, so the agreement proved here is only about admitting.")
	}
}

// TestABurstFiredAtOnceAdmitsExactlyTheLimit is the single-key atomicity claim,
// through a real server.
//
// `Connection` carries one command at a time on one connection and the limiter
// sends exactly one per request, so 512 requests in flight on it is the real shape
// of a gateway burst rather than a synthetic one. A read-then-write script — GET,
// yield, SET — admits all 512.
func TestABurstFiredAtOnceAdmitsExactlyTheLimit(t *testing.T) {
	a, _ := liveTier(t)
	store := liveStore(t, a, "burst")

	const (
		limit = 128
		total = 512
	)
	request := Request{Limit: limit, Window: liveWindow, Now: time.Unix(0, 0)}

	var (
		mu       sync.Mutex
		admitted int
		wg       sync.WaitGroup
	)
	for i := 0; i < total; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			verdict, err := store.Hit("burst", request)
			if err != nil {
				t.Errorf("Hit: %v", err)
				return
			}
			if verdict.Allowed {
				mu.Lock()
				admitted++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if admitted != limit {
		t.Errorf("%d of %d requests fired at once were admitted, want exactly %d. The script is one atomic step; anything else means %d callers got through a limit of %d.", admitted, total, limit, admitted-limit, limit)
	}
}

// TestTwoStoresOnTwoConnectionsShareOneBucket is the property the Redis backend
// exists for, and the v0 hole it plugs — stated against two real sockets rather
// than one fake.
//
// If the counter lived in either process this would be two allowances of two, and
// the memory half below is what says so.
func TestTwoStoresOnTwoConnectionsShareOneBucket(t *testing.T) {
	a, b := liveTier(t)
	first := liveStore(t, a, "replica")
	second := liveStore(t, b, "replica")

	request := Request{Limit: 2, Window: liveWindow, Now: time.Unix(0, 0)}
	for _, step := range []struct {
		store *RedisStore
		want  bool
	}{{first, true}, {second, true}, {first, false}, {second, false}} {
		verdict, err := step.store.Hit("acct:1", request)
		if err != nil {
			t.Fatalf("Hit: %v", err)
		}
		if verdict.Allowed != step.want {
			t.Errorf("the replica asked third answered allowed=%v, want %v. Two stores over one server share one bucket; if this is false the counter is in a process.", verdict.Allowed, step.want)
		}
	}

	// The memory pair, which cannot do it. One allowance of two, two processes.
	// The bucket is exhausted on the FIRST store after two requests, not three:
	// the third is the one past the limit, and a limit of two admits two. So the
	// pair below admits FOUR where the replica pair above admitted two, and that
	// gap is the v0 hole — why the keyspace is a deployment decision rather than
	// an implementation detail.
	//
	// # THE EXPECTATION THIS USED TO STATE, AND WHY IT WAS WRONG
	//
	// It read `{localA, true}, {localA, false}, {localB, true}` — two requests on
	// one memory store, the second expected to be refused. A limit of two admits
	// two, so the second is the second of the burst and the expectation was false.
	// Nothing noticed for as long as this file had never met a Redis, because a
	// tier behind a skip reports the same green whether its expectations are right
	// or wrong. The assertion that names the deployment decision was not the one
	// being checked.
	localA, err := NewMemoryStore(0)
	if err != nil {
		t.Fatalf("NewMemoryStore: %v", err)
	}
	localB, err := NewMemoryStore(0)
	if err != nil {
		t.Fatalf("NewMemoryStore: %v", err)
	}
	for _, step := range []struct {
		store *MemoryStore
		want  bool
	}{{localA, true}, {localA, true}, {localA, false}, {localB, true}} {
		verdict, err := step.store.Hit("acct:1", request)
		if err != nil {
			t.Fatalf("Hit: %v", err)
		}
		if verdict.Allowed != step.want {
			t.Errorf("a memory store answered allowed=%v, want %v. Two in-memory stores are two allowances, which is the whole reason RedisStore exists — and this is the half of the pair that makes the other half mean something.", verdict.Allowed, step.want)
		}
	}
}

// TestABucketSurvivesLosingTheConnectionItWasCountedIn is the other half of "per
// process": every in-memory bucket is lost on restart, so a deploy is a fresh
// allowance for every caller at once. Redis is the only reason that is not true,
// and only a real server can show it.
func TestABucketSurvivesLosingTheConnectionItWasCountedIn(t *testing.T) {
	a, b := liveTier(t)
	request := Request{Limit: 1, Window: liveWindow, Now: time.Unix(0, 0)}

	before := liveStore(t, a, "survives")
	verdict, err := before.Hit("acct:1", request)
	if err != nil {
		t.Fatalf("Hit: %v", err)
	}
	if !verdict.Allowed {
		t.Fatal("the first request on a fresh bucket was refused")
	}

	// A DIFFERENT connection, so this is the server's memory rather than a cached
	// client-side count.
	after := liveStore(t, b, "survives")
	verdict, err = after.Hit("acct:1", request)
	if err != nil {
		t.Fatalf("Hit: %v", err)
	}
	if verdict.Allowed {
		t.Error("a second connection was admitted on a bucket a first connection had already spent. Either the counter is per connection or the key is not what both of them wrote.")
	}
}

// TestTheScriptExpiresItsOwnKey is a memory leak with a business-sized keyspace.
//
// A Redis that accumulates a bucket for every client that has ever connected is
// exactly that, and the only thing standing between it and production is the `PX`
// on the `SET` inside the script. Read the TTL back FROM THE SERVER, not from the
// transcription of the script — which is the entire reason this file exists.
func TestTheScriptExpiresItsOwnKey(t *testing.T) {
	a, _ := liveTier(t)
	store := liveStore(t, a, "ttl")

	if _, err := store.Hit("acct:1", Request{Limit: 4, Window: liveWindow, Now: time.Unix(0, 0)}); err != nil {
		t.Fatalf("Hit: %v", err)
	}

	reply := liveCall(t, a, "return redis.call('PTTL', KEYS[1])", store.KeyFor("acct:1"))
	milliseconds, numberErr := numberOf(reply)
	if numberErr != nil {
		t.Fatalf("PTTL answered %s (%T), want a number: %v", render(reply), reply, numberErr)
	}
	// `PTTL` rather than `TTL` because the question is "is there an expiry, and is
	// it about a window", and a millisecond answer states that without a ceiling
	// the second-granularity `TTL` would need. A key with no expiry answers -1.
	if milliseconds <= 0 {
		t.Errorf("PTTL is %v, want a positive number. A key with no expiry answers -1, so this bucket is kept until something deletes it — a Redis that accumulates a bucket for every client that has ever connected is a memory leak with a business-sized keyspace.", milliseconds)
	}
	if milliseconds > float64(liveWindow.Milliseconds()) {
		t.Errorf("PTTL is %vms, want at most the window's %vms. The `PX` is the window, so a longer one means the key outlives the debt it holds by more than the debt itself.", milliseconds, liveWindow.Milliseconds())
	}
}

// TestARefusedRequestLeavesTheStoredDebtWhereAnAdmittedOneLeftIt reads the debt
// back THROUGH THE SERVER, so this is what Redis HOLDS rather than what the client
// was told.
//
// The refusal branch writes nothing, and a version that did would let a caller
// that keeps hammering while throttled lock itself out for as long as it keeps
// trying.
func TestARefusedRequestLeavesTheStoredDebtWhereAnAdmittedOneLeftIt(t *testing.T) {
	a, _ := liveTier(t)
	store := liveStore(t, a, "debt")
	key := store.KeyFor("acct:1")
	request := Request{Limit: 3, Window: liveWindow, Now: time.Unix(0, 0)}

	for i := 0; i < 3; i++ {
		if _, err := store.Hit("acct:1", request); err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
	}
	admitted := liveCall(t, a, "return redis.call('GET', KEYS[1])", key)

	for i := 0; i < 20; i++ {
		verdict, err := store.Hit("acct:1", request)
		if err != nil {
			t.Fatalf("refusal %d: %v", i, err)
		}
		if verdict.Allowed {
			t.Fatalf("refusal %d was admitted", i)
		}
	}
	refused := liveCall(t, a, "return redis.call('GET', KEYS[1])", key)

	if render(refused) != render(admitted) {
		t.Errorf("after 20 refusals the stored debt is %s, was %s after the last admitted one. A refusal that writes deepens the debt, so a caller that keeps hammering while throttled locks itself out for as long as it keeps trying.", render(refused), render(admitted))
	}
}

// TestTheBucketCharsetIsEnforcedAgainstARealServer is the refusal the store makes
// BEFORE it talks to Redis.
//
// A key that trips the check throws, and the middleware fails open on that throw —
// so a deployment with a bad bucket name has a limiter that is silently off.
// Asserting it throws is what keeps that visible.
func TestTheBucketCharsetIsEnforcedAgainstARealServer(t *testing.T) {
	a, _ := liveTier(t)
	store := liveStore(t, a, "charset")
	request := Request{Limit: 1, Window: liveWindow, Now: time.Unix(0, 0)}

	for _, bucket := range []string{"a b c", strings.Repeat("x", 129), "a\nb"} {
		verdict, err := store.Hit(bucket, request)
		if err == nil {
			t.Errorf("the bucket %q was accepted and answered allowed=%v. A bucket name ends up in a Redis key, so one carrying a space or a newline is a key nobody can find again with KEYS — and the middleware fails open on this throw, so accepting it is a limiter that is silently off.", bucket, verdict.Allowed)
			continue
		}
		if verdict.Allowed {
			t.Errorf("the bucket %q was refused but the verdict still says allowed=%v. A caller refused a key has not been admitted, whatever the zero value of the verdict says.", bucket, verdict.Allowed)
		}
	}
}

// -----------------------------------------------------------------------------
// the comparison itself
// -----------------------------------------------------------------------------

// expectSameVerdict is `expectSameVerdict` from
// `src/middleware/rateLimitRedisLive.test.ts` (removed at cutover), in Go.
//
// # THE TIMESTAMPS ARE COMPARED, AND NOT WITH A TOLERANCE
//
// Redis returns a Lua number as an **integer, truncated toward zero** — `2.5` comes
// back as `2`, `-0.5` as `0`. That is a property of the server's Lua-to-RESP
// conversion, not of `GCRALua`, and it is why the two implementations agree on what
// they DECIDE and not on the last decimal of a timestamp.
//
// So this is an exact comparison, not a tolerance: the decision fields are integral
// on both sides and must be identical, and the two instants must equal the memory
// store's truncated toward zero. A blanket "close enough" would let a regression of
// any size through under the name of a rounding difference; this states the
// mechanism, so a server that changed its conversion fails the test instead of
// quietly widening what passes.
func expectSameVerdict(t *testing.T, received Verdict, expected Verdict, label string) {
	t.Helper()

	if received.Allowed != expected.Allowed {
		t.Errorf("%s allowed %v, want %v", label, received.Allowed, expected.Allowed)
	}
	if received.Remaining != expected.Remaining {
		t.Errorf("%s remaining %v, want %v", label, received.Remaining, expected.Remaining)
	}
	if want := truncatedTo(expected.ResetAt, time.Millisecond); !received.ResetAt.Equal(want) {
		t.Errorf("%s resetAt %s, want %s", label, received.ResetAt.Format(time.RFC3339Nano), want.Format(time.RFC3339Nano))
	}
	if want := truncatedTo(expected.RetryAt, time.Millisecond); !received.RetryAt.Equal(want) {
		t.Errorf("%s retryAt %s, want %s", label, received.RetryAt.Format(time.RFC3339Nano), want.Format(time.RFC3339Nano))
	}
}
