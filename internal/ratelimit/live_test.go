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

const liveWindow = time.Minute

var (
	liveRedisURL      string
	liveRedisRequired bool
)

var liveRun = "live-" + randomToken()

func randomToken() string {
	const alphabet = "0123456789abcdef"
	seed := uint64(time.Now().UnixNano())
	var out strings.Builder
	for i := 0; i < 16; i++ {
		seed ^= seed << 13
		seed ^= seed >> 7
		seed ^= seed << 17
		out.WriteByte(alphabet[seed&0xf])
	}
	return out.String()
}

func TestMain(m *testing.M) {
	liveRedisURL = strings.TrimSpace(os.Getenv("GATEWAY_REDIS_URL"))
	liveRedisRequired = os.Getenv("GATEWAY_REDIS_REQUIRED") == "1"

	if liveRedisURL == "" && liveRedisRequired {
		fmt.Fprintln(os.Stderr,
			"ratelimit: GATEWAY_REDIS_REQUIRED=1 and GATEWAY_REDIS_URL is unset. The live Redis tier"+
				" cannot run, and a run that cannot run it proves nothing about GCRALua. Point"+
				" GATEWAY_REDIS_URL at a redis-server, or unset GATEWAY_REDIS_REQUIRED to skip this"+
				" tier on purpose.")
		os.Exit(1)
	}

	os.Exit(m.Run())
}

var liveTierSkipped bool

const liveCleanup = `
local found = redis.call('KEYS', ARGV[1] .. '*')
for i = 1, #found do redis.call('DEL', found[i]) end
return #found
`

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
			t.Fatalf("GATEWAY_REDIS_URL=%s did not answer: %v", redactRedisURL(liveRedisURL), err)
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

func liveCall(t *testing.T, connection *Connection, script, key string) Value {
	t.Helper()

	value, err := connection.Eval(script, []string{key}, nil)
	if err != nil {
		t.Fatalf("EVAL %q against %q: %v", script, key, err)
	}
	return value
}

func liveStore(t *testing.T, connection *Connection, name string) *RedisStore {
	t.Helper()

	store, err := NewRedisStore(connection, liveRun+"."+name)
	if err != nil {
		t.Fatalf("NewRedisStore: %v", err)
	}
	t.Cleanup(func() { liveCall(t, connection, "return redis.call('DEL', KEYS[1])", store.KeyFor("acct:1")) })
	return store
}


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

	reply, err := a.Eval("return {1, 2, 3}", []string{key}, nil)
	if err != nil {
		t.Fatalf("EVAL returning an array: %v", err)
	}
	items, ok := reply.([]Value)
	if !ok || len(items) != 3 {
		t.Fatalf("an array came back as %s (%T), want three elements", render(reply), reply)
	}

	var replyErr *ReplyError
	_, err = a.Eval("return redis.call('INCR', KEYS[1])", []string{key}, nil)
	if !errors.As(err, &replyErr) {
		t.Errorf("INCR on a string key answered %v, want a *ReplyError. A store that cannot tell an error reply from an answer has no way to fail open.", err)
	}
}

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

func TestAnUnreachableServerThrowsRatherThanResolving(t *testing.T) {
	listener, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("could not open a port to close: %v", err)
	}
	dead := listener.Addr().String()
	_ = listener.Close()

	if _, err := Connect(RedisConnectionOptions{URL: "redis://" + dead, Timeout: 500 * time.Millisecond}); err == nil {
		t.Error("Connect answered a client for a port nothing is listening on. A client that resolves against a dead server turns an outage into a limiter answering \"allowed\" with no error anywhere.")
	}

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

	if refusals == 0 {
		t.Error("24 requests against a limit of 5 over 10s refused nothing, so this proved that the two backends agree about admitting and not that they agree about refusing.")
	}
}

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

	after := liveStore(t, b, "survives")
	verdict, err = after.Hit("acct:1", request)
	if err != nil {
		t.Fatalf("Hit: %v", err)
	}
	if verdict.Allowed {
		t.Error("a second connection was admitted on a bucket a first connection had already spent. Either the counter is per connection or the key is not what both of them wrote.")
	}
}

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
	if milliseconds <= 0 {
		t.Errorf("PTTL is %v, want a positive number. A key with no expiry answers -1, so this bucket is kept until something deletes it — a Redis that accumulates a bucket for every client that has ever connected is a memory leak with a business-sized keyspace.", milliseconds)
	}
	if milliseconds > float64(liveWindow.Milliseconds()) {
		t.Errorf("PTTL is %vms, want at most the window's %vms. The `PX` is the window, so a longer one means the key outlives the debt it holds by more than the debt itself.", milliseconds, liveWindow.Milliseconds())
	}
}

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
