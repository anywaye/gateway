package ratelimit

import (
	"context"
	"math"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

type scriptedCommands struct {
	calls   int
	scripts []string
	keys    []string
	args    []string
}

func (c *scriptedCommands) Eval(script string, keys []string, args []string) (Value, error) {
	c.calls++
	c.scripts = append(c.scripts, script)
	c.keys = append(c.keys, keys...)
	c.args = append(c.args, args...)
	return transcription(keys[0], args), nil
}

func (c *scriptedCommands) Ping(context.Context) (bool, error) { return true, nil }

func transcription(key string, args []string) Value {
	limit := toFloat(args[0])
	window := toFloat(args[1])
	now := toFloat(args[2])

	tat := now
	if stored, ok := fakeRedis[key]; ok {
		tat = stored
	}

	interval := window / limit
	next := math.Max(now, tat) + interval
	delay := next - now

	if delay > window {
		return []Value{int(tat), tat, next - window, 0}
	}

	fakeRedis[key] = next
	used := math.Ceil((next - now) / interval)
	return []Value{1, next, next - interval - window, math.Max(0, limit-used)}
}

var fakeRedis = map[string]float64{}

func resetFakeRedis() { fakeRedis = map[string]float64{} }

func toFloat(value string) float64 {
	parsed, err := strconv.ParseFloat(value, 64)
	if err != nil {
		panic("ratelimit: the transcription was handed an argument that is not a number: " + value)
	}
	return parsed
}

func read(t *testing.T, name string) string {
	t.Helper()

	raw, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("cannot read %s: %v", name, err)
	}
	return string(raw)
}

type parityCase struct {
	name     string
	limit    int
	window   time.Duration
	instants []time.Duration
	want     []Verdict
}

var parityTable = []parityCase{
	{
		name:     "a burst of exactly the limit lands",
		limit:    5,
		window:   time.Minute,
		instants: []time.Duration{0, 0, 0, 0, 0},
		want: []Verdict{
			{Allowed: true, Remaining: 4},
			{Allowed: true, Remaining: 3},
			{Allowed: true, Remaining: 2},
			{Allowed: true, Remaining: 1},
			{Allowed: true, Remaining: 0},
		},
	},
	{
		name:     "one past the limit is refused and does not deepen the debt",
		limit:    5,
		window:   time.Minute,
		instants: []time.Duration{0, 0, 0, 0, 0, 0},
		want: []Verdict{
			{Allowed: true, Remaining: 4},
			{Allowed: true, Remaining: 3},
			{Allowed: true, Remaining: 2},
			{Allowed: true, Remaining: 1},
			{Allowed: true, Remaining: 0},
			{Allowed: false, Remaining: 0},
		},
	},
	{
		name:     "a refused request does not deepen the debt",
		limit:    3,
		window:   time.Minute,
		instants: []time.Duration{0, 0, 0, 0, 0, time.Second * 20},
		want: []Verdict{
			{Allowed: true, Remaining: 2},
			{Allowed: true, Remaining: 1},
			{Allowed: true, Remaining: 0},
			{Allowed: false, Remaining: 0},
			{Allowed: false, Remaining: 0},
			{Allowed: true, Remaining: 0},
		},
	},
	{
		name:   "the allowance does not double at a window edge",
		limit:  5,
		window: time.Minute,
		instants: []time.Duration{
			time.Minute - time.Millisecond, time.Minute - time.Millisecond, time.Minute - time.Millisecond, time.Minute - time.Millisecond, time.Minute - time.Millisecond,
			time.Minute, time.Minute, time.Minute, time.Minute, time.Minute,
		},
		want: []Verdict{
			{Allowed: true, Remaining: 4},
			{Allowed: true, Remaining: 3},
			{Allowed: true, Remaining: 2},
			{Allowed: true, Remaining: 1},
			{Allowed: true, Remaining: 0},
			{Allowed: false, Remaining: 0},
			{Allowed: false, Remaining: 0},
			{Allowed: false, Remaining: 0},
			{Allowed: false, Remaining: 0},
			{Allowed: false, Remaining: 0},
		},
	},
	{
		name:     "the allowance is repaid continuously",
		limit:    4,
		window:   time.Minute,
		instants: []time.Duration{0, 0, 0, 0, time.Second * 30},
		want: []Verdict{
			{Allowed: true, Remaining: 3},
			{Allowed: true, Remaining: 2},
			{Allowed: true, Remaining: 1},
			{Allowed: true, Remaining: 0},
			{Allowed: true, Remaining: 1},
		},
	},
	{
		name:     "an interval that does not divide the window",
		limit:    7,
		window:   time.Minute,
		instants: []time.Duration{0, 0, 0, 0, 0, 0, 0, 0, time.Second * 9, time.Second * 9},
		want: []Verdict{
			{Allowed: true, Remaining: 6},
			{Allowed: true, Remaining: 5},
			{Allowed: true, Remaining: 4},
			{Allowed: true, Remaining: 3},
			{Allowed: true, Remaining: 2},
			{Allowed: true, Remaining: 1},
			{Allowed: true, Remaining: 0},
			{Allowed: false, Remaining: 0},
			{Allowed: true, Remaining: 0},
			{Allowed: false, Remaining: 0},
		},
	},
}

func TestTheTwoCountersAgreeRequestForRequest(t *testing.T) {
	for _, tc := range parityTable {
		t.Run(tc.name, func(t *testing.T) {
			at := time.Unix(1_790_000_000, 0)

			memory, err := NewMemoryStore(0)
			if err != nil {
				t.Fatalf("NewMemoryStore: %v", err)
			}

			resetFakeRedis()
			commands := &scriptedCommands{}
			redis, err := NewRedisStore(commands, "")
			if err != nil {
				t.Fatalf("NewRedisStore: %v", err)
			}

			for i, offset := range tc.instants {
				request := Request{Limit: tc.limit, Window: tc.window, Now: at.Add(offset)}

				fromMemory, err := memory.Hit("parity", request)
				if err != nil {
					t.Fatalf("step %d, memory store: %v", i, err)
				}
				fromRedis, err := redis.Hit("parity", request)
				if err != nil {
					t.Fatalf("step %d, redis store: %v", i, err)
				}

				if !sameAnswer(fromRedis, fromMemory) {
					t.Errorf("step %d at +%s: memory %+v and redis %+v. Two counters that disagree admit different numbers of requests, and the deployment gets whichever one it happens to run.", i, offset, fromMemory, fromRedis)
					continue
				}
				if !sameDecision(fromMemory, tc.want[i]) {
					t.Errorf("step %d at +%s: both counters say %+v, and the reference says %+v. The table is the specification — it was read off `memoryRateLimitStore` in `src/middleware/rateLimitStore.ts` (removed at cutover) — so a disagreement here is a defect in BOTH, not a disagreement between them.", i, offset, fromMemory, tc.want[i])
				}
			}

			if len(commands.keys) != len(tc.instants) {
				t.Fatalf("the redis store sent %d key(s) for %d request(s)", len(commands.keys), len(tc.instants))
			}
			if got := commands.keys[0]; got != "gateway:rl:parity" {
				t.Errorf("the redis key is %q, want gateway:rl:parity — gateway's own namespace is part of the key so two policies never share a bucket", got)
			}
			if len(commands.args) != 3*len(tc.instants) {
				t.Fatalf("the redis store sent %d argument(s) for %d request(s), want 3 each", len(commands.args), len(tc.instants))
			}
			for i, offset := range tc.instants {
				args := commands.args[i*3 : i*3+3]
				for j, want := range []string{
					itoaOf(tc.limit),
					itoaOf(int(tc.window / time.Millisecond)),
					itoaOf(int(at.Add(offset).UnixMilli())),
				} {
					if args[j] != want {
						t.Errorf("step %d sent ARGV[%d] = %q, want %q. The script reads them positionally, and a reordered argument is a limiter that divides a timestamp by a limit.", i, j+1, args[j], want)
					}
				}
			}
		})
	}
}

func TestTheInstantsAreWhereTheArithmeticPutsThem(t *testing.T) {
	for _, tc := range []struct {
		name      string
		limit     int
		window    time.Duration
		instants  []time.Duration
		wantReset []time.Duration
		wantRetry []time.Duration
	}{
		{
			name:     "an interval that divides the window",
			limit:    4,
			window:   time.Minute,
			instants: []time.Duration{0, 0, 0, 0, 0},
			wantReset: []time.Duration{
				15 * time.Second, 30 * time.Second, 45 * time.Second, 60 * time.Second, 60 * time.Second,
			},
			wantRetry: []time.Duration{
				-60 * time.Second, -45 * time.Second, -30 * time.Second, -15 * time.Second, 15 * time.Second,
			},
		},
		{
			name:     "an interval that does not divide the window",
			limit:    7,
			window:   time.Minute,
			instants: []time.Duration{0, 0, 0, 0, 0, 0, 0, 0, time.Second * 9, time.Second * 9},
			wantReset: []time.Duration{
				8571 * time.Millisecond, 17142 * time.Millisecond, 25714 * time.Millisecond,
				34285 * time.Millisecond, 42857 * time.Millisecond, 51428 * time.Millisecond,
				59999 * time.Millisecond, 59999 * time.Millisecond,
				68571 * time.Millisecond, 68571 * time.Millisecond,
			},
			wantRetry: []time.Duration{
				-60 * time.Second, -51429 * time.Millisecond, -42858 * time.Millisecond,
				-34286 * time.Millisecond, -25715 * time.Millisecond, -17143 * time.Millisecond,
				-8572 * time.Millisecond,
				8571 * time.Millisecond,
				-1 * time.Millisecond,
				17142 * time.Millisecond,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, err := NewMemoryStore(0)
			if err != nil {
				t.Fatalf("NewMemoryStore: %v", err)
			}
			at := time.Unix(1_790_000_000, 0)

			for i, offset := range tc.instants {
				verdict, err := store.Hit("instants", Request{Limit: tc.limit, Window: tc.window, Now: at.Add(offset)})
				if err != nil {
					t.Fatalf("step %d: %v", i, err)
				}

				if got := verdict.ResetAt.Sub(at); got != tc.wantReset[i] {
					t.Errorf("step %d at +%s: resetAt is at +%s, want +%s. This is what `RateLimit-Reset` says, and on the refusal branch it is the OLD tat rather than `next` — a client counting down from `next` waits one request longer than it was told to.", i, offset, got, tc.wantReset[i])
				}
				if got := verdict.RetryAt.Sub(at); got != tc.wantRetry[i] {
					t.Errorf("step %d at +%s: retryAt is at +%s, want +%s. This is what `Retry-After` says, and it is the one field a table of allowed/remaining pairs cannot see.", i, offset, got, tc.wantRetry[i])
				}
			}
		})
	}
}


func sameDecision(received Verdict, expected Verdict) bool {
	return received.Allowed == expected.Allowed && received.Remaining == expected.Remaining
}

func sameAnswer(received Verdict, expected Verdict) bool {
	return received.Allowed == expected.Allowed &&
		received.Remaining == expected.Remaining &&
		received.ResetAt.Equal(truncatedTo(expected.ResetAt, time.Millisecond)) &&
		received.RetryAt.Equal(truncatedTo(expected.RetryAt, time.Millisecond))
}

func truncatedTo(instant time.Time, unit time.Duration) time.Time {
	whole := instant.Truncate(unit)
	if whole.After(instant) {
		return whole.Add(unit)
	}
	return whole
}

func TestTheTranscriptionIsTheScript(t *testing.T) {
	source := read(t, "redis.go")

	const declaration = "const GCRALua = `"
	from := strings.Index(source, declaration)
	if from < 0 {
		t.Fatal("redis.go no longer declares GCRALua as a raw string. The parity table transcribes it, so a rename is a finding rather than a rename.")
	}
	body := from + len(declaration)
	to := strings.Index(source[body:], "`")
	if to < 0 {
		t.Fatal("GCRALua's raw string is unterminated")
	}
	script := source[body : body+to]

	for _, must := range []struct{ what, text string }{
		{"one key, not the whole namespace", "KEYS[1]"},
		{"the argument order limit, window, now", "local limit = tonumber(ARGV[1])"},
		{"the argument order window", "local window = tonumber(ARGV[2])"},
		{"the argument order now", "local now = tonumber(ARGV[3])"},
		{"the self-expiring key", "'PX', window"},
		{"the ceil before the subtraction", "math.ceil((next - now) / interval)"},
		{"the old tat on the refusal branch", "return {0, tat, next - window, 0}"},
		{"the floor at zero remaining", "math.max(0, limit - used)"},
		{"the strictly-greater admission test", "if delay > window then"},
	} {
		if !strings.Contains(script, must.text) {
			t.Errorf("GCRALua does not contain %s (%q). The parity table transcribes this script, so a transcription and a script that have drifted are indistinguishable from a transcription and a script that agree — and the live test is the only thing that would notice.", must.what, must.text)
		}
	}

	transcribed := read(t, "parity_test.go")
	for _, must := range []string{
		"args[0]", "args[1]", "args[2]",
		"math.Max(0, limit-used)",
		"next - window, 0}",
	} {
		if !strings.Contains(transcribed, must) {
			t.Errorf("the transcription in parity_test.go does not contain %q, so it is not the transcription of this script.", must)
		}
	}
}

func TestTheMemoryStoreSweepsOnlySettledBuckets(t *testing.T) {
	store, err := NewMemoryStore(2)
	if err != nil {
		t.Fatalf("NewMemoryStore(2): %v", err)
	}

	at := time.Unix(1_790_000_000, 0)
	request := Request{Limit: 5, Window: time.Minute, Now: at}

	for _, key := range []string{"a", "b"} {
		if _, err := store.Hit(key, request); err != nil {
			t.Fatalf("Hit(%q): %v", key, err)
		}
	}
	if _, err := store.Hit("c", request); err != nil {
		t.Fatalf(`Hit("c"): %v`, err)
	}

	if got := store.Size(); got != 3 {
		t.Errorf("after three in-debt arrivals the store holds %d bucket(s), want 3. The sweep must never evict a caller who owes quota.", got)
	}

	later := Request{Limit: 5, Window: time.Minute, Now: at.Add(time.Hour)}
	if _, err := store.Hit("d", later); err != nil {
		t.Fatalf(`Hit("d"): %v`, err)
	}
	if got := store.Size(); got != 1 {
		t.Errorf("after the debts settled the store holds %d bucket(s), want 1 — only `d`. A bucket at `tat <= now` owes nothing, so forgetting it hands the caller exactly the allowance they had already earned.", got)
	}
}

func itoaOf(n int) string { return strconv.Itoa(n) }
