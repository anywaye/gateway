// GCRA's arithmetic, and the parity between the two backends that implement it.
//
// # THE PARITY IS THE POINT, NOT A CONVENIENCE
//
// `MemoryStore` and `RedisStore` compute the same four numbers by two different
// routes: one in Go with a `time.Time`, one in Lua with floats and an integer reply.
// A limiter is only as good as the identity of the thing it is counting, so a
// backend that admits one more request per window than the other is a deployment
// whose limit is the wrong number, and the difference is invisible from either side
// alone.
//
// So `parity_test.go` runs ONE table through both, and the Redis side runs against a
// transcription of the script rather than against a mock's answers. The transcription
// is a liability — it can drift from `GCRALua` — and `TestTheTranscriptionIsTheScript`
// is what holds it.
//
// `live_test.go` runs the REAL script against a real `redis-server`, because a
// transcription cannot find what Redis does to a returned number. The packet names
// that: Redis truncates a Lua float toward zero on the way out.
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

// scriptedCommands answers `EVAL` by running a LINE-FOR-LINE TRANSCRIPTION of
// `GCRALua` in Go.
//
// NOT a mock and NOT a canned answer: it is the algorithm, written out again, so the
// client-side code (key names, argument marshalling, reply decoding) is executed
// against a reply shaped the way Redis shapes one — four integers, in an array — and
// the arithmetic is compared against `MemoryStore`'s independently.
//
// The drift risk is real and is why `TestTheTranscriptionIsTheScript` exists: it reads
// `GCRALua` out of the source and asserts the transcription's structure matches, so a
// change to the script without a change here is a failing test rather than a green
// that proves the transcription agrees with itself.
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

// transcription is `GCRALua` in Go, keeping Lua's arithmetic exactly.
//
// Four details are load-bearing and each is a difference a careless Go version gets
// wrong:
//
//   - `math.ceil` on the used count, so `limit - 1.5` is not truncated to
//     `limit - 1`. Redis truncates the RESULT on the way out, which is why the Lua
//     ceils before it returns rather than relying on the store.
//   - `math.max(0, …)` on the remaining count, so an over-admitted caller is never
//     told it has a negative allowance.
//   - The refusal branch returns the OLD `tat` as its reset, not `next`. Getting
//     that wrong makes a throttled client's `RateLimit-Reset` count down from the
//     wrong instant.
//   - Every value is an INTEGER on the way out, because that is what Redis sends for
//     a Lua number, and a float in the reply is not a shape the client sees.
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

// fakeRedis is the transcription's key space.
//
// A package-level map rather than a field, because it is the store and the store is
// what the transcription is emulating — and because a field would make the
// transcription a different type from the thing it stands in for.
var fakeRedis = map[string]float64{}

// resetFakeRedis empties it between cases. Without this a second case sees the first
// case's debt and every number after the first is wrong.
func resetFakeRedis() { fakeRedis = map[string]float64{} }

// toFloat is `tonumber(ARGV[n])`, and it PARSES rather than casting because Lua's
// `tonumber` on a non-number is nil and Go's `strconv` on a non-number is an error —
// and both of those mean "this reply is not the shape the script returns", which is
// what `verdictOf` refuses.
func toFloat(value string) float64 {
	parsed, err := strconv.ParseFloat(value, 64)
	if err != nil {
		// A script that cannot read its own arguments is a defect in the store, and
		// this is the transcription, so a panic is the honest answer: the test that
		// caused it is broken rather than the code under test.
		panic("ratelimit: the transcription was handed an argument that is not a number: " + value)
	}
	return parsed
}

// read reads a file in this package's own directory, for the test that asserts on
// what `redis.go` SAYS as well as on what it does.
func read(t *testing.T, name string) string {
	t.Helper()

	raw, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("cannot read %s: %v", name, err)
	}
	return string(raw)
}

// parityCase is one row: an allowance and a sequence of instants to hit it at.
type parityCase struct {
	name     string
	limit    int
	window   time.Duration
	instants []time.Duration // offsets from the case's own `at`
	want     []Verdict
}

// The table. It is written out rather than generated because the interesting rows
// are the boundary ones and a generator would produce the middle of the range.
//
// # WHERE THE `want` VALUES CAME FROM
//
// Not from `count()`, and not from this package. Every one was read off the
// REFERENCE — `memoryRateLimitStore` from `src/middleware/rateLimitStore.ts` (removed at cutover), driven
// by these rows' instants and printed — and the transcript is in
// `REPORT-gateway-go-auth-01.md`. A table derived from the implementation under test
// is a test that cannot fail; a table read off the implementation being ported is the
// specification this port is measured against.
//
// Four of the six rows were WRONG when first written, all four in the same direction:
// hand-computed `remaining` that assumed a fixed window's answer. The one that matters
// is "the allowance does not double at a window edge" — it was written as 4 admitted
// across the edge, because 60.001s after the burst the caller looks free. It is not
// free: the reference's own row fires the second burst at `tat + 1ms`, and this now
// does too.
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
		// Strictly greater, so a caller sitting EXACTLY on the threshold is admitted:
		// that is what lets a burst of exactly `limit` land.
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
		// A caller that keeps hammering while throttled must not lock ITSELF out. The
		// refused request above writes nothing, so this one at the same instant is
		// refused identically — and one interval later it is admitted.
		//
		// Admitted with NOTHING left, which is the whole shape of the thing: 20s of a
		// 60s window is two intervals already repaid, this request spends the third,
		// and the debt it leaves is exactly one whole window. A fixed window would have
		// answered "2" here, promising a burst of two that the sliding window would
		// then refuse.
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
		// THE SLIDING BOUND. Five requests one millisecond BEFORE a wall-clock minute
		// and five AT it: a fixed window hands out ten, because the minute rolled. These
		// are the same ten requests the reference's own table fires, and this answers
		// five.
		//
		// The first five land at 59.999s, so their debt runs to 119.999s — still 59.999s
		// of a 60s window in the future when the edge arrives. Adding one more interval
		// puts the debt at 71.999s, which is past the window, so the second five are
		// refused with the SAME `RetryAt` as the sixth request of the first burst would
		// have: one interval, not one minute.
		//
		// This row is the reason `count` exists instead of the code it replaced.
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
		// The window is repaid CONTINUOUSLY rather than in a lump at an edge, so half
		// way through a minute one request's worth of burst room is back: two of the
		// four intervals have been paid, this one spends the third, and one is left.
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
		// A window that does not divide by the limit is where a limiter that truncates
		// its interval goes wrong: 60s over 7 is 8.571s, and rounding it to 8s changes
		// when the caller is repaid.
		//
		// It is also the row where the two backends' timestamps stop being identical,
		// and that is not a tolerance — see `sameAnswer`.
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
			// Nine seconds has repaid one whole interval and 428ms of the next, so this
			// one lands with NOTHING left rather than with six: the burst allowance was
			// seven, it is now 8571ms of one interval away from being whole again.
			{Allowed: true, Remaining: 0},
			{Allowed: false, Remaining: 0},
		},
	},
}

// TestTheTwoCountersAgreeRequestForRequest is the parity table through both backends.
//
// `t.Run` per row and per instant, so a failure names the case AND the step rather
// than printing two verdict lists and leaving a reader to find the difference.
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

			// And the keys and arguments the store sends are the ones the script
			// reads, asserted rather than assumed: `KEYS[1]` is the whole namespace and
			// `ARGV` is limit, window, now IN THAT ORDER.
			if len(commands.keys) != len(tc.instants) {
				t.Fatalf("the redis store sent %d key(s) for %d request(s)", len(commands.keys), len(tc.instants))
			}
			if got := commands.keys[0]; got != "gateway:rl:parity" {
				t.Errorf("the redis key is %q, want gateway:rl:parity — gateway's own namespace is part of the key so two policies never share a bucket", got)
			}
			// The shape is three arguments per request, and a count of anything else
			// means the store is sending something the script cannot read.
			if len(commands.args) != 3*len(tc.instants) {
				t.Fatalf("the redis store sent %d argument(s) for %d request(s), want 3 each", len(commands.args), len(tc.instants))
			}
			// ARGV is [limit, window, now] on every step. The limit and the window are
			// the table's own numbers and do not move; `now` does, because the case
			// steps the clock, and a `now` that did not move would be a limiter that
			// cannot see time pass.
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

// TestTheInstantsAreWhereTheArithmeticPutsThem pins `resetAt` and `retryAt`, which
// the table above cannot.
//
// # WHY IT IS A SEPARATE TABLE
//
// A row of allowed/remaining pairs says what the limiter DECIDED and nothing about
// when. `ResetAt` is what a client reads as `RateLimit-Reset`, `RetryAt` is what a
// throttled client reads as `Retry-After`, and the refusal branch's pair is the one
// that matters most and is the one no allowed/remaining pair can see: both of its
// fields are instants and its `remaining` is a hard-coded zero.
//
// So the numbers below were read off the reference the same way the table's were, and
// this is the reference's own timing assertions from `rateLimitParity.test.ts` —
// `resetAt` one interval on, `retryAt` at or before `now`, and on the refusal
// `retryAt` one interval out and `resetAt` a whole window out — written out as
// literals instead of derived, because a derived expectation is the implementation.
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
			// `window / limit` divides exactly here, so this row is bit-identical to
			// the reference and says so without a caveat. Step 4 is the refusal: it
			// returns the OLD `tat` as its reset (60s, not 75s) and `next - window` as
			// its retry (15s, one interval), which are the two numbers a throttled
			// client acts on.
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
			// `window / limit` does NOT divide here, so this row is the one that had to
			// be measured rather than reasoned about. `60_000 / 7` is
			// 8571.428571…ms, and every number below is that grid truncated to whole
			// milliseconds — the resolution `ResetAt` and `RetryAt` carry, because a
			// `float64` debt becomes an instant through `time.UnixMilli` and because
			// Redis returns a Lua number the same way.
			//
			// # THE TRUNCATION FLOORS A NEGATIVE OFFSET, AND THAT IS WHY STEP 8 IS -1ms
			//
			// `at` is 1_790_000_000_000ms, a positive number, and `at()` truncates the
			// EPOCH value toward zero — which for a positive epoch is a floor. So an
			// instant at +8571.43ms above the base lands a millisecond short, and one
			// at -0.5ms lands a whole millisecond BELOW the base: step 8's `retryAt` is
			// `-1ms`, not `0`. Reading these as `trunc(offset)` gets step 8 wrong and
			// nothing else, which is the worst possible way for a table to be wrong.
			//
			// # WHAT USED TO BE HERE, AND WHY IT WAS WRONG
			//
			// This row used to expect `time.Duration` values on a nanosecond grid —
			// `8571428571ns` per interval, and a `retryAt` of `-3ns` at step 8 — and the
			// comment above them argued for keeping it. The argument was sound and
			// addressed only the timestamps: the port was MORE precise than the
			// reference, by less than the reference's own float error, and every
			// DECISION on the row was identical. What it did not consider is
			// `remaining`, which is `ceil((next - now) / interval)` — a ratio one part
			// in 10^13 either side of a whole number IS the whole answer, and a debt
			// carried in nanoseconds drifts across that boundary where a debt carried in
			// milliseconds does not.
			//
			// `live_test.go` found it against a real redis-server: ten of four hundred
			// randomised steps came back with one fewer unit of allowance than the
			// memory store had just granted, because the two backends were running
			// different arithmetic. So the decision was not "more precise" — it was
			// "a different algorithm, agreeing on the decisions by luck". The nanosecond
			// grid was not worth keeping once it was measured.
			//
			// The last two rows are the two the reference's row would admit and refuse:
			// 9s has repaid one whole interval and 428ms of the next, so the ninth
			// request lands with nothing left, and the tenth is refused.
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
				// REFUSED at step 7: `next - window`, so the eighth interval minus the
				// window — which is why a client told to retry in 8.571s is right and
				// one told to retry in 8s would be hammering.
				8571 * time.Millisecond,
				// Admitted at +9s with `resetAt` at eight intervals: `next - interval -
				// window` lands just before `now`, and the floor puts it a millisecond
				// before rather than level with it.
				-1 * time.Millisecond,
				// REFUSED again, one further interval out.
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

// `intervalOf` was deleted with this row's rewrite, and the reason is worth keeping
// even though the function is gone.
//
// It computed `window / limit` to produce the EXPECTATION, which is the defect in a
// test helper: it re-ran the implementation's own division, so any change to what
// `count` divides by moved the expectation by the same amount and the row could not
// fail. It stayed green through the nanosecond-to-millisecond change for exactly
// that reason. The row above spells its numbers out as literals, for the reason this
// file's own header gives: "a derived expectation is the implementation".

// sameDecision compares the two fields a table row states: whether the request was
// admitted, and what is left of the allowance.
//
// # THE INSTANTS ARE NOT IN THE TABLE, AND `TestTheInstantsAreWhereTheArithmeticPutsThem`
// # IS WHY THAT IS NOT A HOLE
//
// A row states decisions, exactly as the reference's own table does, and the instants
// are pinned separately against the reference transcript — including the refusal
// branch's `RetryAt`, which is the number a throttled client counts down from and the
// one a table of allowed/remaining pairs cannot see.
func sameDecision(received Verdict, expected Verdict) bool {
	return received.Allowed == expected.Allowed && received.Remaining == expected.Remaining
}

// sameAnswer compares the two backends' verdicts, and what it compares is the whole
// point of the function.
//
// # THE TIMESTAMPS ARE COMPARED, AND NOT WITH A TOLERANCE
//
// Redis converts a Lua number to an integer reply by TRUNCATING toward zero: `2.5`
// comes back as `2`. That is a property of the server's Lua-to-RESP conversion, not of
// `GCRALua`, and it is why the two backends agree on what they DECIDE and not on the
// last decimal of a timestamp. The reference says this in the same words, in
// `expectSameVerdict` in `src/middleware/rateLimitRedisLive.test.ts` (removed at cutover), and pins it the
// same way: exact on the two decision fields, and the two instants equal to the memory
// store's truncated toward zero.
//
// # WHY A TOLERANCE WOULD BE WORSE THAN A BUG
//
// `Within(2 * time.Millisecond)` would pass for a server that changed its conversion,
// for an interval rounded to the wrong unit, and for a bucket stored in the wrong
// time base — three different defects, all under the name of a rounding difference.
// `truncatedTo` states the mechanism, so a server that stopped truncating fails this
// instead of quietly widening what passes.
//
// # AND WHY THIS IS NOT THE GO PORT INVENTING IT
//
// `MemoryStore` keeps nanoseconds because the reference's memory store keeps a JS
// `number` of milliseconds at full float precision, and truncating here would be a
// second divergence, in the opposite direction. `RedisStore` truncates because
// `verdictOf` does `time.UnixMilli(int64(...))`, which is the integer Redis already
// sent. Neither side was adjusted to make the other look good.
func sameAnswer(received Verdict, expected Verdict) bool {
	return received.Allowed == expected.Allowed &&
		received.Remaining == expected.Remaining &&
		received.ResetAt.Equal(truncatedTo(expected.ResetAt, time.Millisecond)) &&
		received.RetryAt.Equal(truncatedTo(expected.RetryAt, time.Millisecond))
}

// truncatedTo is `Math.trunc(instant / unit) * unit`, for a `time.Time`.
//
// # TOWARD ZERO, NOT DOWNWARDS, AND THE DIFFERENCE IS NOT COSMETIC
//
// `time.Time.Truncate` rounds DOWNWARDS — it floors, because it works on the duration
// since the zero time. For every instant in this file's table that is the same answer,
// because a rate-limit clock is a wall clock and 2026 is after 1970. For an instant
// before the epoch it is not, and `Math.trunc` — the operation being transcribed —
// rounds toward zero. So the floor is corrected by one unit on the negative side rather
// than relying on the year, which is the difference between transcribing the operation
// and transcribing a result of it.
func truncatedTo(instant time.Time, unit time.Duration) time.Time {
	whole := instant.Truncate(unit)
	if whole.After(instant) {
		// Only reachable on the negative side, and only when the truncation lost
		// something. One unit towards zero is the whole correction.
		return whole.Add(unit)
	}
	return whole
}

// TestTheTranscriptionIsTheScript is what stops the parity table proving a
// transcription agrees with itself.
//
// It reads `GCRALua` out of `redis.go`'s own source and checks that the transcription
// in `parity_test.go` has the same SHAPE: four returns, the same arithmetic calls, the
// same `PX` expiry on the write. It does not check the transcription line for line —
// that would be a second copy of the script in a test, which drifts in a different way
// — and it says so rather than pretending otherwise.
func TestTheTranscriptionIsTheScript(t *testing.T) {
	source := read(t, "redis.go")

	// The declaration's OWN LAST CHARACTER is the opening backtick, so the body
	// starts one past the end of the needle — and the closing backtick is the first
	// one after THAT.
	//
	// # THIS SLICED BACKWARDS FOR A LONG TIME, AND IT PANICKED RATHER THAN FAILED
	//
	//     to := strings.Index(source[from:], "`")                       // the OPENING one
	//     script := source[from+len("const GCRALua = `") : from+to]    // …which is BEFORE the start
	//
	// `from+len(needle)` is one past the opening backtick and `from+to` is AT it, so
	// the low bound was the high bound plus one and Go panicked with
	// "slice bounds out of range" — taking the rest of the package's tests with it,
	// because a panic in one test aborts the binary. It survived that long because
	// `parity_test.go` was still red on the table for unrelated reasons, and a
	// `go test` run that fails earlier in the same binary never reaches it.
	//
	// Worth naming because the failure mode is the wrong one: this test exists to
	// report that the script and its transcription have drifted, and instead of
	// reporting it panicked, which is a smaller claim ("something is broken") dressed
	// as a bigger one. `t.Fatal` on an unparseable script is the shape this wants.
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

	// The four things a transcription that has drifted would get wrong, and the
	// reason each is in the list.
	for _, must := range []struct{ what, text string }{
		{"one key, not the whole namespace", "KEYS[1]"},
		{"the argument order limit, window, now", "local limit = tonumber(ARGV[1])"},
		{"the argument order window", "local window = tonumber(ARGV[2])"},
		{"the argument order now", "local now = tonumber(ARGV[3])"},
		// A Redis that accumulates a bucket for every client that has ever connected is
		// a memory leak with a business-sized keyspace.
		{"the self-expiring key", "'PX', window"},
		{"the ceil before the subtraction", "math.ceil((next - now) / interval)"},
		// The OLD tat on the refusal branch. Getting this wrong makes a throttled
		// client's RateLimit-Reset count down from the wrong instant.
		{"the old tat on the refusal branch", "return {0, tat, next - window, 0}"},
		{"the floor at zero remaining", "math.max(0, limit - used)"},
		// Strictly greater, so a burst of exactly `limit` lands.
		{"the strictly-greater admission test", "if delay > window then"},
	} {
		if !strings.Contains(script, must.text) {
			t.Errorf("GCRALua does not contain %s (%q). The parity table transcribes this script, so a transcription and a script that have drifted are indistinguishable from a transcription and a script that agree — and the live test is the only thing that would notice.", must.what, must.text)
		}
	}

	// And the transcription itself has to be reading the same four numbers.
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

// TestTheMemoryStoreSweepsOnlySettledBuckets is the bound on the memory store, and
// it is the case that makes `maxClients` safe rather than merely present.
//
// Evicting a bucket IN DEBT would be cheaper and would be wrong: forgetting one
// hands that caller a fresh allowance for the price of one extra request, which is the
// self-DoS a rate limiter exists to prevent.
func TestTheMemoryStoreSweepsOnlySettledBuckets(t *testing.T) {
	store, err := NewMemoryStore(2)
	if err != nil {
		t.Fatalf("NewMemoryStore(2): %v", err)
	}

	at := time.Unix(1_790_000_000, 0)
	request := Request{Limit: 5, Window: time.Minute, Now: at}

	// Two buckets in debt, and a third arrival trips the bound.
	for _, key := range []string{"a", "b"} {
		if _, err := store.Hit(key, request); err != nil {
			t.Fatalf("Hit(%q): %v", key, err)
		}
	}
	if _, err := store.Hit("c", request); err != nil {
		t.Fatalf(`Hit("c"): %v`, err)
	}

	// `a` and `b` owe quota, so the sweep that `c`'s arrival triggered dropped
	// nothing — every bucket is still in debt.
	if got := store.Size(); got != 3 {
		t.Errorf("after three in-debt arrivals the store holds %d bucket(s), want 3. The sweep must never evict a caller who owes quota.", got)
	}

	// Far enough ahead that every debt has been repaid, and one more arrival sweeps.
	later := Request{Limit: 5, Window: time.Minute, Now: at.Add(time.Hour)}
	if _, err := store.Hit("d", later); err != nil {
		t.Fatalf(`Hit("d"): %v`, err)
	}
	if got := store.Size(); got != 1 {
		t.Errorf("after the debts settled the store holds %d bucket(s), want 1 — only `d`. A bucket at `tat <= now` owes nothing, so forgetting it hands the caller exactly the allowance they had already earned.", got)
	}
}

// itoaOf is `strconv.Itoa`, under a name that says what it is for: the parity table
// compares the ARGUMENTS the store sends against the values the script reads, and
// both are integers in a test that is about integers.
func itoaOf(n int) string { return strconv.Itoa(n) }
