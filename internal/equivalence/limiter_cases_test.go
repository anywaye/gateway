// The limiter's cases and the two checks that hold this packet's coverage in
// place.
//
// Split out of `equivalence_test.go` because this is the packet's whole subject —
// the limiter's REFUSAL and its store-down behaviour, which nothing compared
// before — and because a reader looking for what the limiter is compared against
// should not have to read a 1400-line file to find out.
//
// # WHAT IS COMPARED, AND IT IS NOT ONLY THE STATUS
//
// `limitsExhausted` compares the status, the problem body byte for byte, and the
// rate-limit headers on the refusal — a 429 that omits `Retry-After`, or carries a
// stale `RateLimit-Reset`, tells a client something different from one that does
// not. The header VALUES are compared through `headerValuesComparedByValue`; the
// rest of the harness compares presence only.
//
// # WHY THE BURST'S FIRST ANSWER IS COMPARED AND NOT ONLY ITS LAST
//
// GCRA spends the allowance continuously, so a burst that overspends by two reaches
// the same refusal as one that overspends by none: same status, same
// `RateLimit-Remaining: 0`, same `Retry-After`. A port that admitted four requests
// where the reference admitted three would therefore agree on the refusal and
// differ only on the way there, in the `RateLimit-Remaining` the admission
// reported. So both ends of the burst are compared and the middle is not.
package equivalence

import (
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// limiterCases are the cases that reach the limiter's two decisions.
//
// Each is asked under ONE scenario rather than both, and the split is the point:
// the refusal case must land inside the allowance on the reference and outside it
// on the Go side for a comparison to mean anything, and only `limitsExhausted`
// has an allowance that small. Asking the refusal case under `counterStoreDown`
// would compare two `200`s — which is the fail-open decision being compared, but
// through the wrong case, and a reader would have to work out which.
//
// # THE PATHS ARE NOT ROUTED, AND THAT IS A FINDING RATHER THAN A CHOICE
//
// The refusal is compared on `/v1/unknown` and `POST /auth/login`, neither of
// which any route table claims, because the Go gateway's limiter is a chi `Use`
// middleware INSIDE the router while the pass-through wraps the router from
// outside (`httpapi.New`: `credentialGate → pass-through → router`). Routed
// traffic therefore never reaches the limiter on the Go side, where on the
// reference `app.use("*", limiter)` is registered before `app.use("/v1/*", proxy)`
// and counts it.
//
// That divergence is not walked past: `TestTheGoSideDoesNotCountRoutedTraffic` asks
// the routed burst directly and holds the difference in place, so the case can be
// moved here when it is fixed rather than forgotten here.
//
// The burst is `limit + 1` and not `limit`, because the last request is the one
// that crosses: with the clock frozen, requests 1..3 are served and the fourth is
// refused.
func limiterCases() []caseSpec {
	relayed := map[string]string{"Accept": "application/json"}

	return []caseSpec{
		// The crossing. One case, four answers, compared at both ends.
		{name: "a burst that spends the allowance", method: http.MethodGet, path: "/v1/unknown",
			headers: relayed, scenarios: []string{ScenarioLimitsExhausted}, burst: equivalenceLimit + 1},

		// The same burst on a different prefix, because a deployment gives `/auth/`
		// its own policy and a limiter that counted one prefix and not another
		// would satisfy the first case and fail this one. The answer is a `404`
		// rather than a login: this scenario mounts no browser surface.
		{name: "a burst against the auth prefix", method: http.MethodPost, path: "/auth/login",
			headers: relayed, scenarios: []string{ScenarioLimitsExhausted}, burst: equivalenceLimit + 1},

		// And the fail-open case, which is the same shape of request under the store
		// that cannot be reached. Compared under this scenario only, so "served" is
		// an answer here rather than an absence of a comparison.
		//
		// This one IS routed, and it agrees on both sides precisely because neither
		// side can count a request it cannot reach: the reference fails open and the
		// Go gateway never gets as far as its limiter. Two implementations reaching
		// the same answer by different routes is the shape a green comparison can
		// hide, so it is said here rather than left to be discovered.
		{name: "a request the limiter could not count", method: http.MethodGet, path: "/v1/pantry/items",
			headers: relayed, scenarios: []string{ScenarioCounterStoreDown}, burst: equivalenceLimit + 1},
	}
}

// TestTheGoSideDoesNotCountRoutedTraffic is the finding, held in place.
//
// Measured on this tree, with both sides frozen at 2026-01-01T00:00:00Z and an
// allowance of three per minute:
//
//	GET /v1/pantry/items   typescript 429 + the rate-limit family
//	                       go         200 + no rate-limit headers at all
//
// The reference counts routed traffic and the Go gateway does not, and the reason
// is the mount order `httpapi.New` documents as deliberate: the limiter is a chi
// `Use` middleware inside the router, and the pass-through wraps the router, so
// traffic the table claims never reaches it. The reference registers
// `app.use("*", limiter)` BEFORE `app.use("/v1/*", proxy)` and therefore counts
// it — which is what `src/routes/table.ts`'s own comment claims gateway does
// ("the limiter still counts the traffic") and what `src/index.ts`'s does ("an
// anonymous request still spends the `gateway-api` bucket").
//
// This is a real gap and not a documentation disagreement: an edge whose limiter
// does not run on forwarded traffic is not limiting the traffic that costs it
// money. It is reported rather than fixed here, and the reason is in its own
// section below.
//
// # WHY IT IS A TEST AND NOT A NOTE
//
// As a note, the next reader believes the comparison covers routed traffic and the
// coverage list in `equivalence_test.go`'s own comment stays wrong. As a test it is
// a difference that CANNOT be forgotten and cannot be silently closed: this fails
// the moment the Go side starts counting, at which point the answer is no longer
// a finding but a fix, and the routed burst moves into `limiterCases` to be
// compared like every other case.
//
// # WHY IT IS NOT FIXED HERE
//
// The obvious fix — move the limiter out of the router and wrap the pass-through
// with it — moves the position of the credential gate relative to the limiter. On
// the reference the `/v1/*` verifier runs BEFORE the limiter; here it is a chi
// middleware that would end up after it, so a request carrying a token that does
// not verify would start being counted, which is the one thing `AGENTS.md` says
// about the ordering: "a token that does not verify is answered 401 and counted
// against nothing."
//
// So fixing this moves the gate too, and that is a change to the order of the
// whole chain in `internal/httpapi` with its own suite to keep honest. It belongs
// to the packet that owns that chain, not to one whose job was to make two
// scenarios reachable.
func TestTheGoSideDoesNotCountRoutedTraffic(t *testing.T) {
	bun, err := exec.LookPath("bun")
	if err != nil {
		skipOrFail(t, "bun is not on PATH, so the TypeScript reference cannot be stood up")
	}

	service := startUpstream(t)

	options, err := optionsFor(ScenarioLimitsExhausted, service.Origin())
	if err != nil {
		t.Fatalf("%v", err)
	}
	referenceURL, stop := standUpReference(t, bun, ScenarioLimitsExhausted, service.Origin())
	defer stop()

	goServer := httptest.NewServer(mustHandler(t, options))
	defer goServer.Close()

	// The routed request is asked against an ALREADY-SPENT allowance: both sides
	// are exhausted on a path neither route table claims first, which is what makes
	// the answer the limiter's decision rather than the router's.
	spend := caseSpec{name: "spending the allowance", method: http.MethodGet, path: "/v1/unknown",
		headers: map[string]string{"Accept": "application/json"}}
	for i := 0; i < equivalenceLimit; i++ {
		ask(t, referenceURL, spend)
	}
	service.take(t)
	for i := 0; i < equivalenceLimit; i++ {
		ask(t, goServer.URL, spend)
	}
	service.take(t)

	routed := caseSpec{name: "a routed request", method: http.MethodGet, path: "/v1/pantry/items",
		headers: map[string]string{"Accept": "application/json"}}
	referenceAnswer := ask(t, referenceURL, routed)
	service.take(t)
	goAnswer := ask(t, goServer.URL, routed)
	service.take(t)

	if referenceAnswer.status != http.StatusTooManyRequests {
		t.Fatalf("the reference answered %d on a routed request with an exhausted bucket, so it is not exhibiting the finding this test holds and the test cannot see it. Ask the reference standalone to find out why.", referenceAnswer.status)
	}
	if goAnswer.status != http.StatusOK {
		t.Fatalf("the Go gateway answered %d on a ROUTED request with an exhausted bucket. It is counting routed traffic now, which RESOLVES the finding: move the routed burst in `limiterCases` so it is compared like every other case, and delete this test.", goAnswer.status)
	}

	// "No headers" alone could be a limiter that answered without announcing, and a
	// 200 WITH headers would be a limiter working. Both halves of the shape, read
	// off the same list the comparison above uses.
	for _, header := range headerValuesComparedByValue {
		if value := goAnswer.headers.Get(header); value != "" {
			t.Errorf("the Go gateway wrote %s: %q on a routed request, so it is announcing a bucket it is not counting. The finding's shape has changed and this test should say so rather than keep passing.", header, value)
		}
	}

	// The evidence is printed, not just asserted, because a reader who arrives at this
	// test to check whether the finding still holds should not have to add a print to
	// find out — and a finding that is only visible in a `t.Logf` on a passing run is
	// a finding that gets lost the first time someone filters test output.
	t.Logf("FINDING HELD: the reference refuses routed traffic (%d, rate-limit headers written) and the Go gateway serves it (%d, none written). Reported, not fixed — see this test's comment.", referenceAnswer.status, goAnswer.status)
}

// TestTheReferenceAndTheGoSideReadTheSameFrozenClock holds the fixture the whole
// comparison rests on.
//
// Both limiters read a FIXED instant, because `RateLimit-Reset` and `Retry-After`
// are functions of it and a live clock makes this a race between two `Date.now()`
// calls rather than a comparison of two implementations. The two literals live in
// two languages that cannot see each other — `FIXED_NOW_MS` in
// `test/equivalence/reference.ts` and `equivalenceNowMillis` here — so they are
// the one number in this package that can silently drift, and a drift shows up as
// a difference in `X-RateLimit-Reset` that reads like a port defect.
//
// So it is asserted from the reference's own source, with a floor under it: the
// literal must be there, must be the same integer, and must be the instant both
// sides' comments claim — which is what makes the assertion about the two sides
// agreeing rather than about one of them matching a number I typed twice.
func TestTheReferenceAndTheGoSideReadTheSameFrozenClock(t *testing.T) {
	source, err := os.ReadFile(filepath.Join("..", "..", "test", "equivalence", "reference.ts"))
	if err != nil {
		t.Fatalf("cannot read test/equivalence/reference.ts: %v", err)
	}

	const declaration = "const FIXED_NOW_MS = 1_767_225_600_000;"
	if !strings.Contains(string(source), declaration) {
		t.Fatalf("test/equivalence/reference.ts does not declare `%s`, so its limiter reads a clock this side cannot match and every rate-limit header in the comparison is a difference about the fixture. Read its FIXED_NOW_MS and set equivalenceNowMillis to the same instant.", declaration)
	}

	// And the instant both comments name, so neither side can be moved without
	// this going red. 2026-01-01T00:00:00Z.
	if got := equivalenceNow().UTC().Format(time.RFC3339); got != "2026-01-01T00:00:00Z" {
		t.Errorf("equivalenceNow is %s and both files' comments say 2026-01-01T00:00:00Z. One of them is now lying about the fixture.", got)
	}
	if equivalenceWindow != time.Minute {
		t.Errorf("equivalenceWindow is %v and the reference declares 60_000ms. The two limiters must spend their allowance at the same rate or the crossing happens on a different request.", equivalenceWindow)
	}
	if equivalenceLimit != 3 {
		t.Errorf("equivalenceLimit is %d and the reference declares 3. The burst in `limiterCases` is limit+1, so this must match or the burst stops crossing.", equivalenceLimit)
	}
}

// TestTheInventoryIsEveryScenarioBothSidesDeclareAndNothingTwice is the count.
//
// The scenario count is asserted rather than left to the summary line, and that is
// the whole reason `inventorySize` exists in `scenarios.go`: a summary that reads
// its own count from `len(scenarios)` cannot report a number the runner did not
// drive, and a hand-maintained literal is a number that goes stale the moment a
// packet adds a scenario and forgets it. Both have happened here — the eleven this
// package's comment used to name were the union of two packets that each edited
// the list without seeing the other.
func TestTheInventoryIsEveryScenarioBothSidesDeclareAndNothingTwice(t *testing.T) {
	if len(scenarios) != inventorySize {
		t.Errorf("scenarios holds %d names and inventorySize says %d. The summary line prints len(scenarios), so the two cannot both be right and one of them is a number somebody typed.", len(scenarios), inventorySize)
	}

	// And no name twice: a duplicated scenario drives the reference twice and
	// reports twice the comparisons that happened, which is the over-reporting the
	// counted comparison total exists to prevent.
	seen := map[string]int{}
	for _, name := range scenarios {
		seen[name]++
	}
	var twice []string
	for name, count := range seen {
		if count > 1 {
			twice = append(twice, name)
		}
	}
	if len(twice) > 0 {
		sort.Strings(twice)
		t.Errorf("scenario(s) %v are in the inventory more than once, so the run compares them twice and prints a comparison count larger than the number of comparisons made", twice)
	}
}
