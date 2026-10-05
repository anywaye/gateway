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
// # ONE OF THESE PATHS IS CLAIMED BY THE ROUTE TABLE, AND THAT USED TO BE THE FINDING
//
// The refusal is compared on `/v1/unknown`, `POST /auth/login` and
// `/v1/pantry/items`. The first two no route table claims; the third one is
// forwarded to a service, and asking it here is what caught the defect this
// packet closes: the Go gateway's limiter was a chi `Use` INSIDE the router
// while the pass-through wrapped the router from outside, so a path the table
// claims never reached it and was relayed uncounted. The reference registers
// `app.use("*", limiter)` before `app.use("/v1/*", proxy)` and counts it.
//
// It was held in place by `TestTheGoSideDoesNotCountRoutedTraffic` rather than
// fixed, so this case could be added here instead of forgotten. A routed refusal
// compared like every other case is where a fixed divergence belongs: a test
// that keeps naming a closed bug outlives its reason.
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

		// The routed one, and the case this file did not have. `/v1/pantry/items` is
		// claimed by the table, so on the reference it is spent by the limiter and
		// never reaches the upstream; on the Go side it used to be relayed with no
		// rate-limit headers at all, which is a `200` where the reference refuses.
		//
		// Asked LAST on purpose, because the allowance is one bucket per identity
		// rather than one per path: the first two cases have already spent it, so
		// this case compares a `429` the routed path spent. A case that asked it
		// first would spend the allowance ON the routed path and the two cases above
		// would then compare a `429` on a path the limiter never saw — a green that
		// reads as coverage of routed traffic while proving nothing about it.
		{name: "a burst on a routed path", method: http.MethodGet, path: "/v1/pantry/items",
			headers: relayed, scenarios: []string{ScenarioLimitsExhausted}, burst: equivalenceLimit + 1},

		// And the fail-open case, which is the same shape of request under the store
		// that cannot be reached. Compared under this scenario only, so "served" is
		// an answer here rather than an absence of a comparison.
		//
		// It is on a routed path deliberately: a fail-open decision that is compared
		// only on paths the router answers is a decision that would look identical if
		// the limiter were never reached at all, which is what the routed refusal
		// above now rules out.
		{name: "a request the limiter could not count", method: http.MethodGet, path: "/v1/pantry/items",
			headers: relayed, scenarios: []string{ScenarioCounterStoreDown}, burst: equivalenceLimit + 1},
	}
}

// TestTheGoSideCountsRoutedTraffic is the finding, INVERTED.
//
// This test used to be named `TestTheGoSideDoesNotCountRoutedTraffic` and asserted
// the defect, because a divergence that is only described gets closed by the next
// reader's assumption. It failed the moment the mount was fixed, which was the
// signal to replace it rather than adjust it.
//
// What it measured then, with both sides frozen at 2026-01-01T00:00:00Z and an
// allowance of three per minute:
//
//	GET /v1/pantry/items   typescript 429 + the rate-limit family
//	                       go         200 + no rate-limit headers at all
//
// The cause was the mount order: the limiter was a chi `Use` INSIDE the router and
// the pass-through wrapped the router, so traffic the table claims never reached
// it. The reference registers `app.use("*", limiter)` BEFORE
// `app.use("/v1/*", proxy)` and therefore counts it — which is what
// `src/routes/table.ts`'s own comment claims gateway does ("the limiter still
// counts the traffic") and what `src/index.ts`'s does ("an anonymous request still
// spends the `gateway-api` bucket"). Two comments in the reference said so, and the
// Go port contradicted both.
//
// # WHY IT IS STILL A TEST AND NOT JUST A CASE IN `limiterCases`
//
// The routed burst is in `limiterCases` now, and this asks the same question for a
// different reason: not "does the comparison agree" but "does the Go gateway COUNT
// it", on a request whose bucket was spent on an unrouted path. That is the property
// the whole comparison rests on and cannot see on its own — a Go side with no limiter
// at all would also agree with the reference on a 200, and a Go side whose limiter
// counted everything twice would agree on a status while spending twice the
// allowance. Both of those were measured here while the mount was being fixed, and
// this is the test that would catch them again.
//
// So it asserts the refusal AND the announced remaining, because those two are
// different claims: a `429` says the limiter ran, and a remaining that tracks the
// reference's says it ran once.
func TestTheGoSideCountsRoutedTraffic(t *testing.T) {
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

	// The reference refusing is the PREMISE, not the finding, and it is checked
	// because a test that cannot see the behaviour it is testing passes for the
	// wrong reason: if the reference served this request the fixture is wrong
	// (a different bucket, a different allowance) and every assertion below would
	// be vacuous.
	if referenceAnswer.status != http.StatusTooManyRequests {
		t.Fatalf("the reference answered %d on a routed request with an exhausted bucket, so the premise this test rests on does not hold and nothing below can mean anything. Ask the reference standalone to find out why.", referenceAnswer.status)
	}

	// The refusal, and not "no headers".
	//
	// The old version of this test asserted the ABSENCE of the rate-limit headers,
	// because a `200` with none was the defect's shape. The fixed direction is the
	// opposite assertion: a limiter that ran announces the bucket it spent. A `200`
	// with headers on it is a limiter working and something else refusing, which is
	// a different defect and would pass a bare status check.
	if goAnswer.status != http.StatusTooManyRequests {
		t.Fatalf("the Go gateway answered %d on a ROUTED request whose bucket was spent by the two sides above, so it is not counting routed traffic. The limiter is mounted around the pass-through (`httpapi.New`, `everyRequest`) and a path the route table claims is answered by that pass-through — read `everyRequest`'s comment before changing the mount.", goAnswer.status)
	}

	// And the announced remaining, which is the half a status cannot see. A Go side
	// whose limiter counted this request TWICE would refuse here exactly as a
	// correct one does, and would differ only in this number. That is not
	// hypothetical: mounting the limiter in both places — on the router and around
	// the pass-through — did precisely this during this packet's fix, and the
	// comparison stayed green on status alone while the two sides' arithmetic
	// parted company by one request per case.
	for _, header := range headerValuesComparedByValue {
		if want, got := referenceAnswer.headers.Get(header), goAnswer.headers.Get(header); got != want {
			t.Errorf("on a routed request the Go gateway wrote %s: %q and the reference wrote %q. The refusal agrees, so this is the limiter counting routed traffic a different number of times than the reference does — the signature of a limiter mounted in both places.", header, got, want)
		}
	}

	// And the upstream, which is the consequence rather than the arithmetic. The
	// spending case above spent three on a path no table claims; a routed request
	// that is refused must not reach the service, because a relayed 4th request is
	// an upstream call this gateway just decided not to make.
	if answer, reached := service.take(t); reached {
		t.Errorf("the Go gateway reached the upstream with %s %s while refusing the same request on the reference. A refusal that still spends an upstream call is a limiter mounted after the pass-through rather than in front of it.", answer.Method, answer.Path)
	}

	// The evidence is printed, not just asserted, because a reader who arrives at
	// this test to check that routed traffic is counted should not have to add a
	// print to find out — and a property that is only visible in a `t.Logf` on a
	// passing run is one that gets lost the first time someone filters test output.
	t.Logf("ROUTED TRAFFIC IS COUNTED: a routed request against an allowance spent on an unrouted path is refused %d on both sides, with the same %d announced headers, and the upstream was not contacted.", goAnswer.status, len(headerValuesComparedByValue))
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
