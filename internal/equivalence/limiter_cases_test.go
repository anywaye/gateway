// The limiter's cases and the tests that hold its two decisions in place.
//
// Split out of the equivalence harness this package used to be, because the
// limiter's REFUSAL and its store-down behavior are properties of the Go gateway
// and not of any comparison, and because a reader looking for what the limiter is
// held down by should not have to read a comparison they can no longer run.
//
// # WHAT IS ASKED, AND AGAINST WHAT
//
// There is nothing to compare against any more: the TypeScript reference was
// removed at the cutover and the comparison that stood it up — 51 cases, 13
// scenarios, 914 comparisons, 0 differences, recorded in `CHANGELOG.md` — cannot
// be repeated. So each case below carries its EXPECTED ANSWER, and the property
// being held down is the one that outlived the reference: the limiter counts the
// traffic the route table claims, it announces the allowance it spent, it does not
// spend a request twice, and it fails OPEN when the counter store is unreachable.
//
// Those are the assertions. A case whose expected answer is derived from what the
// code currently does would be a tautology, and the expected statuses below are
// literals for exactly that reason.
//
// # WHY THE BURST'S FIRST ANSWER IS ASKED AND NOT ONLY ITS LAST
//
// GCRA spends the allowance continuously, so a burst that overspends by two
// reaches the same refusal as one that overspends by none: same status, same
// `RateLimit-Remaining: 0`, same `Retry-After`. A gateway that admitted four
// requests where three were allowed would therefore agree on the refusal and
// differ only in the `RateLimit-Remaining` the admission reported. So both ends of
// the burst are asked and the middle is not.
package equivalence

import (
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cafaye/gateway/internal/ratelimit"
)

// generatedRegistration matches every route the generated document registers, so
// the assertions above are asked against the contract's own routing table rather
// than a list of paths typed here. The pattern is `contractCases`'s old one, kept
// because the one thing it has to be is a pattern that FINDS registrations —
// `internal/api/stripbaseurl` exists to remove the `options.BaseURL+` token that
// made chi's recogniser skip them, and a pattern that matched nothing here would
// make every "the router registered it" assertion vacuous.
var generatedRegistration = regexp.MustCompile(`(?m)^\s*r\.(Get|Post|Put|Patch|Delete|Head)\("([^"]+)"`)

// limiterCases are the cases that reach the limiter's two decisions.
//
// Each is asked under ONE scenario rather than both, and the split is the point:
// the refusal case must land inside the allowance in one and outside it in the
// other for the answers to be distinguishable, and only `limitsExhausted` has an
// allowance that small. Asking the refusal case under `counterStoreDown` would ask
// the same request twice and call the agreement coverage of a refusal.
//
// # ONE OF THESE PATHS IS CLAIMED BY THE ROUTE TABLE, AND THAT USED TO BE THE FINDING
//
// The refusal is asked on `/v1/unknown`, `POST /auth/login` and
// `/v1/pantry/items`. The first two no route table claims; the third one is
// forwarded to a service, and asking it here is what caught the defect this packet
// closes: the Go gateway's limiter was a chi `Use` INSIDE the router while the
// pass-through wrapped the router from outside, so a path the table claims never
// reached it and was relayed uncounted. The TypeScript original registered
// `app.use("*", limiter)` before `app.use("/v1/*", proxy)` and counted it.
//
// It was held in place by `TestTheGoSideDoesNotCountRoutedTraffic` rather than
// fixed, so this case could be added here instead of forgotten. A routed refusal
// asked like every other case is where a fixed divergence belongs: a test that
// keeps naming a closed bug outlives its reason.
//
// Each case is asked under a gateway of its own, so the allowance is spent by this
// case rather than inherited from the one before it. A shared bucket would make the
// order of this table load-bearing, and a reader could not tell which case spent
// what.
func limiterCases() []caseSpec {
	relayed := map[string]string{"Accept": "application/json"}

	return []caseSpec{
		// The crossing. One case, four answers, asked at both ends.
		//
		// `404` first and `429` last: with the clock frozen at an allowance of three
		// per minute, requests 1..3 are served — and an unrouted path is answered by
		// gateway itself, so served means the v0 `404` envelope rather than a `200`.
		// The fourth is refused. The status is deliberately not the interesting half
		// of this case; the announced remaining is, and it is asked below.
		{name: "a burst that spends the allowance", method: http.MethodGet, path: "/v1/unknown",
			headers: relayed, scenarios: []string{ScenarioLimitsExhausted},
			burst: equivalenceLimit + 1,
			want:  limiterWant{first: http.StatusNotFound, last: http.StatusTooManyRequests, remaining: "2", counted: true}},

		// The same burst on a different prefix, because a deployment gives `/auth/`
		// its own policy and a limiter that counted one prefix and not another would
		// satisfy the first case and fail this one. The answer is a `404` on the
		// admitted request rather than a login: this scenario mounts no browser
		// surface.
		{name: "a burst against the auth prefix", method: http.MethodPost, path: "/auth/login",
			headers: relayed, scenarios: []string{ScenarioLimitsExhausted},
			burst: equivalenceLimit + 1,
			want:  limiterWant{first: http.StatusNotFound, last: http.StatusTooManyRequests, remaining: "2", counted: true}},

		// The routed one, and the case this table did not have. `/v1/pantry/items`
		// is claimed by the table, so the burst spends the allowance and the refused
		// request must not reach the upstream.
		{name: "a burst on a routed path", method: http.MethodGet, path: "/v1/pantry/items",
			headers: relayed, scenarios: []string{ScenarioLimitsExhausted},
			burst: equivalenceLimit + 1,
			want:  limiterWant{first: http.StatusOK, last: http.StatusTooManyRequests, remaining: "2", counted: true, upstream: equivalenceLimit}},

		// And the fail-open case, which is the same shape of request under the store
		// that cannot be reached. Served, uncounted, and with NO rate-limit headers
		// at all — a header guessed at would be a promise the gateway is not
		// keeping, and `AGENTS.md` names the absence as the requirement rather than
		// an omission.
		//
		// It is on a routed path deliberately: a fail-open decision asked only on
		// paths the router answers is a decision that would look identical if the
		// limiter were never reached at all, which is what the routed refusal above
		// rules out.
		{name: "a request the limiter could not count", method: http.MethodGet, path: "/v1/pantry/items",
			headers: relayed, scenarios: []string{ScenarioCounterStoreDown},
			burst: equivalenceLimit + 1,
			want:  limiterWant{first: http.StatusOK, last: http.StatusOK, counted: false, upstream: equivalenceLimit + 1}},
	}
}

// TestTheLimiterAnswersWhatEachCaseSaysItAnswers is the table, driven.
//
// Every case gets a gateway of its own and its own recording upstream, and both
// ends of the burst are checked: the status, the announced remaining on the first
// request, the presence of the rate-limit family, and how many requests reached
// the service. `t.Run` per case so a failure names the case rather than the table.
//
// The upstream count is the half a status cannot see, and it is asserted rather
// than inferred from a refusal: a refusal that still spends an upstream call is a
// limiter mounted after the pass-through rather than in front of it.
func TestTheLimiterAnswersWhatEachCaseSaysItAnswers(t *testing.T) {
	for _, spec := range limiterCases() {
		for _, scenario := range spec.scenarios {
			t.Run(scenario+"/"+spec.name, func(t *testing.T) {
				service := startUpstream(t)

				options, err := optionsFor(scenario, service.Origin())
				if err != nil {
					t.Fatalf("%v", err)
				}
				base := newGateway(t, options)

				first, last := askBurst(t, base, spec)

				if first.status != spec.want.first {
					t.Errorf("the first request of the burst answered %d and the case says %d. With the clock frozen this is a function of the allowance alone, so a different status is the gateway refusing earlier or later than its own limit says it does.", first.status, spec.want.first)
				}
				if last.status != spec.want.last {
					t.Errorf("the last request of the burst answered %d and the case says %d. GCRA spends the allowance continuously, so a burst that overspends reaches the same refusal as one that does not — which is why this case is also asked about the FIRST answer above.", last.status, spec.want.last)
				}

				// The announced remaining, on the FIRST request: the only place a
				// gateway that counts a request a different number of times is
				// visible, because the refusal announces the same zero either way.
				if got := first.headers.Get("RateLimit-Remaining"); got != spec.want.remaining {
					t.Errorf("the first request of the burst announced RateLimit-Remaining %q and the case says %q. A limiter mounted in BOTH places — on the router and around the pass-through — refuses at the same request and announces the same zero, and differs only here.", got, spec.want.remaining)
				}

				// The family's presence on the ADMITTED request. `Retry-After` is
				// deliberately not in this loop: it is an instruction set only on a
				// refusal rather than a statement about the allowance, so its absence
				// from a `200` is correct and asserting otherwise would fail on a
				// gateway that is behaving properly.
				for _, header := range ratelimit.RateLimitHeaders {
					wrote := first.headers.Get(header) != ""
					if wrote != spec.want.counted {
						t.Errorf("the first request of the burst %s %s and the case says the family is %s. The headers are left off rather than guessed at when the counter store cannot be reached, and announced when it can.",
							presence(wrote), header, presence(spec.want.counted))
					}
				}
				if spec.want.last == http.StatusTooManyRequests && last.headers.Get("Retry-After") == "" {
					t.Errorf("the refusal carries no Retry-After, and it is the one header on the 429 whose absence changes what a client does next")
				}

				// And how far the burst reached the service.
				if relayed := service.count(); relayed != spec.want.upstream {
					t.Errorf("the upstream received %d request(s) and the case says %d. A request the limiter refuses must not be spent on the service, and a fail-open request must be relayed in full.", relayed, spec.want.upstream)
				}

				// # THE REASON MUST NOT REACH THE CALLER
				//
				// Only under the store-down scenario, because that is the only one
				// where the store and its probe both fail with a message carrying a
				// host and a credential — and both sides log it, which is the design:
				// `ratelimit.failedOpen`'s own comment says so. What must not happen is
				// the message reaching a response body, and this is the harder case for
				// it because a `200` is a body the caller reads. A fail-open path that
				// appended "redis is down" to a served answer would be a leak dressed
				// as helpfulness.
				//
				// This was checked on BOTH answers of the burst on each side, and it is
				// asked against a FORBIDDEN-SUBSTRING list rather than compared between
				// two implementations: agreement is not the property here, and two
				// implementations leaking the same secret would satisfy a comparison.
				//
				// The `/readyz` body is asked too, because that is the one place a
				// reason is SUPPOSED to reach an unauthenticated caller as a dependency
				// name, and "named `redis`" is only a redaction if the host and the
				// credential are not in it as well.
				if scenario == ScenarioCounterStoreDown {
					for _, which := range []struct {
						label string
						body  string
					}{
						{"the admitted response", first.body},
						{"the last response of the burst", last.body},
						{"/readyz", ask(t, base, caseSpec{method: http.MethodGet, path: "/readyz"}).body},
					} {
						for _, part := range thePartsOfTheReasonNeitherSideMayEcho {
							if strings.Contains(which.body, part) {
								t.Errorf("%s carries %q, which is part of the counter store's failure. The reason goes to the log; a caller gets nothing.", which.label, part)
							}
						}
					}
				}
			})
		}
	}
}

// TestTheGoSideCountsRoutedTraffic is the finding, INVERTED, and it is still here
// because it is the one test that would catch the mount moving again.
//
// This test used to be named `TestTheGoSideDoesNotCountRoutedTraffic` and asserted
// the defect, because a divergence that is only described gets closed by the next
// reader's assumption. It failed the moment the mount was fixed, which was the
// signal to replace it rather than adjust it.
//
// What it measured then, with both limiters frozen at 2026-01-01T00:00:00Z and an
// allowance of three per minute:
//
//	GET /v1/pantry/items   typescript 429 + the rate-limit family
//	                       go         200 + no rate-limit headers at all
//
// The cause was the mount order: the limiter was a chi `Use` INSIDE the router and
// the pass-through wrapped the router, so traffic the table claims never reached
// it. Two comments in the TypeScript original said gateway counted it, and the Go
// port contradicted both. Both sides of that comparison are gone; the property is
// not, so the test now asks the Go gateway directly and asserts the numbers the
// reference answered with.
//
// # WHY IT IS STILL A TEST AND NOT JUST A CASE IN `limiterCases`
//
// The routed burst is in `limiterCases` now, and this asks the same question for a
// different reason: not "does the table's own case pass" but "does the Go gateway
// COUNT it", on a request whose bucket was spent on an unrouted path. That is the
// property the whole comparison rested on and could not see on its own — a Go side
// with no limiter at all would also serve a 200 here, and a Go side whose limiter
// counted everything twice would agree on a status while spending twice the
// allowance. Both of those were measured while the mount was being fixed.
//
// So it asserts the refusal AND the announced remaining, because those two are
// different claims: a `429` says the limiter ran, and a remaining that counts down
// one per request says it ran once.
func TestTheGoSideCountsRoutedTraffic(t *testing.T) {
	service := startUpstream(t)

	options, err := optionsFor(ScenarioLimitsExhausted, service.Origin())
	if err != nil {
		t.Fatalf("%v", err)
	}
	base := newGateway(t, options)

	// The allowance is spent on a path neither route table claims, which is what
	// makes the routed answer below the limiter's decision rather than the router's.
	// The remaining is checked on every request, not just at the end: the spending
	// is the arithmetic, and the refusal's own headers cannot show it.
	spend := caseSpec{name: "spending the allowance", method: http.MethodGet, path: "/v1/unknown",
		headers: map[string]string{"Accept": "application/json"}}
	for i := 0; i < equivalenceLimit; i++ {
		want := strconv.Itoa(equivalenceLimit - i - 1)
		got := ask(t, base, spend)

		if got.headers.Get("RateLimit-Remaining") != want {
			t.Fatalf("spending the allowance, request %d: the gateway announced %q remaining and the case says %q. This path is unrouted, so both halves of this test share one bucket and the count is pure limiter arithmetic — a request counted a different number of times than once is the signature of a limiter mounted in both places.", i+1, got.headers.Get("RateLimit-Remaining"), want)
		}
		if got.status != http.StatusNotFound {
			t.Fatalf("spending the allowance, request %d: the gateway answered %d on an unrouted path with allowance left. A path no table claims is answered by gateway itself with the v0 404 envelope, so this is the limiter refusing early.", i+1, got.status)
		}
	}

	routed := caseSpec{name: "a routed request", method: http.MethodGet, path: "/v1/pantry/items",
		headers: map[string]string{"Accept": "application/json"}}
	got := ask(t, base, routed)

	// The refusal, and not "no headers". A `200` with none was the defect's shape;
	// the fixed direction is the opposite assertion, because a limiter that ran
	// announces the bucket it spent. A `200` with headers on it is a limiter
	// working and something else refusing, which is a different defect and would
	// pass a bare status check.
	if got.status != http.StatusTooManyRequests {
		t.Fatalf("the Go gateway answered %d on a ROUTED request whose bucket was spent by the requests above, so it is not counting routed traffic. The limiter is mounted around the pass-through (`httpapi.New`, `everyRequest`) and a path the route table claims is answered by that pass-through — read `everyRequest`'s comment before changing the mount.", got.status)
	}

	// And the announced remaining, which is the half a status cannot see. A gateway
	// whose limiter counted this request TWICE would refuse here exactly as a
	// correct one does and differ only in this number. That is not hypothetical:
	// mounting the limiter in both places did precisely this during the fix.
	if want := "0"; got.headers.Get("RateLimit-Remaining") != want {
		t.Errorf("on a routed request the gateway wrote RateLimit-Remaining: %q and the exhausted bucket should announce %q. The refusal agrees, so this is the limiter counting routed traffic a different number of times than once — the signature of a limiter mounted in both places.", got.headers.Get("RateLimit-Remaining"), want)
	}
	for _, header := range headerValuesComparedByValue {
		if got.headers.Get(header) == "" {
			t.Errorf("on a routed request the gateway wrote no %s. The refusal is what a client reads to decide when to come back, and a refusal missing half its family is a client told to guess.", header)
		}
	}

	// And the upstream, which is the consequence rather than the arithmetic. The
	// requests above spent the bucket on a path no table claims; a routed request
	// that is refused must not reach the service, because a relayed 4th request is
	// an upstream call this gateway just decided not to make.
	if answer, reached := service.take(t); reached {
		t.Errorf("the Go gateway reached the upstream with %s %s while refusing the same request. A refusal that still spends an upstream call is a limiter mounted after the pass-through rather than in front of it.", answer.Method, answer.Path)
	}

	// The evidence is printed, not just asserted, because a reader who arrives at
	// this test to check that routed traffic is counted should not have to add a
	// print to find out — and a property that is only visible in a `t.Logf` on a
	// passing run is one that gets lost the first time someone filters test output.
	t.Logf("ROUTED TRAFFIC IS COUNTED: a routed request against an allowance spent on an unrouted path is refused %d, announces RateLimit-Remaining 0 and all %d rate-limit headers, and the upstream was not contacted.", got.status, len(headerValuesComparedByValue))
}

// TestTheClockTheLimiterReadsIsTheOneTheFixtureClaims is the fixture check.
//
// The limiter reads a FIXED instant, because `RateLimit-Reset` and `Retry-After`
// are functions of it and a live clock makes every case above a race against
// `time.Now()` rather than a statement about the gateway. The literal used to be
// held equal to the reference's own `FIXED_NOW_MS` by reading that file; both
// files are gone, so what is asserted now is the half that is still checkable: the
// constant is the instant every comment in this package claims it is.
//
// That is a smaller claim than the one it replaced and it is not the same one. A
// drift between two languages showed up as a difference in `RateLimit-Reset` that
// read like a port defect; a drift from the documented instant now shows up as this
// test failing, which is a worse place for it to show up and a better one to read.
func TestTheClockTheLimiterReadsIsTheOneTheFixtureClaims(t *testing.T) {
	// The instant every comment in this package names, so neither the constant nor
	// the comments can move without this going red. 2026-01-01T00:00:00Z.
	if got := equivalenceNow().UTC().Format(time.RFC3339); got != "2026-01-01T00:00:00Z" {
		t.Errorf("equivalenceNow is %s and this package's comments say 2026-01-01T00:00:00Z. The frozen clock is what makes a case's expected status a function of the request count rather than of the wall clock, so a moved constant makes every answer above stop meaning what it says.", got)
	}
	if equivalenceWindow != time.Minute {
		t.Errorf("equivalenceWindow is %v and the allowance is documented as three per minute. The limiter spends its allowance at the window's rate, so a different one moves the crossing onto a different request.", equivalenceWindow)
	}
	if equivalenceLimit != 3 {
		t.Errorf("equivalenceLimit is %d and the fixture is documented as three. The bursts above are limit+1, so this must match or they stop crossing.", equivalenceLimit)
	}
}

// TestTheInventoryIsEveryScenarioDeclaredAndNothingTwice is the count.
//
// The scenario count is asserted rather than left to a summary line, and that is
// the whole reason `inventorySize` exists: a summary that reads its own count from
// `len(scenarios)` cannot report a number the runner did not drive, and a
// hand-maintained literal is a number that goes stale the moment a packet adds a
// scenario and forgets it. Both have happened here — the eleven this package's
// comment used to name were the union of two packets that each edited the list
// without seeing the other.
//
// It used to be a comparison between this list and the reference's. There is no
// other list to compare with, so the half that remains is the half about THIS
// list: nothing declared twice, and the count the comments state.
func TestTheInventoryIsEveryScenarioDeclaredAndNothingTwice(t *testing.T) {
	if len(scenarios) != inventorySize {
		t.Errorf("scenarios holds %d names and inventorySize says %d. The two cannot both be right and one of them is a number somebody typed.", len(scenarios), inventorySize)
	}

	// And no name twice: a duplicated scenario would be configured and driven twice,
	// which is the over-reporting the counted total exists to prevent.
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
		t.Errorf("scenario(s) %v are in the inventory more than once, so the run drives them twice and reports more work than it did", twice)
	}

	// And every declared name is one `optionsFor` can actually build, which is the
	// property that made the other list worth holding equal: a scenario in the
	// inventory with no configuration behind it is a scenario that compared nothing
	// and reported green.
	for _, name := range scenarios {
		if _, err := optionsFor(name, "http://upstream.test"); err != nil {
			t.Errorf("scenarios declares %q and optionsFor cannot build it: %v. Every name in the inventory is a configuration, not a label.", name, err)
		}
	}
}

// presence renders a header's presence for a failure message, and says "absent"
// rather than an empty string so a message cannot be read as the header carrying
// nothing at all.
func presence(written bool) string {
	if written {
		return "present"
	}
	return "absent"
}

// declaredAuthOperationsExist is here rather than in the harness because it is the
// one thing about the browser surface the surviving limiter cases depend on: the
// `/auth` routes are registered, which is why `POST /auth/login` answers `404`
// with no browser surface configured rather than being unrouted traffic of a
// different shape.
//
// Kept as a real assertion rather than folded into a case: a `404` is what an
// unrouted path answers too, so a case that expected `404` would be satisfied by a
// gateway that had lost the browser surface entirely.
func TestTheAuthPrefixIsRegisteredSoItsRefusalIsTheRouters(t *testing.T) {
	source, err := os.ReadFile(filepath.Join("..", "api", "api.gen.go"))
	if err != nil {
		t.Fatalf("cannot read internal/api/api.gen.go: %v", err)
	}

	var registered []string
	for _, match := range generatedRegistration.FindAllStringSubmatch(string(source), -1) {
		if strings.HasPrefix(match[2], "/auth/") {
			registered = append(registered, strings.ToUpper(match[1])+" "+match[2])
		}
	}

	if len(registered) == 0 {
		t.Fatalf("read no /auth operation out of internal/api/api.gen.go, so the browser surface is not registered on either side of this assertion and the `404` a limiter case expects on /auth/login cannot be told from a path nobody claims")
	}

	for _, route := range registered {
		t.Logf("/auth route registered: %s", route)
	}
}
