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

	"github.com/anywaye/gateway/internal/ratelimit"
)

var generatedRegistration = regexp.MustCompile(`(?m)^\s*r\.(Get|Post|Put|Patch|Delete|Head)\("([^"]+)"`)

func limiterCases() []caseSpec {
	relayed := map[string]string{"Accept": "application/json"}

	return []caseSpec{
		{name: "a burst that spends the allowance", method: http.MethodGet, path: "/v1/unknown",
			headers: relayed, scenarios: []string{ScenarioLimitsExhausted},
			burst: equivalenceLimit + 1,
			want:  limiterWant{first: http.StatusNotFound, last: http.StatusTooManyRequests, remaining: "2", counted: true}},

		{name: "a burst against the auth prefix", method: http.MethodPost, path: "/auth/login",
			headers: relayed, scenarios: []string{ScenarioLimitsExhausted},
			burst: equivalenceLimit + 1,
			want:  limiterWant{first: http.StatusNotFound, last: http.StatusTooManyRequests, remaining: "2", counted: true}},

		{name: "a burst on a routed path", method: http.MethodGet, path: "/v1/pantry/items",
			headers: relayed, scenarios: []string{ScenarioLimitsExhausted},
			burst: equivalenceLimit + 1,
			want:  limiterWant{first: http.StatusOK, last: http.StatusTooManyRequests, remaining: "2", counted: true, upstream: equivalenceLimit}},

		{name: "a request the limiter could not count", method: http.MethodGet, path: "/v1/pantry/items",
			headers: relayed, scenarios: []string{ScenarioCounterStoreDown},
			burst: equivalenceLimit + 1,
			want:  limiterWant{first: http.StatusOK, last: http.StatusOK, counted: false, upstream: equivalenceLimit + 1}},
	}
}

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

				if got := first.headers.Get("RateLimit-Remaining"); got != spec.want.remaining {
					t.Errorf("the first request of the burst announced RateLimit-Remaining %q and the case says %q. A limiter mounted in BOTH places — on the router and around the pass-through — refuses at the same request and announces the same zero, and differs only here.", got, spec.want.remaining)
				}

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

				if relayed := service.count(); relayed != spec.want.upstream {
					t.Errorf("the upstream received %d request(s) and the case says %d. A request the limiter refuses must not be spent on the service, and a fail-open request must be relayed in full.", relayed, spec.want.upstream)
				}

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

func TestTheGoSideCountsRoutedTraffic(t *testing.T) {
	service := startUpstream(t)

	options, err := optionsFor(ScenarioLimitsExhausted, service.Origin())
	if err != nil {
		t.Fatalf("%v", err)
	}
	base := newGateway(t, options)

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

	if got.status != http.StatusTooManyRequests {
		t.Fatalf("the Go gateway answered %d on a ROUTED request whose bucket was spent by the requests above, so it is not counting routed traffic. The limiter is mounted around the pass-through (`httpapi.New`, `everyRequest`) and a path the route table claims is answered by that pass-through — read `everyRequest`'s comment before changing the mount.", got.status)
	}

	if want := "0"; got.headers.Get("RateLimit-Remaining") != want {
		t.Errorf("on a routed request the gateway wrote RateLimit-Remaining: %q and the exhausted bucket should announce %q. The refusal agrees, so this is the limiter counting routed traffic a different number of times than once — the signature of a limiter mounted in both places.", got.headers.Get("RateLimit-Remaining"), want)
	}
	for _, header := range headerValuesComparedByValue {
		if got.headers.Get(header) == "" {
			t.Errorf("on a routed request the gateway wrote no %s. The refusal is what a client reads to decide when to come back, and a refusal missing half its family is a client told to guess.", header)
		}
	}

	if answer, reached := service.take(t); reached {
		t.Errorf("the Go gateway reached the upstream with %s %s while refusing the same request. A refusal that still spends an upstream call is a limiter mounted after the pass-through rather than in front of it.", answer.Method, answer.Path)
	}

	t.Logf("ROUTED TRAFFIC IS COUNTED: a routed request against an allowance spent on an unrouted path is refused %d, announces RateLimit-Remaining 0 and all %d rate-limit headers, and the upstream was not contacted.", got.status, len(headerValuesComparedByValue))
}

func TestTheClockTheLimiterReadsIsTheOneTheFixtureClaims(t *testing.T) {
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

func TestTheInventoryIsEveryScenarioDeclaredAndNothingTwice(t *testing.T) {
	if len(scenarios) != inventorySize {
		t.Errorf("scenarios holds %d names and inventorySize says %d. The two cannot both be right and one of them is a number somebody typed.", len(scenarios), inventorySize)
	}

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

	for _, name := range scenarios {
		if _, err := optionsFor(name, "http://upstream.test"); err != nil {
			t.Errorf("scenarios declares %q and optionsFor cannot build it: %v. Every name in the inventory is a configuration, not a label.", name, err)
		}
	}
}

func presence(written bool) string {
	if written {
		return "present"
	}
	return "absent"
}

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
