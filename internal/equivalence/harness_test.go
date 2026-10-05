// The request driver the surviving limiter tests share: one case, one answer.
//
// # WHAT SURVIVED HERE AND WHY, AND IT IS NOT THE HARNESS
//
// This package used to stand `test/equivalence/reference.ts` up as a subprocess
// and compare every answer byte for byte. That question is answered — 51 cases, 13
// scenarios, 914 comparisons, 0 differences, recorded in `CHANGELOG.md` — and the
// TypeScript side was removed at the cutover, so the question is no longer
// askable. Everything in this file that existed only to *compare two processes*
// is gone with it.
//
// What is left is the Go side, asked directly: `caseSpec`, `answer`, `ask` and
// `askBurst`. They are here because the limiter's refusal, its announced
// remaining and its fail-open answer are properties of the Go gateway that a
// comparison was never the only way to assert — and the tripwire for the defect
// the comparison found (a routed path the limiter never counted) is one of them.
//
// A reader who came here for the comparison should read `CHANGELOG.md` for what it
// found, and this file for what still holds the port down.
package equivalence

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cafaye/gateway/internal/httpapi"
)

// How long one request gets to answer. Bounded rather than retried: an unbounded
// wait in a test suite is a run that hangs until the job timeout, which is the
// failure mode `AGENTS.md` names.
const requestTimeout = 10 * time.Second

// caseSpec is one request, asked of the Go gateway.
type caseSpec struct {
	name   string
	method string
	path   string

	// The caller's body, for the cases that send one.
	body string

	// Headers the caller sends. Present because the properties under test are
	// about what happens to a header the caller *chose* — a case that sends none
	// cannot tell a dropped header from a header that was never there.
	headers map[string]string

	// How many times this case is asked in a row. One by default.
	//
	// It is a field on the case rather than a loop in the test because a
	// limiter's REFUSAL is a property of a sequence: one request at an allowance
	// of three is served and says nothing about a crossing.
	burst int

	// The scenario this case is asked under, and the expected answer. A limiter
	// that answered identically under both scenarios would be indistinguishable
	// from one that was never mounted, so the two are told apart here rather than
	// by a flag.
	scenarios []string
	want      limiterWant
}

// runsUnder says whether a case is asked in a scenario.
func (c caseSpec) runsUnder(scenario string) bool {
	for _, name := range c.scenarios {
		if name == scenario {
			return true
		}
	}
	return false
}

// limiterWant is what the Go gateway must answer for one case.
//
// Two numbers and a count, and they are not interchangeable. `first` and `last`
// are the ends of a burst; `remaining` is the announced allowance after the FIRST
// request, which is the only place a gateway that spends a request a different
// number of times is visible — a limiter mounted both on the router and around
// the pass-through refuses at exactly the same request and announces the same
// zero, and differs only here. That was measured during the fix this package's
// tripwire now holds down.
type limiterWant struct {
	first int
	last  int

	// The `RateLimit-Remaining` on the first request, and whether the rate-limit
	// family is announced at all. Empty and false under a counter store that
	// cannot be reached: the gateway fails OPEN, and a header it guessed at would
	// be a promise it is not keeping.
	remaining string
	counted   bool

	// How many requests the upstream must have been asked for across the burst.
	// The refusal itself must not reach the service: a relayed request the gateway
	// has just decided not to make is an upstream call that should not have
	// happened.
	upstream int
}

// answer is what the gateway said.
type answer struct {
	status  int
	headers http.Header
	body    string
}

// askBurst drives one case `spec.burst` times in a row and returns the FIRST
// answer and the LAST one.
//
// First and last, and not the middle: the two properties that matter are at the
// ends — the first shows the allowance as it was, the last shows what the limiter
// did with it — and the last is only reachable through the ones before it.
//
// A case with no burst is asked once and returns that one answer as both, which is
// the single-request shape every other assertion here has.
func askBurst(t *testing.T, base string, spec caseSpec) (answer, answer) {
	t.Helper()

	rounds := spec.burst
	if rounds < 1 {
		rounds = 1
	}

	first := ask(t, base, spec)
	last := first
	for round := 1; round < rounds; round++ {
		last = ask(t, base, spec)
	}
	return first, last
}

// ask drives one request at a base URL and reads the whole answer.
func ask(t *testing.T, base string, spec caseSpec) answer {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()

	var reader io.Reader
	if spec.body != "" {
		reader = strings.NewReader(spec.body)
	}
	req, err := http.NewRequestWithContext(ctx, spec.method, base+spec.path, reader)
	if err != nil {
		t.Fatalf("%s %s is not a request this check can build: %v", spec.method, spec.path, err)
	}
	if spec.body != "" {
		req.Header.Set("Content-Type", "application/json")
		req.ContentLength = int64(len(spec.body))
	}
	for name, value := range spec.headers {
		req.Header.Set(name, value)
	}

	// The client follows nothing: a redirect is a difference between two servers
	// and this check exists to find differences, not to normalise them away.
	client := &http.Client{
		Timeout: requestTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	res, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s did not answer: %v", spec.method, spec.path, err)
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("%s %s: reading the body failed: %v", spec.method, spec.path, err)
	}

	return answer{status: res.StatusCode, headers: res.Header.Clone(), body: string(body)}
}

// mustHandler builds the handler `cmd/gateway` serves, or fails with the
// configuration that refused it.
func mustHandler(t *testing.T, options httpapi.Options) http.Handler {
	t.Helper()

	handler, err := httpapi.New(options)
	if err != nil {
		t.Fatalf("httpapi.New refused the %+v configuration: %v", options, err)
	}
	return handler
}

// newGateway stands one Go gateway in process, configured by `options`, and
// returns its base URL.
//
// In process rather than as a built binary: the thing under test is the handler
// `New` returns, which is also what `cmd/gateway` serves.
func newGateway(t *testing.T, options httpapi.Options) string {
	t.Helper()

	server := httptest.NewServer(mustHandler(t, options))
	t.Cleanup(server.Close)
	return server.URL
}
