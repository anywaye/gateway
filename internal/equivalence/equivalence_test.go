// Package equivalence compares the Go gateway against the TypeScript one.
//
// # WHAT THIS IS
//
// The Go service is not done because it compiles. It is done when it answers the
// same as the implementation it is replacing, and the only way to know that is to
// ask both. So this package stands the TypeScript reference up as a subprocess
// (`test/equivalence/reference.ts`), builds the Go gateway in process, drives the
// same requests at both, and fails where the answers differ.
//
// The direction of every difference is fixed: **the TypeScript answer is the
// correct one.** The contract and its suite were written against it, and this
// packet's own instruction is that a suspected defect in the reference is
// reported rather than fixed here. So a divergence is a finding about the port,
// and the report is where it goes.
//
// # WHAT IS COMPARED, AND WHAT IS NOT, AND WHY
//
// ## The response: status, `Content-Type`, body BYTE FOR BYTE
//
// Byte equality is the strongest statement available and it is what caught both
// substrate differences: `/readyz`'s key order, and chi's `405` where the reference
// has none. Two things are taken out of it and both are named rather than assumed:
//
//   - **`trace_id` in a problem document.** Both sides mint a fresh one per
//     response, so a byte comparison of that field fails on every run and the check
//     would have to be loosened rather than fixed. It is *replaced* with a fixed
//     token on both sides and nothing else — every other byte, including the key's
//     presence, its position and its surrounding punctuation, is still compared.
//     The property being taken out is checked independently on each side: Go in
//     `TestTheTraceIdHeaderEqualsTheBodyAndLooksLikeOne`, TypeScript in
//     `src/problem.test.ts`. So the normalisation hides a *difference* between two
//     random values and nothing else.
//
//   - **`X-Trace-Id` across sides.** Present on both or absent on both — the value
//     cannot match and the self-consistency is each side's own test.
//
// ## The response headers: a SET OF NAMES, plus `Content-Type`'s value
//
// `Date`, `Content-Length` and `Connection` are written by the two transports
// rather than by either service, they are not in `openapi/v1.yaml`, and comparing
// them would make every run differ on something neither side chose. `comparedHeaders`
// names the set so a reader can see the exclusion rather than infer it — and the
// rate-limit family is listed as a *statement* that the comparison will start
// failing the day one half of a pair appears without the other.
//
// ## The request the upstream received: method, path, query, and the whole header
//
// This is the half that matters most and it is the reason both sides are pointed
// at **one** recording upstream rather than two. The security properties in this
// packet are mostly not visible in a response body: "the caller's `Authorization`
// never crossed", "`set-cookie` was dropped", "the path was rebuilt rather than
// forwarded" are all claims about what left the process. Comparing them needs both
// gateways to have spoken to the same service.
//
// `transportOwnedHeaders` is the exclusion, and it was **measured** rather than
// guessed — Bun's `fetch` writes `accept-encoding: gzip, deflate, br, zstd`,
// `connection: keep-alive`, `user-agent: Bun/1.3.12` and `host`; `net/http` writes
// `accept-encoding: gzip`, `user-agent: Go-http-client/1.1` and `connection`. Every
// other name is compared, presence and value.
//
// # WHAT THIS DOES NOT COVER
//
// Said here rather than only in the report, because a reader of this file is the
// reader most likely to over-read it:
//
//   - **The principal assertion.** No route table in either scenario declares
//     `principal`, so nothing is minted on either side. MD19's four properties are
//     covered by `internal/httpapi`'s own suite, where the claim set can be read;
//     a `jti` differs per mint and cannot be compared byte for byte, so a minted
//     assertion would make this check compare noise.
//   - **A token that verifies.** `gatedUpstream` configures a verifier on the
//     reference and a refusing gate on the Go side, and no case carries a
//     credential, so both answer 401 from the gate before any key is read.
//   - **The rest of Wave 3.** No API keys, so no `/v1/api-keys/*` operation
//     answers anything but `404`.
//
// # WHAT THE BROWSE SCENARIOS AND THE LIMITER SCENARIOS ADDED
//
// Both were gaps this package recorded about itself rather than defects the
// reference had. The browser surface arrived with the BFF packet and the limiter
// with the two scenarios below, and both times the fix was to build the case
// rather than to widen the comparison.
//
// # THE LIMITER'S TWO DECISIONS, AND WHY THEY ARE TWO SCENARIOS
//
// `limitsExhausted` and `counterStoreDown` answer differently on purpose — one
// refuses and one serves — and a configuration in which they looked alike would
// be indistinguishable from a limiter that was never mounted. So they are
// separate scenarios, asked separate cases, and the run asserts each one actually
// produced its own decision rather than trusting the case list to have asked.
//
// The clock is FROZEN on both sides (`internal/equivalence/limiter.go`), because
// `RateLimit-Reset` and `Retry-After` are functions of it and a live clock makes
// the comparison a race between two `Date.now()` calls rather than a comparison
// of two implementations.
//
// The burst is compared at its FIRST and its LAST request. The refusal alone
// cannot tell two implementations apart — a burst that overspends by two reaches
// the same 429 with the same headers — so the admitted answer is compared too,
// and that is where a different allowance rate shows up.
//   - **A request line whose path is not valid percent-encoding.** `net/http`
//     rejects `%zz` before any handler runs and answers `400`; the reference
//     reaches its handler and answers `404`. See the report: this is a transport
//     difference and not something this port can close without replacing the HTTP
//     parser.
package equivalence

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cafaye/gateway/internal/httpapi"
)

// How long the reference gets to bind its socket, and how long each side gets to
// answer.
//
// Bounded rather than retried: an unbounded wait in a test suite is a run that
// hangs until CI's job timeout, which is the failure mode `AGENTS.md` names —
// "a green that says nothing about the one property it exists to hold" becomes,
// at that point, no result at all. The reference prints a readiness line AFTER
// `Bun.serve`, so its arrival means the socket is open rather than that a process
// started; that is why this is a read and not a sleep.
const (
	referenceStartTimeout = 60 * time.Second
	requestTimeout        = 10 * time.Second
)

// requiredEnv turns this tier's skip into a failure. The mechanism is the one
// `src/middleware/rateLimitRedisLive.test.ts` already keeps, and it is the same
// one for the same reason: a skip nobody can see is a green that verified nothing.
// CI sets it, so "no bun on this runner" is a red there and a counted skip on a
// developer's machine.
const requiredEnv = "GATEWAY_EQUIVALENCE_REQUIRED"

// The reference's readiness line. Matched rather than logged, so the runner can
// tell "it is up" from "it printed something and we hope".
var referenceReady = regexp.MustCompile(`^reference listening on (\S+) scenario=(\S+)$`)

// Compared response headers: `Content-Type` by value, and the presence or absence
// of every other name the contract declares. See the package comment for why the
// transport's own headers are not in here.
var comparedHeaders = []string{
	"Content-Type",
	// core's two error-envelope extensions and the whole rate-limit family. None
	// of them can appear yet — nothing writes a problem document and there is no
	// limiter — so listing them here is a statement that the comparison will start
	// failing the day one of them appears without the other side having it, which
	// is what happens if a packet adds one half of a pair.
	"X-Trace-Id",
	"Set-Cookie",
	"Retry-After",
	"RateLimit-Policy",
	"RateLimit",
	"RateLimit-Limit",
	"RateLimit-Remaining",
	"RateLimit-Reset",
	"X-RateLimit-Limit",
	"X-RateLimit-Remaining",
	"X-RateLimit-Reset",
}

// transportOwnedHeaders are the request headers a client writes on its own account,
// measured rather than guessed (see the package comment). They are excluded from
// the outbound comparison because comparing them compares `net/http` with Bun's
// `fetch`, and neither is a property of gateway.
//
// `Host` is here even though it is not in `http.Header` on the server side — it
// arrives as `Request.Host` — so a reader looking for it does not conclude it is
// compared when it is not.
var transportOwnedHeaders = map[string]bool{
	"Accept-Encoding": true,
	"Connection":      true,
	"User-Agent":      true,
	"Host":            true,
}

// case is one request, asked of both sides.
type caseSpec struct {
	name   string
	method string
	path   string

	// The caller's body, for the one case that sends one.
	body string

	// Headers the caller sends. Present because the properties under test are
	// about what happens to a header the caller *chose* — a case that sends none
	// cannot tell a dropped header from a header that was never there.
	//
	// `Accept` is on every case that reaches the pass-through, and that is not
	// tidiness: Bun's `fetch` supplies `accept: */*` when the caller sent none and
	// `net/http` supplies nothing, so the presence of `accept` at the upstream would
	// be a difference between two transports rather than between two gateways. The
	// exclusion is recorded here rather than discovered as a flaky case.
	headers map[string]string

	// How many times this case is asked of each side in a row. One by default.
	//
	// It is a field on the case rather than a loop in the runner because a
	// limiter's REFUSAL is a property of a sequence: one request at an allowance
	// of three is served on both sides and compares nothing about a crossing.
	// Asking the same request `burst` times and comparing every answer is what
	// makes the crossing observable — including the allowance being spent the same
	// number of times, which the refusal's own headers cannot show, since a burst
	// that overspends by two reaches the same refusal.
	burst int

	// The scenarios this case is asked under. Nil means every scenario, which is
	// right for the contract's own operations and wrong for anything that depends
	// on whether a credential gate is in front of the pass-through — a case that
	// carries a bearer token is refused by the reference's verifier before it
	// verifies anything, and there is nothing on the Go side to compare it with.
	scenarios []string

	// `Name: value` lines ADDED, so a case can send the same header twice. `Set`
	// cannot express that and the duplicated-header difference is one of the things
	// this comparison exists to find.
	extra []string

	// signIn logs in against the SAME base URL first and presents the cookie.
	signIn bool

	// originMatchesBase sends `Origin: <the base URL this case is asked at>`.
	// Per-side, for the same reason `signIn` is: the two sides are on different
	// ephemeral ports and a fixed value would name neither.
	originMatchesBase bool
}

// runsUnder says whether a case is asked in a scenario.
func (c caseSpec) runsUnder(scenario string) bool {
	if c.scenarios == nil {
		return true
	}
	for _, name := range c.scenarios {
		if name == scenario {
			return true
		}
	}
	return false
}

// contractCases is every operation the generated document declares, derived from
// `internal/api/api.gen.go` — the document's own routing table, which
// `bin/prime-go` holds in step with `openapi/v1.yaml` by regenerating and
// diffing.
//
// Derived by content rather than typed, and that is the whole reason: a list of
// seven operations written here would be a second inventory of the contract, and
// an eighth operation landing in the document would be compared against nothing
// while this file still looked complete.
var generatedRegistration = regexp.MustCompile(`(?m)^\s*r\.(Get|Post|Put|Patch|Delete|Head)\("([^"]+)"`)

func contractCases(t *testing.T) ([]caseSpec, error) {
	t.Helper()

	source, err := os.ReadFile(filepath.Join("..", "api", "api.gen.go"))
	if err != nil {
		return nil, err
	}

	var cases []caseSpec
	for _, match := range generatedRegistration.FindAllStringSubmatch(string(source), -1) {
		method := strings.ToUpper(match[1])
		// `HEAD` is registered by `New` rather than by the document, and its
		// behaviour is compared through `edgeCases` instead. Asking it here as
		// well would compare the same property twice.
		if method == http.MethodHead {
			continue
		}
		cases = append(cases, caseSpec{name: method + " " + match[2], method: method, path: match[2]})
	}

	// A reader that found nothing is a failure, not an empty contract: an
	// equivalence check over zero operations compares nothing and reports green.
	if len(cases) == 0 {
		return nil, fmt.Errorf("equivalence: read no operations from internal/api/api.gen.go, so every contract case below passes vacuously")
	}

	sort.Slice(cases, func(i, j int) bool { return cases[i].name < cases[j].name })
	return cases, nil
}

// edgeCases is the hand-written half, and it is hand-written on purpose.
//
// These are not operations the document declares; they are the paths two routers
// disagree about by default, and every one of them was a real difference while
// this port was being written:
//
//   - Hono has no 405 and chi does, so a wrong method on a real path is a case
//     rather than a footnote.
//   - Hono routes `HEAD` to the `GET` handler and chi does not.
//   - A trailing slash, a doubled slash and the wrong case are three different
//     answers in three routers, and gateway's contract has an opinion about none
//     of them beyond "the reference is right".
//   - A query string, because `problem()` writes the path and never the query and
//     a reader should be able to see that property compared rather than asserted.
var edgeCases = []caseSpec{
	{name: "HEAD on a probe", method: http.MethodHead, path: "/healthz"},
	{name: "HEAD on the other probe", method: http.MethodHead, path: "/readyz"},
	{name: "POST to a probe that serves GET", method: http.MethodPost, path: "/healthz"},
	{name: "DELETE to the other probe", method: http.MethodDelete, path: "/readyz"},
	{name: "OPTIONS to a probe", method: http.MethodOptions, path: "/healthz"},
	{name: "PUT to an operation that serves GET", method: http.MethodPut, path: "/v1/me"},
	{name: "the root", method: http.MethodGet, path: "/"},
	{name: "a path nobody declared", method: http.MethodGet, path: "/nope"},
	{name: "a path one segment too deep", method: http.MethodGet, path: "/v1/me/extra"},
	{name: "a trailing slash", method: http.MethodGet, path: "/healthz/"},
	{name: "a doubled slash", method: http.MethodGet, path: "//healthz"},
	{name: "the wrong case", method: http.MethodGet, path: "/HEALTHZ"},
	{name: "a query string", method: http.MethodGet, path: "/healthz?trace=1&x=2"},
	{name: "a query string on a refusal", method: http.MethodGet, path: "/nope?token=caf_secret"},
	{name: "a traversal attempt", method: http.MethodGet, path: "/v1/../v1/me"},
	{name: "an encoded path", method: http.MethodGet, path: "/v1/%6De"},
	{name: "a very long path", method: http.MethodGet, path: "/" + strings.Repeat("x", 512)},
}

// callerHeaders is what the routed cases make the caller send.
//
// Ten headers, of which the pass-through's allowlist names two. The five that are
// credentials or credential-shaped (`authorization`, `cookie`, `proxy-authorization`,
// `x-cafaye-principal`, `x-real-ip`) are the ones that matter: `x-cafaye-principal`
// in particular is the **assertion header**, so a caller that sends one and gets it
// honoured upstream would be able to choose what a service believes about the
// caller — and gateway would be signing over somebody else's claim.
var callerHeaders = map[string]string{
	"Accept":              "application/json",
	"Content-Type":        "application/json",
	"Authorization":       "Bearer " + callerToken,
	"Cookie":              "__Host-bff-session=caller-session",
	"Proxy-Authorization": "Basic Y2FsbGVyOmNhbGxlcg==",
	"X-Cafaye-Principal":  "eyJhbGciOiJub25lIn0.forged.by.the.caller.sig",
	"X-Forwarded-For":     "203.0.113.9",
	"X-Real-Ip":           "203.0.113.9",
	"X-Correlation-Id":    "caller-chosen-correlation",
	"If-None-Match":       `W/"a-caller-supplied-validator"`,
}

// proxyCases are the cases that reach an upstream.
//
// Every one of them is a *rejection* or a *relay* with a stated status, and none of
// them is a happy path alone: the packet asks for the rejections with the same
// status and the same error-envelope shape as the acceptances, and a comparison
// that only asked the questions whose answer is 200 would prove almost nothing about
// a proxy.
//
// They are asked under both routing scenarios, except the ones that carry a
// credential — those are the caller's-own-token cases, and under `gatedUpstream` the
// reference's verifier is asked to verify a token it cannot reach a key set for, so
// the answer there is a different property (the 503 on an unreachable JWKS) that
// belongs to the auth packet's comparison.
func proxyCases() []caseSpec {
	routed := []string{ScenarioRoutedUpstream, ScenarioGatedUpstream}
	caller := []string{ScenarioRoutedUpstream}

	return []caseSpec{
		// The relays.
		{name: "a private route", method: http.MethodGet, path: "/v1/pantry/items", headers: map[string]string{"Accept": "application/json"}, scenarios: routed},
		{name: "a private route with no path left", method: http.MethodGet, path: "/v1/pantry", headers: map[string]string{"Accept": "application/json"}, scenarios: routed},
		{name: "a private route with a trailing slash", method: http.MethodGet, path: "/v1/pantry/items/", headers: map[string]string{"Accept": "application/json"}, scenarios: routed},
		{name: "a service credential, on the longest matching prefix", method: http.MethodGet, path: "/v1/pantry/imports/things", headers: map[string]string{"Accept": "application/json"}, scenarios: routed},
		{name: "a public route", method: http.MethodGet, path: "/v1/catalog/services", headers: map[string]string{"Accept": "application/json"}, scenarios: routed},
		{name: "a query string that crosses verbatim", method: http.MethodGet, path: "/v1/pantry/items?trace=abc&next=%2Fv1%2Fpantry", headers: map[string]string{"Accept": "application/json"}, scenarios: routed},
		{name: "an empty query", method: http.MethodGet, path: "/v1/pantry/items?", headers: map[string]string{"Accept": "application/json"}, scenarios: routed},
		{name: "a segment that is re-encoded", method: http.MethodGet, path: "/v1/pantry/caf%C3%A9%20au%20lait", headers: map[string]string{"Accept": "application/json"}, scenarios: routed},
		{name: "a reserved character in a segment", method: http.MethodGet, path: "/v1/pantry/a%3Fb%23c", headers: map[string]string{"Accept": "application/json"}, scenarios: routed},

		// The caller's credential, and the nine other headers the caller chose.
		{name: "a caller's credential, which must not cross", method: http.MethodGet, path: "/v1/pantry/items", headers: callerHeaders, scenarios: caller},
		{name: "a caller's credential on the public route", method: http.MethodGet, path: "/v1/catalog/services", headers: callerHeaders, scenarios: caller},
		{name: "a caller's credential on the credentialed route", method: http.MethodGet, path: "/v1/pantry/imports/things", headers: callerHeaders, scenarios: caller},

		// The refusals: a path that is not a path this gateway serves.
		{name: "an encoded traversal out of the prefix", method: http.MethodGet, path: "/v1/pantry/%2e%2e/secret", headers: map[string]string{"Accept": "application/json"}, scenarios: routed},
		{name: "a literal traversal out of the prefix", method: http.MethodGet, path: "/v1/pantry/../secret", headers: map[string]string{"Accept": "application/json"}, scenarios: routed},
		{name: "a dot segment inside the prefix", method: http.MethodGet, path: "/v1/pantry/./items", headers: map[string]string{"Accept": "application/json"}, scenarios: routed},
		{name: "a path that resolves to a dot segment", method: http.MethodGet, path: "/v1/pantry/items/..", headers: map[string]string{"Accept": "application/json"}, scenarios: routed},
		{name: "an encoded separator inside a segment", method: http.MethodGet, path: "/v1/pantry/a%2Fb", headers: map[string]string{"Accept": "application/json"}, scenarios: routed},
		{name: "a doubled slash under the prefix", method: http.MethodGet, path: "/v1/pantry//items", headers: map[string]string{"Accept": "application/json"}, scenarios: routed},
		{name: "a byte that is not a character", method: http.MethodGet, path: "/v1/pantry/%ff", headers: map[string]string{"Accept": "application/json"}, scenarios: routed},
		{name: "a sibling that cannot inherit the mount", method: http.MethodGet, path: "/v1/pantryx/items", headers: map[string]string{"Accept": "application/json"}, scenarios: routed},
		{name: "the gateway's own route", method: http.MethodGet, path: "/v1/me", headers: map[string]string{"Accept": "application/json"}, scenarios: routed},

		// The refusals: what the service answered.
		{name: "a 404 from the service is relayed", method: http.MethodGet, path: "/v1/pantry/notfound", headers: map[string]string{"Accept": "application/json"}, scenarios: routed},
		{name: "a 401 from the service is relayed", method: http.MethodGet, path: "/v1/pantry/unauthorized", headers: map[string]string{"Accept": "application/json"}, scenarios: routed},
		{name: "a 5xx from the service is translated", method: http.MethodGet, path: "/v1/pantry/boom", headers: map[string]string{"Accept": "application/json"}, scenarios: routed},
		{name: "a 3xx from the service is translated", method: http.MethodGet, path: "/v1/pantry/redirect", headers: map[string]string{"Accept": "application/json"}, scenarios: routed},
		{name: "a body with no content type is not given one", method: http.MethodGet, path: "/v1/pantry/nocontenttype", headers: map[string]string{"Accept": "application/json"}, scenarios: routed},

		// And a body that crosses.
		{
			name:      "a body crosses with its content type",
			method:    http.MethodPost,
			path:      "/v1/pantry/services",
			headers:   map[string]string{"Accept": "application/json", "Content-Type": "application/json"},
			body:      `{"name":"a service","version":"1.0.0"}`,
			scenarios: routed,
		},
	}
}

// answer is what one side said.
type answer struct {
	status  int
	headers http.Header
	body    string
}

// askBurst drives one case `spec.burst` times in a row at one side and returns the
// FIRST answer and the LAST one.
//
// First and last, not all of them, and the middle answers are not compared because
// the two properties that matter are at the ends: the first request shows the
// allowance as it was, and the last shows what the limiter did with it. Asking the
// whole sequence on BOTH sides and comparing only the ends would still hold the
// allowance, because the last answer is only reachable through the ones before it
// — so a port that admitted a different number of requests before the refusal has
// to show it in `RateLimit-Remaining` on the first request or in the refusal
// itself.
//
// A case with no burst is asked once and returns that one answer as both, which is
// the comparison every other case in this file has always had — the field is
// additive rather than a change to how the existing cases are asked.
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
	// `Content-Type` on a body-bearing case only. A body with no content type is
	// something neither implementation is contracted to read, and the browser
	// surface's cap and object check both happen before it looks.
	if spec.body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for name, value := range spec.headers {
		req.Header.Set(name, value)
	}
	if spec.body != "" {
		req.ContentLength = int64(len(spec.body))
	}
	// Raw lines rather than a second map, because the case that needs one is a
	// DUPLICATED header and `Header.Set` cannot express that. The generated router
	// refuses a repeated `Sec-Fetch-Site` before the handler is reached and the
	// reference has no such refusal — which is one of the reasons
	// `internal/httpapi` installs its own `ErrorHandlerFunc`.
	for _, line := range spec.extra {
		name, value, found := strings.Cut(line, ": ")
		if !found {
			t.Fatalf("extra header %q is not `Name: value`", line)
		}
		req.Header.Add(name, value)
	}

	// A SIGNED-IN case fetches its cookie first, PER SIDE: the session id is minted
	// by the implementation under test, so the two sides hold different ids and one
	// shared header would be a session neither of them knows. That is why this is a
	// field on the case rather than a constant in the table.
	if spec.signIn {
		cookie, err := signIn(base)
		if err != nil {
			t.Fatalf("%s %s could not be asked signed-in: %v", spec.method, spec.path, err)
		}
		req.Header.Set("Cookie", cookie)
	}
	if spec.originMatchesBase {
		req.Header.Set("Origin", base)
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

// traceField matches the one value in a problem document that cannot match across
// two runs: `"trace_id":"<32 hex>"`.
var traceField = regexp.MustCompile(`"trace_id":"[0-9a-f]{32}"`)

// normaliseBody replaces the trace id with a fixed token and nothing else.
//
// The point is stated in the package comment, and repeated here because this
// function is where a reader would go to loosen the comparison: it replaces exactly
// one value and only when it is 32 hex characters in a `"trace_id"` key. A body
// whose trace id is absent, or whose `trace_id` is not 32 hex characters, is
// compared byte for byte like any other — so a gateway that stopped minting one, or
// started minting a short one, still fails here.
func normaliseBody(body string) string {
	return traceField.ReplaceAllString(body, `"trace_id":"<a-trace-id>"`)
}

// diff is one difference between the two answers, rendered for a failure
// message, and the EMPTY STRING when the two agree.
//
// Both sides' values are in it, because a diff that says only what the Go side
// did is half an answer and the reader has to go and run the reference to get the
// other half.
//
// The empty-string-on-agreement contract is load-bearing and was a bug first: the
// header line was written unconditionally, so every case "differed" and the
// 60 differences the first run reported were 56 of them noise.
func diff(spec caseSpec, scenario, which string, reference, port answer) string {
	var b strings.Builder

	if reference.status != port.status {
		fmt.Fprintf(&b, "\n    status:   typescript %d   go %d", reference.status, port.status)
	}

	wantType := reference.headers.Get("Content-Type")
	gotType := port.headers.Get("Content-Type")
	if wantType != gotType {
		fmt.Fprintf(&b, "\n    Content-Type: typescript %q   go %q", wantType, gotType)
	}

	for _, name := range comparedHeaders[1:] {
		inReference := reference.headers.Get(name) != ""
		inGo := port.headers.Get(name) != ""
		if inReference != inGo {
			fmt.Fprintf(&b, "\n    %s: typescript %s   go %s", name, presence(inReference), presence(inGo))
		}
	}

	// And the rate-limit family BY VALUE, on top of the presence comparison above.
	//
	// Only for a case that is under a limiter, and only when both sides wrote the
	// header at all: a header one side did not send is already reported above, and
	// reporting it a second time as a value difference would make one mistake read
	// as two. So this compares the numbers and only the numbers.
	if spec.burst > 0 {
		for _, name := range headerValuesComparedByValue {
			want := reference.headers.Get(name)
			got := port.headers.Get(name)
			if want == "" || got == "" {
				continue
			}
			// And the VALUES must match as strings — byte for byte, including the
			// formatting. `limiter.go`'s comment on `announce` says these numbers
			// are "formatted like JavaScript, deliberately", and `strconv`'s
			// `FormatFloat(v, 'f', -1, 64)` being `String(v)` in JavaScript is a
			// claim about every value a limiter can produce. A Go side that wrote
			// `1.0` where the reference wrote `1` would tell a client something
			// different, so the comparison is on the rendered string and not on the
			// number behind it.
			if want != got {
				fmt.Fprintf(&b, "\n    %s: typescript %q   go %q", name, want, got)
			}
		}
	}

	// Byte equality, with the first byte that differs named: "the bodies differ"
	// over a 400-character refusal body is a sentence nobody reads to the end.
	referenceBody, portBody := normaliseBody(reference.body), normaliseBody(port.body)
	if referenceBody != portBody {
		fmt.Fprintf(&b, "\n    body:     typescript %s", oneLine(reference.body))
		fmt.Fprintf(&b, "\n              go           %s", oneLine(port.body))
		if at := firstDifference(referenceBody, portBody); at >= 0 {
			fmt.Fprintf(&b, "\n    first difference at byte %d", at)
		}
	}

	// The scenario and the request go on LAST and only when there is something to
	// report, so the header costs nothing on the 60-odd cases that agree and
	// cannot be mistaken for a difference.
	if b.Len() == 0 {
		return ""
	}

	fmt.Fprintf(&b, "\n  %s %s  (scenario %s, %s)", spec.method, spec.path, scenario, which)
	return b.String()
}

// diffUpstream is one difference between what the two sides sent to the shared
// upstream, and the empty string when they sent the same thing.
//
// This is where the security properties of this packet are actually visible: "the
// caller's `Authorization` never crossed", "the assertion header is gateway's", "the
// path was rebuilt" are all claims about the request, and a comparison of responses
// alone would pass for an implementation that forwards the caller's cookie and
// happens to produce the same status.
func diffUpstream(spec caseSpec, scenario string, reference, port upstreamAnswer) string {
	var b strings.Builder

	if reference.Method != port.Method {
		fmt.Fprintf(&b, "\n    method:   typescript %s   go %s", reference.Method, port.Method)
	}
	// `EscapedPath`, not `Path`: a segment that reached the service re-encoded is the
	// whole point, and decoding here would make `a%2Fb` and `a/b` look equal.
	if reference.Path != port.Path {
		fmt.Fprintf(&b, "\n    path:     typescript %s   go %s", reference.Path, port.Path)
	}
	if reference.Query != port.Query {
		fmt.Fprintf(&b, "\n    query:    typescript %q   go %q", reference.Query, port.Query)
	}
	if reference.Body != port.Body {
		fmt.Fprintf(&b, "\n    body:     typescript %q   go %q", reference.Body, port.Body)
	}

	// Every header that is not a client's own, compared as a SET OF NAMES and by
	// value. The name set first, so an added header is reported even when its value
	// happens to match.
	compared := map[string]bool{}
	for name := range reference.Header {
		if !transportOwnedHeaders[http.CanonicalHeaderKey(name)] {
			compared[http.CanonicalHeaderKey(name)] = true
		}
	}
	for name := range port.Header {
		if !transportOwnedHeaders[http.CanonicalHeaderKey(name)] {
			compared[http.CanonicalHeaderKey(name)] = true
		}
	}

	names := make([]string, 0, len(compared))
	for name := range compared {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		want, wantThere := reference.Header[http.CanonicalHeaderKey(name)]
		got, gotThere := port.Header[http.CanonicalHeaderKey(name)]
		switch {
		case wantThere != gotThere:
			fmt.Fprintf(&b, "\n    %s: typescript %s   go %s", name, presence(wantThere), presence(gotThere))
		case !wantThere:
			continue
		case strings.Join(want, ", ") != strings.Join(got, ", "):
			fmt.Fprintf(&b, "\n    %s: typescript %q   go %q", name, strings.Join(want, ", "), strings.Join(got, ", "))
		}
	}

	if b.Len() == 0 {
		return ""
	}

	fmt.Fprintf(&b, "\n  %s %s reached the upstream differently  (scenario %s)", spec.method, spec.path, scenario)
	return b.String()
}

func presence(present bool) string {
	if present {
		return "present"
	}
	return "absent"
}

// oneLine truncates a body for a message. 300 characters is chosen because a
// v0 refusal body is 48 bytes and a readiness body is under 100, so anything
// longer than 300 on EITHER side is itself the finding.
func oneLine(body string) string {
	body = strings.ReplaceAll(body, "\n", "\\n")
	if len(body) <= 300 {
		return body
	}
	return body[:300] + fmt.Sprintf("… (%d bytes total)", len(body))
}

// firstDifference is the offset of the first byte the two bodies disagree at, or
// -1. It is the difference between a message a reader can act on and one they
// have to diff by hand.
func firstDifference(a, b string) int {
	shorter := len(a)
	if len(b) < shorter {
		shorter = len(b)
	}
	for i := 0; i < shorter; i++ {
		if a[i] != b[i] {
			return i
		}
	}
	if len(a) == len(b) {
		return -1
	}
	return shorter
}

// TestTheGoGatewayAnswersAsTheTypeScriptOneDoes is the equivalence check.
//
// One loop over the scenarios, and inside each one the derived contract cases,
// the hand-written edge cases and the proxy cases. Every case is compared on
// status, content type, header presence and body bytes; every case that reaches an
// upstream is ALSO compared on the request the upstream received; and every
// difference is reported with both sides' values — the failures accumulate rather
// than stopping at the first, because a port that differs in four places wants all
// four in the report.
func TestTheGoGatewayAnswersAsTheTypeScriptOneDoes(t *testing.T) {
	contract, err := contractCases(t)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// The contract's own operations, the edge cases, the pass-through's cases, and
	// — under the six scenarios that mount one — the browser surface's cases.
	//
	// The browser half is a function of the SCENARIO rather than a constant in this
	// list, which is BFF's design and it is the right one: asking `/auth/register`
	// under `routedUpstream` would compare two `404`s and call it agreement about
	// the surface. It is built per scenario below, not here, so the count printed
	// at the end is the number of comparisons actually made.
	cases := append(append(append([]caseSpec{}, contract...), edgeCases...), proxyCases()...)

	bun, err := exec.LookPath("bun")
	if err != nil {
		skipOrFail(t, "bun is not on PATH, so the TypeScript reference cannot be stood up")
	}

	// ONE recording upstream for the whole run. Both sides are pointed at the same
	// process, so "the same request reached the same upstream" is a comparison and
	// not two inferences. It is started here rather than per scenario so a case can
	// be compared across scenarios without standing anything up twice.
	service := startUpstream(t)

	// The reference is asked through a real socket and the Go gateway through
	// `httptest`, so the two sides travel the same transport. The Go side is
	// in-process because there is no reason to build a binary and manage a port
	// for it, and because the thing under test is the handler `New` returns —
	// which is also what `cmd/gateway` serves.
	//
	// ONE REFERENCE PER SCENARIO, restarted rather than reconfigured: the two
	// sides' configurations are declared in two languages that cannot see each
	// other, and a reference this package could reconfigure in place would be a
	// configuration the Go side had built for the other side. Restarting is
	// slower and it is the only way "both sides were given the same name" stays
	// a fact rather than a hope.
	var differences, comparisons, relayed int

	// What each limiter scenario actually decided, counted on the REFERENCE's
	// answers. The reference is the side whose behaviour is the contract here, and
	// a count taken from the Go side alone would let "the Go side never refused"
	// read as "nothing was refused" rather than as the difference it is.
	refusals := map[string]int{}
	served := map[string]int{}

	for _, scenario := range scenarios {
		asked := 0

		options, err := optionsFor(scenario, service.Origin())
		if err != nil {
			t.Fatalf("%v", err)
		}

		referenceURL, stop := standUpReference(t, bun, scenario, service.Origin())
		goServer := httptest.NewServer(mustHandler(t, options))

		// The browser cases exist only where there IS a browser surface.
		theseCases := cases
		if hasBrowserSurface(scenario) {
			browser, err := browserCases(t, canSignIn(scenario))
			if err != nil {
				t.Fatalf("%v", err)
			}
			theseCases = append(append([]caseSpec{}, cases...), browser...)
		}

		// The limiter's cases, where there is a limiter, so a scenario with no
		// limiter is not asked about one. Derived from the scenario rather than
		// listed, for the reason `hasBrowserSurface` exists.
		if hasLimiter(scenario) {
			theseCases = append(append([]caseSpec{}, theseCases...), limiterCases()...)
		}

		for _, spec := range theseCases {
			if !spec.runsUnder(scenario) {
				continue
			}
			asked++

			// A burst is asked as a burst, and the LAST answer is the one
			// compared for the response while the first is what proves the
			// allowance was spent the same number of times. Both sides are asked
			// the whole sequence before either is compared, so the Go side cannot
			// inherit a warm bucket from the reference's first three requests —
			// they are different processes with different stores, but the ordering
			// is what makes that a fact rather than a hope.
			first, want := askBurst(t, referenceURL, spec)
			wantUpstream, wantReached := service.take(t)

			goFirst, got := askBurst(t, goServer.URL, spec)
			gotUpstream, gotReached := service.take(t)

			// The admitted request, compared on its own. A refusal's headers are
			// the same however far past the threshold the burst went, so an
			// implementation that spends the allowance at the wrong rate produces
			// the same 429 and a different `RateLimit-Remaining` on the way there.
			comparisons++
			if rendered := diff(spec, scenario, "first request of the burst", first, goFirst); rendered != "" {
				differences++
				t.Errorf("the Go gateway answers differently from the TypeScript reference:%s", rendered)
			}

			// # THE REASON MUST NOT REACH THE CALLER, AND THIS IS WHERE THAT IS HELD
			//
			// The fail-open scenario's store and its probe both fail with a message
			// carrying a host and a credential, and both sides log it — that is the
			// design, and `ratelimit.failedOpen`'s own comment says so. What must not
			// happen is the message reaching a response body: `probesDegraded` holds
			// that for a probe under `/readyz`, and this holds it for a request that
			// was SERVED, which is the harder case — a 200 is a body a caller reads,
			// and a fail-open path that appended "redis is down" to it would be a
			// leak dressed as helpfulness.
			//
			// Both sides are checked, and against the ONE list of the parts of the
			// reason — declared in `store.go` beside the message they come from, so a
			// change to that message and a change to what is forbidden from leaking
			// are one edit rather than two.
			//
			// Read out of the answer rather than compared between the two sides on
			// purpose: two sides leaking the same secret is byte equality and would
			// pass the ordinary diff. This is checked against a list of forbidden
			// substrings precisely because agreement is not the property.
			if scenario == ScenarioCounterStoreDown {
				for _, side := range []struct {
					which  string
					answer answer
				}{{"typescript", want}, {"go", got}, {"typescript (first request of the burst)", first}, {"go (first request of the burst)", goFirst}} {
					for _, part := range thePartsOfTheReasonNeitherSideMayEcho {
						if strings.Contains(side.answer.body, part) {
							t.Errorf("scenario %s: the %s response body carries %q, which is part of the counter store's failure. The reason goes to the log; a caller gets nothing.", scenario, side.which, part)
						}
					}
				}
			}

			if want.status == http.StatusTooManyRequests {
				refusals[scenario]++
			}
			if want.status < 300 {
				served[scenario]++
			}

			comparisons++
			if rendered := diff(spec, scenario, "last request of the burst", want, got); rendered != "" {
				differences++
				t.Errorf("the Go gateway answers differently from the TypeScript reference:%s", rendered)
			}

			// The recorded request, when either side made one. "Neither reached it"
			// is agreement and needs no comparison; "one reached it" is the sharpest
			// difference this check can find, so it is reported as its own line rather
			// than as a missing header.
			switch {
			case wantReached != gotReached:
				differences++
				t.Errorf("  %s %s  (scenario %s) reached the upstream: typescript %s, go %s",
					spec.method, spec.path, scenario, presence(wantReached), presence(gotReached))
			case wantReached:
				relayed++
				if rendered := diffUpstream(spec, scenario, wantUpstream, gotUpstream); rendered != "" {
					differences++
					t.Errorf("the Go gateway sends a different request to the upstream:%s", rendered)
				}
			}
		}

		// A scenario nobody asked is a scenario that compared nothing and reported
		// green. That is the failure mode the two-lists check exists for, and it is
		// worth closing at the point it happens rather than after.
		if asked == 0 {
			t.Errorf("scenario %q asked no case at all, so every comparison under it passed vacuously", scenario)
		}
		t.Logf("equivalence: scenario %-16s %3d case(s) asked", scenario, asked)

		goServer.Close()
		stop()
	}

	if differences > 0 {
		t.Errorf("%d of %d case/scenario combinations differ. The TypeScript answer is the correct one: fix the Go side, or — if the reference is genuinely wrong — report it rather than changing it here.", differences, comparisons)
	}

	// # EACH LIMITER SCENARIO MUST HAVE PRODUCED ITS OWN DECISION
	//
	// Counted where the answers were rather than inferred from the inventory,
	// because a `burst` case that never reached a limiter would compare two
	// identical `404`s and call it agreement about a refusal — and that is exactly
	// what a mis-wired `Exempt` looks like.
	//
	// And the two are asserted in OPPOSITE directions, which is the reason they
	// are two scenarios rather than one with a flag: `limitsExhausted` must have
	// refused something, and `counterStoreDown` must have refused NOTHING. A run
	// where the fail-open scenario starts refusing is the fail-closed mistake
	// `internal/ratelimit`'s own comment names — "an outage in the counter store
	// handed to every caller as a 429" — and it would otherwise be green here,
	// because a 429 on both sides is a comparison that agrees.
	if refusals[ScenarioLimitsExhausted] == 0 {
		t.Errorf("scenario %q refused no request, so the 429 was never compared against the reference's own", ScenarioLimitsExhausted)
	}
	if refusals[ScenarioCounterStoreDown] != 0 {
		t.Errorf("scenario %q refused %d request(s) with a counter store that cannot be reached. That is failing CLOSED: an outage in the counter store handed to every caller as a 429. The two sides agreed on it, which is why this is asserted here rather than left to the diff.", ScenarioCounterStoreDown, refusals[ScenarioCounterStoreDown])
	}
	if served[ScenarioCounterStoreDown] == 0 {
		t.Errorf("scenario %q served nothing, so the fail-open decision — served, uncounted, no headers — was never compared", ScenarioCounterStoreDown)
	}

	// The count is printed on a green run too. A check that reports nothing when
	// it agrees has no evidence in it, and "it passed" and "it passed and told me
	// what it compared" are different results.
	// `comparisons` IS COUNTED IN THE LOOP, not computed as
	// `len(cases) x len(scenarios)`. That product was right while every case ran
	// under every scenario; it stopped being right the moment the browser half
	// became a function of the scenario, and a summary that over-reports its own
	// comparisons is a green that costs a reader their trust in the red ones.
	t.Logf("equivalence: %d cases across %d scenarios = %d comparisons, %d differences (status, Content-Type, %d compared headers, body bytes; %d of them also compared the request the upstream received)",
		len(cases), len(scenarios), comparisons, differences, len(comparedHeaders), relayed)
}

func mustHandler(t *testing.T, options httpapi.Options) http.Handler {
	t.Helper()

	handler, err := httpapi.New(options)
	if err != nil {
		t.Fatalf("httpapi.New refused the %+v configuration: %v", options, err)
	}
	return handler
}

// skipOrFail is the counted skip, made countable at the point it happens.
//
// The pattern is `rateLimitRedisLive.test.ts`'s: the tier is environment-gated,
// a skip is a green run that verified nothing, and `GATEWAY_EQUIVALENCE_REQUIRED`
// is what turns "no bun here" into a failure. CI sets it, so this cannot pass
// there without having compared something.
func skipOrFail(t *testing.T, why string) {
	t.Helper()

	if os.Getenv(requiredEnv) == "1" {
		t.Fatalf("GATEWAY_EQUIVALENCE_REQUIRED=1 and the tier could not run: %s. A check that cannot run is not a check that passed.", why)
	}

	t.Skipf("equivalence: DID NOT RUN — %s. Set %s=1 to make this a failure.", why, requiredEnv)
}

// standUpReference launches `test/equivalence/reference.ts` on an ephemeral port,
// waits for its readiness line, and returns its base URL and a stop function.
func standUpReference(t *testing.T, bun, scenario, upstreamOrigin string) (string, func()) {
	t.Helper()

	cmd := exec.Command(bun, filepath.Join("..", "..", "test", "equivalence", "reference.ts"))
	cmd.Env = append(os.Environ(),
		"GATEWAY_EQUIVALENCE_SCENARIO="+scenario,
		"GATEWAY_EQUIVALENCE_PORT=0",
		// Only the routing scenarios read it, and the reference **refuses** rather
		// than falling back when it is unset — so a routing case asked against a
		// reference that had no upstream would be a reference that answered 503 for
		// everything, which is a green with nothing behind it.
		"GATEWAY_EQUIVALENCE_UPSTREAM="+upstreamOrigin,
	)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("cannot pipe the reference's stdout: %v", err)
	}
	// stderr is inherited rather than captured so that a reference that dies
	// during startup says why in the test output instead of vanishing into a pipe
	// nobody reads.
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		t.Fatalf("cannot start the TypeScript reference: %v", err)
	}

	stop := func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
	}

	type ready struct {
		url string
		err error
	}
	arrived := make(chan ready, 1)

	go func() {
		reader := bufio.NewReader(stdout)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				arrived <- ready{err: fmt.Errorf("equivalence: the TypeScript reference stopped before it was ready: %w", err)}
				return
			}
			match := referenceReady.FindStringSubmatch(strings.TrimSpace(line))
			if match == nil {
				continue
			}
			port, convErr := strconv.Atoi(strings.TrimPrefix(match[1], "http://localhost:"))
			if convErr != nil {
				arrived <- ready{err: fmt.Errorf("equivalence: the reference printed an unreadable port %q", match[1])}
				return
			}
			if match[2] != scenario {
				// The reference refuses an unknown scenario and exits, so a mismatch
				// here means the two lists disagree about this scenario's name —
				// which `TestTheGoSideHasAnAnswerForEveryScenarioTheReferenceHas`
				// also checks, from the other side.
				arrived <- ready{err: fmt.Errorf("equivalence: asked for scenario %q and the reference came up as %q", scenario, match[2])}
				return
			}
			arrived <- ready{url: fmt.Sprintf("http://localhost:%d", port)}
			return
		}
	}()

	select {
	case got := <-arrived:
		if got.err != nil {
			stop()
			t.Fatalf("%v", got.err)
		}
		t.Cleanup(stop)
		return got.url, stop

	case <-time.After(referenceStartTimeout):
		stop()
		t.Fatalf("equivalence: the TypeScript reference did not print a readiness line within %s. It may not have started, or bun may be too slow to load the reference on this machine.", referenceStartTimeout)
		return "", func() {}
	}
}

// TestTheSurfaceThisComparesIsTheSurfaceTheSubstrateCanServe is the coverage
// check on the check.
//
// Every status `openapi/v1.yaml` declares that this port can produce has a case
// somewhere in this package, and every status it CANNOT produce is named. The
// second list is the important one: it is what stops "the equivalence check
// passes" from being read as "the contract is satisfied", when the truth is that
// five of the seven operations answer 404 on both sides because neither
// implementation has the subsystem yet.
//
// The refused statuses are derived from the document's own `Problem.status` enum
// and from the two v0 slugs — read out of `internal/api/api.gen.go`, so a status
// added to the document appears here without being typed in.
func TestTheSurfaceThisComparesIsTheSurfaceTheSubstrateCanServe(t *testing.T) {
	canProduce := map[string]string{
		"200": "the two probes, a relayed 2xx from an upstream, and every operation once its subsystem is ported",
		"401": "the credential gate refuses an anonymous caller to a private route, and `gatedUpstream` compares that answer against the reference's own",
		"404": "the v0 envelope for an unknown path, a wrong method and the five unported operations — and a relayed 404 from an upstream",
		"429": "`limitsExhausted` compares it against the reference's own: a burst over an allowance of three, its problem body, and the rate-limit headers on the refusal",
		"503": "two different sentences: a service that could not be reached and a service that answered something unusable",
	}

	// What the substrate cannot produce, and why. Named rather than counted: a
	// number would look like a measurement and this is a list of intentions.
	cannotProduce := map[string]string{
		"400": "the malformed-body check is on registerUser, which is Wave 3",
		"403": "requireSameOrigin and requireScope are Wave 3, and there is no browser surface to gate",
		"409": "registerUser is Wave 3, and the conflict is identity's to answer",
		"413": "the 4 KiB body cap is on registerUser, which is Wave 3",
		"422": "no operation on this surface validates fields; identity's answers are forwarded, not re-derived",
		"423": "a locked account is identity's answer on login, which is Wave 3",
	}

	// The 429 is producible, and it moved out of the "cannot" list when the limiter
	// scenarios landed. It is asserted with the rest below rather than left to the
	// comment: a table that claimed the port cannot refuse is the claim that let a
	// whole packet of scenarios go unbuilt while looking complete.

	// Every status the document declares is either producible or named above. The
	// enum comes from the generated file rather than from this list, so a status
	// added to `openapi/v1.yaml` lands here as an error naming itself.
	declared := declaredProblemStatuses(t)
	var unaccounted []string
	for status := range declared {
		key := strconv.Itoa(status)
		if _, ok := canProduce[key]; ok {
			continue
		}
		if _, ok := cannotProduce[key]; ok {
			continue
		}
		unaccounted = append(unaccounted, key)
	}
	sort.Strings(unaccounted)

	if len(unaccounted) > 0 {
		t.Errorf("openapi/v1.yaml declares status %v and this package accounts for none of them. Either the port can produce it — in which case a case belongs in contractCases — or it cannot, in which case cannotProduce names why.", unaccounted)
	}

	// And the ones that are producible are the ones the surface really writes,
	// asserted rather than listed: a check that only reads its own table is a check
	// that cannot notice the table being wrong.
	for _, status := range []string{"200", "401", "404", "429", "503"} {
		if _, ok := canProduce[status]; !ok {
			t.Errorf("canProduce does not say how the port produces a %s, and it does", status)
		}
	}
}

var problemStatusConst = regexp.MustCompile(`(?m)^\s*(N[0-9]{3})\s+ProblemStatus = ([0-9]{3})$`)

// declaredProblemStatuses reads `Problem.status`'s enum out of the generated
// file. The v0 `404` is not in it — `V0Error` has no status enum — so it is
// added, because the v0 envelope is one of the bodies this port writes.
func declaredProblemStatuses(t *testing.T) map[int]bool {
	t.Helper()

	source, err := os.ReadFile(filepath.Join("..", "api", "api.gen.go"))
	if err != nil {
		t.Fatalf("cannot read internal/api/api.gen.go: %v", err)
	}

	statuses := map[int]bool{404: true}
	for _, match := range problemStatusConst.FindAllStringSubmatch(string(source), -1) {
		statuses[atoiOrPanic(match[2])] = true
	}

	if len(statuses) < 9 {
		t.Fatalf("read %d statuses from Problem.status; openapi/v1.yaml declares nine and the v0 envelope adds the 404. If the generator changed how it writes them, this test has stopped checking anything.", len(statuses))
	}

	return statuses
}

func atoiOrPanic(digits string) int {
	value, err := strconv.Atoi(digits)
	if err != nil {
		panic(err)
	}
	return value
}

// TestTheGoSideHasAnAnswerForEveryScenarioTheReferenceHas is the two-lists
// check.
//
// `test/equivalence/reference.ts` and `scenarios.go` each name the scenarios, and
// neither can read the other at run time — one is TypeScript and one is Go, and
// the reference's list is a `Record` in a subprocess. So the reference's names are
// READ out of its source and compared with this side's.
//
// The alternative — the runner silently comparing a scenario one side does not
// have — produces an empty case list for it, which is a green. This is what makes
// that impossible, and it is the reason a scenario added on one side without the
// other fails the gate rather than being skipped quietly.
func TestTheGoSideHasAnAnswerForEveryScenarioTheReferenceHas(t *testing.T) {
	source, err := os.ReadFile(filepath.Join("..", "..", "test", "equivalence", "reference.ts"))
	if err != nil {
		t.Fatalf("cannot read test/equivalence/reference.ts: %v", err)
	}

	// The keys of the `SCENARIOS` record, read as lines that start at the beginning
	// of one, plus the two routing scenarios this reference *assigns* rather than
	// declares (`SCENARIOS.routedUpstream = …`) because they need the upstream out
	// of the environment.
	//
	// Scoped to the record's own literal. The first version matched every
	// two-space-indented `name: {` in the file and picked up the `jwt:` inside
	// `gatedUpstream`'s options — so the check reported a scenario the reference does
	// not have, which is the failure this whole test exists to prevent, caused by the
	// test.
	body := string(source)
	start := strings.Index(body, "export const SCENARIOS")
	if start < 0 {
		t.Fatalf("cannot find `export const SCENARIOS` in test/equivalence/reference.ts, so this check cannot see the reference's list")
	}
	end := strings.Index(body[start:], "\n};")
	if end < 0 {
		t.Fatalf("cannot find the end of the SCENARIOS record in test/equivalence/reference.ts")
	}
	record := body[start : start+end]

	keys := regexp.MustCompile(`(?m)^  ([A-Za-z][A-Za-z0-9]*): \{`)
	found := map[string]bool{}
	for _, match := range keys.FindAllStringSubmatch(record, -1) {
		found[match[1]] = true
	}

	assigned := regexp.MustCompile(`(?m)^SCENARIOS\.([A-Za-z][A-Za-z0-9]*) =`)
	for _, match := range assigned.FindAllStringSubmatch(body, -1) {
		found[match[1]] = true
	}

	if len(found) == 0 {
		t.Fatalf("no scenarios were read from test/equivalence/reference.ts, so this check cannot tell whether the two sides agree — and neither can the runner")
	}

	var missing []string
	for name := range found {
		if !isScenario(name) {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Errorf("the reference has scenario(s) %v and this package does not. The runner would compare nothing for them and report green.", missing)
	}

	// And the other direction: a scenario this side can build that the reference
	// cannot is a scenario whose Go answer is compared against the WRONG
	// configuration — the runner would fail to start the reference and say so, but
	// only after the whole comparison had been set up.
	var extra []string
	for _, name := range scenarios {
		if !found[name] {
			extra = append(extra, name)
		}
	}
	if len(extra) > 0 {
		t.Errorf("this package has scenario(s) %v and test/equivalence/reference.ts does not, so the reference would fall back to a configuration it was not asked for", extra)
	}
}

func isScenario(name string) bool {
	for _, candidate := range scenarios {
		if candidate == name {
			return true
		}
	}
	return false
}

// TestTheRouteTableBothSidesDeclareIsTheSameThreeEntries is the configuration
// check on the configuration.
//
// The two tables are declared in two languages and in two files, and a prefix
// added to one and not the other would not fail any comparison — it would produce a
// difference on the *cases that use it*, and only if somebody thought to write
// one. So the entries are read out of both sides and compared, by content.
func TestTheRouteTableBothSidesDeclareIsTheSameThreeEntries(t *testing.T) {
	source, err := os.ReadFile(filepath.Join("..", "..", "test", "equivalence", "reference.ts"))
	if err != nil {
		t.Fatalf("cannot read test/equivalence/reference.ts: %v", err)
	}

	// `"/v1/pantry": { baseUrl: upstream }` — one group per field, so a token and a
	// `public` flag are two facts rather than one string. The first version
	// concatenated them and then compared the concatenation, which is how a public
	// entry with no token reported itself as carrying one.
	declared := regexp.MustCompile(`"(/v1/[A-Za-z0-9/_-]*)": \{ baseUrl: upstream(?:, token: "([^"]*)")?(, public: true)? \}`)
	found := map[string]struct {
		token  string
		public bool
	}{}
	for _, match := range declared.FindAllStringSubmatch(string(source), -1) {
		found[match[1]] = struct {
			token  string
			public bool
		}{token: match[2], public: match[3] != ""}
	}

	if len(found) != 3 {
		t.Fatalf("read %d entries from the reference's route table; it declares three. This test is not reading the table.", len(found))
	}

	prefixes := make([]string, 0, len(found))
	for prefix := range found {
		prefixes = append(prefixes, prefix)
	}
	sort.Strings(prefixes)

	for _, prefix := range prefixes {
		declaredEntry := found[prefix]
		target, ok := routesFor("http://upstream.test")[prefix]
		if !ok {
			t.Errorf("the reference routes %q and the Go side does not", prefix)
			continue
		}
		if (target.Token != "") != (declaredEntry.token != "") {
			t.Errorf("%q: the reference carries a token %q and the Go side carries %q; the two tables are the same entry or they are not the same entry", prefix, declaredEntry.token, target.Token)
		}
		if declaredEntry.token != "" && declaredEntry.token != serviceToken {
			t.Errorf("%q: the reference's token is %q and this package compares against %q", prefix, declaredEntry.token, serviceToken)
		}
		if target.Public != declaredEntry.public {
			t.Errorf("%q: the reference says public=%v and the Go side says %v", prefix, declaredEntry.public, target.Public)
		}
	}
}

// route is one `(method, path)` pair, declared here rather than imported from
// `internal/httpapi` — whose `routes_test.go` has its own, for its own check, in the
// other direction (it walks the live router rather than reading the generated file).
// Two declarations of one shape in two packages checking two different halves is the
// right answer: sharing them would make one package's test depend on the other's.
type route struct {
	method string
	path   string
}

func (r route) String() string { return r.method + " " + r.path }

// signIn is one exchange against a base URL, returning a `Cookie` header value.
//
// It is a plain `POST /auth/login` with `Sec-Fetch-Site: same-origin` and the same
// body `browserCases` sends, because the point is to obtain a cookie the other side
// of the comparison cannot have — so a scenario where login is refused (a locked
// account, a withdrawn session) reports the failure rather than pretending the case
// ran. That is deliberate: a silent "no cookie, carry on" would turn a signed-in
// case into a signed-out one and the comparison would still be green.
func signIn(base string) (string, error) {
	req, err := http.NewRequest(http.MethodPost, base+"/auth/login", strings.NewReader(loginBody))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Sec-Fetch-Site", "same-origin")

	client := &http.Client{Timeout: requestTimeout}
	res, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	for _, c := range res.Cookies() {
		if c.Name == sessionCookieName {
			return c.Name + "=" + c.Value, nil
		}
	}
	return "", fmt.Errorf("the sign-in exchange answered %d and set no %s cookie, so the case that follows would silently be a signed-OUT case", res.StatusCode, sessionCookieName)
}

// sessionCookieName is read out of the service rather than typed, so a rename
// cannot leave this package looking for a cookie nobody sets and reporting the
// signed-in cases as "no cookie" forever.
const sessionCookieName = "__Host-bff-session"

// loginBody is what `signIn` and the browser cases send. A constant, and shared,
// so the two cannot drift into sending different things.
const loginBody = `{"email":"a@example.test","password":"pw"}`

func (c caseSpec) withHeaders(headers map[string]string) caseSpec {
	c.headers = headers
	return c
}

func (c caseSpec) withBody(body string) caseSpec {
	c.body = body
	return c
}

func browserCases(t *testing.T, canSignIn bool) ([]caseSpec, error) {
	t.Helper()

	declared, err := declaredAuthRoutes(t)
	if err != nil {
		return nil, err
	}
	if len(declared) == 0 {
		return nil, fmt.Errorf("equivalence: read no /auth operation from internal/api/api.gen.go, so the derived browser cases below pass vacuously")
	}

	// The first half: DERIVED. Every `/auth` operation the generated document
	// declares, asked as a same-origin request with a body so each reaches its
	// handler instead of stopping at the origin gate. Derived because a
	// hand-written list of four routes is a second inventory of the document, and
	// it would compare `403`s for a route added next week while still looking
	// complete.
	cases := make([]caseSpec, 0, len(declared)+16)
	for _, r := range declared {
		spec := caseSpec{
			name:    "same-origin " + r.String(),
			method:  r.method,
			path:    r.path,
			headers: map[string]string{"Sec-Fetch-Site": "same-origin"},
		}
		if r.method != http.MethodGet {
			spec.body = loginBody
		}
		cases = append(cases, spec)
	}

	// The signed-in half. `canSignIn` is DERIVED from the scenario's own overrides,
	// so a scenario that refuses a login simply is not asked these. Asking them
	// anyway would fail in `signIn` — loudly, and about the wrong thing.
	if canSignIn {
		cases = append(cases,
			// A CORRECT SESSION, on both the read and the write. Signed in, so the
			// cookie is one the implementation under test minted itself.
			caseSpec{name: "a correct session on the read", method: http.MethodGet, path: "/auth/me", signIn: true},
			caseSpec{name: "a correct session signing out", method: http.MethodPost, path: "/auth/logout", signIn: true,
				headers: map[string]string{"Sec-Fetch-Site": "same-origin"}},

			// A VALID SESSION COOKIE DOES NOT MAKE A CROSS-ORIGIN POST WORK. This is
			// a different case from the cross-origin ones below, and the reason it
			// exists: those carry no cookie, so a gate that only checked for a cookie
			// would also pass them.
			caseSpec{name: "a cross-origin logout with a live cookie", method: http.MethodPost, path: "/auth/logout", signIn: true,
				headers: map[string]string{"Sec-Fetch-Site": "cross-site"}},
		)
	}

	return append(cases,
		// A CROSS-ORIGIN POST, on each mutating route, and it must be refused. The
		// refusal is the CSRF defence, so this is the case that carries the property
		// the packet calls property 1.
		caseSpec{name: "a cross-origin register", method: http.MethodPost, path: "/auth/register", body: loginBody,
			headers: map[string]string{"Sec-Fetch-Site": "cross-site"}},
		caseSpec{name: "a cross-origin login", method: http.MethodPost, path: "/auth/login", body: loginBody,
			headers: map[string]string{"Sec-Fetch-Site": "cross-site"}},

		// SAME-SITE is a sibling subdomain, and a Lax cookie IS sent to one, so it
		// has something to spend on its parent.
		caseSpec{name: "a same-site login", method: http.MethodPost, path: "/auth/login", body: loginBody,
			headers: map[string]string{"Sec-Fetch-Site": "same-site"}},

		// The `Origin` fallback, both directions: a matching host is allowed even
		// when a TLS-terminating proxy rewrote the scheme, and another host is not.
		//
		// `originMatchesBase` rather than a literal, because the two sides are asked
		// at DIFFERENT ephemeral ports: a fixed `Origin` would name neither, the
		// "names this host" case would compare a REFUSAL on both sides, and the
		// comparison would be green for the wrong reason.
		caseSpec{name: "an Origin naming this host", method: http.MethodPost, path: "/auth/login", body: loginBody,
			originMatchesBase: true},
		caseSpec{name: "an Origin naming another host", method: http.MethodPost, path: "/auth/login", body: loginBody,
			headers: map[string]string{"Origin": "https://evil.test"}},

		// No origin signal at all: not *provably* same-origin, so refused.
		caseSpec{name: "no origin signal at all", method: http.MethodPost, path: "/auth/login", body: loginBody},

		// A DUPLICATED header. The generated router refuses it before the handler
		// reaches it; the reference joins the lines. The two must still agree.
		caseSpec{name: "Sec-Fetch-Site sent twice", method: http.MethodPost, path: "/auth/login", body: loginBody,
			extra: []string{"Sec-Fetch-Site: same-origin", "Sec-Fetch-Site: same-origin"}},

		// A cookie no store has ever heard of: a restart, a swept map.
		caseSpec{name: "a session the store has forgotten", method: http.MethodGet, path: "/auth/me",
			headers: map[string]string{"Cookie": sessionCookieName + "=not-a-real-session"}},

		// A body that is not an object, and one past the cap. Both are refusals that
		// never reach identity, and both sides must refuse identically.
		caseSpec{name: "a body that is not an object", method: http.MethodPost, path: "/auth/register",
			body: `[{"email":"a@example.test"}]`, headers: map[string]string{"Sec-Fetch-Site": "same-origin"}},
		caseSpec{name: "a body past the cap", method: http.MethodPost, path: "/auth/register",
			body:    `{"email":"a@example.test","password":"` + strings.Repeat("x", 4<<10) + `"}`,
			headers: map[string]string{"Sec-Fetch-Site": "same-origin"}},
	), nil
}

// declaredAuthRoutes is the `/auth` subset of the generated registrations, read
// with the same pattern `contractCases` uses rather than typed out.
//
// A subset rather than a new pattern: `contractCases` already proved the pattern
// finds registrations at all, and a second pattern that silently matched nothing
// would make the browser half of the comparison empty while it looked complete.
func declaredAuthRoutes(t *testing.T) ([]route, error) {
	t.Helper()

	source, err := os.ReadFile(filepath.Join("..", "api", "api.gen.go"))
	if err != nil {
		return nil, err
	}

	var routes []route
	for _, match := range generatedRegistration.FindAllStringSubmatch(string(source), -1) {
		path := match[2]
		if !strings.HasPrefix(path, "/auth/") {
			continue
		}
		routes = append(routes, route{method: strings.ToUpper(match[1]), path: path})
	}
	sort.Slice(routes, func(i, j int) bool { return routes[i].String() < routes[j].String() })
	return routes, nil
}
