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
// # THE CASES ARE DERIVED, NOT TYPED
//
// Every operation `openapi/v1.yaml` declares is derived from the generated
// registrations in `internal/api/api.gen.go` — the document's own routing table,
// one translation removed — and each is asked with the method the document gives
// it. So an operation added to the document is asked the day it lands, without
// anybody adding it here.
//
// On top of those, a short table of edge shapes: the wrong method on a path that
// exists, a path with a trailing slash, a doubled slash, the root, the wrong
// case, a query string, and `HEAD`. Those are not the contract; they are the
// places two routers disagree by default, and every one of them was a real
// difference during this packet. They are hand-written and that is stated, because
// a hand-written table is legitimate for "the edge" and illegitimate for "the
// contract" — see the note on `contractCases`.
//
// # WHAT IS COMPARED, AND WHAT IS NOT, AND WHY
//
// Status, `Content-Type`, and the body BYTE FOR BYTE. Byte equality is the
// strongest statement available and it is what caught both substrate
// differences: `/readyz`'s key order, and chi's `405` where the reference has
// none.
//
// Headers are compared as a SET OF NAMES, plus `Content-Type`'s value. Not the
// whole header block, and the exclusion is deliberate: `Date`,
// `Content-Length` and `Connection` are written by the two transports rather than
// by either service, they are not in `openapi/v1.yaml`, and comparing them would
// make every run differ on something neither side chose. `comparedHeaders` names
// the set so a reader can see the exclusion rather than infer it.
//
// # WHAT THIS DOES NOT COVER
//
// Everything Wave 3 owns. There is no bearer token, no API key, no rate limit, no
// `X-Trace-Id`, no `Set-Cookie`, no upstream — so no `401`, no `429`, no problem
// document and no `Set-Cookie` is compared, because the Go service cannot produce
// one. The refusal cases below are the v0 `404` and the v0 `500`, which are the
// only two error bodies the substrate can write. `TestTheSurfaceThisComparesIs
// TheSurfaceTheSubstrateCanServe` asserts that gap rather than leaving it to be
// discovered: a refusal in the contract with no case here is named as a thing the
// check does not know about.
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

// Compared headers: `Content-Type` by value, and the presence or absence of
// every other name the contract declares. See the package comment for why the
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

// case is one request, asked of both sides.
//
// `headers`, `extra`, `body` and `signIn` exist because the browser surface cannot
// be driven without them: `/auth/register` and `/auth/login` are POSTs with a JSON
// body, the origin gate reads two headers, a duplicated header is its own case,
// and a signed-in request needs a cookie the implementation under test minted. They
// are all zero for the derived contract cases and the edge cases, which is what
// keeps those two halves as they were.
type caseSpec struct {
	name    string
	method  string
	path    string
	headers map[string]string

	// `Name: value` lines ADDED, so a case can send the same header twice. `Set`
	// cannot express that and the duplicated-header difference is one of the things
	// this comparison exists to find.
	extra []string

	body string

	// signIn logs in against the SAME base URL first and presents the cookie.
	signIn bool

	// originMatchesBase sends `Origin: <the base URL this case is asked at>`.
	// Per-side, for the same reason `signIn` is: the two sides are on different
	// ephemeral ports and a fixed value would name neither.
	originMatchesBase bool
}

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

// withHeaders returns a copy carrying headers, so a table literal stays readable
// and a case is never mutated after it is built.
func (c caseSpec) withHeaders(headers map[string]string) caseSpec {
	c.headers = headers
	return c
}

func (c caseSpec) withBody(body string) caseSpec {
	c.body = body
	return c
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

// browserCases are the cases the BROWSER SURFACE needs, and they are only asked
// in a scenario that mounts it.
//
// Two halves, and the split is the same as `contractCases` versus `edgeCases`:
//
//   - The first is DERIVED: every `/auth` operation the generated document
//     declares, asked as a same-origin request with a body, so each reaches its
//     handler instead of stopping at the origin gate. Derived because a
//     hand-written list of four routes is a second inventory of the document, and
//     it would compare `403`s for a route added next week while still looking
//     complete.
//   - The second is the packet's OWN LIST, in the order the packet states it: a
//     correct login, a wrong password, an unknown account, a correct session, an
//     expired session, a cross-origin POST, a same-origin POST, and the two
//     header shapes. Those are not operations — they are what a request looks
//     like — so typing them is legitimate and deriving them would be a category
//     error.
//
// # WHAT IS NOT HERE, AND WHY
//
// A REVOKED KEY and a VALID KEY. Both belong to the API-key gate, which is
// another packet and which this repository cannot serve yet, so there is nothing
// to compare and pretending otherwise would be a case comparing two `404`s. The
// `bare` scenario's derived `/v1/*` cases already cover the shape those two would
// have, and the packet's own report names them as not covered.
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

type answer struct {
	status  int
	headers http.Header
	body    string
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
func diff(spec caseSpec, scenario string, reference, port answer) string {
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

	// Byte equality, with the first byte that differs named: "the bodies differ"
	// over a 400-character refusal body is a sentence nobody reads to the end.
	//
	// `trace_id` IS NORMALISED, and that is the one exclusion in a byte-for-byte
	// comparison, so it is worth saying exactly why it is not a weakening: the field
	// is 32 hex characters of `crypto/rand`, generated per response on BOTH sides,
	// so it cannot agree and comparing it would fail every problem document forever
	// — a red that means nothing and a fix that would be to make the field a
	// constant, which is the opposite of what it is for.
	//
	// What is NOT normalised is its PRESENCE or its SHAPE, and both are asserted
	// below. A side that dropped the field, renamed it, or emitted a non-hex value
	// still fails: `TestBothSidesCarryAWellFormedTraceId` is the check, and it is
	// separate so a reader can see which part of the envelope is frozen and which
	// part is required to differ.
	referenceBody := normaliseTraceID(reference.body)
	portBody := normaliseTraceID(port.body)
	if referenceBody != portBody {
		fmt.Fprintf(&b, "\n    body:     typescript %s", oneLine(referenceBody))
		fmt.Fprintf(&b, "\n              go           %s", oneLine(portBody))
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

	// The scenario, the request AND the case's NAME go on LAST and only when there is
	// something to report. The name is the part a reader needs: several cases share
	// a method and a path, and "POST /auth/login differs" does not say which of the
	// seven login cases did.
	fmt.Fprintf(&b, "\n  [%s] %s %s  (scenario %s)", spec.name, spec.method, spec.path, scenario)
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
// One loop over the scenarios, and inside each one the derived contract cases
// followed by the hand-written edge cases. Every case is compared on status,
// content type, header presence and body bytes, and every difference is reported
// with both sides' values — the failures accumulate rather than stopping at the
// first, because a port that differs in four places wants all four in the report.
func TestTheGoGatewayAnswersAsTheTypeScriptOneDoes(t *testing.T) {
	contract, err := contractCases(t)
	if err != nil {
		t.Fatalf("%v", err)
	}

	cases := append(append([]caseSpec{}, contract...), edgeCases...)

	// The TOTAL, computed before the loop rather than inside it, because the case
	// list is a function of the scenario and the summary has to be the number of
	// comparisons that were actually made — not `len(cases) x len(scenarios)`,
	// which would be wrong the moment a scenario mounts the browser surface.
	comparisons := 0
	for _, scenario := range scenarios {
		n := len(cases)
		if hasBrowserSurface(scenario) {
			browser, err := browserCases(t, canSignIn(scenario))
			if err != nil {
				t.Fatalf("%v", err)
			}
			n += len(browser)
		}
		comparisons += n
	}

	bun, err := exec.LookPath("bun")
	if err != nil {
		skipOrFail(t, "bun is not on PATH, so the TypeScript reference cannot be stood up")
	}

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
	var differences int
	for _, scenario := range scenarios {
		options, err := optionsFor(scenario)
		if err != nil {
			t.Fatalf("%v", err)
		}

		// The browser cases only exist where there IS a browser surface, and asking
		// them elsewhere would compare two `404`s and call it agreement about the
		// surface. So the list is a function of the scenario rather than a constant.
		theseCases := append(append([]caseSpec{}, contract...), edgeCases...)
		if hasBrowserSurface(scenario) {
			browser, err := browserCases(t, canSignIn(scenario))
			if err != nil {
				t.Fatalf("%v", err)
			}
			theseCases = append(theseCases, browser...)
		}

		referenceURL, stop := standUpReference(t, bun, scenario)
		goServer := httptest.NewServer(mustHandler(t, options))

		for _, spec := range theseCases {
			want := ask(t, referenceURL, spec)
			got := ask(t, goServer.URL, spec)

			if rendered := diff(spec, scenario, want, got); rendered != "" {
				differences++
				t.Errorf("the Go gateway answers differently from the TypeScript reference:%s", rendered)
			}
		}

		goServer.Close()
		stop()
	}

	if differences > 0 {
		t.Errorf("%d of %d case/scenario combinations differ. The TypeScript answer is the correct one: fix the Go side, or — if the reference is genuinely wrong — report it rather than changing it here.", differences, comparisons)
	}

	// The count is printed on a green run too. A check that reports nothing when
	// it agrees has no evidence in it, and "it passed" and "it passed and told me
	// what it compared" are different results.
	t.Logf("equivalence: %d cases x %d scenarios = %d comparisons, %d differences (status, Content-Type, %d compared headers, body bytes)",
		len(cases), len(scenarios), comparisons, differences, len(comparedHeaders))
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
func standUpReference(t *testing.T, bun, scenario string) (string, func()) {
	t.Helper()

	cmd := exec.Command(bun, filepath.Join("..", "..", "test", "equivalence", "reference.ts"))
	cmd.Env = append(os.Environ(),
		"GATEWAY_EQUIVALENCE_SCENARIO="+scenario,
		"GATEWAY_EQUIVALENCE_PORT=0",
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
		"200": "the two probes, and every operation once its subsystem is ported",
		"404": "the v0 envelope, for an unknown path, a wrong method and the five unported operations",
	}

	// What the substrate cannot produce, and why. Named rather than counted: a
	// number would look like a measurement and this is a list of intentions.
	cannotProduce := map[string]string{
		"400": "the malformed-body check is on registerUser, which is Wave 3",
		"401": "the bearer-token gate and the API-key store are Wave 3, and no verifier means there is nothing to authenticate against",
		"403": "requireSameOrigin and requireScope are Wave 3, and there is no browser surface to gate",
		"409": "registerUser is Wave 3, and the conflict is identity's to answer",
		"413": "the 4 KiB body cap is on registerUser, which is Wave 3",
		"422": "no operation on this surface validates fields; identity's answers are forwarded, not re-derived",
		"423": "a locked account is identity's answer on login, which is Wave 3",
		"429": "there is no limiter yet; ProbePaths is the floor it will be built on",
		"503": "the probes report per-dependency availability in /readyz's body, not as a problem document",
	}

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

	// And the two that are producible are the two the v0 envelope and the probes
	// actually write, asserted rather than listed: a check that only reads its own
	// table is a check that cannot notice the table being wrong.
	for _, status := range []string{"200", "404"} {
		if _, ok := canProduce[status]; !ok {
			t.Errorf("canProduce does not say how the substrate produces a %s, and it does", status)
		}
	}
}

var problemStatusConst = regexp.MustCompile(`(?m)^\s*(N[0-9]{3})\s+ProblemStatus = ([0-9]{3})$`)

// declaredProblemStatuses reads `Problem.status`'s enum out of the generated
// file. The v0 `404` is not in it — `V0Error` has no status enum — so it is
// added, because the v0 envelope is one of the two bodies this port writes.
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

	// `bare: {},` and `oneProbeOk: {` — the keys of the SCENARIOS record, read
	// as lines that start at the beginning of one.
	keys := regexp.MustCompile(`(?m)^  ([A-Za-z][A-Za-z0-9]*): \{`)
	found := map[string]bool{}
	for _, match := range keys.FindAllStringSubmatch(string(source), -1) {
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

// traceIDField is the one field in this comparison that is REQUIRED to differ
// between the two answers, and the regex is what makes it an assertion rather than
// a comment: a side that dropped the key, renamed it, or emitted a non-hex value
// does not match, and `TestBothSidesCarryAWellFormedTraceId` fails.
var traceIDField = regexp.MustCompile(`"trace_id":"[0-9a-f]{32}"`)

// normaliseTraceID replaces the field with a constant so the rest of the document
// can be compared byte for byte.
func normaliseTraceID(body string) string {
	return traceIDField.ReplaceAllString(body, `"trace_id":"<per-response>"`)
}

// TestBothSidesCarryAWellFormedTraceId is what the normalisation above is allowed
// to assume, and it is asserted on BOTH sides for every problem document compared.
//
// The normalisation would be a hole if it also hid a side that had LOST the field,
// or that emitted three of them, or that emitted something other than 32 hex
// characters. So the shape is checked here instead: every problem document both
// implementations produced in this run carries exactly one, it is 32 hex
// characters, and the `X-Trace-Id` header — which the comparison already requires
// to be present on both sides — matches it.
//
// Derived from the RUN rather than from a table of cases, so a document that stops
// being a problem document is caught rather than skipped.
func TestBothSidesCarryAWellFormedTraceId(t *testing.T) {
	bun, err := exec.LookPath("bun")
	if err != nil {
		skipOrFail(t, "bun is not on PATH, so the TypeScript reference cannot be stood up")
	}

	var checked, documents int
	for _, scenario := range scenarios {
		if !hasBrowserSurface(scenario) {
			// The three non-browser scenarios answer `404`, which is the v0 envelope
			// and carries no trace id at all. Saying so is the point: they are skipped
			// for a NAMEABLE reason rather than by a filename pattern.
			continue
		}

		options, err := optionsFor(scenario)
		if err != nil {
			t.Fatalf("%v", err)
		}
		referenceURL, stop := standUpReference(t, bun, scenario)
		goServer := httptest.NewServer(mustHandler(t, options))
		checked++

		specs, err := browserCases(t, canSignIn(scenario))
		if err != nil {
			t.Fatalf("%v", err)
		}
		for _, spec := range specs {
			for _, base := range []string{referenceURL, goServer.URL} {
				res := ask(t, base, spec)
				if !strings.Contains(res.headers.Get("Content-Type"), "problem+json") {
					continue
				}
				documents++

				matches := traceIDField.FindAllString(res.body, -1)
				if len(matches) != 1 {
					t.Errorf("%s %s against %s: %d trace_id field(s) in a problem document (%q), and it must be exactly one of 32 hex characters",
						spec.method, spec.path, base, len(matches), res.body)
					continue
				}
				value := strings.TrimSuffix(strings.TrimPrefix(matches[0], `"trace_id":"`), `"`)
				if header := res.headers.Get("X-Trace-Id"); header != value {
					t.Errorf("%s %s against %s: the body's trace_id is %s and the X-Trace-Id header is %q. core's conventions say they are the same value, and a mismatch is how a support ticket stops being traceable.",
						spec.method, spec.path, base, value, header)
				}
			}
		}

		goServer.Close()
		stop()
	}

	if checked == 0 || documents == 0 {
		t.Fatalf("checked %d browser scenario(s) and saw %d problem document(s). No trace_id was verified, and the normalisation in `diff` would then be hiding something it should not.", checked, documents)
	}
	t.Logf("trace id: %d problem document(s) across %d browser scenario(s), each with exactly one 32-hex trace_id matching its X-Trace-Id header", documents, checked)
}

func isScenario(name string) bool {
	for _, candidate := range scenarios {
		if candidate == name {
			return true
		}
	}
	return false
}
