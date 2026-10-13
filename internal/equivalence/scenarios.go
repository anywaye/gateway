// The Go scenarios: thirteen named configurations of the gateway, and
// `optionsFor`, the one function that knows what any of them IS.
//
// This file WAS the counterpart to `test/equivalence/reference.ts`, and the two
// were read by the same runner: a scenario name had to exist on both sides or the
// runner refused to start rather than comparing a scenario against nothing. The
// reference was removed at the cutover, so that half of the arrangement is gone and
// the file is now the only account of what each scenario is FOR.
//
// The names are declared here as data rather than in the scenarios themselves
// because a test needs to enumerate them, and a `switch` inside a builder is not
// something a caller can read the keys of. The table is the inventory and
// `inventorySize` is its asserted length.
//
// # WHICH SCENARIOS ARE STILL DRIVEN, AND WHY THE OTHERS ARE HERE
//
// Two of the thirteen are asked by the surviving limiter tests: `limitsExhausted`
// and `counterStoreDown`, because the limiter's refusal and its fail-open answer
// are the two decisions that outlived the comparison. The other eleven are not
// driven by anything today.
//
// They are kept rather than deleted, and the reason is that they are CONFIGURATIONS
// and not tests: each is a probe set or a route table or a scripted identity, and
// what a later packet would need in order to restore this coverage properly is a
// case list against these configurations rather than thirteen new scenarios. Which
// of them get cases, and what those cases assert without a reference to compare
// against, is the next packet's call and not this one's.
//
// # WHAT A SCENARIO CAN AND CANNOT DO
//
// A probe set and a route table — which is enough to exercise `/readyz`'s body,
// the pass-through's relayed answers, its two 503s, the refusals a path nobody
// claims, and (with a gate configured) the 401. It is not enough to exercise
// anything else Wave 3 owns, and that limit is stated in the report rather than
// discovered by a reader who assumed more.
package equivalence

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"time"

	"github.com/cafaye/gateway/internal/httpapi"
	"github.com/cafaye/gateway/internal/session"
	"github.com/cafaye/gateway/internal/sessiontest"
)

// Scenario names.
//
// There used to be a second list of these in TypeScript and a test holding the two
// equal by reading that one out of its source. That test is gone with the
// reference; what is left is this list, and `TestTheInventoryIsEveryScenario
// DeclaredAndNothingTwice` checks the one property still checkable about it — that
// every name in it is a configuration `optionsFor` can build.
const (
	// ScenarioBare is nothing configured: the two probes and nothing else.
	ScenarioBare = "bare"

	// ScenarioOneProbeOk is one dependency answering.
	ScenarioOneProbeOk = "oneProbeOk"

	// ScenarioProbesDegraded is three dependencies: one healthy, one refusing,
	// and one throwing. The refusal and the throw are the two shapes a healthy
	// scenario cannot reach, and the throw carries a host, a port and a
	// credential so the comparison can prove none of them reach a response body.
	ScenarioProbesDegraded = "probesDegraded"

	// ScenarioRoutedUpstream is a route table in front of a recording upstream and
	// **no credential gate** — which was the reference's own state when no `jwt`
	// option was configured. That absence was the point: it is the configuration in
	// which an anonymous request is *relayed*, so comparing it compared the
	// pass-through's own answers with nothing above them to soften a difference.
	ScenarioRoutedUpstream = "routedUpstream"

	// ScenarioGatedUpstream is the same table with a credential gate in front of
	// it, which is where the standing 401 comes from: an anonymous caller to a
	// private route, a public route that still answers, and a probe that still
	// answers.
	//
	// The Go side's gate refuses rather than verifies — verification is the auth
	// packet's — and that was enough, because what this scenario compared was the
	// **refusal and its position**, not the token check behind it. `jwt` was given
	// real values on the reference side and no request carried a credential, so the
	// reference answered 401 from its own gate without fetching a key set.
	ScenarioGatedUpstream = "gatedUpstream"

	// The browser surface, healthy. The scenario that compares the four
	// `/auth` routes end to end.
	ScenarioBff = "bff"

	// The ways identity can refuse or withdraw, each its own scenario because the
	// point of comparing them is that they must NOT look alike in the wrong places
	// and MUST look alike in the right one.
	ScenarioBffBadCredentials = "bffBadCredentials"
	ScenarioBffUnknownAccount = "bffUnknownAccount"
	ScenarioBffAccountLocked  = "bffAccountLocked"
	ScenarioBffIdentityBroken = "bffIdentityBroken"
	ScenarioBffWithdrawn      = "bffSessionWithdrawn"

	// The limiter's REFUSAL: a limiter at an allowance small enough that a burst
	// crosses it, with the clock frozen so the crossing is a function of the
	// request count and not of the wall clock.
	//
	// Every other scenario runs at an allowance no burst in this suite can reach,
	// so this is the only one that ever compared the `429` — its status, its
	// problem body, and the rate-limit headers ON the refusal — and it is now the
	// only one asked about a refusal at all. A client reads those, not the headers
	// on the requests that were admitted.
	ScenarioLimitsExhausted = "limitsExhausted"

	// The limiter over a counter store that cannot be reached, which FAILS OPEN:
	// served, uncounted, no rate-limit headers, and `/readyz` naming `redis`.
	//
	// A separate scenario from the refusal above, and the reason is the whole
	// point of both: one answers 429 and the other answers 200. A configuration
	// where they looked alike would be indistinguishable from a limiter that was
	// never mounted, so the two must not look alike.
	ScenarioCounterStoreDown = "counterStoreDown"
)

// scenarios is the inventory, and it used to be the order the runner drove them.
//
// THIRTEEN, and the last two are why: `limitsExhausted` and `counterStoreDown`
// were named by `worker/gateway-go-auth-01` and no case anywhere built on them,
// which is the same shape as a comment asserting a property the code does not have.
// The count is asserted rather than written down, in
// `TestTheInventoryIsEveryScenarioDeclaredAndNothingTwice`.
//
// The union is written out in full rather than assembled because the second list
// it was held against is gone. A scenario named here with no configuration behind
// it used to be caught by reading the TypeScript list and comparing the two; what
// replaces that is weaker and local: `TestTheInventory…` calls `optionsFor` for
// every name, so a name that is only a label is a failing gate rather than a
// silently unconfigured scenario. The first eleven grew that way for the same
// reason it was checked: the proxy packet added two and the BFF packet added five,
// from the same three, without either seeing the other.
var scenarios = []string{
	ScenarioBare,
	ScenarioOneProbeOk,
	ScenarioProbesDegraded,
	ScenarioRoutedUpstream,
	ScenarioGatedUpstream,
	ScenarioBff,
	ScenarioBffBadCredentials,
	ScenarioBffUnknownAccount,
	ScenarioBffAccountLocked,
	ScenarioBffIdentityBroken,
	ScenarioBffWithdrawn,
	ScenarioLimitsExhausted,
	ScenarioCounterStoreDown,
}

// The inventory length, asserted by name so a scenario added without moving this
// number is a failing gate rather than a summary line that quietly reads nine.
const inventorySize = 13

// The dependency names the degraded scenario registers, in the order both sides
// declare them.
//
// NOT ALPHABETICAL, and that is the whole point of the list. `/readyz` renders
// `deps` in registration order because `Options.Probes` is a slice rather than a
// map — and a `map[string]ProbeStatus` would render in the order
// `encoding/json` sorts keys. So the two orders are only distinguishable if the
// names are declared in an order that is not already sorted, and the first draft
// of this file used `aperture, identity, redis`, which IS sorted: a planted
// mutation swapping the hand-written ordering for `json.Marshal(api.Readiness)`
// then passed, and the property was untested. Found by planting the mutation and
// finding it did not fail, which is the only way to find this one.
const (
	degradedHealthy  = "redis"
	degradedRefusing = "identity"
	degradedThrowing = "aperture"
)

// The identity fixtures the browser scenarios script, with the expiry the BFF
// packet pinned and the day it runs out.
//
// `fixtureExpiry` HAS A SHELF LIFE and this is the second reader who needs to be
// told: the day 2027-01-15 passes, these scenarios begin failing on a DATE rather
// than on a defect, and the failure will look like a session bug. The literal is
// the fixture's to change and the comment is what stops the next reader treating
// a red run as a finding.
const (
	fixtureToken    = "identity-token-abcdef0123456789"
	fixtureUserID   = "11111111-2222-3333-4444-555555555555"
	fixtureEmail    = "a@example.test"
	fixtureExpiry   = "2027-01-15T09:00:00.000Z"
	fixtureIdentity = "http://identity.test"
)

// clock is the one time source in this package, so a scenario that signs in and
// then reads the session is not racing the wall clock between the two.
var clock = func() time.Time { return time.Now() }

// The route table both routed scenarios declare, in the same shape the reference
// builds from `GATEWAY_EQUIVALENCE_UPSTREAM`.
//
// Three entries and three different shapes, because a table with one entry per
// test proves one thing:
//
//   - `/v1/pantry` — no credential. An entry whose absence of a token is
//     meaningful: the upstream must see **no** `Authorization` at all.
//   - `/v1/pantry/imports` — a service credential. A nested prefix, so the longest
//     match wins, and the only entry whose `authorization` must be gateway's.
//   - `/v1/catalog` — `public: true`. No token and no claims, which is the shape
//     MD18 ruled and the only way to answer without a caller credential.
//
// No entry declares `principal` claims: the reference needs `ASSERTION_SIGNING_KEY_FILE`
// to mint assertions, and configuring one means a generated key on both sides and a
// `jti` that differs per mint — which cannot be compared byte for byte and would
// make the check compare noise. The assertion's four properties are covered by
// `internal/httpapi`'s own suite, where the claim set can be read; that limit is
// named in the report under what the comparison does not cover.
const (
	routePlain   = "/v1/pantry"
	routeTokened = "/v1/pantry/imports"
	routePublic  = "/v1/catalog"

	// serviceToken is the per-upstream credential a routed scenario is configured
	// with. It is a literal rather than a random value so a recorded request can be
	// compared for equality — and it was deliberately different from the caller's
	// token the deleted proxy cases carried, because "the caller's credential never
	// crosses" was the property the comparison was there for.
	serviceToken = "equivalence-service-token"
)

func routesFor(upstreamOrigin string) httpapi.RouteTable {
	return httpapi.RouteTable{
		routePlain:   {BaseURL: upstreamOrigin},
		routeTokened: {BaseURL: upstreamOrigin, Token: serviceToken},
		routePublic:  {BaseURL: upstreamOrigin, Public: true},
	}
}

// optionsFor builds the gateway configuration for one scenario, or an error
// naming the scenario it does not know.
//
// The error rather than a zero `Options`: a typo in a scenario name would
// otherwise compare an unconfigured gateway against a configured reference and
// report every difference, which is noise that hides the real ones. The runner
// checks the names against the inventory before calling this, and this checks
// again — two checks on one thing is cheap, and the second is the one that fails
// when the runner's list and this list are edited in different commits.
//
// `upstreamOrigin` is the recording upstream's base URL, and it is an argument
// rather than something read from the environment: the reference is a subprocess
// configured through its own environment, and a Go side that reached into its own
// would be a side configured differently from the other one.
func optionsFor(scenario, upstreamOrigin string) (httpapi.Options, error) {
	switch scenario {
	case ScenarioBare:
		// The zero value is the configuration, not a stand-in for one: with
		// nothing to probe there are no probes, and `/readyz` answers `{}` which
		// is what the document says that means.
		return httpapi.Options{}, nil

	case ScenarioOneProbeOk:
		return httpapi.Options{Probes: []httpapi.NamedProbe{
			{Name: "identity", Probe: alwaysOK},
		}}, nil

	case ScenarioProbesDegraded:
		return httpapi.Options{Probes: []httpapi.NamedProbe{
			{Name: degradedHealthy, Probe: alwaysOK},
			{Name: degradedRefusing, Probe: alwaysUnavailable},
			{Name: degradedThrowing, Probe: func(context.Context) error {
				// The shape of a dependency that is up and broken, which is the
				// case `AGENTS.md` calls out: a driver that answers 5xx reached
				// the readiness endpoint with no log line, so the message here
				// stands in for the detail that must never reach a caller.
				return errors.New("dial tcp://identity.internal:8080: connect: connection refused (password=hunter2)")
			}},
		}}, nil

	case ScenarioRoutedUpstream, ScenarioGatedUpstream:
		if upstreamOrigin == "" {
			return httpapi.Options{}, fmt.Errorf("equivalence: scenario %q needs a recording upstream and none was started, so every case below would compare a gateway that forwards nothing against one that forwards to nothing", scenario)
		}

		options := httpapi.Options{Probes: []httpapi.NamedProbe{{Name: degradedHealthy, Probe: alwaysOK}}, Routes: routesFor(upstreamOrigin)}
		if scenario == ScenarioGatedUpstream {
			// The refusal, not the verification. `internal/httpapi`'s own suite is
			// where the 401 is asserted in detail; here it is enough that a gate is
			// configured and that it refuses, because the reference's gate refuses
			// for the same reason and with the same envelope.
			options.Authenticate = func(*http.Request) (*httpapi.Principal, error) {
				return nil, errNoCredential
			}
		}
		return options, nil

	case ScenarioBff, ScenarioBffBadCredentials, ScenarioBffUnknownAccount,
		ScenarioBffAccountLocked, ScenarioBffIdentityBroken, ScenarioBffWithdrawn:
		return browserSurface(overridesFor(scenario))

	case ScenarioLimitsExhausted, ScenarioCounterStoreDown:
		if upstreamOrigin == "" {
			return httpapi.Options{}, fmt.Errorf("equivalence: scenario %q needs a recording upstream and none was started, so the limiter's own answer would be compared against a gateway that forwarded nothing", scenario)
		}

		limiter, err := limiterFor(scenario)
		if err != nil {
			return httpapi.Options{}, fmt.Errorf("equivalence: scenario %q: %w", scenario, err)
		}

		// `redis` in both, deliberately: it is the name the store has in a
		// deployment, and it is the name `/readyz` must use so the gap between
		// "served" and "unlimited" is visible rather than silent. The two scenarios
		// differ only in whether that probe answers.
		options := httpapi.Options{
			Probes:  []httpapi.NamedProbe{{Name: degradedHealthy, Probe: probeFor(scenario)}},
			Routes:  routesFor(upstreamOrigin),
			Limiter: limiter,
		}
		return options, nil

	default:
		return httpapi.Options{}, fmt.Errorf("equivalence: no Go scenario named %q; known: %v", scenario, scenarios)
	}
}

func alwaysOK(context.Context) error          { return nil }
func alwaysUnavailable(context.Context) error { return errors.New("unavailable") }

var errNoCredential = errors.New("no bearer token")

// --------------------------------------------------------------------------
// the recording upstream
// --------------------------------------------------------------------------

// upstreamAnswer is one recorded request, plus the response the upstream gave it.
type upstreamAnswer struct {
	Method string
	// The path as the upstream SAW it — `EscapedPath`, because a segment that
	// reached the service re-encoded is the whole point of the comparison and
	// decoding it here would hide the difference between `a%2Fb` and `a/b`.
	Path  string
	Query string

	// The headers this check compares. Not the whole block: `Accept-Encoding`,
	// `User-Agent` and `Connection` are written by the two transports rather than
	// by either gateway, and comparing them would compare `net/http` with undici.
	Header http.Header

	Body string

	// Status, Content-Type and Set-Cookie as the upstream sent them, so a case can
	// be chosen to produce a 3xx, a 5xx or a cookie and the comparison is the same
	// comparison either way.
	Status      int
	ContentType string
	SetCookie   []string
}

// upstream is the service both gateways are pointed at.
//
// It is a real socket and it is shared: both sides talk to the **same** process, so
// "the same request reached the same upstream" is a comparison and not two
// inferences. Answers are keyed off the path so a case can ask for a 500 or a
// redirect without either gateway knowing the difference.
type upstream struct {
	server *httptest.Server

	mu      sync.Mutex
	last    upstreamAnswer
	arrived int
}

func startUpstream(t interface {
	Fatalf(string, ...any)
	Cleanup(func())
}) *upstream {
	u := &upstream{}
	u.server = httptest.NewServer(http.HandlerFunc(u.serve))
	t.Cleanup(u.server.Close)

	return u
}

// Origin is the base URL to put in both sides' route table.
func (u *upstream) Origin() string { return u.server.URL }

// take returns what the upstream last received and forgets it, so one case's
// record cannot be mistaken for the next one's.
//
// Forgetting rather than merely reading is deliberate: a check that compares two
// records and finds them equal because both are the *same* first request has
// compared nothing, and that failure looks exactly like a pass.
func (u *upstream) take(t interface{ Fatalf(string, ...any) }) (upstreamAnswer, bool) {
	u.mu.Lock()
	defer u.mu.Unlock()

	if u.arrived == 0 {
		return upstreamAnswer{}, false
	}
	u.arrived = 0
	return u.last, true
}

// count is how many requests the upstream has received since the last `take` or
// `count`, and it forgets them too.
//
// A separate method rather than a loop over `take` because the upstream records
// the LAST request and a counter: `take` therefore reports one request per call
// however many arrived, so asking "how many requests did this burst spend on the
// service" by calling it until it stops empty measures the number of calls. That
// is the count a case about relaying wants to be wrong about, silently.
func (u *upstream) count() int {
	u.mu.Lock()
	defer u.mu.Unlock()

	arrived := u.arrived
	u.arrived = 0
	return arrived
}

func (u *upstream) serve(w http.ResponseWriter, r *http.Request) {
	body := make([]byte, 0)
	if r.Body != nil {
		buffered := make([]byte, 4096)
		for {
			read, err := r.Body.Read(buffered)
			body = append(body, buffered[:read]...)
			if err != nil {
				break
			}
		}
	}

	recorded := upstreamAnswer{
		Method: r.Method,
		Path:   r.URL.EscapedPath(),
		Query:  r.URL.RawQuery,
		Header: r.Header.Clone(),
		Body:   string(body),
	}

	// The answers, by the last segment. A path the table does not know about never
	// arrives here, so the set is small and every one of it is a status the
	// pass-through has an opinion about.
	switch {
	case strings.HasSuffix(r.URL.EscapedPath(), "/boom"):
		// A 5xx carrying the platform's own topology and a credential, so the
		// comparison can prove none of it reaches the caller or the problem body.
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusInternalServerError)
		recorder(w, `<html>dial tcp 10.0.3.7:8080: token=cafaye_equivalence_secret</html>`)

	case strings.HasSuffix(r.URL.EscapedPath(), "/redirect"):
		w.Header().Set("Location", "/ok")
		w.WriteHeader(http.StatusFound)
		recorder(w, "moved")

	case strings.HasSuffix(r.URL.EscapedPath(), "/unauthorized"):
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusUnauthorized)
		recorder(w, `{"code":"unauthorized","detail":"the service refuses this caller"}`)

	case strings.HasSuffix(r.URL.EscapedPath(), "/notfound"):
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusNotFound)
		recorder(w, `{"code":"not_found","detail":"no such service"}`)

	case strings.HasSuffix(r.URL.EscapedPath(), "/nocontenttype"):
		// The one header this package cannot express through `Header().Set`: a key
		// present with no values, which is how a response with no content type at
		// all is written. Used to compare a relay that does not invent one.
		w.Header()["Content-Type"] = []string{}
		w.WriteHeader(http.StatusOK)
		recorder(w, `untyped on purpose`)

	default:
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Set-Cookie", "__Host-bff-session=written-from-behind-the-edge; Path=/; Secure")
		w.WriteHeader(http.StatusOK)
		recorder(w, `{"ok":true}`)
	}

	recorded.Status = statusOf(w)
	recorded.ContentType = w.Header().Get("Content-Type")
	recorded.SetCookie = w.Header().Values("Set-Cookie")

	u.mu.Lock()
	u.last = recorded
	u.arrived++
	u.mu.Unlock()
}

// statusOf reads back the status the upstream answered, which `httptest`'s
// recorder keeps for exactly this. There is no other way to say "the status this
// case produced" without keeping a second answer path, and a case that chose its
// status twice could choose two different ones.
func statusOf(w http.ResponseWriter) int {
	recorder, ok := w.(*httptest.ResponseRecorder)
	if !ok {
		return 0
	}
	return recorder.Code
}

func recorder(w http.ResponseWriter, body string) {
	_, _ = w.Write([]byte(body))
}

// identityAnswer is one scripted identity response.
type identityAnswer struct {
	status  int
	body    string
	headers map[string]string
}

// overridesFor is the ONE place that says what identity answers in each browser
// scenario, and `optionsFor` and `canSignIn` both read it.
//
// One source for both, and the reason is a bug the split would have caused: the
// first version had the overrides inline in `optionsFor` and derived `canSignIn`
// from the scenario NAME. Those are two lists of the same fact, so a scenario that
// stopped refusing a login kept being asked the signed-in cases, `signIn` failed,
// and the comparison reported a failure about the sign-in helper rather than about
// the case that was no longer meaningful.
func overridesFor(scenario string) map[string]identityAnswer {
	switch scenario {
	case ScenarioBffBadCredentials:
		return map[string]identityAnswer{
			"/v1/session": {status: http.StatusUnauthorized, body: `{"error":"invalid_credentials","detail":"that password is not correct"}`},
		}
	case ScenarioBffUnknownAccount:
		return map[string]identityAnswer{
			"/v1/session": {status: http.StatusUnauthorized, body: `{"error":"no_such_user","detail":"no account has that email address"}`},
		}
	case ScenarioBffAccountLocked:
		return map[string]identityAnswer{
			"/v1/session": {status: http.StatusLocked, body: `{"error":"account_locked"}`, headers: map[string]string{"Retry-After": "900"}},
		}
	case ScenarioBffIdentityBroken:
		// Up and answering 500, which is the outage shape `unusable()` exists for
		// and the one that must NOT collapse into `unreachable()`.
		return map[string]identityAnswer{
			"/v1/session": {status: http.StatusInternalServerError, body: `<html>identity: undefined is not a function</html>`},
			"/v1/me":      {status: http.StatusInternalServerError, body: `<html>identity: undefined is not a function</html>`},
			"/healthz":    {status: http.StatusInternalServerError},
		}
	case ScenarioBffWithdrawn:
		return map[string]identityAnswer{
			"/v1/me": {status: http.StatusUnauthorized, body: `{"error":"unauthorized"}`},
		}
	default:
		return nil
	}
}

// browserSurface is a gateway with the four `/auth` routes mounted and identity
// scripted.
//
// The store is STILL `sessiontest`, the fixture, and the reason is a property of
// what these scenarios were FOR rather than an absence.
//
// A browser scenario drove the Go gateway and the TypeScript reference at the same
// requests and compared the bytes. The reference's store was `memorySessionStore()`,
// a `Map`, so for the two sides to be comparable the Go side had to be a
// per-process map too: swapping in Redis here would have made the Go side depend on
// a server the reference does not have, and a scenario that cannot run is not a
// comparison.
//
// So these scenarios compared the PORT's answers given a working store, and they
// never could say what a deployment would put behind one. That limit is unchanged
// by `internal/sessionredis` existing, and it is stated here rather than discovered
// by a reader who assumed more: the shipped store is proved in
// `internal/httpapi/runtime_session_test.go`, against a real `redis-server`, and it
// is proved on its own terms rather than by comparison — because comparison is the
// one method that cannot reach it while the reference is a `Map`.
func browserSurface(overrides map[string]identityAnswer) (httpapi.Options, error) {
	return httpapi.Options{BFF: &httpapi.BffOptions{
		IdentityURL: fixtureIdentity,
		Sessions:    sessiontest.New(clock),
		Doer:        scriptedDoer(overrides),
		Now:         clock,
	}}, nil
}

// scriptedDoer is the TypeScript reference's `scriptedIdentity` (removed at
// cutover), in Go.
//
// Keyed on the path rather than switching on it, so an override is exactly one
// route — the same shape the reference used, because a `switch` with a shared
// `default` is how a scenario meant to break one route ends up breaking another.
func scriptedDoer(overrides map[string]identityAnswer) httpapi.Doer {
	return doerFunc(func(r *http.Request) (*http.Response, error) {
		if override, overridden := overrides[r.URL.Path]; overridden {
			return override.response(), nil
		}
		return defaultIdentityAnswer(r.URL.Path).response(), nil
	})
}

func defaultIdentityAnswer(path string) identityAnswer {
	switch path {
	case "/healthz":
		return identityAnswer{status: http.StatusOK}
	case "/v1/session":
		return identityAnswer{status: http.StatusOK, body: `{"token":"` + fixtureToken + `","expires_at":"` + fixtureExpiry + `"}`}
	case "/v1/me":
		return identityAnswer{status: http.StatusOK, body: `{"id":"` + fixtureUserID + `","email":"` + fixtureEmail + `"}`}
	case "/v1/users":
		return identityAnswer{status: http.StatusCreated, body: `{"id":"` + fixtureUserID + `","email":"` + fixtureEmail + `"}`}
	default:
		return identityAnswer{status: http.StatusNotFound, body: `{}`}
	}
}

func (a identityAnswer) response() *http.Response {
	header := http.Header{"Content-Type": []string{"application/json"}}
	for name, value := range a.headers {
		header.Set(name, value)
	}
	return &http.Response{StatusCode: a.status, Header: header, Body: io.NopCloser(strings.NewReader(a.body))}
}

// doerFunc turns a function into a `Doer`, which is the only thing this package
// needs of one.
type doerFunc func(r *http.Request) (*http.Response, error)

func (f doerFunc) Do(r *http.Request) (*http.Response, error) { return f(r) }

// theCookie is the session cookie name, read out of the service rather than
// written here, so a rename cannot make this package compare a cookie nobody sets.
var _ = httpapi.SessionCookie

// theStoreIsTheFixture states the limitation in the type system as far as it can:
// `session.Session` is what the interface hands back, and this package never sees
// the token except through the interface.
var _ session.SessionStore = sessiontest.New(nil)
