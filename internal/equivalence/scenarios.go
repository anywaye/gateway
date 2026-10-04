// The Go scenarios, and the one place the equivalence check is told what the Go
// gateway is configured with for each of them.
//
// This file is the counterpart to `test/equivalence/reference.ts`, and the two
// are read by the same runner: a scenario name in `TestTheGoSideHasAnAnswerFor
// EveryScenarioTheReferenceHas` must exist on both sides, or the runner refuses
// to start rather than comparing a scenario against nothing.
//
// The names are declared here as data rather than in the scenarios themselves
// because the test needs to enumerate them, and a `switch` inside a builder is
// not something a caller can read the keys of. `optionsFor` is the only function
// that knows what any scenario IS; the table above it is the inventory.
//
// # WHAT A SCENARIO CAN AND CANNOT DO
//
// A probe set AND a browser surface, and nothing else. The limiter, the JWT
// verifier and the pass-through are other packets, so a scenario cannot drive
// them; what it CAN drive is every operation whose answer this repository can now
// produce, which is all seven of them.
//
// # THE FIXTURES ARE THE SAME FIXTURES, IN TWO LANGUAGES
//
// Every id, token and expiry below is a literal, and it is the SAME literal as in
// `reference.ts`. That is deliberate and it is the reason the comparison can be
// byte equality: a login body carries `expires_at`, so a relative expiry would
// render differently on each side and fail for a reason that is not a port
// defect. Nothing here is random and nothing is relative to now.
//
// `TestTheTwoSidesAgreeOnEverySharedFixture` reads BOTH files and compares the
// literals, because a fixture that drifted is a difference that reads as a port
// defect and is not one — and that check is what stops the next person who edits
// one file from spending an afternoon on the other.
package equivalence

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/cafaye/gateway/internal/httpapi"
	"github.com/cafaye/gateway/internal/session"
	"github.com/cafaye/gateway/internal/sessiontest"
)

// Scenario names. Both sides' lists are the same nine, and
// `TestTheGoSideHasAnAnswerForEveryScenarioTheReferenceHas` holds them equal by
// reading the reference's.
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

	// The browser surface, healthy. The scenario that compares the four
	// `/auth` routes end to end.
	ScenarioBff = "bff"

	// The four ways identity can refuse or withdraw, each its own scenario
	// because the point of comparing them is that they must NOT look alike in the
	// wrong places and MUST look alike in the right one.
	ScenarioBffBadCredentials = "bffBadCredentials"
	ScenarioBffUnknownAccount = "bffUnknownAccount"
	ScenarioBffAccountLocked  = "bffAccountLocked"
	ScenarioBffIdentityBroken = "bffIdentityBroken"
	ScenarioBffWithdrawn      = "bffSessionWithdrawn"
)

// scenarios is the inventory, in the order the runner drives them.
var scenarios = []string{
	ScenarioBare,
	ScenarioOneProbeOk,
	ScenarioProbesDegraded,
	ScenarioBff,
	ScenarioBffBadCredentials,
	ScenarioBffUnknownAccount,
	ScenarioBffAccountLocked,
	ScenarioBffIdentityBroken,
	ScenarioBffWithdrawn,
}

// hasBrowserSurface is the derived set of scenarios that configure a browser
// surface, and it is what the case list is built from.
//
// DERIVED from the inventory rather than typed, because a scenario that mounts the
// browser surface but is not in this set is a scenario whose four `/auth` answers
// are compared as `404`s on both sides — a green that proves nothing about the
// surface it was written for. `TestEveryScenarioThatMountsTheSurfaceIsCompared` is
// the other direction.
func hasBrowserSurface(scenario string) bool {
	return strings.HasPrefix(scenario, "bff")
}

// The dependency names the degraded scenario registers, in the order both sides
// declare them.
//
// NOT ALPHABETICAL, and that is the whole point of the list. `/readyz` renders
// `deps` in registration order because `Options.Probes` is a slice rather than a
// map — and a `map[string]ProbeStatus` would render in the order `encoding/json`
// sorts keys. So the two orders are only distinguishable if the names are declared
// in an order that is not already sorted, and the first draft of this file used
// `aperture, identity, redis`, which IS sorted: a planted mutation swapping the
// hand-written ordering for `json.Marshal(api.Readiness)` then passed, and the
// property was untested. Found by planting the mutation and finding it did not
// fail, which is the only way to find this one.
const (
	degradedHealthy  = "redis"
	degradedRefusing = "identity"
	degradedThrowing = "aperture"
)

// FIXTURE. Same literals as `reference.ts`; see this file's header and
// `TestTheTwoSidesAgreeOnEverySharedFixture`.
const (
	fixtureToken    = "identity-token-abcdef0123456789"
	fixtureUserID   = "11111111-2222-3333-4444-555555555555"
	fixtureEmail    = "a@example.test"
	fixtureExpiry   = "2027-01-15T09:00:00.000Z"
	fixtureIdentity = "http://identity.test"
)

// WHY `fixtureExpiry` IS WHERE IT IS, AND WHY THAT IS A FINDING
//
// It has to be in a window, and the window is measured rather than chosen:
//
//   - LATER THAN THE WALL CLOCK, or the reference's own `memorySessionStore`
//     treats the record as already expired (`expiresAt <= now()`), answers `401`
//     where the Go store — which reads an injected clock — answers `200`, and the
//     comparison reports a difference that is about the date.
//   - WITHIN 400 DAYS OF THE WALL CLOCK, because `hono/cookie` REFUSES to
//     serialise a cookie whose expiry is more than 400 days out: it throws, and
//     the reference's `onError` turns that into a `500 {"error":"internal_error"}`.
//     The Go port serves the same login `200`, because `net/http` has no such cap.
//
// So this is a REAL divergence between the two implementations, and it is not a
// porting mistake on either side: the reference cannot issue a session longer than
// about a year, and the Go service can. Whether the Go service SHOULD is a
// decision about session lifetimes, not a porting detail, and the packet's report
// is where it goes rather than a line changed here to make a check green.
//
// 2027-01-15 is roughly three months after this was written and comfortably inside
// the 400-day cap. When it passes, both sides will agree that the session is
// expired — except the Go store's clock is injected and fixed, so this fixture
// WILL start failing on 2027-01-15 and needs a new literal. That is stated here
// rather than discovered, and `TestTheFixtureExpiryIsInsideTheReferenceCookieWindow`
// is what says so out loud.
const (
	// fixtureExpiryWindow is the cap `hono/cookie` enforces, in days. 400.
	fixtureExpiryWindowDays = 400
)

// now is the clock every browser-surface scenario is built with.
//
// REAL, not fixed, and the reason is the window above: the reference's session
// store reads `Date.now()`, so the two sides only agree about a session's
// liveness if the Go side reads the same clock the reference does. A fixed Go
// clock makes every fixture expiry a bet on what year it is.
// `clock` is a function rather than a value so a test can replace it without
// reaching into the package's variables — and there is one such test, because the
// fixture window below is a real constraint with a real failure date.
var clock = func() time.Time { return time.Now() }

// optionsFor builds the gateway configuration for one scenario, or an error
// naming the scenario it does not know.
//
// The error rather than a zero `Options`: a typo in a scenario name would
// otherwise compare an unconfigured gateway against a configured reference and
// report every difference, which is noise that hides the real ones. The runner
// checks the names against the inventory before calling this, and this checks
// again — two checks on one thing is cheap, and the second is the one that fails
// when the runner's list and this list are edited in different commits.
func optionsFor(scenario string) (httpapi.Options, error) {
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

	case ScenarioBff, ScenarioBffBadCredentials, ScenarioBffUnknownAccount,
		ScenarioBffAccountLocked, ScenarioBffIdentityBroken, ScenarioBffWithdrawn:
		return browserSurface(overridesFor(scenario))

	default:
		return httpapi.Options{}, fmt.Errorf("equivalence: no Go scenario named %q; known: %v", scenario, scenarios)
	}
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

// canSignIn is whether a sign-in exchange succeeds in this scenario, DERIVED from
// the overrides rather than named.
//
// The signed-in cases — a correct session on the read, signing out with a live
// cookie — only mean anything where login works. Asking them where it does not
// would compare a `401` with a `401` and call it agreement about a session; and
// `signIn` failing loudly is the right answer with the wrong message.
func canSignIn(scenario string) bool {
	_, refused := overridesFor(scenario)["/v1/session"]
	return !refused
}

// browserSurface is a gateway with the four `/auth` routes mounted and identity
// scripted.
//
// The store is `sessiontest`, the fixture — this packet ships no session store and
// `internal/session` records why. So what these scenarios compare is the PORT's
// answers given a working store, and they cannot say anything about what a
// deployment would put behind one. That limit is stated here rather than
// discovered by a reader who assumed more.
func browserSurface(overrides map[string]identityAnswer) (httpapi.Options, error) {
	return httpapi.Options{BFF: &httpapi.BffOptions{
		IdentityURL: fixtureIdentity,
		Sessions:    sessiontest.New(clock),
		Doer:        scriptedDoer(overrides),
		Now:         clock,
	}}, nil
}

// scriptedDoer is `reference.ts`'s `scriptedIdentity`, in Go.
//
// Keyed on the path rather than switching on it, so an override is exactly one
// route — the same shape the reference uses, because a `switch` with a shared
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

func alwaysOK(context.Context) error          { return nil }
func alwaysUnavailable(context.Context) error { return errors.New("unavailable") }

// theCookie is the session cookie name, read out of the service rather than
// written here, so a rename cannot make this package compare a cookie nobody sets.
var _ = httpapi.SessionCookie

// theStoreIsTheFixture states the limitation in the type system as far as it can:
// `session.Session` is what the interface hands back, and this package never sees
// the token except through the interface.
var _ session.SessionStore = sessiontest.New(nil)
