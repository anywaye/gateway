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

	"github.com/anywaye/gateway/internal/httpapi"
	"github.com/anywaye/gateway/internal/session"
	"github.com/anywaye/gateway/internal/sessiontest"
)

const (
	ScenarioBare = "bare"

	ScenarioOneProbeOk = "oneProbeOk"

	ScenarioProbesDegraded = "probesDegraded"

	ScenarioRoutedUpstream = "routedUpstream"

	ScenarioGatedUpstream = "gatedUpstream"

	ScenarioBff = "bff"

	ScenarioBffBadCredentials = "bffBadCredentials"
	ScenarioBffUnknownAccount = "bffUnknownAccount"
	ScenarioBffAccountLocked  = "bffAccountLocked"
	ScenarioBffIdentityBroken = "bffIdentityBroken"
	ScenarioBffWithdrawn      = "bffSessionWithdrawn"

	ScenarioLimitsExhausted = "limitsExhausted"

	ScenarioCounterStoreDown = "counterStoreDown"
)

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

const inventorySize = 13

const (
	degradedHealthy  = "redis"
	degradedRefusing = "identity"
	degradedThrowing = "aperture"
)

const (
	fixtureToken    = "identity-token-abcdef0123456789"
	fixtureUserID   = "11111111-2222-3333-4444-555555555555"
	fixtureEmail    = "a@example.test"
	fixtureExpiry   = "2027-01-15T09:00:00.000Z"
	fixtureIdentity = "http://identity.test"
)

var clock = func() time.Time { return time.Now() }

const (
	routePlain   = "/v1/pantry"
	routeTokened = "/v1/pantry/imports"
	routePublic  = "/v1/catalog"

	serviceToken = "equivalence-service-token"
)

func routesFor(upstreamOrigin string) httpapi.RouteTable {
	return httpapi.RouteTable{
		routePlain:   {BaseURL: upstreamOrigin},
		routeTokened: {BaseURL: upstreamOrigin, Token: serviceToken},
		routePublic:  {BaseURL: upstreamOrigin, Public: true},
	}
}

func optionsFor(scenario, upstreamOrigin string) (httpapi.Options, error) {
	switch scenario {
	case ScenarioBare:
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
				return errors.New("dial tcp://identity.internal:8080: connect: connection refused (password=hunter2)")
			}},
		}}, nil

	case ScenarioRoutedUpstream, ScenarioGatedUpstream:
		if upstreamOrigin == "" {
			return httpapi.Options{}, fmt.Errorf("equivalence: scenario %q needs a recording upstream and none was started, so every case below would compare a gateway that forwards nothing against one that forwards to nothing", scenario)
		}

		options := httpapi.Options{Probes: []httpapi.NamedProbe{{Name: degradedHealthy, Probe: alwaysOK}}, Routes: routesFor(upstreamOrigin)}
		if scenario == ScenarioGatedUpstream {
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


type upstreamAnswer struct {
	Method string
	Path  string
	Query string

	Header http.Header

	Body string

	Status      int
	ContentType string
	SetCookie   []string
}

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

func (u *upstream) take(t interface{ Fatalf(string, ...any) }) (upstreamAnswer, bool) {
	u.mu.Lock()
	defer u.mu.Unlock()

	if u.arrived == 0 {
		return upstreamAnswer{}, false
	}
	u.arrived = 0
	return u.last, true
}

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

	switch {
	case strings.HasSuffix(r.URL.EscapedPath(), "/boom"):
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusInternalServerError)
		recorder(w, `<html>dial tcp 10.0.3.7:8080: token=anywaye_equivalence_secret</html>`)

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

type identityAnswer struct {
	status  int
	body    string
	headers map[string]string
}

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

func browserSurface(overrides map[string]identityAnswer) (httpapi.Options, error) {
	return httpapi.Options{BFF: &httpapi.BffOptions{
		IdentityURL: fixtureIdentity,
		Sessions:    sessiontest.New(clock),
		Doer:        scriptedDoer(overrides),
		Now:         clock,
	}}, nil
}

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

type doerFunc func(r *http.Request) (*http.Response, error)

func (f doerFunc) Do(r *http.Request) (*http.Response, error) { return f(r) }

var _ = httpapi.SessionCookie

var _ session.SessionStore = sessiontest.New(nil)
