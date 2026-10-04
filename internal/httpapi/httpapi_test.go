package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

// ask drives one request through a gateway built from `options`, and returns the
// recorder. Every assertion in this file goes through it, so there is one place
// that builds the handler under test and one place that would have to change if
// `New`'s shape did.
func ask(t *testing.T, options Options, method, path string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()

	handler, err := New(options)
	if err != nil {
		t.Fatalf("New(%+v) refused the configuration: %v", options, err)
	}

	var body io.Reader
	if method == http.MethodPost || method == http.MethodPut || method == http.MethodPatch {
		body = strings.NewReader("{}")
	}

	req := httptest.NewRequest(method, path, body)
	for name, value := range headers {
		req.Header.Set(name, value)
	}

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

// bare is the gateway with nothing configured, which is the configuration the
// TypeScript reference is stood up with by `internal/equivalence`. It is a
// function rather than a shared `Options` value because `Options` holds a slice
// and a shared slice is one careless `append` away from being mutated across
// tests.
func bare(t *testing.T) Options {
	t.Helper()
	return Options{}
}

// decode reads a JSON body into `into`, failing the test with both bodies if it
// does not fit. The message carries what was actually on the wire, because a
// failure that says "expected {deps:{}}" and nothing else makes the reader go
// and print it.
func decode(t *testing.T, rec *httptest.ResponseRecorder, into any) {
	t.Helper()

	if err := json.Unmarshal(rec.Body.Bytes(), into); err != nil {
		t.Fatalf("body is not the JSON this test asked for (%v)\n  status: %d\n  headers: %v\n  body: %s",
			err, rec.Code, rec.Header(), rec.Body.String())
	}
}

// --------------------------------------------------------------------------
// the two operations this packet serves
// --------------------------------------------------------------------------

func TestLivenessAnswersOkWithTheDocumentsShape(t *testing.T) {
	rec := ask(t, bare(t), http.MethodGet, "/healthz", nil)

	if rec.Code != http.StatusOK {
		t.Errorf("status is %d, want 200", rec.Code)
	}
	// The content type is asserted on every response in this file rather than on
	// the happy path only, because `AGENTS.md` names this: "`/readyz` returning
	// 200 with the wrong shape is a failure, not a pass", and a client that
	// branches on it cannot tell a v0 envelope from core's.
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type is %q, want application/json", got)
	}

	var body struct {
		Status string `json:"status"`
	}
	decode(t, rec, &body)

	if body.Status != "ok" {
		t.Errorf(`body is {"status":%q}, want {"status":"ok"}`, body.Status)
	}
	// Byte-for-byte, not field-by-field. The document declares `Health` with
	// `additionalProperties: false` and one field, so any other key is a document
	// violation that a struct decode into this shape would silently drop.
	if got := strings.TrimSpace(rec.Body.String()); got != `{"status":"ok"}` {
		t.Errorf("body is %s, want {\"status\":\"ok\"} exactly — a field the document does not declare", got)
	}
}

func TestReadinessWithNoProbesAnswersAnEmptyObjectNotNull(t *testing.T) {
	rec := ask(t, bare(t), http.MethodGet, "/readyz", nil)

	if rec.Code != http.StatusOK {
		t.Errorf("status is %d, want 200", rec.Code)
	}
	// `{"deps":null}` would satisfy a client that reads `deps.identity` and get
	// nothing; the document says an app with no probes answers `{}`.
	if got := strings.TrimSpace(rec.Body.String()); got != `{"deps":{}}` {
		t.Errorf("body is %s, want {\"deps\":{}}", got)
	}
}

func TestReadinessNamesTheDependencyThatIsDownAndNotWhyItIsDown(t *testing.T) {
	rec := ask(t, Options{Probes: []NamedProbe{
		{Name: "identity", Probe: func(context.Context) error { return nil }},
		// The message is the finding: it carries a host, a port and a
		// credential, and an unauthenticated caller must not be a way to learn
		// that a dependency's host sits at a particular address.
		{Name: "redis", Probe: func(context.Context) error {
			return errors.New("dial tcp://db.internal:5432: password=hunter2")
		}},
	}}, http.MethodGet, "/readyz", nil)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status is %d, want 503", rec.Code)
	}

	var body struct {
		Deps map[string]string `json:"deps"`
	}
	decode(t, rec, &body)

	if body.Deps["identity"] != "ok" {
		t.Errorf(`deps.identity is %q, want "ok" — one dependency being down does not say anything about the other`, body.Deps["identity"])
	}
	if body.Deps["redis"] != "unavailable" {
		t.Errorf(`deps.redis is %q, want "unavailable"`, body.Deps["redis"])
	}
	if len(body.Deps) != 2 {
		t.Errorf("deps has %d entries, want 2: a probe registered here and nowhere else", len(body.Deps))
	}
	if strings.Contains(rec.Body.String(), "db.internal") || strings.Contains(rec.Body.String(), "hunter2") {
		t.Errorf("the body leaked the dependency's address or credential: %s", rec.Body.String())
	}
}

// The ordering case, and it is the reason `Options.Probes` is a slice.
//
// `encoding/json` sorts map keys, so a `map[string]ProbeStatus` would answer
// `{"redis":"unavailable","identity":"ok"}` where the TypeScript reference
// answers `{"identity":"ok","redis":"unavailable"}`. Both are the same object and
// `internal/equivalence` compares the bytes, so this is a difference the port
// would have shipped. The assertion is on the byte string, not on the decoded
// map, because a decoded map has already thrown the order away.
func TestReadinessRendersDependenciesInTheOrderTheyWereRegistered(t *testing.T) {
	// Deliberately not alphabetical: `encoding/json` sorts map keys, so an
	// alphabetical expectation would be satisfied by the very implementation this
	// is written against.
	rec := ask(t, Options{Probes: []NamedProbe{
		{Name: "redis", Probe: alwaysOK},
		{Name: "identity", Probe: alwaysOK},
		{Name: "aperture", Probe: alwaysOK},
	}}, http.MethodGet, "/readyz", nil)

	got := strings.TrimSpace(rec.Body.String())
	want := `{"deps":{"redis":"ok","identity":"ok","aperture":"ok"}}`
	if got != want {
		t.Errorf("body is %s\nwant   %s\nThe order is the caller's, not the encoder's: Object.entries preserves insertion order in the reference and encoding/json sorts map keys.", got, want)
	}
}

func TestAProbeThatPanicsIsOneUnavailableDependency(t *testing.T) {
	rec := ask(t, Options{Probes: []NamedProbe{
		{Name: "identity", Probe: func(context.Context) error { panic("the driver exploded") }},
	}}, http.MethodGet, "/readyz", nil)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status is %d, want 503 — a probe that panics is unavailable, not a dead process", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "exploded") {
		t.Errorf("the body leaked the panic value: %s", rec.Body.String())
	}
}

// The boundedness case. `src/probe.ts` puts *hangs* in the list of things a
// probe may do that mean "unavailable", and a `context.Context` a probe may
// ignore is not a bound on one — so `runProbe` supplies the deadline. This is
// the only test that lowers `probeTimeout`, and it restores it.
func TestAProbeThatIgnoresItsContextIsStillBounded(t *testing.T) {
	restore := probeTimeout
	probeTimeout = 50 * time.Millisecond
	t.Cleanup(func() { probeTimeout = restore })

	// A probe that neither looks at its context nor returns: the shape that
	// would hang a request forever.
	blocked := make(chan struct{})
	t.Cleanup(func() { close(blocked) })

	done := make(chan int, 1)
	go func() {
		done <- ask(t, Options{Probes: []NamedProbe{
			{Name: "identity", Probe: func(context.Context) error {
				<-blocked
				return nil
			}},
		}}, http.MethodGet, "/readyz", nil).Code
	}()

	select {
	case code := <-done:
		if code != http.StatusServiceUnavailable {
			t.Errorf("status is %d, want 503 — a probe that hangs is one unavailable dependency", code)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("/readyz did not answer within 10s while a probe ignored its context: the timeout is not being applied")
	}
}

func TestTheTimeoutIsOnlyEverLoweredInATest(t *testing.T) {
	// `probeTimeout` is a variable so one test can run in milliseconds. A
	// variable is a hole, so this closes it: the only assignment outside the
	// declaration is in this package's own tests, and one in production code
	// would be a deadline an operator could not see.
	assigned := regexp.MustCompile(`(?m)^\s*(probeTimeout\s*=|const probeTimeout)`)

	for _, name := range packageFiles(t) {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		if assigned.MatchString(read(t, name)) {
			t.Errorf("%s assigns probeTimeout. It is a variable so one test can lower it; production code changing it would be a deadline an operator cannot see.", name)
		}
	}
}

// --------------------------------------------------------------------------
// the refusals
// --------------------------------------------------------------------------

// Every route refusal answers the v0 envelope, and the three shapes it can take
// — an unknown path, a path with a trailing segment, and a method the route does
// not serve — all produce the SAME bytes. The method case is the one that is a
// decision rather than an inheritance: chi's default is a `405` with an empty
// body, and the TypeScript reference has no 405 at all, so `New` points
// `MethodNotAllowed` at the same writer as `NotFound`.
func TestEveryRouteRefusalIsTheV0NotFoundEnvelope(t *testing.T) {
	const wantBody = `{"error":"not_found","message":"no such route"}`

	cases := []struct {
		name   string
		method string
		path   string
	}{
		{"an unknown path", http.MethodGet, "/nope"},
		{"the root", http.MethodGet, "/"},
		{"a path with a trailing segment", http.MethodGet, "/healthz/extra"},
		{"a path with a trailing slash", http.MethodGet, "/healthz/"},
		{"a doubled slash", http.MethodGet, "//healthz"},
		{"a path in the wrong case", http.MethodGet, "/HEALTHZ"},
		{"a post to a probe", http.MethodPost, "/healthz"},
		{"a delete to a probe", http.MethodDelete, "/readyz"},
		{"an options to a probe", http.MethodOptions, "/healthz"},
		{"a get to a mutating operation", http.MethodGet, "/auth/login"},
		{"a post to the principal route", http.MethodPost, "/v1/me"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := ask(t, bare(t), tc.method, tc.path, nil)

			if rec.Code != http.StatusNotFound {
				t.Errorf("status is %d, want 404 — chi answers 405 for a method mismatch and Hono answers 404, and the contract declares only the second", rec.Code)
			}
			if got := rec.Header().Get("Content-Type"); got != "application/json" {
				t.Errorf("Content-Type is %q, want application/json — the v0 envelope is not core's problem document", got)
			}
			if got := strings.TrimSpace(rec.Body.String()); got != wantBody {
				t.Errorf("body is %s, want %s", got, wantBody)
			}
		})
	}
}

// `HEAD /healthz` answers `200` with an empty body on the TypeScript reference,
// because Hono routes `HEAD` to the `GET` handler. chi does not, so this is a
// registration rather than an inheritance, and it is on the two probe paths
// rather than everywhere: HEAD is how an orchestrator and a health checker ask,
// and a gateway that answers 404 to `HEAD /healthz` is a process that looks
// dead to the tool whose job is to notice it is alive.
func TestHeadOnAProbePathAnswersTheSameAsGet(t *testing.T) {
	for _, path := range sortedKeys(ProbePaths) {
		t.Run(path, func(t *testing.T) {
			rec := ask(t, bare(t), http.MethodHead, path, nil)

			if rec.Code != http.StatusOK {
				t.Errorf("HEAD %s is %d, want 200 — the reference answers 200, having routed HEAD to the GET handler", path, rec.Code)
			}
			if got := rec.Header().Get("Content-Type"); got != "application/json" {
				t.Errorf("Content-Type is %q, want application/json", got)
			}
			if rec.Body.Len() != 0 {
				t.Errorf("HEAD %s has a body (%q); a HEAD answer carries headers only", path, rec.Body.String())
			}
		})
	}
}

// The five operations this packet does not serve, and the two it does. Both
// halves are named lists, which is what makes an operation ADDED to the document
// a failure rather than a silence: `openapi/v1.yaml` gaining an eighth operation
// puts a route on the router that appears in neither list, and this test says so.
func TestEveryOperationIsEitherServedOrDeclined(t *testing.T) {
	// What each operation answers with a gateway built with nothing configured,
	// and WHY. `served` is its own answer; `declined` is the reference's answer
	// for an operation it does not register either.
	served := map[string]string{
		"GET /healthz": `{"status":"ok"}`,
		"GET /readyz":  `{"deps":{}}`,
	}
	declined := map[string]string{
		// `GET /v1/me` — the bearer-token gate is Wave 3, and
		// `src/index.ts` does not register the route without a verifier.
		"GET /v1/me": `{"error":"not_found","message":"no such route"}`,
		// The four `/auth` routes — the BFF and the session store are Wave 3, and
		// `src/index.ts` does not register them without an identity to ask.
		"POST /auth/register": `{"error":"not_found","message":"no such route"}`,
		"POST /auth/login":    `{"error":"not_found","message":"no such route"}`,
		"POST /auth/logout":   `{"error":"not_found","message":"no such route"}`,
		"GET /auth/me":        `{"error":"not_found","message":"no such route"}`,
	}

	// `HEAD` is excluded here and held separately by
	// `TestHeadOnAProbePathAnswersTheSameAsGet` and `TestTheHeadRoutesAreTheProbePaths`:
	// it is not an operation the document declares, and `New` registers it.
	routes := servedRoutes(t)
	for _, route := range routes {
		if route.method == http.MethodHead {
			continue
		}
		method, path := route.method, route.path
		want, ok := served[method+" "+path]
		if !ok {
			want, ok = declined[method+" "+path]
		}
		if !ok {
			t.Errorf("%s %s is on the router and in neither list: an operation added to openapi/v1.yaml has to be decided — served, or declined with the reference's answer.", method, path)
			continue
		}

		rec := ask(t, bare(t), method, path, nil)
		if got := strings.TrimSpace(rec.Body.String()); got != want {
			t.Errorf("%s %s answered %s\nwant %s", method, path, got, want)
		}
	}
}

// --------------------------------------------------------------------------
// configuration arrives as an argument
// --------------------------------------------------------------------------

// The property `guard/AGENTS.md` asks for, in the form the Go port can lose: two
// differently-configured gateways in ONE process, each answering for itself.
func TestTwoAppsCoexistInOneProcess(t *testing.T) {
	healthy := Options{Probes: []NamedProbe{
		{Name: "identity", Probe: alwaysOK},
	}}
	degraded := Options{Probes: []NamedProbe{
		{Name: "identity", Probe: alwaysUnavailable},
		{Name: "redis", Probe: alwaysOK},
	}}

	if got := strings.TrimSpace(ask(t, healthy, http.MethodGet, "/readyz", nil).Body.String()); got != `{"deps":{"identity":"ok"}}` {
		t.Errorf("the first app answered %s", got)
	}
	if got := strings.TrimSpace(ask(t, degraded, http.MethodGet, "/readyz", nil).Body.String()); got != `{"deps":{"identity":"unavailable","redis":"ok"}}` {
		t.Errorf("the second app answered %s", got)
	}
	// And the first is unchanged afterwards, which is the part a package-level
	// global would get wrong.
	if got := strings.TrimSpace(ask(t, healthy, http.MethodGet, "/readyz", nil).Body.String()); got != `{"deps":{"identity":"ok"}}` {
		t.Errorf("the first app answered %s on its second call — one app's configuration reached the other", got)
	}
}

// The check rather than the promise. Go gives a package no way to say "I do not
// read the environment", and `os.Getenv` is available to any package at any
// time — so this reads the sources instead.
//
// It is scoped rather than absolute: `env.go` DOES call `os.Getenv`, once, and
// that is the reader every other value in this package comes from. What has to
// hold is that no second call site exists anywhere, because the property being
// protected is not "the environment is never read" — `cmd/gateway` has to read it
// somewhere — it is that there is exactly one place that does.
func TestExactlyOneFileInThisPackageTouchesTheProcessEnvironment(t *testing.T) {
	// `runtime.go`'s own doc comment names `os.Getenv` in prose, and
	// `env.go`'s header names `Bun.env`, so the pattern matches a line rather
	// than a call: only an actual invocation counts as a second reader.
	callers := regexp.MustCompile(`\bos\.(Getenv|LookupEnv|Environ)\s*\(`)
	const reader = "env.go"

	found := map[string]int{}
	for _, name := range packageFiles(t) {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		found[name] = len(callers.FindAllString(read(t, name), -1))
	}

	if sites := found[reader]; sites != 1 {
		t.Errorf("%s has %d call site(s) reading the process environment, want exactly 1. The reader is a function and not a default value precisely so this number can be held.", reader, sites)
	}

	var others []string
	for name, sites := range found {
		if name != reader && sites > 0 {
			others = append(others, name)
		}
	}
	if len(others) > 0 {
		sort.Strings(others)
		t.Errorf("%v call os.Getenv. Configuration arrives as an argument: the environment is read through the `Env` reader in %s, which takes its source as an argument.", others, reader)
	}
}

// TestRuntimeOptionsBuildsAnAddressAndHandsNewItsOptions is the reader's "and it
// produces a gateway" assertion.
//
// # WHAT CHANGED HERE, AND WHY IT IS NOT A DELETION
//
// The old version asserted `len(config.Options.Probes) == 0` — "nothing has been
// given a dependency to probe yet". That was true while `RuntimeOptions` built
// probes for no subsystems, and it is false now that the verifier and the counter
// store are ported: a gateway built from the environment registers `identity`, and
// `redis` when there is a `REDIS_URL`. The assertion moved to
// `TestTheProbeOrderIsIdentityThenRedis` rather than being dropped, because the
// thing it was actually about — a probe is registered only when a subsystem behind
// it exists — is still the property, and it is now a positive statement about two
// named probes rather than a count of zero.
//
// The `Routes` and `Assert` assertions stayed, and they are unchanged: an
// environment that names neither must still configure neither.
func TestRuntimeOptionsBuildsAnAddressAndHandsNewItsOptions(t *testing.T) {
	env := mapEnv(map[string]string{"PORT": "9001"})

	config, err := RuntimeOptions(env)
	if err != nil {
		t.Fatalf("RuntimeOptions refused a valid environment: %v", err)
	}
	t.Cleanup(config.CloseResources)

	if config.Addr != ":9001" {
		t.Errorf("Addr is %q, want :9001", config.Addr)
	}
	if config.Options.Routes != nil {
		t.Errorf("RuntimeOptions configured %+v from an environment that named no ROUTE_TABLE", config.Options.Routes)
	}
	if config.Options.Assert != nil {
		t.Error("RuntimeOptions configured a minter from an environment that named no signing key")
	}

	// And the handler built from that configuration answers, which is the point:
	// the port is how the process is reached and is not a handler option.
	rec := ask(t, config.Options, http.MethodGet, "/healthz", nil)
	if rec.Code != http.StatusOK {
		t.Errorf("the gateway built from RuntimeOptions answered %d on /healthz", rec.Code)
	}
}
func TestAnUnreadablePortIsARefusalToBoot(t *testing.T) {
	for _, raw := range []string{"abc", "0", "-1", "70000", "80 80", "8080.0", "1e3", ""} {
		t.Run(strconv.Quote(raw), func(t *testing.T) {
			config, err := RuntimeOptions(mapEnv(map[string]string{"PORT": raw}))

			want := raw != "" // empty is unset, and unset is the default
			if want == (err == nil) {
				t.Fatalf("PORT=%q gave err=%v, and %v", raw, err, map[bool]string{true: "it should be a refusal to boot", false: "it should be the default"})
			}
			if err != nil && !errors.Is(err, ErrNotConfigured) {
				t.Errorf("PORT=%q gave %v, which is not ErrNotConfigured — a caller cannot tell its own mistake from a defect", raw, err)
			}
			if err == nil && config.Addr != ":"+defaultPort {
				t.Errorf("PORT=%q gave Addr %q, want :%s — an empty variable is what an unset one looks like in a compose file", raw, config.Addr, defaultPort)
			}
		})
	}
}

// --------------------------------------------------------------------------
// invalid configuration is an error, not a fallback
// --------------------------------------------------------------------------

func TestAConfigurationItCannotServeIsRefusedAtConstruction(t *testing.T) {
	cases := []struct {
		name   string
		probes []NamedProbe
		why    string
	}{
		{
			name:   "a probe with no name",
			probes: []NamedProbe{{Probe: alwaysOK}},
			why:    `/readyz would render {"deps":{"":"ok"}}`,
		},
		{
			name:   "a probe with no function",
			probes: []NamedProbe{{Name: "identity"}},
			why:    "the dependency would answer unavailable forever, so a configuration mistake would read as an outage",
		},
		{
			name: "two probes with one name",
			probes: []NamedProbe{
				{Name: "identity", Probe: alwaysOK},
				{Name: "identity", Probe: alwaysUnavailable},
			},
			why: `/readyz can only report one "identity", and the second would silently win`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			handler, err := New(Options{Probes: tc.probes})

			if err == nil {
				t.Fatalf("New accepted it: %s", tc.why)
			}
			if handler != nil {
				t.Error("New returned a handler as well as an error; a refusal to serve must not hand back something servable")
			}
			if !errors.Is(err, ErrNotConfigured) {
				t.Errorf("err is %v, which is not ErrNotConfigured", err)
			}
		})
	}
}

func TestAValidConfigurationIsNotRefused(t *testing.T) {
	// The other direction, and it is the one that keeps the three refusals above
	// honest: a checker that only proves the rejections passes a `validate` that
	// refuses everything.
	for _, probes := range [][]NamedProbe{
		nil,
		{},
		{{Name: "identity", Probe: alwaysOK}},
		{{Name: "identity", Probe: alwaysOK}, {Name: "redis", Probe: alwaysOK}},
	} {
		if _, err := New(Options{Probes: probes}); err != nil {
			t.Errorf("New refused %d probe(s): %v", len(probes), err)
		}
	}
}

// --------------------------------------------------------------------------
// the fixtures
// --------------------------------------------------------------------------

func alwaysOK(context.Context) error          { return nil }
func alwaysUnavailable(context.Context) error { return errors.New("unavailable") }

// mapEnv is an `Env` over a table, which is how a test drives the reader without
// a process environment. This is the whole point of the `Env` argument: the
// production reader is `OSEnv` and this one is a map, and neither can reach the
// other.
func mapEnv(vars map[string]string) Env {
	return func(key string) string { return vars[key] }
}

// packageFiles is this package's own `.go` sources, derived from the directory
// rather than written down. A list in the source would go stale the day a file
// is added, and a check that reads a stale list reports a green over nothing.
func packageFiles(t *testing.T) []string {
	t.Helper()

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("cannot read this package's directory: %v", err)
	}

	var names []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".go") {
			names = append(names, entry.Name())
		}
	}
	if len(names) == 0 {
		t.Fatal("no .go files found in this package's directory, so the checks that read them are checking nothing")
	}

	sort.Strings(names)
	return names
}

// read reads a file by name, relative to this package's directory. Generated
// code and fixtures live outside it, so the callers say `../api/api.gen.go`.
func read(t *testing.T, name string) string {
	t.Helper()

	body, err := os.ReadFile(filepath.Clean(name))
	if err != nil {
		t.Fatalf("cannot read %s: %v", name, err)
	}
	return string(body)
}

func sortedKeys(set map[string]struct{}) []string {
	keys := make([]string, 0, len(set))
	for key := range set {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func sortedNames(set map[string]bool) []string {
	names := make([]string, 0, len(set))
	for name := range set {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
