package httpapi

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/cafaye/gateway/internal/ratelimit"
)

// The wiring, end to end: a gateway built by `RuntimeOptions` from an ENVIRONMENT,
// not from a hand-assembled `Options`.
//
// # WHY THIS FILE EXISTS AT ALL
//
// Every other test of the browser surface builds `Options{BFF: &bff}` with a
// `sessiontest` double, which proves the port and nothing about the deployment.
// The gap that let the Go service ship with no session store at all is exactly
// this one: nothing ever went from "these two variables are set" to "the four
// routes are served", so nobody could tell a store that was missing from a store
// that was configured and unused. `internal/sessiontest`'s guard proves the FIXTURE
// is not linked in; nothing proved a real store was.
//
// # A REAL REDIS, AND WHY IT IS NOT OPTIONAL HERE
//
// The store is exercised against a real `redis-server`, not a fake, because the
// fake cannot be wrong in the ways Redis is: a `SET` that does not report `OK`, a
// `GET` that answers `nil` where the fake answers `""`, a `PX` that Redis refuses.
// A green here means the wire commands are right.
//
// It runs in-process by EXECUTING `redis-server` on a free port, so it needs no
// environment variable and cannot be skipped — which is the property the
// environment-gated tiers in this repository had to be given three mechanisms to
// fake. There is no `GATEWAY_REDIS_URL` here and no skip: a developer with no
// Redis gets a failing test saying so, not a green about nothing.

// TestARuntimeGatewaySignsInAndReadsItsOwnSession is the packet's headline,
// asserted: the Go binary serves the browser surface from its own build.
//
// It asserts the whole exchange rather than a status — login, the cookie, `/me`
// with it, and a session that is gone after logout — because a store that accepted
// a `Put` and silently failed to answer a `Get` would pass a 200-on-login test and
// this is the assertion that catches it.
func TestARuntimeGatewaySignsInAndReadsItsOwnSession(t *testing.T) {
	identity := newIdentityStub(t)
	redisURL := startRedis(t)

	config, err := RuntimeOptions(mapEnv(map[string]string{
		"PORT":         "9107",
		"REDIS_URL":    redisURL,
		"IDENTITY_URL": identity.url,
	}))
	if err != nil {
		t.Fatalf("RuntimeOptions refused an environment with a browser surface configured: %v", err)
	}
	t.Cleanup(config.CloseResources)

	if config.Options.BFF == nil {
		t.Fatalf("IDENTITY_URL and REDIS_URL are both set and RuntimeOptions built no browser surface, so /auth/* answers the v0 404 on a configured deployment. That is the failure this file exists to make loud.")
	}

	handler, err := New(config.Options)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Login. Same-origin, because the origin gate is in front of the route and a
	// cross-origin POST is refused before any of this matters.
	login := send(t, handler, http.MethodPost, "/auth/login",
		`{"email":"a@example.test","password":"pw"}`, sameOrigin())
	if login.StatusCode != http.StatusOK {
		t.Fatalf("POST /auth/login answered %d, want 200. body: %s", login.StatusCode, readBody(t, login))
	}

	cookie := SessionCookie + "=" + sessionCookieValue(login)
	if sessionCookieValue(login) == "" {
		t.Fatalf("the login set no %s cookie: %v", SessionCookie, login.Header["Set-Cookie"])
	}
	if strings.Contains(readBody(t, login), identity.token) {
		t.Errorf("the login body carries the identity token, which is the whole thing the cookie exists to prevent: %s", readBody(t, login))
	}

	// `/me` with the cookie: the store is read, and the token is put in a Bearer
	// for identity. If the stored value did not survive the round trip, `/me`
	// answers 401 — which is why this is the assertion and not the login's 200.
	me := send(t, handler, http.MethodGet, "/auth/me", "", map[string]string{"Cookie": cookie})
	if me.StatusCode != http.StatusOK {
		t.Fatalf("GET /auth/me with a fresh cookie answered %d, want 200. body: %s", me.StatusCode, readBody(t, me))
	}
	if !strings.Contains(readBody(t, me), identity.email) {
		t.Errorf("/auth/me did not answer the signed-in account: %s", readBody(t, me))
	}

	// Logout, then the same cookie. A `Delete` that did nothing is the failure a
	// sign-out test has to make loud, because the browser has already discarded its
	// copy and the stale cookie is exactly what a stolen one looks like.
	out := send(t, handler, http.MethodPost, "/auth/logout", "", map[string]string{
		"Sec-Fetch-Site": "same-origin",
		"Cookie":         cookie,
	})
	if out.StatusCode != http.StatusNoContent && out.StatusCode != http.StatusOK {
		t.Fatalf("POST /auth/logout answered %d, want 204. body: %s", out.StatusCode, readBody(t, out))
	}
	after := send(t, handler, http.MethodGet, "/auth/me", "", map[string]string{"Cookie": cookie})
	if after.StatusCode != http.StatusUnauthorized {
		t.Errorf("GET /auth/me with a cookie the browser was just told to discard answered %d, want 401. A Delete that does not delete leaves a live session behind the only credential that names it", after.StatusCode)
	}
}

// TestASessionSurvivesTheProcessThatCreatedIt is the property the reference's
// `Map` cannot have, and the reason this store exists at all.
//
// A SECOND gateway is built from the same environment — a second replica — and it
// reads a session the FIRST one created. With a per-process store this is a 401,
// and it is a 401 that looks like a login bug and is debugged as one. So the
// assertion is made against a genuinely separate handler and a genuinely separate
// store instance, not by calling `Get` twice on one object.
func TestASessionSurvivesTheProcessThatCreatedIt(t *testing.T) {
	identity := newIdentityStub(t)
	redisURL := startRedis(t)
	vars := map[string]string{"PORT": "9108", "REDIS_URL": redisURL, "IDENTITY_URL": identity.url}

	first, err := RuntimeOptions(mapEnv(vars))
	if err != nil {
		t.Fatalf("RuntimeOptions: %v", err)
	}
	firstHandler, err := New(first.Options)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	login := send(t, firstHandler, http.MethodPost, "/auth/login",
		`{"email":"a@example.test","password":"pw"}`, sameOrigin())
	if login.StatusCode != http.StatusOK {
		t.Fatalf("the first gateway's login answered %d, want 200. body: %s", login.StatusCode, readBody(t, login))
	}
	cookie := SessionCookie + "=" + sessionCookieValue(login)

	// Replica two, built separately. Same environment, so it has its own handler,
	// its own store and its own connection — and the same Redis, which is the point.
	second, err := RuntimeOptions(mapEnv(vars))
	if err != nil {
		t.Fatalf("RuntimeOptions for the second replica: %v", err)
	}
	t.Cleanup(second.CloseResources)
	t.Cleanup(first.CloseResources)

	secondHandler, err := New(second.Options)
	if err != nil {
		t.Fatalf("New for the second replica: %v", err)
	}

	res := send(t, secondHandler, http.MethodGet, "/auth/me", "", map[string]string{"Cookie": cookie})
	if res.StatusCode != http.StatusOK {
		t.Errorf("a replica that did not serve the login answered %d for that session, want 200. A browser session stored per process is signed out by the load balancer's next choice, and the symptom reads as a login bug. body: %s", res.StatusCode, readBody(t, res))
	}
}

// TestANoStoreMeansNoBrowserSurfaceRatherThanADegradedOne.
//
// Three environments and one table. The middle one is the whole reason the row
// exists: `IDENTITY_URL` set with no `REDIS_URL` is a deployment that LOOKS
// configured and is not, and `README.md`'s own rule — "a variable an operator sets
// that changes nothing is worse than one they cannot set, because it looks
// configured and configures a 404" — is the one being obeyed here by declining.
func TestANoStoreMeansNoBrowserSurfaceRatherThanADegradedOne(t *testing.T) {
	for _, tc := range []struct {
		name        string
		vars        map[string]string
		wantSurface bool
	}{
		{"neither variable", map[string]string{"PORT": "9109"}, false},
		{"an identity but no shared store", map[string]string{"PORT": "9109", "IDENTITY_URL": "http://identity.test"}, false},
		{"a shared store but no identity", map[string]string{"PORT": "9109", "REDIS_URL": "redis://127.0.0.1:6379"}, false},
		{"both", map[string]string{"PORT": "9109", "REDIS_URL": "redis://127.0.0.1:6379", "IDENTITY_URL": "http://identity.test"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config, err := RuntimeOptions(mapEnv(tc.vars))
			if err != nil {
				t.Fatalf("RuntimeOptions: %v", err)
			}
			t.Cleanup(config.CloseResources)

			if got := config.Options.BFF != nil; got != tc.wantSurface {
				t.Fatalf("a browser surface was built: %v, want %v. A per-process store is the shape this packet exists to stop, so an IDENTITY_URL without a REDIS_URL configures nothing rather than something worse", got, tc.wantSurface)
			}
		})
	}
}

// # THE TWO BELOW ARE THE SILENCE THAT WAS THE BUG
//
// "no silent 404 on a configured browser surface" is a claim about what an
// OPERATOR SEES, and these two are the only places it can be checked: the routes
// themselves.

// TestAConfiguredBrowserSurfaceNeverDeclinesTheFourRoutes, at the routing layer,
// with nothing configured at all.
func TestAnUnconfiguredGatewayDeclinesTheFourRoutesAsTheReferenceDoes(t *testing.T) {
	config, err := RuntimeOptions(mapEnv(map[string]string{"PORT": "9110"}))
	if err != nil {
		t.Fatalf("RuntimeOptions: %v", err)
	}
	t.Cleanup(config.CloseResources)

	handler, err := New(config.Options)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	for _, spec := range []struct{ method, path string }{
		{http.MethodPost, "/auth/login"},
		{http.MethodPost, "/auth/register"},
		{http.MethodPost, "/auth/logout"},
		{http.MethodGet, "/auth/me"},
	} {
		res := send(t, handler, spec.method, spec.path, "{}", sameOrigin())
		if res.StatusCode != http.StatusNotFound {
			t.Errorf("%s %s with no browser surface answered %d, want 404 — which is what `createApp({})` gives", spec.method, spec.path, res.StatusCode)
		}
	}
}

// TestAConfiguredBrowserSurfaceAnswersItsOwnRoutesRatherThanDecliningThem is the
// direct statement of the headline, and it is deliberately in this file rather than
// derived from the one above.
//
// The two look like the same assertion and are opposites: one says an UNCONFIGURED
// gateway declines, this one says a CONFIGURED one does not. A gateway that
// answered 404 to `/auth/login` while holding both variables is the exact defect
// the packet was raised for, and the way to catch it is to configure one and look.
func TestAConfiguredBrowserSurfaceAnswersItsOwnRoutesRatherThanDecliningThem(t *testing.T) {
	identity := newIdentityStub(t)
	redisURL := startRedis(t)

	config, err := RuntimeOptions(mapEnv(map[string]string{
		"PORT":         "9111",
		"REDIS_URL":    redisURL,
		"IDENTITY_URL": identity.url,
	}))
	if err != nil {
		t.Fatalf("RuntimeOptions: %v", err)
	}
	t.Cleanup(config.CloseResources)

	handler, err := New(config.Options)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Each route is asked for something it will REFUSE, and what matters is the
	// status family: an origin gate answering 403, an unauthenticated read
	// answering 401. A 404 in any of these four is a decline, and a decline here
	// is a gateway that looks configured and is not.
	for _, spec := range []struct {
		name, method, path, body string
		headers                  map[string]string
		want                     int
	}{
		{"a cross-origin login is the gate's 403", http.MethodPost, "/auth/login", `{"email":"a@example.test","password":"pw"}`,
			map[string]string{"Sec-Fetch-Site": "cross-site"}, http.StatusForbidden},
		{"an unauthenticated read is a 401", http.MethodGet, "/auth/me", "", nil, http.StatusUnauthorized},
		// Same-origin, or the ORIGIN GATE answers 403 first and the 401 is never
		// reached. The gate is in front of all four routes, which is why this case
		// sends the header and the cross-origin case above does not — two refusals
		// from one route, and they have to be asked for differently.
		{"an unauthenticated logout is a 401", http.MethodPost, "/auth/logout", "", sameOrigin(), http.StatusUnauthorized},
	} {
		t.Run(spec.name, func(t *testing.T) {
			res := send(t, handler, spec.method, spec.path, spec.body, spec.headers)
			if res.StatusCode != spec.want {
				t.Errorf("%s %s answered %d, want %d. A 404 or 501 here is the defect this packet was raised for: the route is mounted, and the refusal is the one the reference gives", spec.method, spec.path, res.StatusCode, spec.want)
			}
			if got := res.Header.Get("Content-Type"); !strings.HasPrefix(got, "application/problem+json") {
				t.Errorf("Content-Type is %q on a %d. A refusal asserts the whole envelope, not just the status", got, spec.want)
			}
		})
	}

	// `/auth/register` has no unauthenticated refusal to ask for — it is the route
	// that CREATES a session — so it is asked for cross-origin, which every browser
	// route shares.
	res := send(t, handler, http.MethodPost, "/auth/register", `{"email":"a@example.test","password":"pw"}`,
		map[string]string{"Sec-Fetch-Site": "cross-site"})
	if res.StatusCode != http.StatusForbidden {
		t.Errorf("POST /auth/register answered %d cross-origin, want 403 — the origin gate is in front of it and the four routes decline together or not at all", res.StatusCode)
	}
}

// TestAnUnusableIdentityURLIsARefusalToBoot, because `/auth/*` answering 404 under
// a mistyped `IDENTITY_URL` looks like a routing bug and will be debugged as one.
//
// # IT ASSERTS THROUGH `New`, AND THAT IS THE POINT
//
// `RuntimeOptions` does NOT validate the URL — it hands it to `NewBff`, which does,
// and this test asserts through `New` because **that is the path `cmd/gateway`
// takes**: `RuntimeOptions` then `New`, and an error from either stops the process
// before it listens. Asserting on `RuntimeOptions` alone would have passed on a
// deployment that boots and then answers 404 on four routes, which is the failure
// this test exists to rule out.
//
// One validator for one variable is the reason the check is not duplicated into
// `runtime.go`: a second copy of the http(s)-and-no-path rule is a second sentence
// to keep in step with the first.
func TestAnUnusableIdentityURLIsARefusalToBoot(t *testing.T) {
	for _, value := range []string{"identity.test", "ftp://identity.test", "http://identity.test/v1", "http://identity.test?a=1"} {
		t.Run(value, func(t *testing.T) {
			config, err := RuntimeOptions(mapEnv(map[string]string{
				"PORT":         "9112",
				"REDIS_URL":    "redis://127.0.0.1:6379",
				"IDENTITY_URL": value,
			}))
			if err == nil {
				t.Cleanup(config.CloseResources)
			}

			_, err = New(config.Options)
			if err == nil {
				t.Errorf("IDENTITY_URL=%q built a serving gateway. A browser surface that cannot reach identity answers 404 on four routes, which reads as a routing bug", value)
			}
		})
	}
}

// identityStub is identity's answers, served over a real socket rather than
// injected as a `Doer`.
//
// Because `RuntimeOptions` builds its own `http.Client` and nothing in it is
// replaceable from the environment, a test that handed the BFF a `Doer` would be
// proving the test's own function rather than the configuration — and the
// configuration is the thing under test. The HTTP client behind the code under test
// is also the one thing a real deployment gets for free, so it is the one thing worth
// not stubbing here.
//
// The `/v1/me` handler refuses any request that is not carrying the token it minted.
// That is not decoration: a `/me` that answered 200 without the credential from the
// store would pass every other assertion in this file while the store was never
// read at all, and "the browser surface works" would be a claim about the handler
// rather than about the store.
type identityStubT struct {
	url    string
	token  string
	email  string
	server *http.Server
}

func newIdentityStub(t *testing.T) *identityStubT {
	t.Helper()

	stub := &identityStubT{
		token: "identity-token-for-the-runtime-session-test",
		email: "a@example.test",
	}

	mux := http.NewServeMux()

	// The three routes the browser surface calls, and each one refuses a request
	// that is not carrying what it should be. That refusal is the assertion: a
	// `/me` that answered 200 without the credential out of Redis would pass every
	// other check in this file while the store was never read, and "the browser
	// surface works" would be a claim about the handler rather than about the store.
	requiresToken := func(w http.ResponseWriter, r *http.Request) bool {
		if r.Header.Get("Authorization") == "Bearer "+stub.token {
			return true
		}
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"error":"invalid_credentials"}`)
		return false
	}

	mux.HandleFunc("/v1/session", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			// Login. The expiry is in the PAST relative to nothing — it is far
			// future — because `login` refuses a session whose expiry has already
			// passed, and a fixed far-future string keeps a failing assertion
			// naming the same instant on both runs.
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"token":"`+stub.token+`","expires_at":"2031-03-04T05:06:07.000Z"}`)

		case http.MethodDelete:
			if !requiresToken(w, r) {
				return
			}
			w.WriteHeader(http.StatusNoContent)

		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})

	mux.HandleFunc("/v1/me", func(w http.ResponseWriter, r *http.Request) {
		if !requiresToken(w, r) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"cd000000-0000-4000-8000-000000000009","email":"`+stub.email+`"}`)
	})

	listener, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("could not listen for the identity stub: %v", err)
	}
	stub.url = "http://" + listener.Addr().String()
	stub.server = &http.Server{Handler: mux}
	go func() { _ = stub.server.Serve(listener) }()
	t.Cleanup(func() { _ = stub.server.Close() })

	return stub
}

// send is one request through a built handler, with the host the origin gate and
// the cookie parser expect.
func send(t *testing.T, handler http.Handler, method, path, body string, headers map[string]string) testResponse {
	t.Helper()

	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, "https://gateway.test"+path, reader)
	for name, value := range headers {
		req.Header.Set(name, value)
	}

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return testResponse{rec.Result()}
}

// startRedis is a real `redis-server` on a free port, for this process only.
//
// It EXECUTES the binary rather than dialing a URL an operator set, which is the
// whole reason this tier needs no `GATEWAY_REDIS_URL` and cannot be skipped: the
// alternative is a green that says nothing about the wire commands whenever the
// developer's Redis is not running, which is the class of bug this repository has
// now been bitten by three times — the limiter's `TestMain` exiting 0 before
// `m.Run`, the equivalence tier's skip into a void, and the codegen step's `||
// true`.
//
// A developer with no `redis-server` on their PATH gets a FAILING test that says
// so, which is a better outcome than a passing test that proved nothing: this is the
// only tier in the Go tree that cannot lie about having run.
//
// The server is started with `--save ”` and `--appendonly no` so it writes
// nothing to disk, and its directory is `t.TempDir()` so a crashed run cannot leave
// a `dump.rdb` in the working tree.
func startRedis(t *testing.T) string {
	t.Helper()

	binary, err := exec.LookPath("redis-server")
	if err != nil {
		t.Fatalf("this test needs a real `redis-server` on PATH and there is none, so the session store's wire commands are unproven. Install one, or accept that /auth/* has never been run against Redis: %v", err)
	}

	dir := t.TempDir()
	listener, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("could not find a free port for redis-server: %v", err)
	}
	addr := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatalf("could not release the port redis-server is to use: %v", err)
	}

	server := exec.CommandContext(context.Background(), binary,
		"--port", portOf(addr),
		"--bind", "127.0.0.1",
		"--save", "",
		"--appendonly", "no",
		"--dir", dir,
	)
	if err := server.Start(); err != nil {
		t.Fatalf("starting redis-server: %v", err)
	}
	t.Cleanup(func() {
		_ = server.Process.Kill()
		_, _ = server.Process.Wait()
	})

	url := "redis://" + addr
	waitForRedis(t, url, server)
	t.Cleanup(func() {
		// Only this test's keys. `FLUSHDB` would empty whatever Redis the operator
		// meant, and `GATEWAY_REDIS_URL` pointing at a shared server is the case
		// that turns a convenience into an incident.
		connection, err := ratelimit.Connect(ratelimit.RedisConnectionOptions{URL: url})
		if err != nil {
			return
		}
		defer func() { _ = connection.Close() }()
		_, _ = connection.Eval(dropSessionKeys, nil, nil)
	})
	return url
}

// dropSessionKeys removes this package's namespace and nothing else.
//
// `KEYS gateway:sess:*` rather than `FLUSHALL`: a test that empties a database to
// clean up after itself is a test that can empty a developer's database, and the
// namespace is the reason it does not need to.
const dropSessionKeys = `
local found = redis.call('KEYS', 'gateway:sess:*')
for i = 1, #found do redis.call('DEL', found[i]) end
return #found
`

// waitForRedis dials until the server answers, and FAILS rather than sleeping on.
//
// A `time.Sleep` here would be a fixed guess: too short on a loaded machine and the
// test fails for a reason that is not the store's, too long and every run pays it.
// Polling with a deadline is bounded on both sides.
func waitForRedis(t *testing.T, url string, server *exec.Cmd) {
	t.Helper()

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if server.ProcessState != nil {
			t.Fatalf("redis-server exited before it accepted a connection; its output was %q", server.ProcessState)
		}
		connection, err := ratelimit.Connect(ratelimit.RedisConnectionOptions{URL: url, Timeout: 250 * time.Millisecond})
		if err == nil {
			if ok, pingErr := connection.Ping(context.Background()); pingErr == nil && ok {
				_ = connection.Close()
				return
			}
			_ = connection.Close()
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("redis-server at %s did not answer a PING within 10s. The session store's commands are unproven rather than passing, which is the point of running a real one", url)
}

func portOf(addr string) string {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "6379"
	}
	return port
}
