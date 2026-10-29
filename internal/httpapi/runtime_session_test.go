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

	"github.com/anywaye/gateway/internal/ratelimit"
)


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

	me := send(t, handler, http.MethodGet, "/auth/me", "", map[string]string{"Cookie": cookie})
	if me.StatusCode != http.StatusOK {
		t.Fatalf("GET /auth/me with a fresh cookie answered %d, want 200. body: %s", me.StatusCode, readBody(t, me))
	}
	if !strings.Contains(readBody(t, me), identity.email) {
		t.Errorf("/auth/me did not answer the signed-in account: %s", readBody(t, me))
	}

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

	for _, spec := range []struct {
		name, method, path, body string
		headers                  map[string]string
		want                     int
	}{
		{"a cross-origin login is the gate's 403", http.MethodPost, "/auth/login", `{"email":"a@example.test","password":"pw"}`,
			map[string]string{"Sec-Fetch-Site": "cross-site"}, http.StatusForbidden},
		{"an unauthenticated read is a 401", http.MethodGet, "/auth/me", "", nil, http.StatusUnauthorized},
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

	res := send(t, handler, http.MethodPost, "/auth/register", `{"email":"a@example.test","password":"pw"}`,
		map[string]string{"Sec-Fetch-Site": "cross-site"})
	if res.StatusCode != http.StatusForbidden {
		t.Errorf("POST /auth/register answered %d cross-origin, want 403 — the origin gate is in front of it and the four routes decline together or not at all", res.StatusCode)
	}
}

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

func send(t *testing.T, handler http.Handler, method, path, body string, headers map[string]string) testResponse {
	t.Helper()

	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequestWithContext(context.Background(), method, "https://gateway.test"+path, reader)
	for name, value := range headers {
		req.Header.Set(name, value)
	}

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return testResponse{rec.Result()}
}

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
		connection, err := ratelimit.Connect(ratelimit.RedisConnectionOptions{URL: url})
		if err != nil {
			return
		}
		defer func() { _ = connection.Close() }()
		_, _ = connection.Eval(dropSessionKeys, nil, nil)
	})
	return url
}

const dropSessionKeys = `
local found = redis.call('KEYS', 'gateway:sess:*')
for i = 1, #found do redis.call('DEL', found[i]) end
return #found
`

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
