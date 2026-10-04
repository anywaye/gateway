package httpapi

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/cafaye/gateway/internal/sessiontest"
)

// The browser surface's properties, in the order `src/bff/auth.test.ts` states
// them and in the order the packet lists them.
//
// # THE SESSION STORE IS A FIXTURE
//
// Every test here builds its store with `sessiontest`, and there is no other
// implementation in this module — that is the deferral `internal/session`
// records, and `TestNoProductionFileImportsTheSessionDouble` holds it. So a green
// suite here is a statement about the PORT, not a statement that a deployment has
// somewhere to put a session, and the report says the same thing in prose.
//
// # NOTHING IN THIS FILE OPENS A SOCKET
//
// `Doer` is the seam, and the identity below is a function. `TestNoFileInThisPackage
// TalksToARealSocket` is what keeps that true by reading this package's sources,
// because a test that quietly reached for `http.Get` would still pass and would
// stop being a statement about the request gateway sends.

const (
	// A fixed, far-future expiry. Fixed rather than `time.Now().Add(...)` so a
	// failing assertion names the same instant on both runs, and so the
	// equivalence check can put the SAME `expires_at` in front of both
	// implementations and compare the bytes.
	futureExpiry = "2031-03-04T05:06:07.000Z"

	// The identity token the fixture identity mints. Every leak assertion below
	// searches for exactly this string, so a test fails on the credential rather
	// than on a count.
	identityToken = "identity-token-abcdef0123456789"
)

// doerFunc turns a function into a `Doer`.
type doerFunc func(r *http.Request) (*http.Response, error)

func (f doerFunc) Do(r *http.Request) (*http.Response, error) { return f(r) }

// harness is one built gateway plus the things a test needs to look at.
//
// The Doer is a FUNCTION so a test scripts identity's answer for one route and
// records what was sent. `calls` is appended under no lock because these tests
// drive one request at a time; `go test -race` is part of the gate and the
// equivalence scenarios are the ones that go concurrent, and they build their own.
type harness struct {
	handler  http.Handler
	sessions *sessiontest.Store
	calls    []*http.Request
	bodies   []string
	now      time.Time
}

// build assembles a gateway with the browser surface mounted, and fails the test
// if it cannot — a harness that silently served a `404` would make every
// assertion below a vacuous green.
func build(t *testing.T, identity func(*http.Request) (*http.Response, error), options ...func(*BffOptions)) *harness {
	t.Helper()

	h := &harness{now: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)}
	h.sessions = sessiontest.New(func() time.Time { return h.now })

	bff := BffOptions{
		IdentityURL: "http://identity.test",
		Sessions:    h.sessions,
		Now:         func() time.Time { return h.now },
		Doer: doerFunc(func(r *http.Request) (*http.Response, error) {
			h.calls = append(h.calls, r.Clone(context.Background()))
			if r.Body != nil {
				raw, _ := io.ReadAll(r.Body)
				h.bodies = append(h.bodies, string(raw))
			} else {
				h.bodies = append(h.bodies, "")
			}
			return identity(r)
		}),
	}
	for _, option := range options {
		option(&bff)
	}

	handler, err := New(Options{BFF: &bff})
	if err != nil {
		t.Fatalf("New refused a browser-surface configuration: %v", err)
	}
	h.handler = handler
	return h
}

// answer is an identity answer, built rather than fetched.
func answer(status int, body string, headers ...string) *http.Response {
	res := &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     http.Header{},
	}
	// `Retry-After` and friends arrive as pairs so a test cannot pass a header
	// without a value and quietly assert on an absent one.
	for i := 0; i+1 < len(headers); i += 2 {
		res.Header.Set(headers[i], headers[i+1])
	}
	return res
}

// sameOrigin is the header a browser sends on a request it attributes to this
// page, and the ONLY one a test needs for a mutating route to work.
func sameOrigin() map[string]string {
	return map[string]string{"Sec-Fetch-Site": "same-origin"}
}

func cookies(res *http.Response) []*http.Cookie {
	return (&http.Response{Header: res.Header}).Cookies()
}

// The session id out of a `Set-Cookie`, or "".
func sessionCookieValue(res *http.Response) string {
	for _, c := range cookies(res) {
		if c.Name == SessionCookie {
			return c.Value
		}
	}
	return ""
}

// do asks the gateway and returns the recorded answer.
func (h *harness) do(t *testing.T, method, path string, body string, headers map[string]string) *http.Response {
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
	h.handler.ServeHTTP(rec, req)
	return rec.Result()
}

// signedIn logs in and returns the cookie header value, so a test about a later
// request does not have to re-derive the exchange.
func (h *harness) signedIn(t *testing.T) string {
	t.Helper()

	res := h.do(t, http.MethodPost, "/auth/login", `{"email":"a@example.test","password":"pw"}`, sameOrigin())
	if res.StatusCode != http.StatusOK {
		t.Fatalf("the fixture login answered %d, so a test that signed in first cannot mean anything", res.StatusCode)
	}
	return SessionCookie + "=" + sessionCookieValue(res)
}

// loginIdentity answers the two routes a signed-in browser reaches.
func loginIdentity(res *http.Response) func(*http.Request) (*http.Response, error) {
	return func(r *http.Request) (*http.Response, error) {
		switch r.URL.Path {
		case identitySession:
			if r.Method == http.MethodPost {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(`{"token":"` + identityToken + `","expires_at":"` + futureExpiry + `"}`)),
					Header:     http.Header{},
				}, nil
			}
			return res, nil
		case identityMe:
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(`{"id":"11111111-2222-3333-4444-555555555555","email":"a@example.test"}`)),
				Header:     http.Header{},
			}, nil
		default:
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{}`)), Header: http.Header{}}, nil
		}
	}
}

// PROPERTY 1 — the origin gate. Both directions, because a gate that refuses
// everything is also a gate.

// A cross-origin POST is refused, and identity is never asked.
func TestACrossOriginPostIsRefusedAndIdentityIsNeverAsked(t *testing.T) {
	h := build(t, func(*http.Request) (*http.Response, error) {
		t.Error("identity was asked; the origin gate should have answered before it")
		return answer(http.StatusOK, `{"token":"x","expires_at":"`+futureExpiry+`"}`), nil
	})

	for _, path := range []string{"/auth/register", "/auth/login", "/auth/logout"} {
		res := h.do(t, http.MethodPost, path, `{"email":"a@example.test","password":"pw"}`,
			map[string]string{"Sec-Fetch-Site": "cross-site"})

		if res.StatusCode != http.StatusForbidden {
			t.Errorf("POST %s with Sec-Fetch-Site: cross-site answered %d, and the origin gate's answer is 403", path, res.StatusCode)
		}
		if got := sessionCookieValue(res); got != "" {
			t.Errorf("POST %s set a session cookie on a refused request: %q", path, got)
		}
	}
	if len(h.calls) != 0 {
		t.Errorf("identity was called %d time(s) behind a refused origin gate", len(h.calls))
	}
}

// A same-origin POST succeeds. The other direction, and the one a gate written
// as "refuse anything that is not provably same-origin" gets wrong by being
// written as "refuse everything".
func TestASameOriginPostSucceeds(t *testing.T) {
	h := build(t, func(*http.Request) (*http.Response, error) {
		return answer(http.StatusCreated, `{"id":"11111111-2222-3333-4444-555555555555","email":"a@example.test"}`), nil
	})

	res := h.do(t, http.MethodPost, "/auth/register", `{"email":"a@example.test","password":"pw"}`, sameOrigin())

	if res.StatusCode != http.StatusCreated {
		t.Fatalf("a same-origin registration answered %d, and the origin gate's other direction is that it succeeds. Body: %s", res.StatusCode, readBody(t, res))
	}
	if len(h.calls) != 1 {
		t.Errorf("identity was called %d time(s) for a same-origin registration, and it is called exactly once", len(h.calls))
	}
}

// The four values of `Sec-Fetch-Site` are not equally acceptable, and the two that
// are refused are refused for different reasons that both matter.
func TestOnlySameOriginSecFetchSitePasses(t *testing.T) {
	cases := []struct {
		value string
		want  int
		why   string
	}{
		{"same-origin", http.StatusCreated, "the only value that claims this origin"},
		{"same-site", http.StatusForbidden, "a sibling subdomain, which a Lax cookie IS sent to — so it has something to spend"},
		{"cross-site", http.StatusForbidden, "the attack"},
		{"none", http.StatusForbidden, "the agent could not attribute the request to a page, which is not a claim of same-origin"},
		{"SAME-ORIGIN", http.StatusCreated, "compared as a token, so a user agent changing case is not an outage"},
		{" same-origin ", http.StatusCreated, "whitespace is not a value"},
		{"same-origin-ish", http.StatusForbidden, "a value that is not one of the four is refused, NOT treated as absent"},
	}

	for _, tc := range cases {
		t.Run(tc.value, func(t *testing.T) {
			h := build(t, func(*http.Request) (*http.Response, error) {
				return answer(http.StatusCreated, `{"id":"11111111-2222-3333-4444-555555555555","email":"a@example.test"}`), nil
			})

			res := h.do(t, http.MethodPost, "/auth/register", `{"email":"a@example.test","password":"pw"}`,
				map[string]string{"Sec-Fetch-Site": tc.value})

			if res.StatusCode != tc.want {
				t.Errorf("Sec-Fetch-Site: %q answered %d and the gate's answer is %d — %s", tc.value, res.StatusCode, tc.want, tc.why)
			}
		})
	}
}

// `Origin` is the fallback, and it is compared by HOST and not by origin.
func TestOriginIsComparedByHostNotByScheme(t *testing.T) {
	cases := []struct {
		name   string
		origin string
		want   int
	}{
		{"the same host and scheme", "https://gateway.test", http.StatusCreated},
		{"a TLS-terminating proxy rewrote the scheme", "http://gateway.test", http.StatusCreated},
		{"a different host", "https://evil.test", http.StatusForbidden},
		{"a subdomain of this host", "https://auth.gateway.test", http.StatusForbidden},
		{"the literal null", "null", http.StatusForbidden},
		{"not a URL at all", "://", http.StatusForbidden},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := build(t, func(*http.Request) (*http.Response, error) {
				return answer(http.StatusCreated, `{"id":"11111111-2222-3333-4444-555555555555","email":"a@example.test"}`), nil
			})

			res := h.do(t, http.MethodPost, "/auth/register", `{"email":"a@example.test","password":"pw"}`,
				map[string]string{"Origin": tc.origin})

			if res.StatusCode != tc.want {
				t.Errorf("Origin: %s answered %d and the gate's answer is %d", tc.origin, res.StatusCode, tc.want)
			}
		})
	}
}

// A request that states NEITHER header is refused: it is not provably same-origin.
func TestARequestThatStatesNeitherHeaderIsRefused(t *testing.T) {
	h := build(t, func(*http.Request) (*http.Response, error) {
		t.Error("identity was asked for a request that stated no origin at all")
		return answer(http.StatusOK, `{}`), nil
	})

	res := h.do(t, http.MethodPost, "/auth/login", `{"email":"a@example.test","password":"pw"}`, nil)

	if res.StatusCode != http.StatusForbidden {
		t.Errorf("a POST stating neither header answered %d, and an unstated origin is not a same-origin one", res.StatusCode)
	}
}

// When a request states BOTH and they disagree, the gate believes the stricter.
func TestDisagreeingOriginSignalsAreRefused(t *testing.T) {
	h := build(t, func(*http.Request) (*http.Response, error) {
		t.Error("identity was asked for a request whose two origin signals disagree")
		return answer(http.StatusOK, `{}`), nil
	})

	res := h.do(t, http.MethodPost, "/auth/login", `{"email":"a@example.test","password":"pw"}`, map[string]string{
		"Sec-Fetch-Site": "same-origin",
		"Origin":         "https://evil.test",
	})

	if res.StatusCode != http.StatusForbidden {
		t.Errorf("Sec-Fetch-Site: same-origin with Origin: evil answered %d. A browser is consistent, so this is a client choosing what each header says and the gate must believe the stricter one.", res.StatusCode)
	}
}

// A read is not gated. CSRF defence protects a caller from a page they did not
// navigate to, and `GET /auth/me` changes nothing.
func TestTheReadIsNotGated(t *testing.T) {
	h := build(t, loginIdentity(answer(http.StatusNoContent, "")))
	cookie := h.signedIn(t)

	res := h.do(t, http.MethodGet, "/auth/me", "", map[string]string{"Cookie": cookie, "Sec-Fetch-Site": "cross-site"})

	if res.StatusCode != http.StatusOK {
		t.Errorf("GET /auth/me with a hostile Sec-Fetch-Site answered %d. The gate is CSRF defence and a read needs none.", res.StatusCode)
	}
}

// A header sent twice is not a value the contract accepts, and the generated
// router refuses it before the handler is reached. The reference has no such
// refusal — its framework joins the two lines — so the answer here has to be the
// origin gate's.
func TestAHeaderSentTwiceIsTheOriginGatesAnswer(t *testing.T) {
	h := build(t, func(*http.Request) (*http.Response, error) {
		t.Error("identity was asked for a request with a duplicated header")
		return answer(http.StatusOK, `{}`), nil
	})

	req := httptest.NewRequest(http.MethodPost, "https://gateway.test/auth/login", strings.NewReader(`{"email":"a@x.test","password":"pw"}`))
	req.Header.Add("Sec-Fetch-Site", "same-origin")
	req.Header.Add("Sec-Fetch-Site", "same-origin")

	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, req)

	res := rec.Result()
	if res.StatusCode != http.StatusForbidden {
		t.Errorf("Sec-Fetch-Site sent twice answered %d. The reference joins the lines, gets `same-origin, same-origin`, and refuses it with 403 — so the generator's own 400 is a difference no client asked for.", res.StatusCode)
	}
	if strings.Contains(readBody(t, res), "Sec-Fetch-Site") {
		t.Errorf("the refusal names the header: %s. A body that describes the gateway's internals to an unauthenticated caller is the thing every other refusal here avoids.", readBody(t, res))
	}
}

// PROPERTY 2 — the session cookie.

// The cookie is exactly the `__Host-` contract, and it expires when identity's
// session does.
func TestTheSessionCookieIsTheHostPrefixedContract(t *testing.T) {
	h := build(t, loginIdentity(answer(http.StatusNoContent, "")))

	res := h.do(t, http.MethodPost, "/auth/login", `{"email":"a@example.test","password":"pw"}`, sameOrigin())

	var found *http.Cookie
	for _, c := range cookies(res) {
		if c.Name == SessionCookie {
			found = c
		}
	}
	if found == nil {
		t.Fatalf("a successful login set no %s cookie. Headers: %v", SessionCookie, res.Header)
	}

	if found.Name != "__Host-bff-session" {
		t.Errorf("the cookie is named %q. The `__Host-` prefix is a guarantee the BROWSER enforces — Secure, Path=/, no Domain — and it is the reason a sibling domain cannot set it.", found.Name)
	}
	if !found.Secure {
		t.Error("the cookie is not Secure, and `__Host-` requires it: a browser refuses to store a `__Host-` cookie without it, which would silently drop every session.")
	}
	if !found.HttpOnly {
		t.Error("the cookie is not HttpOnly, and HttpOnly is the entire reason a session id is safer in a cookie than a token in a page: a cross-site script cannot read it.")
	}
	if found.Path != "/" {
		t.Errorf("the cookie's Path is %q and `__Host-` requires `/`.", found.Path)
	}
	if found.SameSite != http.SameSiteLaxMode {
		t.Errorf("the cookie is SameSite=%v and it is Lax, not Strict: a Strict cookie is not sent on the top-level navigation a user follows straight after signing in.", found.SameSite)
	}
	if got, want := found.Expires.UTC().Format(time.RFC3339), "2031-03-04T05:06:07Z"; got != want {
		t.Errorf("the cookie expires at %s and it must expire when IDENTITY's session does (%s). A gateway-side TTL would be a second answer to how long a session is good for.", got, want)
	}
}

// The clearing cookie repeats every attribute, because a browser matches a
// deletion on name, domain and path.
func TestClearingTheCookieRepeatsEveryAttribute(t *testing.T) {
	h := build(t, loginIdentity(answer(http.StatusNoContent, "")))
	cookie := h.signedIn(t)

	res := h.do(t, http.MethodPost, "/auth/logout", "", map[string]string{"Cookie": cookie, "Sec-Fetch-Site": "same-origin"})

	var cleared *http.Cookie
	for _, c := range cookies(res) {
		if c.Name == SessionCookie && c.Value == "" {
			cleared = c
		}
	}
	if cleared == nil {
		t.Fatalf("signing out sent no empty %s cookie, so the browser keeps the one it has. Headers: %v", SessionCookie, res.Header)
	}
	if cleared.Path != "/" || !cleared.Secure || !cleared.HttpOnly || cleared.SameSite != http.SameSiteLaxMode {
		t.Errorf("the clearing cookie is %+v and it must repeat Path, Secure, HttpOnly and SameSite from the setting cookie. A deletion missing one leaves the original in place, which is the precise bug that makes sign-out appear to do nothing.", cleared)
	}
	if cleared.MaxAge != -1 && cleared.Expires.After(time.Unix(0, 0)) {
		t.Errorf("the clearing cookie has MaxAge=%d and Expires=%s, and neither says this is over", cleared.MaxAge, cleared.Expires)
	}
}

// PROPERTY 3 — the browser never receives an identity token. Source and
// behaviour, because a leak test that only greps finds the handler that forgot
// and not the one that was never written.

// PROPERTY 4 — one sentence for every refused credential. Two DIFFERENT causes,
// and the comparison is byte equality of everything a caller can see.
func TestTwoRefusalCausesProduceIdenticalResponses(t *testing.T) {
	// The two cases identity must be able to distinguish internally and must NOT
	// be able to distinguish through this gateway. The upstream bodies are
	// deliberately different documents, so an implementation that forwarded
	// either would fail this.
	causes := map[string]string{
		"a wrong password":   `{"error":"invalid_credentials","detail":"that password is not correct for this account"}`,
		"an unknown account": `{"error":"no_such_user","detail":"no account has that email address"}`,
	}

	var answers []*http.Response
	for name, upstream := range causes {
		h := build(t, func(*http.Request) (*http.Response, error) {
			return answer(http.StatusUnauthorized, upstream), nil
		})

		res := h.do(t, http.MethodPost, "/auth/login", `{"email":"a@example.test","password":"pw"}`, sameOrigin())

		if res.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s: identity answered 401 and this answered %d", name, res.StatusCode)
		}
		if got := sessionCookieValue(res); got != "" {
			t.Errorf("%s: a refused login set a session cookie: %q", name, got)
		}
		answers = append(answers, res)
	}

	first, second := answers[0], answers[1]
	// Read once. A body can only be read once, and reading it twice to compare it
	// twice is how a test ends up comparing two empty strings.
	firstRaw, secondRaw := readBody(t, first), readBody(t, second)
	firstBody, secondBody := withoutTraceID(firstRaw), withoutTraceID(secondRaw)

	if firstBody != secondBody {
		t.Errorf("two refusal causes produced different bodies, and a login endpoint whose 401 varies by cause is an account-enumeration oracle:\n  cause A: %s\n  cause B: %s", firstBody, secondBody)
	}
	// `trace_id` is deliberately DIFFERENT on every response — it is a correlation
	// id for one failed response, and it is the only field allowed to vary. So it
	// is removed before the comparison rather than the comparison being dropped,
	// because a body comparison that ignores a whole envelope proves less than
	// one that ignores a field.
	if traceIDOf(firstRaw) == "" || traceIDOf(secondRaw) == "" {
		t.Errorf("a problem document carries no trace_id: %s / %s", firstRaw, secondRaw)
	}

	if !strings.Contains(firstBody, `"detail":"email or password is not correct"`) {
		t.Errorf("the 401 detail is not the one fixed sentence. Body: %s", firstBody)
	}
	if strings.Contains(firstBody, "no_such_user") || strings.Contains(firstBody, "invalid_credentials") {
		t.Errorf("the refusal forwards identity's own slug: %s. Which of the two slugs reaches the browser is the enumeration.", firstBody)
	}
}

// The two 401s also have to be the same STATUS and the same code, not merely the
// same sentence — a caller branching on either would still be enumerating.
func TestTheTwoRefusalsAgreeOnStatusAndContentType(t *testing.T) {
	var types []string
	for _, upstream := range []string{`{"error":"a"}`, `{"error":"b"}`} {
		body := upstream
		h := build(t, func(*http.Request) (*http.Response, error) { return answer(http.StatusUnauthorized, body), nil })

		res := h.do(t, http.MethodPost, "/auth/login", `{"email":"a@x.test","password":"pw"}`, sameOrigin())
		if res.StatusCode != http.StatusUnauthorized {
			t.Errorf("identity answered 401 and this answered %d", res.StatusCode)
		}
		types = append(types, res.Header.Get("Content-Type"))
	}

	if types[0] != types[1] {
		t.Errorf("the two refusals were served as %q and %q", types[0], types[1])
	}
	if types[0] != problemContentType {
		t.Errorf("a refusal is served as %q and core's envelope is %q", types[0], problemContentType)
	}
}

// A lockout travels with its window. Collapsing it into the 401 above would tell
// someone with the RIGHT password to try again, and be refused again.
func TestALockedAccountIs423AndItsRetryAfterTravels(t *testing.T) {
	cases := []struct {
		retry      string
		wantEcho   bool
		whyItIsNot string
	}{
		{"900", true, "a seconds-form window is seconds and must reach the browser"},
		{"0", true, "zero is digits and means come straight back"},
		{"Wed, 21 Oct 2026 07:28:00 GMT", false, "an HTTP-date is a seconds-form header this gateway does not rewrite, so it is not echoed rather than echoed wrongly"},
		{"soon", false, "a value that is not a duration is not forwarded into a browser's cache of when to retry a login"},
	}

	for _, tc := range cases {
		t.Run(tc.retry, func(t *testing.T) {
			h := build(t, func(*http.Request) (*http.Response, error) {
				return answer(http.StatusLocked, `{"error":"locked"}`, "Retry-After", tc.retry), nil
			})

			res := h.do(t, http.MethodPost, "/auth/login", `{"email":"a@example.test","password":"pw"}`, sameOrigin())

			if res.StatusCode != http.StatusLocked {
				t.Fatalf("a locked account answered %d, and the status must stay 423 rather than collapsing into the 401", res.StatusCode)
			}
			echoed := res.Header.Get("Retry-After")
			if tc.wantEcho && echoed != tc.retry {
				t.Errorf("Retry-After was %q and it should be %q", echoed, tc.retry)
			}
			if !tc.wantEcho && echoed != "" {
				t.Errorf("Retry-After was echoed as %q — %s", echoed, tc.whyItIsNot)
			}
			if h.sessions.Size() != 0 {
				t.Errorf("a refused login stored %d session(s); a refused credential must leave nothing behind", h.sessions.Size())
			}
		})
	}
}

// PROPERTY 5 — a revoked session is dead on the next request.

// `/auth/me` with a live session proxies with the stored token, and the browser
// learns nothing but the account.
func TestMeProxiesWithTheStoredTokenAndReturnsOnlyTheAccount(t *testing.T) {
	h := build(t, loginIdentity(answer(http.StatusNoContent, "")))
	cookie := h.signedIn(t)
	before := len(h.calls)

	res := h.do(t, http.MethodGet, "/auth/me", "", map[string]string{"Cookie": cookie})

	if res.StatusCode != http.StatusOK {
		t.Fatalf("GET /auth/me answered %d. Body: %s", res.StatusCode, readBody(t, res))
	}
	if len(h.calls) != before+1 {
		t.Fatalf("GET /auth/me made %d call(s) to identity", len(h.calls)-before)
	}
	if got := h.calls[len(h.calls)-1].Header.Get("Authorization"); got != "Bearer "+identityToken {
		t.Errorf("identity was asked with Authorization %q and it must be the stored token, in a Bearer header", got)
	}

	body := readBody(t, res)
	assertNoToken(t, "the /auth/me body", body)
	// EXACT equality, and the field ORDER is part of it: the equivalence check
	// compares bytes and `api.User` would render email first.
	if body != `{"id":"11111111-2222-3333-4444-555555555555","email":"a@example.test"}` {
		t.Errorf("the /auth/me body is %s and it must be `id` then `email` and nothing else — the reference's order, the reference's width, and the bytes the comparison needs", body)
	}
}

// An expired session is a 401 and identity is never asked: the record is already
// dead and there is nothing to revoke.
func TestAnExpiredSessionIs401AndIdentityIsNeverAsked(t *testing.T) {
	h := build(t, loginIdentity(answer(http.StatusNoContent, "")))
	cookie := h.signedIn(t)
	before := len(h.calls)

	// The clock moves PAST the expiry the fixture identity minted.
	h.now = time.Date(2032, 1, 1, 0, 0, 0, 0, time.UTC)

	res := h.do(t, http.MethodGet, "/auth/me", "", map[string]string{"Cookie": cookie})

	if res.StatusCode != http.StatusUnauthorized {
		t.Errorf("an expired session answered %d, and an expired session is a 401", res.StatusCode)
	}
	if len(h.calls) != before {
		t.Errorf("an expired session made %d call(s) to identity; there is no live token to spend", len(h.calls)-before)
	}
	if sessionCookieValue(res) != "" {
		t.Error("the expired session's cookie was not cleared, so the browser keeps presenting a record that can never work again")
	}
}

// identity withdrawing the token drops the local record, so the revocation is true
// from THIS request on rather than at the token's expiry.
func TestAWithdrawnSessionIs401AndTheRecordIsDropped(t *testing.T) {
	withdrawn := false
	h := build(t, func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == identityMe && withdrawn {
			return answer(http.StatusUnauthorized, `{"error":"unauthorized"}`), nil
		}
		return loginIdentity(answer(http.StatusNoContent, ""))(r)
	})
	cookie := h.signedIn(t)

	// The happy path first, so the record is demonstrably live.
	if res := h.do(t, http.MethodGet, "/auth/me", "", map[string]string{"Cookie": cookie}); res.StatusCode != http.StatusOK {
		t.Fatalf("the session was not live to begin with: %d", res.StatusCode)
	}

	withdrawn = true
	res := h.do(t, http.MethodGet, "/auth/me", "", map[string]string{"Cookie": cookie})

	if res.StatusCode != http.StatusUnauthorized {
		t.Errorf("a session identity withdrew answered %d, and a withdrawal is a 401", res.StatusCode)
	}
	if h.sessions.Size() != 0 {
		t.Errorf("the withdrawn session is still in the store (%d record(s)); dropping it is what makes the revocation true now rather than at the token's expiry", h.sessions.Size())
	}
	if sessionCookieValue(res) != "" {
		t.Error("a withdrawn session's cookie was not cleared")
	}
}

// A session the store has forgotten clears the cookie: a signed-out user whose
// every request looks like a server that forgot them is the failure this avoids.
func TestAForgottenSessionIs401AndTheCookieIsCleared(t *testing.T) {
	h := build(t, loginIdentity(answer(http.StatusNoContent, "")))
	cookie := h.signedIn(t)

	// The store forgets it — a restart, a swept map — and the browser keeps
	// presenting the id it was given.
	forget(t, h, cookie)

	res := h.do(t, http.MethodGet, "/auth/me", "", map[string]string{"Cookie": cookie})
	if res.StatusCode != http.StatusUnauthorized {
		t.Errorf("a session the store has forgotten answered %d, and it is a 401", res.StatusCode)
	}
	if sessionCookieValue(res) != "" {
		t.Error("the cookie for a forgotten session was not cleared, so the browser keeps presenting it")
	}
}

// An identity OUTAGE is a 503 and the session SURVIVES it. Treating an outage as a
// revocation signs everybody out whenever identity hiccups.
func TestAnIdentityOutageIs503AndTheSessionSurvivesIt(t *testing.T) {
	down := false
	h := build(t, func(r *http.Request) (*http.Response, error) {
		if down && r.URL.Path == identityMe {
			return nil, errors.New("dial tcp 10.0.0.1:8080: connect: connection refused")
		}
		return loginIdentity(answer(http.StatusNoContent, ""))(r)
	})
	cookie := h.signedIn(t)

	down = true
	res := h.do(t, http.MethodGet, "/auth/me", "", map[string]string{"Cookie": cookie})

	if res.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("an identity outage answered %d, and it is a 503 — a 401 would tell the browser to discard a session that is still good", res.StatusCode)
	}
	assertNoToken(t, "the outage body", readBody(t, res))
	if h.sessions.Size() != 1 {
		t.Errorf("the store holds %d record(s) after an outage; an outage must not sign anybody out", h.sessions.Size())
	}
}

// Signing out drops the record, tells identity, and a later `/auth/me` is a 401
// with no call at all.
func TestSignOutRevokesLocallyAndUpstream(t *testing.T) {
	h := build(t, loginIdentity(answer(http.StatusNoContent, "")))
	cookie := h.signedIn(t)

	res := h.do(t, http.MethodPost, "/auth/logout", "", map[string]string{"Cookie": cookie, "Sec-Fetch-Site": "same-origin"})
	if res.StatusCode != http.StatusNoContent {
		t.Fatalf("signing out answered %d. Body: %s", res.StatusCode, readBody(t, res))
	}
	if h.sessions.Size() != 0 {
		t.Errorf("the store holds %d record(s) after signing out", h.sessions.Size())
	}
	if len(h.bodies) == 0 || h.bodies[len(h.bodies)-1] != "" {
		t.Error("identity was not told to revoke")
	}

	before := len(h.calls)
	after := h.do(t, http.MethodGet, "/auth/me", "", map[string]string{"Cookie": cookie})
	if after.StatusCode != http.StatusUnauthorized {
		t.Errorf("/auth/me after signing out answered %d", after.StatusCode)
	}
	if len(h.calls) != before {
		t.Errorf("/auth/me after signing out called identity %d time(s)", len(h.calls)-before)
	}
}

// Signing out with no cookie is a 401, and identity is never asked: a 204 would
// report that something happened when there was no session to end.
func TestSignOutWithNoCookieIs401(t *testing.T) {
	h := build(t, func(*http.Request) (*http.Response, error) {
		t.Error("identity was asked to revoke a session that was never presented")
		return answer(http.StatusNoContent, ""), nil
	})

	res := h.do(t, http.MethodPost, "/auth/logout", "", sameOrigin())

	if res.StatusCode != http.StatusUnauthorized {
		t.Errorf("signing out with no cookie answered %d, and it is a 401", res.StatusCode)
	}
}

// A cookie the store has forgotten still signs the browser out: there is provably
// nothing to revoke, which is the state the caller asked for.
func TestSigningOutWithAForgottenCookieIs204AndStillClears(t *testing.T) {
	h := build(t, loginIdentity(answer(http.StatusNoContent, "")))
	cookie := h.signedIn(t)
	forget(t, h, cookie)

	res := h.do(t, http.MethodPost, "/auth/logout", "", map[string]string{"Cookie": cookie, "Sec-Fetch-Site": "same-origin"})

	if res.StatusCode != http.StatusNoContent {
		t.Errorf("signing out a forgotten session answered %d. Refusing is what makes sign-out look broken.", res.StatusCode)
	}
	if sessionCookieValue(res) != "" {
		t.Error("the cookie was not cleared, so the browser keeps presenting it")
	}
}

// A session identity has already revoked is a 204, because that is the end state
// the caller asked for.
func TestSigningOutAnAlreadyRevokedSessionIs204(t *testing.T) {
	for _, status := range []int{http.StatusNoContent, http.StatusUnauthorized, http.StatusNotFound} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			revoking := status
			h := build(t, func(r *http.Request) (*http.Response, error) {
				if r.URL.Path == identitySession && r.Method == http.MethodDelete {
					return answer(revoking, ""), nil
				}
				return loginIdentity(answer(http.StatusNoContent, ""))(r)
			})
			cookie := h.signedIn(t)

			res := h.do(t, http.MethodPost, "/auth/logout", "", map[string]string{"Cookie": cookie, "Sec-Fetch-Site": "same-origin"})
			if res.StatusCode != http.StatusNoContent {
				t.Errorf("identity answering %d on revoke produced %d, and 401/404/204 are all the same end state", revoking, res.StatusCode)
			}
		})
	}
}

// An identity that cannot be told still signs the browser out, and says so.
func TestSigningOutWhileIdentityIsDownStillSignsOutAndSays503(t *testing.T) {
	down := false
	h := build(t, func(r *http.Request) (*http.Response, error) {
		if down && r.URL.Path == identitySession && r.Method == http.MethodDelete {
			return nil, errors.New("identity is not there")
		}
		return loginIdentity(answer(http.StatusNoContent, ""))(r)
	})
	cookie := h.signedIn(t)
	down = true

	res := h.do(t, http.MethodPost, "/auth/logout", "", map[string]string{"Cookie": cookie, "Sec-Fetch-Site": "same-origin"})

	if res.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("signing out while identity is down answered %d, and it is a 503 — the local record IS gone and the caller is told the token may outlive it", res.StatusCode)
	}
	if h.sessions.Size() != 0 {
		t.Errorf("the store holds %d record(s); failing to sign a browser out is worse than a token that outlives its revocation", h.sessions.Size())
	}
	if sessionCookieValue(res) != "" {
		t.Error("the cookie was not cleared even though the local record is gone")
	}
}

// The store being DOWN is a 503 on every route that touches it, and never a 401:
// a 401 would send a signed-in browser to sign in again over an outage.
func TestAStoreThatIsDownIs503Not401(t *testing.T) {
	h := build(t, loginIdentity(answer(http.StatusNoContent, "")))
	cookie := h.signedIn(t)

	down := build(t, func(*http.Request) (*http.Response, error) { return answer(http.StatusOK, `{}`), nil },
		func(o *BffOptions) { o.Sessions = sessiontest.Fail{} })

	res := down.do(t, http.MethodGet, "/auth/me", "", map[string]string{"Cookie": cookie})
	if res.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("/auth/me with the store down answered %d, and it is a 503", res.StatusCode)
	}

	res = down.do(t, http.MethodPost, "/auth/logout", "", map[string]string{"Cookie": cookie, "Sec-Fetch-Site": "same-origin"})
	if res.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("signing out with the store down answered %d, and it is a 503", res.StatusCode)
	}
	_ = h
}

// Two logins are two sessions, and neither reuses the other's id. A session id is
// minted here and never accepted from the caller — fixation needs an id the
// attacker knows first.
func TestEveryLoginMintsAFreshSessionId(t *testing.T) {
	h := build(t, loginIdentity(answer(http.StatusNoContent, "")))

	seen := map[string]bool{}
	for i := 0; i < 8; i++ {
		res := h.do(t, http.MethodPost, "/auth/login", `{"email":"a@example.test","password":"pw"}`, sameOrigin())
		id := sessionCookieValue(res)
		if id == "" {
			t.Fatalf("login %d set no session cookie", i)
		}
		if seen[id] {
			t.Fatalf("login %d was handed session id %q, which an earlier login already had. A session id the caller can influence is the cookie-fixation vector.", i, id)
		}
		seen[id] = true
	}

	if h.sessions.Size() != len(seen) {
		t.Errorf("the store holds %d record(s) for %d distinct ids; the cookie must be a pointer at a record, not a decoration", h.sessions.Size(), len(seen))
	}
}

// The cookie's value is the key the record is stored under.
func TestTheCookieIsTheKeyTheRecordIsStoredUnder(t *testing.T) {
	h := build(t, loginIdentity(answer(http.StatusNoContent, "")))

	res := h.do(t, http.MethodPost, "/auth/login", `{"email":"a@example.test","password":"pw"}`, sameOrigin())

	held := h.sessions.Held()
	if len(held) != 1 || held[0] != sessionCookieValue(res) {
		t.Errorf("the cookie is %q and the store holds %v; a browser sending a cookie that is not a key is signed out on the very next request", sessionCookieValue(res), held)
	}
}

// PROPERTY: registration is not a login, and the body reaches identity untouched.

// A registration returns `{id, email}` and NO cookie — identity has not minted a
// session, so a cookie here would stand for nothing.
func TestRegisterReturnsTheAccountAndNoCookie(t *testing.T) {
	h := build(t, func(*http.Request) (*http.Response, error) {
		return answer(http.StatusCreated, `{"id":"11111111-2222-3333-4444-555555555555","email":"a@example.test","password_digest":"sha256:deadbeef","role":"admin"}`), nil
	})

	res := h.do(t, http.MethodPost, "/auth/register", `{"email":"a@example.test","password":"pw"}`, sameOrigin())

	if res.StatusCode != http.StatusCreated {
		t.Fatalf("registration answered %d. Body: %s", res.StatusCode, readBody(t, res))
	}
	if sessionCookieValue(res) != "" {
		t.Error("a registration set a session cookie. A registration is not a login; identity has minted nothing for this browser to hold.")
	}

	body := readBody(t, res)
	if body != `{"id":"11111111-2222-3333-4444-555555555555","email":"a@example.test"}` {
		t.Errorf("the registration body is %s. It is an ALLOWLIST — a field identity adds next month must not reach a browser response today by being copied, and a digest has no business in a page.", body)
	}
}

// The caller's body reaches identity verbatim. Only "is this an object" is decided
// here: whether an address is deliverable and a password strong enough is
// identity's call, in one place.
func TestTheCallersBodyReachesIdentityVerbatim(t *testing.T) {
	sent := `{"email":"a@example.test","password":"pw","display_name":"A","extra":{"nested":[1,2]},"unicode":"héllo ☃"}`
	h := build(t, func(*http.Request) (*http.Response, error) {
		return answer(http.StatusCreated, `{"id":"11111111-2222-3333-4444-555555555555","email":"a@example.test"}`), nil
	})

	h.do(t, http.MethodPost, "/auth/register", sent, sameOrigin())

	if len(h.bodies) != 1 || h.bodies[0] != sent {
		t.Errorf("identity received %q and it must be the caller's bytes unchanged. Re-encoding a body is a second parser and a second answer to what the request said.", h.bodies)
	}
}

// The two body refusals, and the third for the cap.
func TestMalformedBodiesAreRefusedAndIdentityIsNeverAsked(t *testing.T) {
	oversized := `{"email":"a@example.test","password":"` + strings.Repeat("x", maxBodyBytes) + `"}`

	cases := []struct {
		name string
		body string
		want int
	}{
		{"not JSON at all", `email=a@example.test`, http.StatusBadRequest},
		{"a JSON array", `[{"email":"a@example.test"}]`, http.StatusBadRequest},
		{"a JSON string", `"a@example.test"`, http.StatusBadRequest},
		{"JSON null", `null`, http.StatusBadRequest},
		{"JSON true", `true`, http.StatusBadRequest},
		{"an empty body", ``, http.StatusBadRequest},
		{"one byte past the cap", oversized, http.StatusRequestEntityTooLarge},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := build(t, func(*http.Request) (*http.Response, error) {
				t.Errorf("identity was asked for a body gateway refuses to forward")
				return answer(http.StatusCreated, `{"id":"1","email":"a@x.test"}`), nil
			})

			res := h.do(t, http.MethodPost, "/auth/register", tc.body, sameOrigin())

			if res.StatusCode != tc.want {
				t.Errorf("a body that is %s answered %d, and its answer is %d", tc.name, res.StatusCode, tc.want)
			}
			if res.Header.Get("Content-Type") != problemContentType {
				t.Errorf("the refusal is served as %q, and a refusal in this service is core's envelope", res.Header.Get("Content-Type"))
			}
		})
	}
}

// A body just inside the cap is forwarded: an off-by-one here fails a registration
// identity would accept.
func TestABodyJustInsideTheCapIsForwarded(t *testing.T) {
	padding := maxBodyBytes - len(`{"email":"a@example.test","password":""}`)
	body := `{"email":"a@example.test","password":"` + strings.Repeat("x", padding) + `"}`

	h := build(t, func(*http.Request) (*http.Response, error) {
		return answer(http.StatusCreated, `{"id":"11111111-2222-3333-4444-555555555555","email":"a@example.test"}`), nil
	})

	res := h.do(t, http.MethodPost, "/auth/register", body, sameOrigin())

	if res.StatusCode != http.StatusCreated {
		t.Errorf("a body of exactly %d bytes answered %d, and the cap is inclusive", len(body), res.StatusCode)
	}
}

// The identity refusals registration can produce, mapped and not guessed at.
func TestIdentitysRegistrationRefusalsAreMapped(t *testing.T) {
	cases := []struct {
		name     string
		upstream int
		body     string
		want     int
		fields   int
	}{
		{"a duplicate account is a conflict", http.StatusConflict, `{"error":"conflict"}`, http.StatusConflict, 0},
		{"a validation failure keeps its field errors", http.StatusUnprocessableEntity,
			`{"errors":[{"field":"email","code":"not_an_email"},{"field":"password","code":"too_short"},{"field":"x","nope":1}]}`,
			http.StatusUnprocessableEntity, 2},
		{"a create answered with 200 is unusable", http.StatusOK, `{"id":"1","email":"a@x.test"}`, http.StatusServiceUnavailable, 0},
		{"a create answered with 500 is unusable", http.StatusInternalServerError, `boom`, http.StatusServiceUnavailable, 0},
		{"a create answered with an HTML page is unusable", http.StatusCreated, `<html>oops`, http.StatusServiceUnavailable, 0},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := build(t, func(*http.Request) (*http.Response, error) { return answer(tc.upstream, tc.body), nil })

			res := h.do(t, http.MethodPost, "/auth/register", `{"email":"a@example.test","password":"pw"}`, sameOrigin())

			if res.StatusCode != tc.want {
				t.Errorf("identity answered %d and this answered %d", tc.upstream, res.StatusCode)
			}
			if tc.fields > 0 {
				if got := strings.Count(readBody(t, res), `"field":`); got != tc.fields {
					t.Errorf("the 422 carries %d field error(s) and it must carry %d: a sign-up form renders these, and dropping one leaves the browser saying \"something went wrong\" about a field identity named exactly. Body: %s", got, tc.fields, readBody(t, res))
				}
			}
		})
	}
}

// Identity being unreachable is a 503 whose detail names no host — an anonymous
// browser is not allowed to learn where identity lives.
func TestAnUnreachableIdentityIs503AndNamesNoHost(t *testing.T) {
	h := build(t, func(*http.Request) (*http.Response, error) {
		return nil, errors.New("dial tcp 10.0.0.1:8080: connect: connection refused")
	})

	res := h.do(t, http.MethodPost, "/auth/login", `{"email":"a@example.test","password":"pw"}`, sameOrigin())

	if res.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("an unreachable identity answered %d", res.StatusCode)
	}
	body := readBody(t, res)
	for _, leak := range []string{"10.0.0.1", "identity.test", "8080", "connection refused"} {
		if strings.Contains(body, leak) {
			t.Errorf("the 503 body names %q: %s. The URL, the status and the socket error are the platform's to know; an anonymous browser is not.", leak, body)
		}
	}
}

// A hung identity is bounded by the timeout rather than holding the request.
func TestAHungIdentityIsBounded(t *testing.T) {
	h := build(t, func(*http.Request) (*http.Response, error) {
		// Ignores its context on purpose: that is the `Doer` the timer exists for,
		// and a `Doer` that honoured the deadline would not test the timer.
		time.Sleep(2 * time.Second)
		return answer(http.StatusOK, `{}`), nil
	}, func(o *BffOptions) { o.IdentityTimeout = 60 * time.Millisecond })

	started := time.Now()
	res := h.do(t, http.MethodPost, "/auth/login", `{"email":"a@example.test","password":"pw"}`, sameOrigin())
	took := time.Since(started)

	if res.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("a hung identity answered %d, and it is a 503", res.StatusCode)
	}
	if took > time.Second {
		t.Errorf("the request took %s and the 60ms timeout did not bound it. A handler that cannot be stopped is a request that never finishes.", took)
	}
}

// A session identity minted with an unusable expiry is refused, and NOTHING is
// stored: a cookie would be set and the next request would refuse it, which is a
// login that reports success and signs the user out.
func TestASessionWithNoUsableExpiryIsRefusedAndNothingIsStored(t *testing.T) {
	cases := map[string]string{
		"no token":              `{"expires_at":"` + futureExpiry + `"}`,
		"an empty token":        `{"token":"","expires_at":"` + futureExpiry + `"}`,
		"no expiry":             `{"token":"` + identityToken + `"}`,
		"an empty expiry":       `{"token":"` + identityToken + `","expires_at":""}`,
		"an unparseable expiry": `{"token":"` + identityToken + `","expires_at":"next tuesday"}`,
		"an expiry in the past": `{"token":"` + identityToken + `","expires_at":"2020-01-01T00:00:00Z"}`,
	}

	for name, upstream := range cases {
		t.Run(name, func(t *testing.T) {
			body := upstream
			h := build(t, func(*http.Request) (*http.Response, error) { return answer(http.StatusOK, body), nil })

			res := h.do(t, http.MethodPost, "/auth/login", `{"email":"a@example.test","password":"pw"}`, sameOrigin())

			if res.StatusCode != http.StatusServiceUnavailable {
				t.Errorf("a session with %s answered %d, and it is a 503", name, res.StatusCode)
			}
			if sessionCookieValue(res) != "" {
				t.Error("a session that was refused set a cookie, so the next request refuses a cookie the browser was just given")
			}
			if h.sessions.Size() != 0 {
				t.Errorf("a refused login stored %d record(s)", h.sessions.Size())
			}
		})
	}
}

// The login body says when the session runs out and nothing else.
func TestTheLoginBodyCarriesTheExpiryAndNothingElse(t *testing.T) {
	h := build(t, loginIdentity(answer(http.StatusNoContent, "")))

	res := h.do(t, http.MethodPost, "/auth/login", `{"email":"a@example.test","password":"pw"}`, sameOrigin())

	if res.StatusCode != http.StatusOK {
		t.Fatalf("a login answered %d. Body: %s", res.StatusCode, readBody(t, res))
	}
	body := readBody(t, res)
	if body != `{"expires_at":"`+futureExpiry+`"}` {
		t.Errorf("the login body is %s and it must be exactly the expiry. Echoing the token would hand the page a long-lived credential that the HttpOnly cookie exists to keep away from it.", body)
	}
	assertNoToken(t, "the login body", body)
}

// CONFIGURATION: the refusals happen at construction.

// A malformed identity URL is a refusal to build, not a 503 on every sign-in.
func TestAMalformedIdentityURLIsARefusalToBuild(t *testing.T) {
	cases := map[string]string{
		"empty":                        "",
		"not a URL":                    "identity:8080",
		"a scheme that is not http(s)": "grpc://identity:8080",
		"a path":                       "http://identity:8080/v1",
		"a query":                      "http://identity:8080?x=1",
	}

	for name, url := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := NewBff(BffOptions{IdentityURL: url, Sessions: sessiontest.New(nil)})
			if !errors.Is(err, ErrNotConfigured) {
				t.Errorf("NewBff(%q) returned %v, and it must refuse to build. A configuration mistake that only shows up as a 503 on every login is one an operator diagnoses from logs.", url, err)
			}
		})
	}
}

// A trailing slash is what an operator types out of habit, and keeping it would
// join into `//v1/users`.
func TestATrailingSlashIsDropped(t *testing.T) {
	bff, err := NewBff(BffOptions{IdentityURL: "http://identity.test:8080/", Sessions: sessiontest.New(nil)})
	if err != nil {
		t.Fatalf("NewBff refused a trailing slash: %v", err)
	}
	if got := bff.target(identitySession); got != "http://identity.test:8080/v1/session" {
		t.Errorf("the session route resolves to %q, and a base carrying its slash puts it at //v1/session", got)
	}
}

// A negative timeout is a refusal, and a zero one is the default rather than "no
// limit".
func TestTheTimeoutIsValidatedAndZeroMeansTheDefault(t *testing.T) {
	if _, err := NewBff(BffOptions{IdentityURL: "http://identity.test", Sessions: sessiontest.New(nil), IdentityTimeout: -1}); !errors.Is(err, ErrNotConfigured) {
		t.Errorf("a negative timeout returned %v, and it must be a refusal", err)
	}

	bff, err := NewBff(BffOptions{IdentityURL: "http://identity.test", Sessions: sessiontest.New(nil)})
	if err != nil {
		t.Fatalf("NewBff refused the zero value: %v", err)
	}
	if bff.timeout != defaultIdentityTimeout {
		t.Errorf("an unset timeout is %s, and zero must mean the %s default rather than no limit", bff.timeout, defaultIdentityTimeout)
	}
}

// A browser surface with no session store is a refusal to build: four routes that
// cannot tell a signed-in user from a stranger are not a gateway.
func TestABrowserSurfaceWithNoSessionStoreIsARefusalToBuild(t *testing.T) {
	_, err := NewBff(BffOptions{IdentityURL: "http://identity.test"})
	if !errors.Is(err, ErrNotConfigured) {
		t.Errorf("NewBff with no store returned %v, and it must refuse to build", err)
	}
	if _, err := New(Options{BFF: &BffOptions{IdentityURL: "http://identity.test"}}); !errors.Is(err, ErrNotConfigured) {
		t.Errorf("New with a storeless BFF returned %v, and it must refuse to build", err)
	}
}

// WITHOUT a browser surface the four routes decline with the reference's `404` —
// the answer `createApp({})` gives, since it does not register `/auth/*` without an
// identity to ask.
func TestWithoutABrowserSurfaceTheFourRoutesAre404(t *testing.T) {
	handler, err := New(Options{})
	if err != nil {
		t.Fatalf("New refused an empty configuration: %v", err)
	}

	for _, spec := range []struct{ method, path string }{
		{http.MethodPost, "/auth/register"},
		{http.MethodPost, "/auth/login"},
		{http.MethodPost, "/auth/logout"},
		{http.MethodGet, "/auth/me"},
	} {
		req := httptest.NewRequest(spec.method, "https://gateway.test"+spec.path, strings.NewReader(`{}`))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		res := rec.Result()
		if res.StatusCode != http.StatusNotFound {
			t.Errorf("%s %s with no browser surface answered %d, and the reference answers 404 because it does not register the route at all", spec.method, spec.path, res.StatusCode)
		}
		if got := readBody(t, res); got != `{"error":"not_found","message":"no such route"}` {
			t.Errorf("%s %s answered %q, and it must be the v0 envelope the reference writes for an unregistered route", spec.method, spec.path, got)
		}
	}
}

// A configured identity registers itself as a probe, and it is FIRST, because
// `/readyz` renders `deps` in registration order and `encoding/json` sorts map
// keys — which is the entire reason `Options.Probes` is a slice.
func TestAConfiguredIdentityRegistersAProbeAndItIsFirst(t *testing.T) {
	h := build(t, func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == identityHealthz {
			return answer(http.StatusOK, ""), nil
		}
		return answer(http.StatusOK, `{}`), nil
	})

	res := h.do(t, http.MethodGet, "/readyz", "", nil)

	if res.StatusCode != http.StatusOK {
		t.Fatalf("/readyz answered %d", res.StatusCode)
	}
	if got := readBody(t, res); got != `{"deps":{"identity":"ok"}}` {
		t.Errorf("/readyz is %s and a configured identity answers `{\"deps\":{\"identity\":\"ok\"}}` — the reference registers identity unconditionally and Redis only when REDIS_URL is set", got)
	}
}

// A dependency that is DOWN is reported by name and not by detail: a readiness
// endpoint that fails because of its own credentials is not a readiness check.
func TestADownDependencyIsUnavailableAndNamesNoReason(t *testing.T) {
	h := build(t, func(*http.Request) (*http.Response, error) {
		return nil, errors.New("dial tcp://identity.internal:8080: connect: connection refused (password=hunter2)")
	})

	res := h.do(t, http.MethodGet, "/readyz", "", nil)

	if res.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("/readyz with a down identity answered %d, and it is a 503", res.StatusCode)
	}
	body := readBody(t, res)
	if body != `{"deps":{"identity":"unavailable"}}` {
		t.Errorf("/readyz is %s and it must be `{\"deps\":{\"identity\":\"unavailable\"}}`", body)
	}
	for _, leak := range []string{"hunter2", "identity.internal", "refused"} {
		if strings.Contains(body, leak) {
			t.Errorf("/readyz names %q: %s. Which dependency failed is named; why it failed is not.", leak, body)
		}
	}
}

// PROPERTY 3, as a source check. The behavioural tests above search for one
// literal token; this reads the file to catch the handler that writes a token
// without the fixture's literal ever appearing in it.
func TestTheBrowserNeverReceivesTheIdentityToken(t *testing.T) {
	source, err := os.ReadFile("bff.go")
	if err != nil {
		t.Fatalf("cannot read bff.go: %v", err)
	}

	// Every line that writes a response, or sets a cookie on one.
	writes := regexp.MustCompile(`(?m)^\s*(?:writeJSON|writeRawJSON|writeProblem|setSessionCookie|clearSessionCookie|http\.SetCookie)\(`)
	found := false
	for i, line := range strings.Split(string(source), "\n") {
		if !writes.MatchString(line) {
			continue
		}
		found = true
		if strings.Contains(line, "session.Token") || strings.Contains(line, "sessionID") && strings.Contains(line, "Token") {
			t.Errorf("bff.go:%d writes a token into a response: %s", i+1, strings.TrimSpace(line))
		}
	}

	if !found {
		t.Fatalf("no line in bff.go matched %s, so this check is comparing nothing. A check that stops matching is worse than no check: it is a green that costs a reader their trust in the red ones.", writes)
	}
}

// Every mutating route is gated and the read is not, read out of the DOCUMENT
// rather than out of a hand-written list — a list would go stale the day an
// operation is added, and would report "all mutating routes are gated" about a
// route nobody looked at.
func TestTheOriginGateCoversEveryMutatingRouteAndOnlyThose(t *testing.T) {
	generated, err := os.ReadFile(filepath.Join("..", "api", "api.gen.go"))
	if err != nil {
		t.Fatalf("cannot read the generated file: %v", err)
	}

	registrations := regexp.MustCompile(`(?m)^\s*r\.(Get|Post|Put|Patch|Delete)\("([^"]+)"`)
	var authRoutes int
	for _, match := range registrations.FindAllStringSubmatch(string(generated), -1) {
		method, path := strings.ToUpper(match[1]), match[2]
		if !strings.HasPrefix(path, "/auth/") {
			continue
		}
		authRoutes++

		handler := build(t, func(*http.Request) (*http.Response, error) {
			t.Errorf("identity was asked for a request the origin gate should have stopped")
			return answer(http.StatusOK, `{}`), nil
		}).handler

		req := httptest.NewRequest(method, "https://gateway.test"+path, strings.NewReader(`{}`))
		// A body gateway refuses, so a `400` means the request REACHED the
		// handler, and a `403` means the gate stopped it in front.
		req.Header.Set("Sec-Fetch-Site", "cross-site")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		gated := rec.Result().StatusCode == http.StatusForbidden
		mutating := method != http.MethodGet
		if gated != mutating {
			t.Errorf("%s %s: gated=%v, and the gate covers every mutating route and only those", method, path, gated)
		}
	}

	if authRoutes != 4 {
		t.Errorf("read %d /auth registration(s) out of the generated file and openapi/v1.yaml declares four. If the generator changed how it writes a registration, this test has stopped checking anything.", authRoutes)
	}
}

// No file in this package opens a socket. The `Doer` seam is the reason the
// assertions above are about what gateway SENDS, and a test that reached for
// `http.Get` would still pass and would stop being that.
func TestNoFileInThisPackageTalksToARealSocket(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("cannot read this package's directory: %v", err)
	}

	// Deliberately NOT a filename pattern. A check that searched for `*_test.go`
	// would miss a test file this package happens not to name that way, and a
	// check that searched for `test` in the name would find nothing in a Go
	// package whose tests are `bff_test.go` only by accident. The scope is the
	// directory, and the thing searched for is the call.
	forbidden := regexp.MustCompile(`http\.(Get|Post|Head|DefaultClient\.Do)\(|\bhttptest\.NewServer\(`)

	var files int
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") {
			continue
		}
		files++
		source, err := os.ReadFile(entry.Name())
		if err != nil {
			t.Fatalf("cannot read %s: %v", entry.Name(), err)
		}
		if match := forbidden.Find(source); match != nil {
			t.Errorf("%s calls %q. `Doer` is the seam and this package opens no sockets; a real one would add the network's opinions to every assertion about what gateway sends.", entry.Name(), match)
		}
	}

	if files == 0 {
		t.Fatal("no .go file was found in this package, so this check compared nothing")
	}
}

// assertNoToken is the one place the literal credential is searched for, so a
// failure names what leaked rather than a string comparison.
func assertNoToken(t *testing.T, where, body string) {
	t.Helper()

	if strings.Contains(body, identityToken) {
		t.Errorf("%s carries the identity token: %s. The browser holds a session id and nothing else; that is the entire BFF claim.", where, body)
	}
}

func readBody(t *testing.T, res *http.Response) string {
	t.Helper()

	raw, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("cannot read the response body: %v", err)
	}
	return string(raw)
}

// forget drops the record a `Cookie` header names, so a test can stand in for a
// store that lost it — a restart, a swept map.
func forget(t *testing.T, h *harness, cookie string) {
	t.Helper()

	if err := h.sessions.Delete(context.Background(), strings.TrimPrefix(cookie, SessionCookie+"=")); err != nil {
		t.Fatalf("the fixture store refused a delete: %v", err)
	}
}

// traceIDField is the one field a problem document is allowed to vary between two
// otherwise-identical answers.
var traceIDField = regexp.MustCompile(`"trace_id":"[0-9a-f]{32}"`)

// withoutTraceID replaces it with a constant, so a body comparison can be about
// everything else instead of being dropped.
func withoutTraceID(body string) string {
	return traceIDField.ReplaceAllString(body, `"trace_id":"<id>"`)
}

// traceIDOf is the raw match, or "" when the document carries none.
func traceIDOf(body string) string { return traceIDField.FindString(body) }
