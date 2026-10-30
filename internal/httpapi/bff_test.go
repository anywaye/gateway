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

	"github.com/anywaye/gateway/internal/sessiontest"
)

func TestTheProblemEnvelopeIsTheReferencesFieldOrder(t *testing.T) {
	h := build(t, func(*http.Request) (*http.Response, error) {
		return answer(http.StatusUnauthorized, `{"error":"invalid_credentials"}`).Response, nil
	})

	res := h.do(t, http.MethodPost, "/auth/login", `{"email":"a@example.test","password":"pw"}`, sameOrigin())
	body := withoutTraceID(readBody(t, res))

	want := `{"type":"https://docs.anywaye.com/errors/unauthorized","title":"Unauthorized","status":401,` +
		`"detail":"email or password is not correct","instance":"/auth/login","code":"unauthorized","trace_id":"<id>"}`
	if body != want {
		t.Errorf("the problem document is\n  %s\nand it must be\n  %s\n\nThe field ORDER is part of the contract: `internal/equivalence` compared bodies byte for byte, and `api.Problem`'s generated order is alphabetical where `src/problem.ts` (removed at cutover) is not.", body, want)
	}

	created := build(t, func(*http.Request) (*http.Response, error) {
		return answer(http.StatusCreated, `{"id":"11111111-2222-3333-4444-555555555555","email":"a@example.test"}`).Response, nil
	}).do(t, http.MethodPost, "/auth/register", `{"email":"a@example.test","password":"pw"}`, sameOrigin())

	if strings.Contains(readBody(t, created), `"errors"`) {
		t.Errorf("a 201 carries `errors`: %s. The key is absent rather than empty so a client rendering a form can tell \"no fields failed\" from \"this response is not about fields\".", readBody(t, created))
	}
}

func TestAValidationFailureKeepsFieldBeforeCodeAndIsLast(t *testing.T) {
	h := build(t, func(*http.Request) (*http.Response, error) {
		return answer(http.StatusUnprocessableEntity, `{"errors":[{"field":"email","code":"not_an_email"},{"field":"password","code":"too_short"}]}`).Response, nil
	})

	res := h.do(t, http.MethodPost, "/auth/register", `{"email":"nope","password":"x"}`, sameOrigin())

	body := withoutTraceID(readBody(t, res))
	tail := `,"errors":[{"field":"email","code":"not_an_email"},{"field":"password","code":"too_short"}]}`
	if !strings.HasSuffix(body, tail) {
		t.Errorf("the 422 is\n  %s\nand it must END with\n  %s\n\n`errors` is last and each entry is `field` then `code`: the reference's literal is `{ field, code }`, and `api.FieldError`'s generated order is the reverse because the generator sorts.", body, tail)
	}
}


const (
	futureExpiry = "2031-03-04T05:06:07.000Z"

	identityToken = "identity-token-abcdef0123456789"
)

type doerFunc func(r *http.Request) (*http.Response, error)

func (f doerFunc) Do(r *http.Request) (*http.Response, error) { return f(r) }

type harness struct {
	handler  http.Handler
	sessions *sessiontest.Store
	calls    []*http.Request
	bodies   []string
	now      time.Time
}

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

type testResponse struct{ *http.Response }

func answer(status int, body string, headers ...string) testResponse {
	res := &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     http.Header{},
	}
	for i := 0; i+1 < len(headers); i += 2 {
		res.Header.Set(headers[i], headers[i+1])
	}
	return testResponse{res}
}

func sameOrigin() map[string]string {
	return map[string]string{"Sec-Fetch-Site": "same-origin"}
}

func cookies(res testResponse) []*http.Cookie {
	return (&http.Response{Header: res.Header}).Cookies()
}

func sessionCookieValue(res testResponse) string {
	for _, c := range cookies(res) {
		if c.Name == SessionCookie {
			return c.Value
		}
	}
	return ""
}

func setsSessionCookie(res testResponse) bool {
	for _, c := range cookies(res) {
		if c.Name == SessionCookie && c.Value != "" {
			return true
		}
	}
	return false
}

func clearsSessionCookie(res testResponse) bool {
	for _, c := range cookies(res) {
		if c.Name != SessionCookie || c.Value != "" {
			continue
		}
		if c.MaxAge < 0 || (!c.Expires.IsZero() && !c.Expires.After(time.Unix(0, 0))) {
			return true
		}
	}
	return false
}

func (h *harness) do(t *testing.T, method, path string, body string, headers map[string]string) testResponse {
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
	h.handler.ServeHTTP(rec, req)
	return testResponse{rec.Result()}
}

func (h *harness) signedIn(t *testing.T) string {
	t.Helper()

	res := h.do(t, http.MethodPost, "/auth/login", `{"email":"a@example.test","password":"pw"}`, sameOrigin())
	if res.StatusCode != http.StatusOK {
		t.Fatalf("the fixture login answered %d, so a test that signed in first cannot mean anything", res.StatusCode)
	}
	return SessionCookie + "=" + sessionCookieValue(res)
}

func loginIdentity(res testResponse) doerFunc {
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
			return res.Response, nil
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


func TestACrossOriginPostIsRefusedAndIdentityIsNeverAsked(t *testing.T) {
	h := build(t, func(*http.Request) (*http.Response, error) {
		t.Error("identity was asked; the origin gate should have answered before it")
		return answer(http.StatusOK, `{"token":"x","expires_at":"`+futureExpiry+`"}`).Response, nil
	})

	for _, path := range []string{"/auth/register", "/auth/login", "/auth/logout"} {
		res := h.do(t, http.MethodPost, path, `{"email":"a@example.test","password":"pw"}`,
			map[string]string{"Sec-Fetch-Site": "cross-site"})

		if res.StatusCode != http.StatusForbidden {
			t.Errorf("POST %s with Sec-Fetch-Site: cross-site answered %d, and the origin gate's answer is 403", path, res.StatusCode)
		}
		if setsSessionCookie(res) {
			t.Errorf("POST %s set a session cookie on a refused request", path)
		}
	}
	if len(h.calls) != 0 {
		t.Errorf("identity was called %d time(s) behind a refused origin gate", len(h.calls))
	}
}

func TestASameOriginPostSucceeds(t *testing.T) {
	h := build(t, func(*http.Request) (*http.Response, error) {
		return answer(http.StatusCreated, `{"id":"11111111-2222-3333-4444-555555555555","email":"a@example.test"}`).Response, nil
	})

	res := h.do(t, http.MethodPost, "/auth/register", `{"email":"a@example.test","password":"pw"}`, sameOrigin())

	if res.StatusCode != http.StatusCreated {
		t.Fatalf("a same-origin registration answered %d, and the origin gate's other direction is that it succeeds. Body: %s", res.StatusCode, readBody(t, res))
	}
	if len(h.calls) != 1 {
		t.Errorf("identity was called %d time(s) for a same-origin registration, and it is called exactly once", len(h.calls))
	}
}

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
				return answer(http.StatusCreated, `{"id":"11111111-2222-3333-4444-555555555555","email":"a@example.test"}`).Response, nil
			})

			res := h.do(t, http.MethodPost, "/auth/register", `{"email":"a@example.test","password":"pw"}`,
				map[string]string{"Sec-Fetch-Site": tc.value})

			if res.StatusCode != tc.want {
				t.Errorf("Sec-Fetch-Site: %q answered %d and the gate's answer is %d — %s", tc.value, res.StatusCode, tc.want, tc.why)
			}
		})
	}
}

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
				return answer(http.StatusCreated, `{"id":"11111111-2222-3333-4444-555555555555","email":"a@example.test"}`).Response, nil
			})

			res := h.do(t, http.MethodPost, "/auth/register", `{"email":"a@example.test","password":"pw"}`,
				map[string]string{"Origin": tc.origin})

			if res.StatusCode != tc.want {
				t.Errorf("Origin: %s answered %d and the gate's answer is %d", tc.origin, res.StatusCode, tc.want)
			}
		})
	}
}

func TestARequestThatStatesNeitherHeaderIsRefused(t *testing.T) {
	h := build(t, func(*http.Request) (*http.Response, error) {
		t.Error("identity was asked for a request that stated no origin at all")
		return answer(http.StatusOK, `{}`).Response, nil
	})

	res := h.do(t, http.MethodPost, "/auth/login", `{"email":"a@example.test","password":"pw"}`, nil)

	if res.StatusCode != http.StatusForbidden {
		t.Errorf("a POST stating neither header answered %d, and an unstated origin is not a same-origin one", res.StatusCode)
	}
}

func TestDisagreeingOriginSignalsAreRefused(t *testing.T) {
	h := build(t, func(*http.Request) (*http.Response, error) {
		t.Error("identity was asked for a request whose two origin signals disagree")
		return answer(http.StatusOK, `{}`).Response, nil
	})

	res := h.do(t, http.MethodPost, "/auth/login", `{"email":"a@example.test","password":"pw"}`, map[string]string{
		"Sec-Fetch-Site": "same-origin",
		"Origin":         "https://evil.test",
	})

	if res.StatusCode != http.StatusForbidden {
		t.Errorf("Sec-Fetch-Site: same-origin with Origin: evil answered %d. A browser is consistent, so this is a client choosing what each header says and the gate must believe the stricter one.", res.StatusCode)
	}
}

func TestTheReadIsNotGated(t *testing.T) {
	h := build(t, loginIdentity(answer(http.StatusNoContent, "")))
	cookie := h.signedIn(t)

	res := h.do(t, http.MethodGet, "/auth/me", "", map[string]string{"Cookie": cookie, "Sec-Fetch-Site": "cross-site"})

	if res.StatusCode != http.StatusOK {
		t.Errorf("GET /auth/me with a hostile Sec-Fetch-Site answered %d. The gate is CSRF defense and a read needs none.", res.StatusCode)
	}
}

func TestAHeaderSentTwiceTakesTheFirstValue(t *testing.T) {
	for _, first := range []string{"same-origin", "cross-site"} {
		t.Run(first, func(t *testing.T) {
			h := build(t, func(*http.Request) (*http.Response, error) {
				return answer(http.StatusCreated, `{"id":"11111111-2222-3333-4444-555555555555","email":"a@example.test"}`).Response, nil
			})

			req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "https://gateway.test/auth/register", strings.NewReader(`{"email":"a@x.test","password":"pw"}`))
			req.Header.Add("Sec-Fetch-Site", first)
			req.Header.Add("Sec-Fetch-Site", "cross-site")

			rec := httptest.NewRecorder()
			h.handler.ServeHTTP(rec, req)
			res := rec.Result()

			want := http.StatusCreated
			if first != "same-origin" {
				want = http.StatusForbidden
			}
			if res.StatusCode != want {
				t.Errorf("Sec-Fetch-Site sent twice, first value %q, answered %d and the first value's answer is %d. The reference takes the first value; refusing a doubled header would look stricter and would be a divergence.", first, res.StatusCode, want)
			}
			if got := res.Header.Get("Content-Type"); strings.HasPrefix(got, "text/plain") {
				t.Errorf("the answer is %q, which is the GENERATED ROUTER's refusal. `collapseRepeatedHeaders` exists so the router never sees a repeated header, and a body shape that is not in `openapi/v1.yaml` must never reach a caller.", got)
			}
		})
	}
}

func TestTheParameterRefusalIsUnreachableForTheDeclaredHeaders(t *testing.T) {
	for _, header := range []string{"Sec-Fetch-Site", "Origin"} {
		t.Run(header, func(t *testing.T) {
			h := build(t, func(*http.Request) (*http.Response, error) {
				return answer(http.StatusCreated, `{"id":"11111111-2222-3333-4444-555555555555","email":"a@example.test"}`).Response, nil
			})

			value := map[string]string{"Sec-Fetch-Site": "same-origin", "Origin": "https://gateway.test"}[header]

			req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "https://gateway.test/auth/register", strings.NewReader(`{"email":"a@x.test","password":"pw"}`))
			req.Header.Add(header, value)
			req.Header.Add(header, value)

			rec := httptest.NewRecorder()
			h.handler.ServeHTTP(rec, req)
			res := rec.Result()

			if res.StatusCode != http.StatusCreated {
				t.Errorf("%s sent twice answered %d, and it must reach the handler and be answered there. A duplicate-header refusal is the generated router's, and it is not an answer this contract describes.", header, res.StatusCode)
			}
			if len(h.calls) != 1 {
				t.Errorf("%s sent twice made %d call(s) to identity, and the handler behind it was reached exactly once", header, len(h.calls))
			}
		})
	}
}


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


func TestTwoRefusalCausesProduceIdenticalResponses(t *testing.T) {
	causes := map[string]string{
		"a wrong password":   `{"error":"invalid_credentials","detail":"that password is not correct for this account"}`,
		"an unknown account": `{"error":"no_such_user","detail":"no account has that email address"}`,
	}

	var answers []testResponse
	for name, upstream := range causes {
		h := build(t, func(*http.Request) (*http.Response, error) {
			return answer(http.StatusUnauthorized, upstream).Response, nil
		})

		res := h.do(t, http.MethodPost, "/auth/login", `{"email":"a@example.test","password":"pw"}`, sameOrigin())

		if res.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s: identity answered 401 and this answered %d", name, res.StatusCode)
		}
		if got := sessionCookieValue(res); got != "" {
			t.Errorf("%s: a refused login set a session cookie: %q", name, got)
		}
		if h.sessions.Size() != 0 {
			t.Errorf("%s: a refused login stored %d record(s). A refused credential must leave nothing behind — a record nobody was told about is a session that exists and cannot be used.", name, h.sessions.Size())
		}
		answers = append(answers, res)
	}

	first, second := answers[0], answers[1]
	firstRaw, secondRaw := readBody(t, first), readBody(t, second)
	firstBody, secondBody := withoutTraceID(firstRaw), withoutTraceID(secondRaw)

	if firstBody != secondBody {
		t.Errorf("two refusal causes produced different bodies, and a login endpoint whose 401 varies by cause is an account-enumeration oracle:\n  cause A: %s\n  cause B: %s", firstBody, secondBody)
	}
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

func TestTheTwoRefusalsAgreeOnStatusAndContentType(t *testing.T) {
	var types []string
	for _, upstream := range []string{`{"error":"a"}`, `{"error":"b"}`} {
		body := upstream
		h := build(t, func(*http.Request) (*http.Response, error) {
			return answer(http.StatusUnauthorized, body).Response, nil
		})

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
				return answer(http.StatusLocked, `{"error":"locked"}`, "Retry-After", tc.retry).Response, nil
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
	if body != `{"id":"11111111-2222-3333-4444-555555555555","email":"a@example.test"}` {
		t.Errorf("the /auth/me body is %s and it must be `id` then `email` and nothing else — the reference's order, the reference's width, and the bytes the comparison needs", body)
	}
}

func TestAnExpiredSessionIs401AndIdentityIsNeverAsked(t *testing.T) {
	h := build(t, loginIdentity(answer(http.StatusNoContent, "")))
	cookie := h.signedIn(t)
	before := len(h.calls)

	h.now = time.Date(2032, 1, 1, 0, 0, 0, 0, time.UTC)

	res := h.do(t, http.MethodGet, "/auth/me", "", map[string]string{"Cookie": cookie})

	if res.StatusCode != http.StatusUnauthorized {
		t.Errorf("an expired session answered %d, and an expired session is a 401", res.StatusCode)
	}
	if len(h.calls) != before {
		t.Errorf("an expired session made %d call(s) to identity; there is no live token to spend", len(h.calls)-before)
	}
	if !clearsSessionCookie(res) {
		t.Error("the expired session's cookie was not cleared, so the browser keeps presenting a record that can never work again")
	}
}

func TestAWithdrawnSessionIs401AndTheRecordIsDropped(t *testing.T) {
	withdrawn := false
	h := build(t, func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == identityMe && withdrawn {
			return answer(http.StatusUnauthorized, `{"error":"unauthorized"}`).Response, nil
		}
		return loginIdentity(answer(http.StatusNoContent, ""))(r)
	})
	cookie := h.signedIn(t)

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
	if !clearsSessionCookie(res) {
		t.Error("a withdrawn session's cookie was not cleared")
	}
}

func TestAForgottenSessionIs401AndTheCookieIsCleared(t *testing.T) {
	h := build(t, loginIdentity(answer(http.StatusNoContent, "")))
	cookie := h.signedIn(t)

	forget(t, h, cookie)

	res := h.do(t, http.MethodGet, "/auth/me", "", map[string]string{"Cookie": cookie})
	if res.StatusCode != http.StatusUnauthorized {
		t.Errorf("a session the store has forgotten answered %d, and it is a 401", res.StatusCode)
	}
	if !clearsSessionCookie(res) {
		t.Error("the cookie for a forgotten session was not cleared, so the browser keeps presenting it")
	}
}

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

func TestSignOutWithNoCookieIs401(t *testing.T) {
	h := build(t, func(*http.Request) (*http.Response, error) {
		t.Error("identity was asked to revoke a session that was never presented")
		return answer(http.StatusNoContent, "").Response, nil
	})

	res := h.do(t, http.MethodPost, "/auth/logout", "", sameOrigin())

	if res.StatusCode != http.StatusUnauthorized {
		t.Errorf("signing out with no cookie answered %d, and it is a 401", res.StatusCode)
	}
}

func TestSigningOutWithAForgottenCookieIs204AndStillClears(t *testing.T) {
	h := build(t, loginIdentity(answer(http.StatusNoContent, "")))
	cookie := h.signedIn(t)
	forget(t, h, cookie)

	res := h.do(t, http.MethodPost, "/auth/logout", "", map[string]string{"Cookie": cookie, "Sec-Fetch-Site": "same-origin"})

	if res.StatusCode != http.StatusNoContent {
		t.Errorf("signing out a forgotten session answered %d. Refusing is what makes sign-out look broken.", res.StatusCode)
	}
	if !clearsSessionCookie(res) {
		t.Error("the cookie was not cleared, so the browser keeps presenting it")
	}
}

func TestSigningOutAnAlreadyRevokedSessionIs204(t *testing.T) {
	for _, status := range []int{http.StatusNoContent, http.StatusUnauthorized, http.StatusNotFound} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			revoking := status
			h := build(t, func(r *http.Request) (*http.Response, error) {
				if r.URL.Path == identitySession && r.Method == http.MethodDelete {
					return answer(revoking, "").Response, nil
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
	if !clearsSessionCookie(res) {
		t.Error("the cookie was not cleared even though the local record is gone")
	}
}

func TestANonRevokingLogoutIsUnreachableNotUnusable(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusInternalServerError, http.StatusTooManyRequests} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			revoking := status
			h := build(t, func(r *http.Request) (*http.Response, error) {
				if r.URL.Path == identitySession && r.Method == http.MethodDelete {
					return answer(revoking, "not a revocation").Response, nil
				}
				return loginIdentity(answer(http.StatusNoContent, ""))(r)
			})
			cookie := h.signedIn(t)

			res := h.do(t, http.MethodPost, "/auth/logout", "", map[string]string{"Cookie": cookie, "Sec-Fetch-Site": "same-origin"})

			if res.StatusCode != http.StatusServiceUnavailable {
				t.Fatalf("identity answering %d to a revoke produced %d, and it is a 503", revoking, res.StatusCode)
			}
			body := readBody(t, res)
			if !strings.Contains(body, `"detail":"the authentication service could not be reached"`) {
				t.Errorf("the 503 says %q. The reference's logout answers `unreachable()`, not `unusable()` — a caller that can tell those two apart can tell whether identity was REACHED, and `unreachable` is the answer that says it was not.", body)
			}
			if h.sessions.Size() != 0 {
				t.Errorf("the store holds %d record(s); the browser must be signed out even when identity cannot confirm it", h.sessions.Size())
			}
		})
	}
}

func TestAStoreThatIsDownIs503Not401(t *testing.T) {
	h := build(t, loginIdentity(answer(http.StatusNoContent, "")))
	cookie := h.signedIn(t)

	down := build(t, func(*http.Request) (*http.Response, error) { return answer(http.StatusOK, `{}`).Response, nil },
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

func TestTheCookieIsTheKeyTheRecordIsStoredUnder(t *testing.T) {
	h := build(t, loginIdentity(answer(http.StatusNoContent, "")))

	res := h.do(t, http.MethodPost, "/auth/login", `{"email":"a@example.test","password":"pw"}`, sameOrigin())

	held := h.sessions.Held()
	if len(held) != 1 || held[0] != sessionCookieValue(res) {
		t.Errorf("the cookie is %q and the store holds %v; a browser sending a cookie that is not a key is signed out on the very next request", sessionCookieValue(res), held)
	}
}


func TestRegisterReturnsTheAccountAndNoCookie(t *testing.T) {
	h := build(t, func(*http.Request) (*http.Response, error) {
		return answer(http.StatusCreated, `{"id":"11111111-2222-3333-4444-555555555555","email":"a@example.test","password_digest":"sha256:deadbeef","role":"admin"}`).Response, nil
	})

	res := h.do(t, http.MethodPost, "/auth/register", `{"email":"a@example.test","password":"pw"}`, sameOrigin())

	if res.StatusCode != http.StatusCreated {
		t.Fatalf("registration answered %d. Body: %s", res.StatusCode, readBody(t, res))
	}
	if setsSessionCookie(res) {
		t.Error("a registration set a session cookie. A registration is not a login; identity has minted nothing for this browser to hold.")
	}

	body := readBody(t, res)
	if body != `{"id":"11111111-2222-3333-4444-555555555555","email":"a@example.test"}` {
		t.Errorf("the registration body is %s. It is an ALLOWLIST — a field identity adds next month must not reach a browser response today by being copied, and a digest has no business in a page.", body)
	}
}

func TestTheCallersBodyReachesIdentityVerbatim(t *testing.T) {
	sent := `{"email":"a@example.test","password":"pw","display_name":"A","extra":{"nested":[1,2]},"unicode":"héllo ☃"}`
	h := build(t, func(*http.Request) (*http.Response, error) {
		return answer(http.StatusCreated, `{"id":"11111111-2222-3333-4444-555555555555","email":"a@example.test"}`).Response, nil
	})

	h.do(t, http.MethodPost, "/auth/register", sent, sameOrigin())

	if len(h.bodies) != 1 || h.bodies[0] != sent {
		t.Errorf("identity received %q and it must be the caller's bytes unchanged. Re-encoding a body is a second parser and a second answer to what the request said.", h.bodies)
	}
}

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
				return answer(http.StatusCreated, `{"id":"1","email":"a@x.test"}`).Response, nil
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

func TestABodyJustInsideTheCapIsForwarded(t *testing.T) {
	padding := maxBodyBytes - len(`{"email":"a@example.test","password":""}`)
	body := `{"email":"a@example.test","password":"` + strings.Repeat("x", padding) + `"}`

	h := build(t, func(*http.Request) (*http.Response, error) {
		return answer(http.StatusCreated, `{"id":"11111111-2222-3333-4444-555555555555","email":"a@example.test"}`).Response, nil
	})

	res := h.do(t, http.MethodPost, "/auth/register", body, sameOrigin())

	if res.StatusCode != http.StatusCreated {
		t.Errorf("a body of exactly %d bytes answered %d, and the cap is inclusive", len(body), res.StatusCode)
	}
}

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
			h := build(t, func(*http.Request) (*http.Response, error) { return answer(tc.upstream, tc.body).Response, nil })

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

func TestAPanickingIdentityIsA503AndNotADeadGateway(t *testing.T) {
	h := build(t, func(*http.Request) (*http.Response, error) {
		panic("identity: nil pointer dereference in the token verifier")
	})

	res := h.do(t, http.MethodPost, "/auth/login", `{"email":"a@example.test","password":"pw"}`, sameOrigin())

	if res.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("a panicking identity answered %d, and it is a 503", res.StatusCode)
	}
	assertNoToken(t, "the panic body", readBody(t, res))
}

func TestAHungIdentityIsBounded(t *testing.T) {
	h := build(t, func(*http.Request) (*http.Response, error) {
		time.Sleep(2 * time.Second)
		return answer(http.StatusOK, `{}`).Response, nil
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
			h := build(t, func(*http.Request) (*http.Response, error) { return answer(http.StatusOK, body).Response, nil })

			res := h.do(t, http.MethodPost, "/auth/login", `{"email":"a@example.test","password":"pw"}`, sameOrigin())

			if res.StatusCode != http.StatusServiceUnavailable {
				t.Errorf("a session with %s answered %d, and it is a 503", name, res.StatusCode)
			}
			if setsSessionCookie(res) {
				t.Error("a session that was refused set a cookie, so the next request refuses a cookie the browser was just given")
			}
			if h.sessions.Size() != 0 {
				t.Errorf("a refused login stored %d record(s)", h.sessions.Size())
			}
		})
	}
}

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

func TestATrailingSlashIsDropped(t *testing.T) {
	bff, err := NewBff(BffOptions{IdentityURL: "http://identity.test:8080/", Sessions: sessiontest.New(nil)})
	if err != nil {
		t.Fatalf("NewBff refused a trailing slash: %v", err)
	}
	if got := bff.target(identitySession); got != "http://identity.test:8080/v1/session" {
		t.Errorf("the session route resolves to %q, and a base carrying its slash puts it at //v1/session", got)
	}
}

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

func TestABrowserSurfaceWithNoSessionStoreIsARefusalToBuild(t *testing.T) {
	_, err := NewBff(BffOptions{IdentityURL: "http://identity.test"})
	if !errors.Is(err, ErrNotConfigured) {
		t.Errorf("NewBff with no store returned %v, and it must refuse to build", err)
	}
	if _, err := New(Options{BFF: &BffOptions{IdentityURL: "http://identity.test"}}); !errors.Is(err, ErrNotConfigured) {
		t.Errorf("New with a storeless BFF returned %v, and it must refuse to build", err)
	}
}

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
		req := httptest.NewRequestWithContext(context.Background(), spec.method, "https://gateway.test"+spec.path, strings.NewReader(`{}`))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		res := testResponse{rec.Result()}
		if res.StatusCode != http.StatusNotFound {
			t.Errorf("%s %s with no browser surface answered %d, and the reference answers 404 because it does not register the route at all", spec.method, spec.path, res.StatusCode)
		}
		if got := readBody(t, res); got != `{"error":"not_found","message":"no such route"}` {
			t.Errorf("%s %s answered %q, and it must be the v0 envelope the reference writes for an unregistered route", spec.method, spec.path, got)
		}
	}
}

func TestABrowserSurfaceRegistersNoProbeAndTheReferenceAgrees(t *testing.T) {
	h := build(t, func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == identityHealthz {
			t.Error("identity's liveness endpoint was asked; nothing registered a probe for it")
		}
		return answer(http.StatusOK, `{}`).Response, nil
	})

	res := h.do(t, http.MethodGet, "/readyz", "", nil)

	if res.StatusCode != http.StatusOK {
		t.Fatalf("/readyz answered %d", res.StatusCode)
	}
	if got := readBody(t, res); got != `{"deps":{}}` {
		t.Errorf("/readyz is %s and with a browser surface and no registered probe it is `{\"deps\":{}}` — which is `createApp({bff})`", got)
	}
}

func TestARegisteredIdentityProbeReportsByNameAndNeverByReason(t *testing.T) {
	cases := map[string]struct {
		identity func(*http.Request) (*http.Response, error)
		want     string
		status   int
	}{
		"healthy": {
			identity: func(r *http.Request) (*http.Response, error) {
				if r.URL.Path == identityHealthz {
					return answer(http.StatusOK, "").Response, nil
				}
				return answer(http.StatusOK, `{}`).Response, nil
			},
			want:   `{"deps":{"aperture":"ok","identity":"ok"}}`,
			status: http.StatusOK,
		},
		"the transport failed": {
			identity: func(*http.Request) (*http.Response, error) {
				return nil, errors.New("dial tcp://identity.internal:8080: connect: connection refused (password=hunter2)")
			},
			want:   `{"deps":{"aperture":"ok","identity":"unavailable"}}`,
			status: http.StatusServiceUnavailable,
		},
		"identity answered 500": {
			identity: func(r *http.Request) (*http.Response, error) {
				if r.URL.Path == identityHealthz {
					return answer(http.StatusInternalServerError, "<html>stack trace: password=hunter2</html>").Response, nil
				}
				return answer(http.StatusOK, `{}`).Response, nil
			},
			want:   `{"deps":{"aperture":"ok","identity":"unavailable"}}`,
			status: http.StatusServiceUnavailable,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			h := build(t, tc.identity, func(o *BffOptions) {})

			handler, err := New(Options{
				BFF: &BffOptions{
					IdentityURL: "http://identity.test",
					Sessions:    h.sessions,
					Now:         func() time.Time { return h.now },
					Doer: doerFunc(func(r *http.Request) (*http.Response, error) {
						if r.URL.Path == identityHealthz {
							return tc.identity(r)
						}
						return answer(http.StatusOK, `{}`).Response, nil
					}),
				},
				Probes: []NamedProbe{
					{Name: "aperture", Probe: func(context.Context) error { return nil }},
					{Name: "identity", Probe: (&Bff{identityURL: "http://identity.test", doer: doerFunc(tc.identity), timeout: defaultIdentityTimeout, now: func() time.Time { return h.now }}).IdentityProbe()},
				},
			})
			if err != nil {
				t.Fatalf("New refused the configuration: %v", err)
			}

			req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "https://gateway.test/readyz", nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			res := testResponse{rec.Result()}

			if res.StatusCode != tc.status {
				t.Errorf("/readyz answered %d and it must be %d", res.StatusCode, tc.status)
			}
			body := readBody(t, res)
			if body != tc.want {
				t.Errorf("/readyz is %s and it must be %s — the ORDER is registration order, which is why these two names are not alphabetical", body, tc.want)
			}
			for _, leak := range []string{"hunter2", "identity.internal", "refused", "upstream", "stack"} {
				if strings.Contains(body, leak) {
					t.Errorf("/readyz names %q: %s. Which dependency failed is named; why it failed is not.", leak, body)
				}
			}
		})
	}
}

func TestTheBrowserNeverReceivesTheIdentityToken(t *testing.T) {
	source, err := os.ReadFile("bff.go")
	if err != nil {
		t.Fatalf("cannot read bff.go: %v", err)
	}

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
			return answer(http.StatusOK, `{}`).Response, nil
		}).handler

		req := httptest.NewRequestWithContext(context.Background(), method, "https://gateway.test"+path, strings.NewReader(`{}`))
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

func TestNoFileInThisPackageTalksToARealSocket(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("cannot read this package's directory: %v", err)
	}

	forbidden := regexp.MustCompile(`http\.(Get|Post|Head|DefaultClient\.Do)\(|\bhttptest\.NewServer\(`)

	exempt := map[string]string{
		"proxy_test.go": "records the outbound request; a double would assert the properties against itself",
	}

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
			if why, ok := exempt[entry.Name()]; ok {
				t.Logf("%s calls %q, which is exempt: %s", entry.Name(), match, why)
				continue
			}
			t.Errorf("%s calls %q. `Doer` is the seam and this package opens no sockets; a real one would add the network's opinions to every assertion about what gateway sends.", entry.Name(), match)
		}
	}

	for name := range exempt {
		if _, err := os.Stat(name); err != nil {
			t.Errorf("the exemption names %s, which does not exist: an exemption that matches no file is a hole with a comment on it", name)
		}
	}

	if files == 0 {
		t.Fatal("no .go file was found in this package, so this check compared nothing")
	}
}

func assertNoToken(t *testing.T, where, body string) {
	t.Helper()

	if strings.Contains(body, identityToken) {
		t.Errorf("%s carries the identity token: %s. The browser holds a session id and nothing else; that is the entire BFF claim.", where, body)
	}
}

func readBody(t *testing.T, res testResponse) string {
	t.Helper()

	raw, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("cannot read the response body: %v", err)
	}
	_ = res.Body.Close()
	return string(raw)
}

func forget(t *testing.T, h *harness, cookie string) {
	t.Helper()

	if err := h.sessions.Delete(context.Background(), strings.TrimPrefix(cookie, SessionCookie+"=")); err != nil {
		t.Fatalf("the fixture store refused a delete: %v", err)
	}
}

var traceIDField = regexp.MustCompile(`"trace_id":"[0-9a-f]{32}"`)

func withoutTraceID(body string) string {
	return traceIDField.ReplaceAllString(body, `"trace_id":"<id>"`)
}

func traceIDOf(body string) string { return traceIDField.FindString(body) }
