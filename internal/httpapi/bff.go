package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/anywaye/gateway/internal/api"
	"github.com/anywaye/gateway/internal/session"
)


// SessionCookie is the session cookie's name.
//
// The `__Host-` prefix is a contract the BROWSER enforces — `Secure`, `Path=/`,
// and no `Domain` — which makes the cookie impossible for a subdomain or a
// plain-HTTP sibling origin to set or overwrite. That is the cookie-fixation
// vector a plain `session` cookie leaves open, and it is why this is a constant
// rather than a value in a handler.
//
// It is a constant and not a configured name on purpose: a configurable cookie
// name is a way to ship this gateway without the `__Host-` guarantee, which is
// the one property the cookie is for.
const SessionCookie = "__Host-bff-session"

const (
	identityRegister = "/v1/users"
	identitySession  = "/v1/session"
	identityMe       = "/v1/me"
	identityHealthz  = "/healthz"
)

const defaultIdentityTimeout = 5 * time.Second

const maxBodyBytes = 4 << 10

// Doer is the part of `*http.Client` this file uses.
//
// An interface so the suite never opens a socket, and for the reason
// `src/bff/auth.ts` (removed at cutover) gives its own `FetchFn`: the assertions here are about what
// gateway SENDS and what it does with the ANSWER, and a real server would add
// the network's opinions to both.
type Doer interface {
	Do(req *http.Request) (*http.Response, error)
}

// BffOptions configures the browser surface.
//
// An argument rather than something read from the environment inside this
// package, for the property `Options` states: there is nowhere in
// `internal/httpapi` that CAN read the environment, so a test can build two
// differently configured apps in one process — which is exactly what
// `internal/equivalence` did.
type BffOptions struct {
	IdentityURL string

	Sessions session.SessionStore

	Doer Doer

	IdentityTimeout time.Duration

	Now func() time.Time
}

// Bff is the built browser surface: four handlers and the gate three of them sit
// behind.
type Bff struct {
	identityURL string
	sessions    session.SessionStore
	doer        Doer
	timeout     time.Duration
	now         func() time.Time
}

// NewBff validates and builds the surface.
//
// It returns an error rather than panicking, and it validates BEFORE assembling,
// so a malformed configuration is a refusal to construct the gateway rather than
// a `503` on every sign-in the operator then has to read logs to diagnose.
// `IDENTITY_URL=identity:8080` has to be a refusal to boot for exactly that
// reason — the same rule the JWT verifier applies, which is a separate packet.
func NewBff(options BffOptions) (*Bff, error) {
	base, err := parseIdentityURL(options.IdentityURL)
	if err != nil {
		return nil, err
	}
	if options.Sessions == nil {
		return nil, fmt.Errorf("%w: BffOptions.Sessions is nil, and the browser surface with no session store is four routes that cannot tell a signed-in user from a stranger", ErrNotConfigured)
	}

	timeout := options.IdentityTimeout
	if timeout == 0 {
		timeout = defaultIdentityTimeout
	}
	if timeout < 0 {
		return nil, fmt.Errorf("%w: BffOptions.IdentityTimeout must be greater than zero, got %s", ErrNotConfigured, timeout)
	}

	doer := options.Doer
	if doer == nil {
		doer = http.DefaultClient
	}
	now := options.Now
	if now == nil {
		now = time.Now
	}

	return &Bff{identityURL: base, sessions: options.Sessions, doer: doer, timeout: timeout, now: now}, nil
}

// IdentityProbe reports whether identity is reachable, for `/readyz`.
//
// identity's own LIVENESS endpoint rather than one of the four auth routes: a
// probe that authenticates would need a credential to answer, and a readiness
// check that can fail on its own credentials is not a readiness check.
//
// Registered by `New` when `Options.BFF` is set, and nowhere else — see the
// `Options.Probes` comment for why that is where a dependency registers.
func (b *Bff) IdentityProbe() Probe {
	return func(ctx context.Context) error {
		answer, err := b.call(ctx, http.MethodGet, identityHealthz, callOptions{})
		if err != nil {
			return err
		}
		defer drain(answer)

		if answer.StatusCode != http.StatusOK {
			return fmt.Errorf("identity answered %d on %s", answer.StatusCode, identityHealthz)
		}
		return nil
	}
}

type callOptions struct {
	body  string
	token string
}

func (b *Bff) call(ctx context.Context, method, path string, options callOptions) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, b.identityURL+path, bodyReader(options.body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("accept", "application/json")
	if options.body != "" {
		req.Header.Set("content-type", "application/json")
	}
	if options.token != "" {
		req.Header.Set("authorization", "Bearer "+options.token)
	}

	return within(ctx, b.timeout, b.doer, req, method+" "+path)
}

func within(ctx context.Context, timeout time.Duration, do Doer, req *http.Request, what string) (*http.Response, error) {
	bounded, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	type outcome struct {
		res *http.Response
		err error
	}

	answered := make(chan outcome, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				answered <- outcome{err: fmt.Errorf("%s panicked: %v", what, r)}
			}
		}()
		res, err := do.Do(req.WithContext(bounded)) //nolint:bodyclose // the response is returned to the caller, which closes it via drain().
		answered <- outcome{res: res, err: err}
	}()

	select {
	case got := <-answered:
		return got.res, got.err
	case <-bounded.Done():
		return nil, fmt.Errorf("%s did not answer within %s", what, timeout)
	}
}

// Register is `POST /auth/register`: an account, and deliberately NOT a login.
//
// A `201` hands back `{id, email}` and NO COOKIE. Identity has not minted a
// session, so a cookie here would stand for nothing, and the browser would send it
// on every request until something refused it.
func (b *Bff) Register(w http.ResponseWriter, r *http.Request) {
	body, ok := b.readSubmittedBody(w, r)
	if !ok {
		return
	}

	answer, err := b.call(r.Context(), http.MethodPost, identityRegister, callOptions{body: body})
	if err != nil {
		log.Printf("gateway: identity call failed: %v", err)
		writeProblem(w, r, unreachable())
		return
	}

	switch answer.StatusCode {
	case http.StatusCreated:
		document, isJSON := jsonOf(answer)
		account, shaped := userOf(document)
		if !shaped {
			writeProblem(w, r, unusable(b.target(identityRegister), answer.StatusCode, document, isJSON))
			return
		}
		writeJSON(w, r, http.StatusCreated, account)

	case http.StatusUnprocessableEntity:
		document, _ := jsonOf(answer)
		writeProblem(w, r, Problem{
			Status: 422,
			Code:   api.ProblemCodeValidationFailed,
			Detail: "the request has an invalid field",
			Errors: fieldErrorsOf(document),
		})

	case http.StatusConflict:
		writeProblem(w, r, Problem{
			Status: 409,
			Code:   api.ProblemCodeConflict,
			Detail: "an account already exists for that email address",
		})

	default:
		drain(answer)
		writeProblem(w, r, unusable(b.target(identityRegister), answer.StatusCode, nil, false))
	}
}

// Login is `POST /auth/login`: an exchange, and the only route that mints a
// credential for a browser.
//
// The order is the contract: identity's refusal is mapped, the session is refused
// unless it has a parseable future expiry, and only THEN is anything stored or
// set. A login that reports success and signs the user out on the next request is
// worse than a login that failed.
func (b *Bff) Login(w http.ResponseWriter, r *http.Request) {
	body, ok := b.readSubmittedBody(w, r)
	if !ok {
		return
	}

	answer, err := b.call(r.Context(), http.MethodPost, identitySession, callOptions{body: body}) //nolint:bodyclose // Login always drains it: refuseLogin and jsonOf each close.
	if err != nil {
		log.Printf("gateway: identity call failed: %v", err)
		writeProblem(w, r, unreachable())
		return
	}
	if answer.StatusCode != http.StatusOK {
		b.refuseLogin(w, r, answer)
		return
	}

	document, isJSON := jsonOf(answer)
	session, shaped := sessionOf(document)
	if !shaped || !session.ExpiresAt.After(b.now()) {
		writeProblem(w, r, unusable(b.target(identitySession), answer.StatusCode, document, isJSON))
		return
	}

	sessionID := uuid.NewString()
	if err := b.sessions.Put(r.Context(), sessionID, *session); err != nil {
		log.Printf("gateway: could not store a new session: %v", err)
		writeProblem(w, r, unreachable())
		return
	}

	setSessionCookie(w, sessionID, session.ExpiresAt)

	writeRawJSON(w, r, http.StatusOK, `{"expires_at":"`+isoMillis(session.ExpiresAt)+`"}`)
}

// Logout is `POST /auth/logout`, and it signs the browser out even when identity
// cannot be told.
//
// Failing to sign a browser out is worse than a token that outlives its
// revocation until `exp`, and the caller is told the difference rather than left
// to assume it: a `204` means identity confirmed, and a `503` means the local
// record is already gone and the token may outlive it.
func (b *Bff) Logout(w http.ResponseWriter, r *http.Request) {
	sessionID := sessionIDOf(r)
	if sessionID == "" {
		writeProblem(w, r, Problem{
			Status: 401,
			Code:   api.ProblemCodeUnauthorized,
			Detail: "no session cookie was presented",
		})
		return
	}

	session, err := b.sessions.Get(r.Context(), sessionID)
	if err != nil {
		log.Printf("gateway: could not read the session store: %v", err)
		writeProblem(w, r, unreachable())
		return
	}
	if session == nil {
		clearSessionCookie(w)
		w.WriteHeader(http.StatusNoContent)
		return
	}

	if err := b.sessions.Delete(r.Context(), sessionID); err != nil {
		log.Printf("gateway: could not drop a session record: %v", err)
		writeProblem(w, r, unreachable())
		return
	}
	clearSessionCookie(w)

	answer, err := b.call(r.Context(), http.MethodDelete, identitySession, callOptions{token: session.Token})
	if err != nil {
		log.Printf("gateway: identity call failed: %v", err)
		writeProblem(w, r, unreachable())
		return
	}

	switch answer.StatusCode {
	case http.StatusNoContent, http.StatusUnauthorized, http.StatusNotFound:
		drain(answer)
		w.WriteHeader(http.StatusNoContent)
	default:
		drain(answer)
		writeProblem(w, r, unreachable())
	}
}

// Me is `GET /auth/me`: the browser's account, proxied with the stored token.
//
// Two distinctions are load-bearing. A `401` from identity is a WITHDRAWAL and
// drops the local record, so it is true from this request on rather than at the
// token's expiry; a `503` is an OUTAGE and does not, because treating an outage
// as a revocation signs everybody out whenever identity hiccups.
func (b *Bff) Me(w http.ResponseWriter, r *http.Request) {
	sessionID := sessionIDOf(r)
	if sessionID == "" {
		writeProblem(w, r, Problem{
			Status: 401,
			Code:   api.ProblemCodeUnauthorized,
			Detail: "no session cookie was presented",
		})
		return
	}

	session, err := b.sessions.Get(r.Context(), sessionID)
	if err != nil {
		log.Printf("gateway: could not read the session store: %v", err)
		writeProblem(w, r, unreachable())
		return
	}
	if session == nil {
		clearSessionCookie(w)
		writeProblem(w, r, Problem{
			Status: 401,
			Code:   api.ProblemCodeUnauthorized,
			Detail: "the session is no longer valid",
		})
		return
	}

	answer, err := b.call(r.Context(), http.MethodGet, identityMe, callOptions{token: session.Token})
	if err != nil {
		log.Printf("gateway: identity call failed: %v", err)
		writeProblem(w, r, unreachable())
		return
	}

	switch answer.StatusCode {
	case http.StatusOK:
		document, isJSON := jsonOf(answer)
		account, shaped := userOf(document)
		if !shaped {
			writeProblem(w, r, unusable(b.target(identityMe), answer.StatusCode, document, isJSON))
			return
		}
		writeJSON(w, r, http.StatusOK, account)

	case http.StatusUnauthorized:
		if err := b.sessions.Delete(r.Context(), sessionID); err != nil {
			log.Printf("gateway: could not drop a withdrawn session: %v", err)
		}
		clearSessionCookie(w)
		writeProblem(w, r, Problem{
			Status: 401,
			Code:   api.ProblemCodeUnauthorized,
			Detail: "the session is no longer valid",
		})

	default:
		drain(answer)
		writeProblem(w, r, unusable(b.target(identityMe), answer.StatusCode, nil, false))
	}
}

// RequireSameOrigin refuses a request that is not provably same-origin.
//
// It is mounted on the three MUTATING routes and not on `GET /auth/me`, and the
// reason is `src/index.ts` (removed at cutover)'s: the gate is for requests that change something, and
// on the prefix it would demand an `Origin` header from a read that has nothing
// to protect.
//
// # THERE IS NO DOUBLE-SUBMIT TOKEN HERE, AND ADDING ONE WOULD BE A REGRESSION
//
// The README says it outright — a token is not present because the origin gate IS
// the defense, and adding one would be "a second thing to get right for the same
// protection". The failure mode is worth being concrete about, because the
// reasoning is what stops the next reader from "improving" this:
//
//   - A double-submit token is verified against something the SERVER holds, and
//     the only thing this server holds is a session id it cannot read — it is an
//     HttpOnly cookie by design. So the second cookie would be readable by the
//     very cross-site script the first one hides from, which means the token is
//     compared against a value the ATTACKER supplied. That is not a second
//     defense; it is the same defense with the secret moved somewhere public.
//   - It survives being implemented wrongly. Two cookies, one readable and one
//     not, is exactly the shape of the `__Host-` fixation bug above, and the
//     prefix that prevents that does not exist for a non-prefixed cookie.
//
// So the CSRF defense is one mechanism, the browser enforces the part of it that
// matters, and this gate is the part a caller cannot forge.
func RequireSameOrigin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isSameOrigin(r) {
			writeProblem(w, r, Problem{
				Status: 403,
				Code:   api.ProblemCodeForbidden,
				Detail: "this request is not from the same origin",
			})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func isSameOrigin(r *http.Request) bool {
	site := firstValue(r.Header.Values("Sec-Fetch-Site"))
	origin := firstValue(r.Header.Values("Origin"))

	if site != "" && !strings.EqualFold(site, "same-origin") {
		return false
	}
	if origin != "" && hostOf(origin) != r.Host {
		return false
	}

	return site != "" || origin != ""
}

func firstValue(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return strings.TrimSpace(values[0])
}

func collapseRepeatedHeaders(next http.Handler) http.Handler {
	names := []string{http.CanonicalHeaderKey("Sec-Fetch-Site"), http.CanonicalHeaderKey("Origin")}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, name := range names {
			if values := r.Header[name]; len(values) > 1 {
				r.Header[name] = values[:1]
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (b *Bff) refuseLogin(w http.ResponseWriter, r *http.Request, answer *http.Response) {
	switch answer.StatusCode {
	case http.StatusUnauthorized:
		drain(answer)
		writeProblem(w, r, Problem{
			Status: 401,
			Code:   api.ProblemCodeUnauthorized,
			Detail: "email or password is not correct",
		})

	case http.StatusLocked:
		retry := answer.Header.Get("Retry-After")
		drain(answer)
		if isDigits(retry) {
			w.Header().Set("Retry-After", retry)
		}
		writeProblem(w, r, Problem{
			Status: 423,
			Code:   api.ProblemCodeAccountLocked,
			Detail: "too many failed sign-in attempts for this account",
		})

	default:
		drain(answer)
		writeProblem(w, r, unusable(b.target(identitySession), answer.StatusCode, nil, false))
	}
}

func (b *Bff) readSubmittedBody(w http.ResponseWriter, r *http.Request) (string, bool) {
	if declared := r.Header.Get("Content-Length"); declared != "" {
		if n, ok := parseContentLength(declared); ok && n > maxBodyBytes {
			writeProblem(w, r, tooLarge())
			return "", false
		}
	}

	if r.Body == nil {
		writeProblem(w, r, notAnObject())
		return "", false
	}

	raw, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes+1))
	if err != nil {
		writeProblem(w, r, notAnObject())
		return "", false
	}
	if len(raw) > maxBodyBytes {
		writeProblem(w, r, tooLarge())
		return "", false
	}

	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		writeProblem(w, r, notAnObject())
		return "", false
	}
	if _, isObject := value.(map[string]any); !isObject {
		writeProblem(w, r, notAnObject())
		return "", false
	}

	return string(raw), true
}

type user struct {
	ID    string `json:"id"`
	Email string `json:"email"`
}

func jsonOf(answer *http.Response) (any, bool) {
	defer drain(answer)

	raw, err := io.ReadAll(io.LimitReader(answer.Body, maxBodyBytes))
	if err != nil || len(raw) == 0 {
		return nil, false
	}

	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, false
	}
	return value, true
}

func sessionOf(document any) (*session.Session, bool) {
	object, isObject := document.(map[string]any)
	if !isObject {
		return nil, false
	}

	token, tokenIsString := object["token"].(string)
	expires, expiresIsString := object["expires_at"].(string)
	if !tokenIsString || token == "" || !expiresIsString || expires == "" {
		return nil, false
	}

	at, err := time.Parse(time.RFC3339, expires)
	if err != nil {
		return nil, false
	}

	return &session.Session{Token: token, ExpiresAt: at.UTC()}, true
}

func userOf(document any) (*user, bool) {
	object, isObject := document.(map[string]any)
	if !isObject {
		return nil, false
	}

	id, idIsString := object["id"].(string)
	email, emailIsString := object["email"].(string)
	if !idIsString || id == "" || !emailIsString || email == "" {
		return nil, false
	}

	return &user{ID: id, Email: email}, true
}

func fieldErrorsOf(document any) []api.FieldError {
	object, isObject := document.(map[string]any)
	if !isObject {
		return nil
	}
	raw, isArray := object["errors"].([]any)
	if !isArray {
		return nil
	}

	var kept []api.FieldError
	for _, entry := range raw {
		item, isObject := entry.(map[string]any)
		if !isObject {
			continue
		}
		field, fieldIsString := item["field"].(string)
		code, codeIsString := item["code"].(string)
		if fieldIsString && codeIsString {
			kept = append(kept, api.FieldError{Field: field, Code: code})
		}
	}
	return kept
}

var sessionCookie = http.Cookie{
	Name:     SessionCookie,
	Path:     "/",
	Secure:   true,
	HttpOnly: true,
	SameSite: http.SameSiteLaxMode,
}

func setSessionCookie(w http.ResponseWriter, value string, expiresAt time.Time) {
	c := sessionCookie
	c.Value = value
	c.Expires = expiresAt.UTC()
	http.SetCookie(w, &c)
}

func clearSessionCookie(w http.ResponseWriter) {
	c := sessionCookie
	c.Value = ""
	c.Expires = time.Unix(0, 0).UTC()
	c.MaxAge = -1
	http.SetCookie(w, &c)
}

func sessionIDOf(r *http.Request) string {
	for _, c := range r.Cookies() {
		if c.Name == SessionCookie {
			return c.Value
		}
	}
	return ""
}

func isoMillis(at time.Time) string {
	return at.UTC().Format("2006-01-02T15:04:05.000Z")
}

func hostOf(value string) string {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Host == "" {
		return ""
	}
	return parsed.Host
}

func drain(answer *http.Response) {
	if answer == nil || answer.Body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(answer.Body, maxBodyBytes))
	_ = answer.Body.Close()
}

func isDigits(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func parseContentLength(value string) (int, bool) {
	n := 0
	for _, r := range value {
		if r < '0' || r > '9' {
			return 0, false
		}
		n = n*10 + int(r-'0')
	}
	return n, true
}

func bodyReader(body string) io.Reader {
	if body == "" {
		return nil
	}
	return strings.NewReader(body)
}

func (b *Bff) target(path string) string { return b.identityURL + path }

func unreachable() Problem {
	return Problem{Status: 503, Code: api.ProblemCodeUnavailable, Detail: "the authentication service could not be reached"}
}

func notAnObject() Problem {
	return Problem{Status: 400, Code: api.ProblemCodeInvalidJSON, Detail: "the request body must be a JSON object"}
}

func tooLarge() Problem {
	return Problem{
		Status: 413,
		Code:   api.ProblemCodePayloadTooLarge,
		Detail: fmt.Sprintf("the request body is larger than %d bytes", maxBodyBytes),
	}
}

func unusable(target string, status int, body any, isJSON bool) Problem {
	shape := "no body"
	if isJSON {
		switch body.(type) {
		case map[string]any, []any:
			shape = "a JSON document"
		default:
			shape = fmt.Sprintf("%T", body)
		}
	}

	log.Printf("gateway: identity %s answered %d (%s), which this contract does not cover", target, status, shape)

	return Problem{
		Status: 503,
		Code:   api.ProblemCodeUnavailable,
		Detail: "the authentication service answered with something unusable",
	}
}

func parseIdentityURL(value string) (string, error) {
	text := strings.TrimSpace(value)
	if text == "" {
		return "", fmt.Errorf("%w: BffOptions.IdentityURL must be a non-empty string", ErrNotConfigured)
	}

	parsed, err := url.Parse(text)
	if err != nil || !parsed.IsAbs() || parsed.Host == "" {
		return "", fmt.Errorf("%w: BffOptions.IdentityURL must be an absolute URL, got %q", ErrNotConfigured, value)
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return "", fmt.Errorf("%w: BffOptions.IdentityURL must be http(s), got %q", ErrNotConfigured, value)
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return "", fmt.Errorf("%w: BffOptions.IdentityURL must be a base URL with no path, got %q", ErrNotConfigured, value)
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("%w: BffOptions.IdentityURL must be a base URL with no query or fragment, got %q", ErrNotConfigured, value)
	}

	return parsed.Scheme + "://" + parsed.Host, nil
}
