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

// The browser-facing half of the gateway: a BFF.
//
// A browser talks to gateway and to nothing else. It never holds identity's
// token, never sees identity's endpoints, and never gets to choose a credential:
// it holds a session id out of a `__Host-` cookie that gateway minted, and
// gateway swaps that id for the token when a request needs one. A token in a
// page is a token a cross-site script can read; a session id in an HttpOnly
// cookie is not.
//
// Ported from `src/bff/auth.ts` (removed at cutover), which WAS the reference:
// where this file and that one disagreed, that one was right, and the difference
// was a finding about the port rather than a choice made here. `CHANGELOG.md`
// records what the two answered between them; there is nothing to compare against
// now, so this file is the only account of why the browser surface answers the way
// it does.
//
// # THE PROPERTIES THIS FILE EXISTS TO HOLD
//
//  1. The origin gate is the CSRF defense. There is no double-submit token and
//     there must not be one — `RequireSameOrigin` says why in full, and the
//     reason is not "we did not get to it".
//  2. The session cookie is `__Host-bff-session`. The prefix is a guarantee the
//     BROWSER enforces, and it is the reason a sibling domain cannot set it.
//  3. The browser never receives an identity token. Nothing below writes one into
//     a response body, and `TestTheBrowserNeverReceivesTheIdentityToken` reads
//     this file's own source to hold that rather than trusting the prose.
//  4. Password rules, lockout and enumeration are IDENTITY's. The body is
//     forwarded untouched and identity's refusals are mapped — a `423` with its
//     `Retry-After`, a `401` with ONE fixed sentence. That mapping is the
//     contract, and a `401` whose message varies by cause is account
//     enumeration, which is the single easiest thing to get wrong in this file.
//  5. A revoked session is dead on the next request: `/auth/me` drops the record
//     when identity withdraws it rather than at the token's expiry.
//  6. Rate limiting on `/auth/*` keys on the CLIENT ADDRESS, because a browser
//     session has no principal yet. The limiter is a separate packet; what
//     belongs to this one is the fact that nothing here invents a principal, so
//     the bucket a browser lands in is still derived from the socket.

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

// identity's routes, as the guard-03 contract fixes them. Named, not derived from
// a base: a route table an operator could extend is a table whose answers this
// file has no cases for.
const (
	identityRegister = "/v1/users"
	identitySession  = "/v1/session"
	identityMe       = "/v1/me"
	identityHealthz  = "/healthz"
)

// defaultIdentityTimeout bounds one call to identity.
const defaultIdentityTimeout = 5 * time.Second

// maxBodyBytes is the most of a request body this service will hold: an address
// and a password, and the same 4 KiB identity caps its own bodies at. A
// registration is well under 1 KB; the rest is room for encoding and for a client
// that sends a field gateway will not forward.
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
	// IdentityURL is identity's base URL: http(s), and with no path. This is NOT
	// the token issuer. The issuer is the https origin tokens are *verified*
	// against, and this is the service address sessions are *requested* from.
	IdentityURL string

	// Sessions is where a browser session lives between requests. Required — see
	// `session.go` for why this packet ships no implementation of one and what it
	// is waiting for. A BFF with no store is a refusal to BUILD, not a gateway
	// serving sign-in on nothing.
	Sessions session.SessionStore

	// Doer is how identity is reached. Nil means `http.DefaultClient`.
	Doer Doer

	// IdentityTimeout bounds one call to identity. Zero means
	// `defaultIdentityTimeout`.
	IdentityTimeout time.Duration

	// Now is the clock, injectable so a test can present an already-expired
	// session without sleeping through one. Nil means `time.Now`.
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

// callOptions is one call's inputs. The token is a field rather than a context
// value because it is the only per-call secret, and a `context.Context` is a worse
// place to keep one than an argument nobody else reads.
type callOptions struct {
	body  string
	token string
}

// call is one request to identity, or an error when there was no answer to have.
//
// The deadline lives on the request, so a real client is stopped at the dial, the
// TLS handshake and every byte of the body, and `within` stops one that ignores
// it. Two mechanisms rather than one because they fail in different directions: a
// context alone bounds a well-behaved client, and a timer alone bounds an
// ill-behaved one.
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

// within runs one call under a deadline, on its own goroutine.
//
// A context deadline bounds a `Doer` that honors it and cannot bound one that
// does not, and an injected `Doer` is exactly the kind that might not: the whole
// point of the seam is that a test can supply something that is not a real HTTP
// client. So the deadline is enforced twice — on the context, which stops a real
// client, and by selecting against a timer, which stops any client at all.
//
// WHAT THAT COSTS, stated rather than hidden: a `Doer` that ignores its context
// is still running when this returns, and nothing in Go can stop it. That is
// accepted for the same reason `runProbe` accepts it, and with the same
// reasoning — the alternative is a handler that hangs forever, and a leaked
// goroutine behind a test double is a bounded cost while a hung request is not.
func within(ctx context.Context, timeout time.Duration, do Doer, req *http.Request, what string) (*http.Response, error) {
	bounded, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	type outcome struct {
		res *http.Response
		err error
	}

	// Buffered, so the goroutine below can always finish and be collected even
	// after the deadline has fired. An unbuffered channel would block a returning
	// Doer forever, which is the leak this is trying to bound.
	answered := make(chan outcome, 1)
	go func() {
		// Deferred, so a panicking `Doer` becomes an outcome rather than taking
		// the process down. A dependency that crashes should be a `503` on one
		// request, not a dead gateway.
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
		// The URL, the status and the socket error are the platform's to know. An
		// anonymous browser is not.
		log.Printf("gateway: identity call failed: %v", err)
		writeProblem(w, r, unreachable())
		return
	}

	switch answer.StatusCode {
	case http.StatusCreated:
		// Parsed once: a 201 that is not a user is recorded with what it actually
		// was, and a consumed body read twice reports as absent when it was not.
		document, isJSON := jsonOf(answer)
		account, shaped := userOf(document)
		if !shaped {
			writeProblem(w, r, unusable(b.target(identityRegister), answer.StatusCode, document, isJSON))
			return
		}
		writeJSON(w, r, http.StatusCreated, account)

	case http.StatusUnprocessableEntity:
		document, _ := jsonOf(answer)
		// A sign-up form renders these; dropping them leaves the browser saying
		// "something went wrong" about a field identity named exactly.
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
		// Anything else — a 200, a 500, a body that is not a user — is identity
		// saying something this contract does not cover, and guessing at it would
		// be gateway inventing an account.
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
	// A session with no expiry, an unparseable one, or one already in the past is
	// not a session: the cookie would be set and the very next request would
	// refuse it, which is a login that reports success and signs the user out.
	if !shaped || !session.ExpiresAt.After(b.now()) {
		writeProblem(w, r, unusable(b.target(identitySession), answer.StatusCode, document, isJSON))
		return
	}

	// Minted here, never accepted from the caller. Fixation needs an id the
	// attacker knows first, and a fresh v4 UUID is the reason they cannot.
	sessionID := uuid.NewString()
	if err := b.sessions.Put(r.Context(), sessionID, *session); err != nil {
		// A session the browser was not told about is not a session. Answering 200
		// here would hand the caller a cookie for a record that is not there.
		log.Printf("gateway: could not store a new session: %v", err)
		writeProblem(w, r, unreachable())
		return
	}

	setSessionCookie(w, sessionID, session.ExpiresAt)

	// The body says when the session runs out and nothing else. Echoing the token
	// would hand the page a long-lived credential that the HttpOnly cookie exists
	// to keep away from it.
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
		// identity answers 401 here too, for the same reason: a 204 would report
		// that something happened when there was no session to end.
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
		// A cookie the store has forgotten — a restart, a swept map. The browser is
		// not signed in and there is provably nothing to revoke, which is the state
		// the caller asked for. Refusing is what makes sign-out look broken.
		clearSessionCookie(w)
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// Dropped locally first, on purpose — see this function's header.
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

	// 204 is a revocation. 401 and 404 are a token identity has already
	// forgotten, which is the same end state reached by another route.
	switch answer.StatusCode {
	case http.StatusNoContent, http.StatusUnauthorized, http.StatusNotFound:
		drain(answer)
		w.WriteHeader(http.StatusNoContent)
	default:
		// `unreachable()`, NOT `unusable()`, and that is the reference's own choice
		// rather than an omission: `src/bff/auth.ts` (removed at cutover)'s logout answers
		// `revoked ? 204 : unreachable()`, so a non-revoking answer on THIS route is
		// reported as "we could not complete the sign-out" and is not written to the
		// log. The port answered `unusable()` here, which logged a line and named a
		// different detail, and `internal/equivalence` found it on its first run with
		// both answers printed.
		//
		// What the caller is NOT told is which of the two happened — `unreachable` and
		// `unusable` are both a 503 with the same code — and that is correct: the
		// sign-out itself has already succeeded locally either way, and the only
		// thing left uncertain is how long a token may outlive its revocation.
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
	// Cleared on the way out, not left in place: a cookie whose record is gone can
	// never work again, and a browser that keeps presenting it is a signed-out user
	// whose every request looks like a server that forgot them.
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
		// Parsed once and reused. A body can only be read once, so a second read
		// would be null — and reporting "no body" for a 200 that carried a document
		// is a log line that lies to whoever reads it.
		document, isJSON := jsonOf(answer)
		account, shaped := userOf(document)
		if !shaped {
			writeProblem(w, r, unusable(b.target(identityMe), answer.StatusCode, document, isJSON))
			return
		}
		writeJSON(w, r, http.StatusOK, account)

	case http.StatusUnauthorized:
		// identity withdrew it — a sign-out everywhere, or a revoked session.
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
		// Every status that is not a 200 is recorded by `unusable()` — including a
		// 5xx, which is the case that used to pass through silently, because the
		// call only logs when the TRANSPORT fails and a dependency that is up and
		// returning 500 is answering perfectly well.
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

// isSameOrigin reports whether a request provably comes from this origin.
//
// Two signals, and a request has to produce one of them:
//
//	Sec-Fetch-Site   set by the user agent and not by the page, so it is an
//	                assertion no cross-site requester can make. Only
//	                `same-origin` passes. `cross-site` is the attack, and
//	                `same-site` is a sibling subdomain — which a Lax cookie IS
//	                sent to, so a subdomain that can post to its parent has
//	                something to spend. `none` means the agent could not attribute
//	                the request to a page, which is not a claim of same-origin, and
//	                nothing in this flow needs it.
//
//	Origin           the fallback for an agent that sends no fetch metadata.
//	                Compared by HOST, not by origin: a TLS-terminating proxy
//	                rewrites the scheme gateway sees while the browser's header
//	                still says https, and comparing it would 403 every real
//	                browser. The host is the one the browser addressed the request
//	                to, and a cross-site requester cannot choose it.
//
// A request with NEITHER is refused. Every browser sends one of the two, and a
// client that sends neither has no ambient credential to abuse — but it is also
// not *provably* same-origin, and this gate refuses what it cannot prove. curl
// and the test suite state their origin; a browser never has to.
func isSameOrigin(r *http.Request) bool {
	// The FIRST value, not a joined one, and that is MEASURED rather than assumed:
	// the reference answers `200` — with the cookie — to a request carrying
	// `Sec-Fetch-Site: same-origin` TWICE, so its framework hands the gate one value
	// rather than `same-origin, same-origin`. The first version of this file joined
	// them — the WHATWG `Headers` rule — and refused, and `internal/equivalence`
	// reported the difference in all six browser scenarios with the reference's `200`
	// on one side and this gate's `403` on the other.
	//
	// So the direction of the fix is the one the evidence points at, not the one that
	// looks stricter: TypeScript was the reference, and a "stricter" gate that answered
	// differently was a divergence.
	site := firstValue(r.Header.Values("Sec-Fetch-Site"))
	origin := firstValue(r.Header.Values("Origin"))

	// Compared as a token, not as a string: a user agent that changed the casing of
	// a header value would otherwise lock every browser out of sign-in, and
	// case-folding four known tokens is not something an attacker can forge.
	if site != "" && !strings.EqualFold(site, "same-origin") {
		return false
	}
	if origin != "" && hostOf(origin) != r.Host {
		return false
	}

	// The request has to state one of them, and when it states both they have to
	// agree. A browser sends them consistently, so a disagreement is not a browser:
	// it is a client that chose what each header says, and the gate believes the
	// stricter of the two rather than the friendlier one.
	return site != "" || origin != ""
}

// firstValue is the first value of a repeated header, trimmed, or "".
//
// Trimmed because a value's leading whitespace is significant to no one and Hono
// trims it.
func firstValue(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return strings.TrimSpace(values[0])
}

// collapseRepeatedHeaders reduces a repeated single-valued header to its first
// value, before the generated router reads it.
//
// # WHY THIS EXISTS, MEASURED
//
// `oapi-codegen` refuses a header parameter sent more than once and answers a
// `text/plain` `400` before any handler runs. The reference has no such refusal and
// no such answer: it answers `200` to a doubled `Sec-Fetch-Site: same-origin`.
//
// So without this middleware the Go service would answer `400 text/plain` to
// something the reference serves, and the two answers would differ in status, in
// content type and in whether a cookie was set. `internal/equivalence` had a case for
// it precisely because this was found rather than foreseen.
//
// # AND WHY IT IS FIRST-VALUE RATHER THAN "REFUSE IT"
//
// Because the reference does not refuse it. Refusing a doubled `Sec-Fetch-Site` looks
// stricter and is a divergence; the gate's job is to decide same-originness, and a
// doubled header is a malformed request rather than a cross-site one. The first
// value is what the reference's framework hands the gate, so that is what the gate
// gets.
//
// # THE SCOPE IS A NAMED SET, AND THAT IS A LIMITATION
//
// The two names are the contract's two header parameters on the browser surface.
// Named rather than derived, because deriving them means parsing
// `internal/api/api.gen.go` for parameter declarations at run time, which is more
// machinery than two constants justify — and the tripwire is elsewhere: a NEW header
// parameter this does not collapse would be refused by the generated router with a
// `text/plain` `400`, and the equivalence check compares every operation the document
// declares, so the day one is added the difference appears as a red rather than as a
// surprise.
func collapseRepeatedHeaders(next http.Handler) http.Handler {
	// `http.CanonicalHeaderKey` of each, computed ONCE at construction rather than
	// per request: this runs on every request in the service.
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

// refuseLogin maps identity's refusals, and nothing else.
//
// Each route maps only the statuses identity documents for THAT route; a status
// the contract does not cover is a 503 rather than a guess, because a guess here
// is how a 423 turns into a 401 and a lockout turns into a retry loop the caller
// owns.
func (b *Bff) refuseLogin(w http.ResponseWriter, r *http.Request, answer *http.Response) {
	switch answer.StatusCode {
	case http.StatusUnauthorized:
		// ONE sentence for every refused credential. Varying it per case is how a
		// login endpoint becomes an account-enumeration oracle: "no such account"
		// and "wrong password" must be the same bytes, the same status and the
		// same detail, because the browser cannot tell which case it hit.
		drain(answer)
		writeProblem(w, r, Problem{
			Status: 401,
			Code:   api.ProblemCodeUnauthorized,
			Detail: "email or password is not correct",
		})

	case http.StatusLocked:
		// The window travels with the answer. Collapsing the lockout into the 401
		// above would tell someone with the RIGHT password to try again, and be
		// refused again, for a quarter of an hour.
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

// readSubmittedBody returns the caller's bytes UNTOUCHED, or writes the refusal
// itself and reports false.
//
// Only "is this an object" is decided here. Whether an address is deliverable and
// a password strong enough is IDENTITY's call, in one place, under the same rules
// every other client of identity gets — a second set of rules in the gateway is a
// second answer to "what is a valid password", and two answers is a way to sign
// someone in on a password the identity service would refuse.
//
// The cap is enforced while reading, not after, because reading the whole body
// first is `text()` in another language: an unauthenticated caller would choose
// how much of this process a single request holds. identity caps its own bodies at
// 4 KiB, so a request that big is one identity would refuse to read anyway — and
// refusing it here means gateway never held it either.
func (b *Bff) readSubmittedBody(w http.ResponseWriter, r *http.Request) (string, bool) {
	// A declared `Content-Length` over the limit is answered from the header alone,
	// so the common case costs no read at all.
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

	// One byte past the cap, so "exactly at the limit" is accepted and "one past
	// it" is not — an off-by-one here is either a request that fails when identity
	// would accept it, or a read past the bound the cap exists to hold.
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
	// An array is not an object, and `null` is not either. `map[string]any` is the
	// test, rather than a shape check, because it is the same question the
	// reference asks: `typeof value === "object" && value !== null && !Array.isArray`.
	if _, isObject := value.(map[string]any); !isObject {
		writeProblem(w, r, notAnObject())
		return "", false
	}

	return string(raw), true
}

// user is the user document, rendered by this file rather than by `api.User`.
//
// Two reasons, both of them about the BYTES.
//
// The first is ordering: `api.User` declares `Email` before `ID`, so marshaling
// it writes `{"email":…,"id":…}` where the reference writes `{"id":…,"email":…}`.
// `internal/equivalence` compared bodies byte for byte, so that is a failure and
// not a note.
//
// The second is width: this is an ALLOWLIST rather than a filter, so a field
// identity adds next month must not reach a browser response today by being
// copied, and a password digest that turns up in the user document has no
// business in a page.
//
// The field order below is therefore part of the contract, and reordering it is an
// equivalence break.
type user struct {
	ID    string `json:"id"`
	Email string `json:"email"`
}

// jsonOf reads a body, and reports whether it was JSON at all.
//
// The two answers are separate because `json.Unmarshal` into `any` cannot tell
// "an HTML error page" from "an empty body": both are an error, and both have to
// reach the log as "not JSON" rather than as "a JSON document", which is a log
// line lying about the shape of an outage to the operator who has just been sent
// to look at it.
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

// sessionOf is a token and the instant it stops being one.
//
// `(nil, false)` means "not a usable session", whatever the shape of the document
// was. A session with no token, no expiry, an unparseable expiry or an empty
// string is not a session, and treating any of the four as one is a login that
// reports success and fails on the very next request.
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

// userOf is `{id, email}` and nothing else, or nothing.
//
// An empty string is not a value here. `""` is what a document with the key
// present but blank produces, and forwarding it would render an empty address in
// a page that a sign-up form just filled in.
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

// fieldErrorsOf keeps identity's per-field failures only if they are shaped like
// core's.
//
// identity is a trusted dependency, but this array is data the gateway renders
// into a page, and a field name is not a place to accept an arbitrary document.
// An array that survives the filter with nothing in it is returned as nil rather
// than as an empty list, because `errors: []` in a 422 says "no fields failed" and
// a client branching on the key would read that as a different answer.
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

// sessionCookie is every attribute the session cookie is set with, in one place.
//
// The deletion repeats them verbatim, because a browser matches a cookie to delete
// on name, domain and path: a deletion missing one of them leaves the original in
// place, which is the precise bug that makes "sign out" appear to do nothing.
//
// `SameSite=Lax` and not `Strict`, because a Strict cookie is not sent on the
// top-level navigation a user follows straight after signing in. Lax is a
// deliberate narrowing of `Strict`, and it is the reason `same-site` is refused
// by the origin gate rather than welcomed: a Lax cookie IS sent to a sibling
// subdomain, so a subdomain has something to spend on its parent.
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

// sessionIDOf is the browser's session id, or "".
//
// `""` rather than an error, and no error is needed: the caller refuses a request
// with no cookie, and a cookie whose value is empty IS a request with no cookie.
func sessionIDOf(r *http.Request) string {
	for _, c := range r.Cookies() {
		if c.Name == SessionCookie {
			return c.Value
		}
	}
	return ""
}

// isoMillis renders an instant the way `Date.prototype.toISOString` does: always
// UTC, always exactly three fractional digits.
//
// `time.RFC3339Nano` DROPS trailing zeros, so `2026-01-01T00:00:00Z` and
// `2026-01-01T00:00:00.000Z` are the same instant and two different byte
// sequences — and this body is compared byte for byte against the reference.
// Fixed-width millis are the only spelling both sides produce for every value.
func isoMillis(at time.Time) string {
	return at.UTC().Format("2006-01-02T15:04:05.000Z")
}

// hostOf is a URL's `host:port`, or "" for anything that is not a URL — the
// literal `null` included, which is what `Origin: null` sends and which the
// reference's `new URL("null")` throws on.
//
// Compared against `r.Host`, which is where Go puts the authority the client
// addressed the request to. `r.URL` is only a path on a server request, so
// `r.URL.Host` is empty and comparing against it would refuse every request.
func hostOf(value string) string {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Host == "" {
		return ""
	}
	return parsed.Host
}

// drain closes a response body so the connection can be reused.
//
// Every call site is a path that has already decided what it is going to answer,
// so the body is no longer needed; leaving it unread is a connection the pool
// cannot reuse, and one per session on an identity serving every browser.
func drain(answer *http.Response) {
	if answer == nil || answer.Body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(answer.Body, maxBodyBytes))
	_ = answer.Body.Close()
}

// isDigits is `/^\d+$/` — a `Retry-After` gateway will echo back.
//
// A seconds-form `Retry-After` is refused rather than passed through, and the
// header is then simply absent: the alternative is forwarding whatever a
// dependency chain put there into a browser's cache of when to retry a login.
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

// parseContentLength reads a numeric header, and anything else is "not a number".
//
// A non-numeric `Content-Length` falls through to the read, where the limit
// applies anyway — so a header a caller made up is not a way to skip the cap.
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

// bodyReader is the request body for a forwarded call, and nil for none.
//
// `nil` rather than an empty reader, because the two produce different requests:
// an empty reader carries `Content-Length: 0` and a body the transport will try
// to write, where `src/bff/auth.ts` (removed at cutover) sends no body at all for a `GET` or a
// `DELETE`. The assertions in `bff_test.go` are about the request that leaves.
func bodyReader(body string) io.Reader {
	if body == "" {
		return nil
	}
	return strings.NewReader(body)
}

func (b *Bff) target(path string) string { return b.identityURL + path }

// unreachable is the 503 for identity being unreachable.
//
// 503 and not 401 because the caller's credentials were never examined, and a 401
// would send them to rotate a credential that is fine.
//
// It is a fixed string: the URL, the status and the socket error are in the log,
// and an anonymous browser is not allowed to learn which.
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

// unusable is "identity answered with something this contract does not cover", and
// it is written down.
//
// It returns the refusal rather than writing it, because every call site is
//
//	writeProblem(w, r, unusable(…))
//
// and a function that both logged and wrote would need each of those to be a
// two-way branch on an error that is not an error.
//
// The reason this takes the call's path and status rather than nothing is that
// the alternative was a SILENT failure. `call` only logs when the TRANSPORT
// fails, so an identity that is up and returning 500 — a broken deploy, an OOM, a
// panic, which is what most dependency outages actually look like — reached this
// point with no log line at all. The caller got a 503 and the operator got nothing
// to correlate it against.
//
// Only the URL, the status and the SHAPE of a body are recorded. A dependency's
// error page is exactly where a credential turns up, and this repository never
// writes one down.
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

// parseIdentityURL is identity's base URL, reduced to an origin.
//
// NO PATH, because the routes above are appended to it: a base carrying one would
// put `/v1/session` somewhere nobody is serving it. The trailing slash is dropped,
// because it is what an operator types out of habit and keeping it would join into
// `//v1/users`.
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

	// Rebuilt from the parsed parts rather than trimmed, because that is what
	// guarantees the trailing slash is gone: `http://identity:8080/` and
	// `http://identity:8080` both reduce to the second.
	return parsed.Scheme + "://" + parsed.Host, nil
}
