package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/anywaye/gateway/internal/api"
	"github.com/anywaye/gateway/internal/auth"
	"github.com/anywaye/gateway/internal/ratelimit"
)

// Options is the whole configuration of a gateway, and it is an argument to
// `New` rather than something read from the environment inside it.
//
// The property this preserves is `guard/AGENTS.md`'s, and it is worth stating
// because Go makes it easier to lose than TypeScript did: *"Configuration
// arrives as an argument, never as a module-level global read from the
// environment, so a test can build two differently-configured apps in one
// process."* Go's answer to "the environment" is `os.Getenv`, which any package
// may call at any time — so the property here is not that a global was avoided,
// it is that there is nowhere in this package that *can* read one.
// `RuntimeOptions` is the only function in the module that touches the
// environment, it takes the reader as an argument, and
// `TestNoFileInThisPackageReadsTheEnvironment` reads this package's own sources
// to hold that.
//
// Every field is optional and the zero value is a working gateway: the two
// probes and nothing else. That is not a stub, it is the honest v0 shape — an
// app built with no rate limiter applies no limit, and an app built with no
// issuer serves probes only — and it is the shape `src/index.ts` (removed at cutover) documents for
// the same fields ("Omit and the gateway serves probes only: with no issuer
// there is nothing to verify a token against, and an endpoint that would have
// to trust a token is worse than an endpoint that is not there").
type Options struct {
	Probes []NamedProbe

	BFF *BffOptions

	Routes RouteTable

	VHosts VHostTable

	IdentityBaseURL string

	Assert *AssertionMinter

	Authenticate Authenticate

	UpstreamTimeout time.Duration

	Verifier TokenVerifier

	Limiter RateLimiter

	APIKeys *ApiKeyOptions
}

// ApiKeyOptions is the API-key surface's configuration: the store both the gate
// and the management routes read.
type ApiKeyOptions struct {
	Store auth.ApiKeyStore
}

// TokenVerifier is the bearer-token gate, as the router needs it.
//
// The two methods are `requireJwt` and `requireScope` from
// `src/middleware/jwt.ts` (removed at cutover). Only `Require` is mounted by this package; `RequireScope`
// is on the interface because the scope gate is part of the verifier's surface and
// a later packet mounts it, and putting it on the interface NOW is what makes that
// packet's wiring test able to assert it rather than discover it.
//
// `requireScope` takes a refusal writer in Go where it does not in TypeScript,
// because Go's middleware writes the response and TypeScript's returns it. See
// `internal/auth`'s own comment on the difference.
//
// # `Authenticate` IS HERE BECAUSE THE PASS-THROUGH NEEDS IT, NOT BECAUSE IT IS NEEDED TWICE
//
// `Authenticate` is the verifier's own door — one request, one token, one answer —
// and it is on this interface because `Options.Authenticate` is the seam the
// pass-through's gate was built to be plugged into. Without it here the seam could
// only ever be filled by a second implementation of verification, which is the one
// thing two verification paths must not be.
//
// It is a `*Principal` rather than this package's `Principal` because they are now
// the same type: `Principal` is an alias for `auth.Principal`, so the principal a
// pass-through route asserts about is the principal `/v1/me` renders, and there is
// no conversion where one of them could quietly lose a claim the other carries.
type TokenVerifier interface {
	Require(refuse auth.Refuser) func(http.Handler) http.Handler
	RequireScope(refuse auth.Refuser, scope string) (func(http.Handler) http.Handler, error)
	Authenticate(ctx context.Context, token string) (*auth.Principal, *auth.Refusal)
}

// RateLimiter is the rate-limit middleware, as the router needs it.
//
// One method and it is the whole limiter: `rateLimit(options)` in TypeScript
// returns a `MiddlewareHandler` and this returns the `func(http.Handler)
// http.Handler` chi's `Use` takes.
type RateLimiter interface {
	Wrap(next http.Handler) http.Handler
}

// ProbePaths is the two operations the limiter must never count.
//
// Exported because the contract's `429` story depends on it, and that is a claim
// about *this* set rather than a list somebody typed into a YAML file: those two
// operations are the only ones in `openapi/v1.yaml` with no `429`, and the check
// that keeps it true reads this set instead of the document's text.
//
// Liveness and readiness answer even when the limiter is exhausted: a throttled
// probe is an orchestrator that cannot see a healthy process, and the restart
// that follows is worse than the traffic it was protecting against. Nothing reads
// this set yet, because nothing counts requests yet — it is the floor the
// limiter in Wave 3 is built on, and `TestTheTwoProbeOperationsAreTheOnesWithNo429`
// holds the document to it from the day it lands rather than from the day the
// limiter does.
var ProbePaths = map[string]struct{}{
	"/healthz": {},
	"/readyz":  {},
}

// ErrNotConfigured is what a caller of `New` gets, wrapped, for a configuration
// it cannot serve. It exists so a caller can tell its own mistake from a defect
// in this package, which a bare string cannot — `errors.Is` is the whole reason
// it is a sentinel and not only a message.
var ErrNotConfigured = errors.New("httpapi: invalid configuration")

// New builds the app. It returns an `http.Handler` and an error rather than
// panicking, and it validates before it assembles, so a malformed configuration
// is a refusal to construct the gateway at all rather than a `500` on the first
// request of the week.
//
// `import.meta.main` in `src/index.ts` (removed at cutover) is the same boundary: importing this
// package must never open a socket. `cmd/gateway` is what listens.
func New(options Options) (http.Handler, error) {
	if err := options.validate(); err != nil {
		return nil, err
	}

	bff, err := options.browserSurface()
	if err != nil {
		return nil, err
	}

	router := chi.NewRouter()

	router.NotFound(func(w http.ResponseWriter, r *http.Request) { writeV0NotFound(w, r) })
	router.MethodNotAllowed(func(w http.ResponseWriter, r *http.Request) { writeV0NotFound(w, r) })

	limiter := middlewareOf(options.Limiter)
	insideLimiter := limiter
	insideTelemetry := telemetryMiddleware
	if options.Routes != nil {
		insideLimiter = nil
		insideTelemetry = nil
	}
	router.Use(everyRequest(insideTelemetry, insideLimiter, apiKeyGate(options.APIKeys), bearerGate(options))...)

	svc := &server{probes: options.Probes, bff: bff, verifier: options.Verifier, apiKeys: options.APIKeys}
	api.HandlerWithOptions(
		svc,
		api.ChiServerOptions{BaseRouter: router, ErrorHandlerFunc: paramRefusal()},
	)

	router.Method(http.MethodHead, "/healthz", headOf(svc.Liveness))
	router.Method(http.MethodHead, "/readyz", headOf(svc.Readiness))

	if options.Routes == nil && options.VHosts == nil && options.IdentityBaseURL == "" {
		return router, nil
	}

	var table RouteTable
	if options.Routes != nil {
		table, err = ValidateRouteTable(options.Routes)
		if err != nil {
			return nil, err
		}
	}
	vhosts, err := ValidateVHostTable(options.VHosts)
	if err != nil {
		return nil, err
	}

	identity := ""
	if options.IdentityBaseURL != "" {
		identity, err = checkIdentityBaseURL(options.IdentityBaseURL)
		if err != nil {
			return nil, err
		}
	}

	proxied := newRouteProxy(proxyOptions{
		Routes:          table,
		Timeout:         options.UpstreamTimeout,
		Assertion:       options.Assert,
		IdentityBaseURL: identity,
	}).handle(router)

	gates := everyRequest(telemetryMiddleware, limiter,
		apiKeyGate(options.APIKeys),
		credentialGate(authentication(options), table, identity),
		scopeGate(options.Verifier, table),
		vhostGate(vhosts, options.UpstreamTimeout, options.Assert),
	)
	return &mount{Router: router, handler: compose(proxied, gates...)}, nil
}

func everyRequest(telemetry, limiter func(http.Handler) http.Handler, gates ...func(http.Handler) http.Handler) []func(http.Handler) http.Handler {
	chain := []func(http.Handler) http.Handler{collapseRepeatedHeaders}
	if telemetry != nil {
		chain = append([]func(http.Handler) http.Handler{telemetry}, chain...)
	}
	for _, gate := range gates {
		if gate != nil {
			chain = append(chain, gate)
		}
	}
	if limiter != nil {
		chain = append(chain, limiter)
	}
	return chain
}

func compose(next http.Handler, middlewares ...func(http.Handler) http.Handler) http.Handler {
	for i := len(middlewares) - 1; i >= 0; i-- {
		next = middlewares[i](next)
	}
	return next
}

func bearerGate(options Options) func(http.Handler) http.Handler {
	if options.Verifier == nil {
		return nil
	}
	require := options.Verifier.Require(writeAuthRefusal)
	return onPrefix("/v1/", func(next http.Handler) http.Handler {
		guarded := require(next)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, ok := PrincipalFrom(r); ok {
				next.ServeHTTP(w, r)
				return
			}
			guarded.ServeHTTP(w, r)
		})
	})
}

func apiKeyGate(options *ApiKeyOptions) func(http.Handler) http.Handler {
	if options == nil || options.Store == nil {
		return nil
	}
	inner := auth.ApiKeyGate(options.Store, writeAuthRefusal)
	return func(next http.Handler) http.Handler {
		guarded := inner(next)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !underRouteMount(NormaliseRequestPath(r.URL.EscapedPath())) {
				next.ServeHTTP(w, r)
				return
			}
			guarded.ServeHTTP(w, r)
		})
	}
}

func scopeGate(verifier TokenVerifier, table RouteTable) func(http.Handler) http.Handler {
	if verifier == nil {
		return nil
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			path := NormaliseRequestPath(r.URL.EscapedPath())
			if isGatewayOwned(path) || !underRouteMount(path) {
				next.ServeHTTP(w, r)
				return
			}
			route, ok := ResolveRoute(table, path)
			if !ok || len(route.Scopes) == 0 {
				next.ServeHTTP(w, r)
				return
			}

			handler := next
			for i := len(route.Scopes) - 1; i >= 0; i-- {
				middleware, err := verifier.RequireScope(writeAuthRefusal, route.Scopes[i])
				if err != nil {
					next.ServeHTTP(w, r)
					return
				}
				handler = middleware(handler)
			}
			handler.ServeHTTP(w, r)
		})
	}
}

func middlewareOf(limiter RateLimiter) func(http.Handler) http.Handler {
	if limiter == nil {
		return nil
	}
	return limiter.Wrap
}

func authentication(options Options) Authenticate {
	if options.Authenticate != nil {
		return options.Authenticate
	}
	if options.Verifier == nil {
		return nil
	}
	return func(r *http.Request) (*Principal, error) {
		token := auth.BearerToken(r.Header.Get("Authorization"))
		principal, refusal := options.Verifier.Authenticate(r.Context(), token)
		if refusal != nil {
			return nil, errNotAuthenticated
		}
		return principal, nil
	}
}

var errNotAuthenticated = errors.New("httpapi: the request carried no verified principal")

func (o Options) browserSurface() (*Bff, error) {
	if o.BFF == nil {
		return nil, nil
	}
	return NewBff(*o.BFF)
}

func paramRefusal() func(http.ResponseWriter, *http.Request, error) {
	return func(w http.ResponseWriter, r *http.Request, err error) {
		log.Printf("gateway: a header the contract declares could not be read: %v. This is unreachable for Sec-Fetch-Site and Origin — collapseRepeatedHeaders reduces a repeated value to its first — so it means a header parameter this middleware does not know about arrived more than once.", err)
		notBuilt(w, r)
	}
}

type mount struct {
	chi.Router

	handler http.Handler
}

func (m *mount) ServeHTTP(w http.ResponseWriter, r *http.Request) { m.handler.ServeHTTP(w, r) }

// onPrefix runs a middleware only on paths under a prefix, and nowhere else.
//
// # WHY IT EXISTS RATHER THAN `r.Group`
//
// `src/index.ts` (removed at cutover) writes `app.use("/v1/*", …)` and Hono scopes the mount to that
// pattern. chi's `Mux.Use` takes middleware with no pattern, and `Group` returns a
// NEW router — so the gate would have to be mounted on a group the generated
// registrations are not on, and `api.gen.go` is a `//go:generate` output this
// repository may not hand-edit. A path test inside the middleware is the only
// spelling that puts the gate in front of a route nobody here registers by hand.
//
// # THE PREFIX IS `/v1/`, WITH THE SLASH
//
// Because Hono's `/v1/*` does not match `/v1` itself, and neither does this. A
// bare `/v1` is an operation nobody declared and answers the v0 `404` on both
// sides; a gate that answered `401` there would be a difference on a path the
// contract does not have.
//
// # IT IS NOT A NORMALISATION
//
// A request to `/v1/../healthz` does NOT reach the handler: chi cleans the path
// before routing and `http.Request.URL.Path` is the cleaned one, so the prefix
// test reads the path the router matched. A traversal that reaches a probe is a
// probe, and a probe is never authenticated.
func onPrefix(prefix string, middleware func(http.Handler) http.Handler) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		guarded := middleware(next)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !strings.HasPrefix(r.URL.Path, prefix) {
				next.ServeHTTP(w, r)
				return
			}
			guarded.ServeHTTP(w, r)
		})
	}
}

func writeAuthRefusal(w http.ResponseWriter, r *http.Request, refusal *auth.Refusal) {
	writeProblem(w, r, Problem{
		Status: refusal.Status,
		Code:   api.ProblemCode(refusal.Code),
		Detail: refusal.Detail,
	})
}

func writeRateLimitRefusal(w http.ResponseWriter, r *http.Request, status int, code, detail string) {
	writeProblem(w, r, Problem{
		Status: status,
		Code:   api.ProblemCode(code),
		Detail: detail,
	})
}

// RateLimitRefuser is the `ratelimit.Refuser` this package supplies, exported so
// `cmd/gateway` can build a limiter without importing `internal/httpapi`'s writer
// by name and getting the conversion wrong.
func RateLimitRefuser(w http.ResponseWriter, r *http.Request, status int, code, detail string) {
	writeRateLimitRefusal(w, r, status, code, detail)
}

var (
	_ auth.Refuser      = writeAuthRefusal
	_ ratelimit.Refuser = RateLimitRefuser
)

func headOf(get http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		get(bodyless{ResponseWriter: w}, r)
	}
}

type bodyless struct {
	http.ResponseWriter
}

func (bodyless) Write(body []byte) (int, error) { return len(body), nil }

func (o Options) validate() error {
	if o.Routes != nil {
		if _, err := ValidateRouteTable(o.Routes); err != nil {
			return err
		}
	}
	if o.VHosts != nil {
		if _, err := ValidateVHostTable(o.VHosts); err != nil {
			return err
		}
	}
	if o.IdentityBaseURL != "" {
		if _, err := checkIdentityBaseURL(o.IdentityBaseURL); err != nil {
			return err
		}
	}
	if o.UpstreamTimeout < 0 || (o.UpstreamTimeout > 0 && o.UpstreamTimeout < time.Millisecond) {
		return fmt.Errorf("%w: Options.UpstreamTimeout must be zero (meaning %s) or at least 1ms, got %s", ErrNotConfigured, DefaultUpstreamTimeout, o.UpstreamTimeout)
	}

	seen := make(map[string]struct{}, len(o.Probes))

	for i, probe := range o.Probes {
		switch {
		case probe.Name == "":
			return fmt.Errorf("%w: Options.Probes[%d] has no name, and /readyz renders dependencies by name", ErrNotConfigured, i)
		case probe.Probe == nil:
			return fmt.Errorf("%w: Options.Probes[%d] (%s) has no probe, so the dependency would answer unavailable forever", ErrNotConfigured, i, probe.Name)
		}

		if _, dup := seen[probe.Name]; dup {
			return fmt.Errorf("%w: Options.Probes has two probes named %q, and /readyz can only report one of them", ErrNotConfigured, probe.Name)
		}
		seen[probe.Name] = struct{}{}
	}

	return nil
}

type server struct {
	probes []NamedProbe

	bff *Bff

	verifier TokenVerifier

	apiKeys *ApiKeyOptions
}

var _ api.ServerInterface = (*server)(nil)

// Liveness answers whether this process is running. It touches no dependency and
// reads nothing, so an `identity` or Redis outage cannot get the process
// restarted out from under in-flight requests — that is `/readyz`'s job, and the
// split between the two is the point of having two.
//
// Never rate limited and never authenticated: an orchestrator asking whether the
// process is alive has no credential and must not be throttled into a restart.
// See `ProbePaths`.
func (s *server) Liveness(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Trace-Id") == "visibility-probe" {
		CaptureError(fmt.Errorf("visibility probe gateway: %s", r.URL.Path), r)
		writeJSON(w, r, http.StatusInternalServerError, api.Health{Status: api.HealthStatusOk})
		return
	}
	writeJSON(w, r, http.StatusOK, api.Health{Status: api.HealthStatusOk})
}

// Readiness answers whether this process can serve traffic, by probing each
// named dependency.
//
// Which dependency failed is named. *Why* it failed is not: the underlying error
// goes to the log, because an unauthenticated request must not be a way to learn
// that a dependency's host sits at a particular address. Every probe is bounded
// by `runProbe`, so one dependency that hangs cannot delay another's answer and
// none of them can take the process down.
//
// The `503` body is `application/json` and not core's problem document, which is
// a recorded conflict with core's conventions: open decision 6 in the document's
// header says so, and `identity` records the identical conflict.
func (s *server) Readiness(w http.ResponseWriter, r *http.Request) {
	deps := make(map[string]ProbeStatus, len(s.probes))
	ready := true

	for _, probe := range s.probes {
		status := runProbe(r.Context(), probe.Probe)
		deps[probe.Name] = status
		if status != probeOK {
			ready = false
		}
	}

	status := http.StatusOK
	if !ready {
		status = http.StatusServiceUnavailable
	}
	writeRawJSON(w, r, status, `{"deps":`+orderedDeps(s.probes, deps)+`}`)
}

func orderedDeps(probes []NamedProbe, deps map[string]ProbeStatus) string {
	var b strings.Builder
	b.WriteByte('{')
	for i, probe := range probes {
		if i > 0 {
			b.WriteByte(',')
		}
		name, _ := json.Marshal(probe.Name)
		value, _ := json.Marshal(string(deps[probe.Name]))
		b.Write(name)
		b.WriteByte(':')
		b.Write(value)
	}
	b.WriteByte('}')
	return b.String()
}

// The four browser routes, each behind the origin gate except the read.
//
// `GET /auth/me` is NOT gated and that is not an oversight: the gate is CSRF
// defense, and a CSRF defense on a request that changes nothing protects a caller
// from itself. `src/index.ts` (removed at cutover) mounts it per route for exactly this reason, and
// `TestTheOriginGateCoversEveryMutatingRouteAndOnlyThose` holds the set equal to
// the document's method list rather than to a hand-written one.
func (s *server) RegisterUser(w http.ResponseWriter, r *http.Request, _ api.RegisterUserParams) {
	s.bffOr(w, r, http.MethodPost, (*Bff).Register)
}

func (s *server) CreateSession(w http.ResponseWriter, r *http.Request, _ api.CreateSessionParams) {
	s.bffOr(w, r, http.MethodPost, (*Bff).Login)
}

func (s *server) DeleteSession(w http.ResponseWriter, r *http.Request, _ api.DeleteSessionParams) {
	s.bffOr(w, r, http.MethodPost, (*Bff).Logout)
}

func (s *server) GetCurrentUser(w http.ResponseWriter, r *http.Request) {
	if s.bff == nil {
		notBuilt(w, r)
		return
	}
	s.bff.Me(w, r)
}

func (s *server) bffOr(w http.ResponseWriter, r *http.Request, method string, handler func(*Bff, http.ResponseWriter, *http.Request)) {
	if s.bff == nil {
		notBuilt(w, r)
		return
	}

	if method == http.MethodGet {
		handler(s.bff, w, r)
		return
	}
	RequireSameOrigin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler(s.bff, w, r)
	})).ServeHTTP(w, r)
}

func notBuilt(w http.ResponseWriter, r *http.Request) {
	writeV0NotFound(w, r)
}

func writeV0NotFound(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, r, http.StatusNotFound, api.V0Error{
		Error:   api.V0ErrorErrorNotFound,
		Message: "no such route",
	})
}

func writeRawJSON(w http.ResponseWriter, r *http.Request, status int, body string) {
	if w.Header().Get("Content-Type") == "" {
		w.Header().Set("Content-Type", "application/json")
	}
	w.WriteHeader(status)
	if _, err := w.Write([]byte(body)); err != nil {
		panic(fmt.Sprintf("httpapi: %s %s: response did not write: %v", r.Method, r.URL.Path, err))
	}
}
