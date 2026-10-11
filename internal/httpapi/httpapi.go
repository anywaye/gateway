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

	"github.com/cafaye/gateway/internal/api"
	"github.com/cafaye/gateway/internal/auth"
	"github.com/cafaye/gateway/internal/ratelimit"
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
	// Readiness probes by dependency name, in the order `/readyz` renders them.
	// A caller registers them here, by hand, and a configured `BFF` is NOT one of
	// them — measured rather than assumed: `createApp({bff})` answers
	// `{"deps":{}}`, because the `identity` probe is registered by
	// `runtimeOptions`, which reads `IDENTITY_URL` and is not something this package
	// does. Auto-registering it here made `/readyz` differ from the reference in
	// every browser scenario, at byte 9.
	//
	// The ORDER is not decoration: `/readyz` renders `deps` in registration order
	// because this is a slice and not a map, and `encoding/json` sorts map keys.
	Probes []NamedProbe

	// BFF is the browser surface: the four `/auth` routes, the session cookie and
	// the origin gate. NIL means none of it, and the four routes then decline with
	// the reference's `404` — which is what `createApp({})` does, so a gateway
	// configured with nothing serves the same answer the reference does.
	//
	// Not a pointer for its own sake: the reference's `AppOptions.bff` is
	// `BffOptions | undefined`, and "there is an identity to ask" is a fact about
	// the deployment rather than an empty struct. A `BffOptions{}` with an empty
	// `IdentityURL` would be a browser surface that cannot reach identity, and
	// `NewBff` refuses that — so the two spellings would not even both build.
	BFF *BffOptions

	// Which path prefix goes to which service, or nil for none.
	//
	// Nil is a *configuration*, not an absence: a gateway with no table forwards
	// nothing, and that is the honest shape for an app built without services —
	// a gateway that invented a destination would be an open proxy. A non-nil
	// table is validated here, before anything is assembled, so a malformed one is
	// a refusal to construct the gateway at all rather than a 404 on the first
	// request of the week. An **empty** non-nil table is refused by the validator,
	// because an operator who meant to configure routing and got nothing is the
	// case that must not pass silently.
	//
	// `ParseRouteTable` is what a deployment calls, and it is where the refusals
	// about *JSON spellings* live — `"public": "true"`, `"principal": []`.
	Routes RouteTable

	// Which hostname goes to which backend, or nil for none.
	//
	// Nil is the honest default and the reason this field is additive: a gateway
	// with no vhost table routes exactly what it routed before this field
	// existed, by path prefix alone. A non-nil table is validated here, before
	// anything is assembled, so a malformed one is a refusal to construct the
	// gateway at all rather than a 404 on the first request of the week. An
	// **empty** non-nil table is refused by the validator, because an operator
	// who meant to configure the api/auth split and got nothing is the case that
	// must not pass silently.
	//
	// `ParseVHostTable` is what a deployment calls. See `vhost.go` for why this
	// is a second table rather than host fields on the entries, and why it
	// carries no authz of its own.
	VHosts VHostTable

	// The principal minter, or nil for none.
	//
	// Nil means **no assertion is minted on any route** — which is the state every
	// deployment that has not configured a signing key is in, and the reason the
	// feature is additive rather than a change: an unconfigured gateway sends
	// exactly the headers it sent before this option existed.
	//
	// Configuring it still asserts nothing on a route whose entry did not declare
	// claims, and never on a `public` entry. Both are stated where they are
	// enforced — `ValidateRouteTable`'s refusals and `routeProxy.assertionFor`.
	Assert *AssertionMinter

	// The credential gate, or nil for none.
	//
	// Nil means the gate is **not registered**, which is the reference's own
	// behaviour when no `jwt` option was configured: an app with a route table and
	// no verifier relays an anonymous request to a private route. That is not a
	// hole this option opens and not one it closes — it is what the TypeScript
	// original did, and reproducing it is what let the equivalence check compare two
	// unconfigured gateways byte for byte.
	//
	// The packet that ports RS256 verification fills this in, and nothing else
	// changes: see `gate.go` for why the refusal, its detail string and its
	// position above the pass-through are already the reference's.
	Authenticate Authenticate

	// How long one call to a service may take. Defaults to
	// `DefaultUpstreamTimeout`.
	//
	// Not configurable from the environment and deliberately not a retry budget:
	// there is no retry, no circuit breaker and no health check, and each of those
	// is absent on purpose — they are a packet that says what they cost.
	UpstreamTimeout time.Duration

	// The bearer-token verifier, or nothing.
	//
	// Nil is the honest v0 shape and it is `createApp`'s: "Omit and the gateway
	// serves probes only: with no issuer there is nothing to verify a token
	// against, and an endpoint that would have to trust a token is worse than an
	// endpoint that is not there." So a nil verifier does not mount a gate that
	// refuses everything — it mounts NO gate, and `GET /v1/me` declines with the
	// reference's own `404` for an operation that is not there.
	//
	// The field is an interface rather than a concrete verifier so a test can put
	// a stand-in in front of the router without a JWKS server, and so the package
	// that decides WHEN a token is verified does not own HOW.
	Verifier TokenVerifier

	// The limiter, or nothing. Omitted means gateway applies no limit at all,
	// which is the honest v0 default for an app built without one rather than a
	// limit that exists only in the config.
	Limiter RateLimiter

	// The API-key surface: the store the three `/v1/api-keys` management routes
	// and the authentication gate read, or nil for none of it.
	//
	// Nil means a gateway that does not authenticate keys and declines the three
	// management routes with the reference's `404` — which is the same answer
	// `createApp({})` gives for the browser surface, and the same honest shape.
	// Configuring it mounts the key gate in front of the bearer gate on the API
	// surface and serves the three routes.
	//
	// The store is a seam, not a concrete type, so a deployment can back it with
	// whatever survives a restart. The v0 implementation is one process; see
	// `TODO(guard-07)` and the README for why a shared store is a later packet.
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

	// The generated router. `openapi/v1.yaml` IS the routing table — the
	// document, not this file, decides what is mounted — and
	// `internal/httpapi/routes_test.go` holds the two together in both
	// directions, so a route cannot appear here without the document naming it
	// and an operation cannot leave the document without this router noticing.
	router := chi.NewRouter()

	// Hono has one notFound handler and no 405, and gateway inherits both:
	// chi's default `405` would answer `405` with an empty body where the
	// reference answers `404` with a document, and a client branching on the
	// status would see a method the contract does not declare. Both refusals go
	// to one writer, and `TestAMethodTheRouteDoesNotServeIsANotFound` holds it
	// to the reference's answer rather than to chi's.
	router.NotFound(func(w http.ResponseWriter, r *http.Request) { writeV0NotFound(w, r) })
	router.MethodNotAllowed(func(w http.ResponseWriter, r *http.Request) { writeV0NotFound(w, r) })

	// # THE MOUNTS, IN THIS ORDER, AND THE ORDER IS THE WHOLE ARGUMENT
	//
	// 0. the server span, which `everyRequest` puts outermost,
	// 1. the repeated-header reduction, which is not a gate and must be first,
	// 2. authentication, resolved before anything decides to spend an upstream call,
	// 3. the limiter on everything, routed traffic included.
	//
	// Authentication BEFORE the limiter, and the reason is the reference's: "the
	// key is the strongest identity the request has, and the strongest identity is
	// only known once a token has been verified." Mounted the other way round, a
	// request refused by the auth gate would still be counted — under `ip:unknown`,
	// because that is all a rejected request has — and a flood of forged tokens
	// would exhaust the shared anonymous bucket for every legitimate anonymous
	// caller. That is the amplifier, and it costs one line of ordering.
	//
	// The header reduction is before both because it is not a gate: it rewrites the
	// request the gates read, and a gate that had already decided a request carried
	// no `Origin` would be deciding it about a value the gateway then throws away.
	// `collapseRepeatedHeaders` says why it exists — `oapi-codegen` refuses a header
	// parameter sent twice with a `text/plain` 400, the reference has no such
	// refusal, and without this middleware the two answers differ on status, in
	// content type and in whether a cookie was set.
	//
	// ## ONLY THE BEARER GATE IS A `Use` HERE, AND THAT IS THE FIX
	//
	// The other two are mounted by `everyRequest`, and the reason is the shape of
	// this router rather than a preference. **chi's `Use` wraps the routes
	// registered on the router it is called on.** It is not a chain the whole
	// handler passes through — the pass-through in `New` is mounted ON TOP of this
	// router and, for a path the route table claims, never calls it at all. So a
	// limiter mounted here is a limiter that runs on gateway's own routes and not
	// on the traffic gateway forwards, which is the expensive kind: it reaches an
	// upstream that does work.
	//
	// That was measured, not argued: with the limiter mounted here and both sides
	// frozen at 2026-01-01T00:00:00Z on an allowance of three, `GET
	// /v1/pantry/items` was a `429` with the whole `RateLimit-*` family on the
	// reference and a `200` with no rate-limit headers at all here. The port had
	// believed itself immune to an ordering hazard Hono has and chi does not — the
	// hazard is real in both, and in chi it is worse: in Hono a `use` registered
	// after a route does not run either, but a `Use` is still evaluated for every
	// request that reaches the router, so the mistake is only invisible until
	// something is mounted in front.
	//
	// chi does still require `Use` before any route is registered, and
	// `api.HandlerWithOptions` is what registers the seven — which is why this
	// list is computed here and mounted in one call. The bearer gate belongs to
	// the contract's own routes; the credential gate above the pass-through is
	// `Authenticate`, and it is a different seam on purpose (see `authentication`).
	//
	// ## THE TWO PLACEMENTS OF ONE CHAIN, AND WHY IT IS NOT MOUNTED IN BOTH
	//
	// With no pass-through the whole chain belongs to chi: the reduction, the
	// bearer gate, the limiter — `everyRequest`'s order, all three on the router.
	// With a pass-through only the bearer gate stays here and the other two are
	// wrapped around the proxy further down.
	//
	// The limiter is the one that cannot be in both. The pass-through calls
	// `next` for a path no table claims, so a limiter on the router counts those
	// requests a second time on top of the wrapper's count: measured, the Go side
	// reported `RateLimit-Remaining: 1` on the first request of a run where the
	// reference reported `2`, because it had spent twice what the reference had.
	// A bucket spent twice per request is a limiter with half the allowance it
	// announces — and a comparison that only compares statuses reads it as
	// agreement.
	limiter := middlewareOf(options.Limiter)
	insideLimiter := limiter
	insideTelemetry := telemetryMiddleware
	if options.Routes != nil {
		insideLimiter = nil
		insideTelemetry = nil
	}
	// The API-key gate runs before the bearer gate so a caller presenting a key is
	// judged on the key, and both are principal-aware so a request the outer chain
	// already authenticated is not verified a second time.
	router.Use(everyRequest(insideTelemetry, insideLimiter, apiKeyGate(options.APIKeys), bearerGate(options))...)

	svc := &server{probes: options.Probes, bff: bff, verifier: options.Verifier, apiKeys: options.APIKeys}
	api.HandlerWithOptions(
		svc,
		api.ChiServerOptions{BaseRouter: router, ErrorHandlerFunc: paramRefusal()},
	)

	// `HEAD` on the two probe paths, registered explicitly because chi does not
	// route `HEAD` to a `GET` handler and Hono does. The reference answers `200`
	// with an empty body on `HEAD /healthz`; without these two lines chi would
	// answer `405`, which is why this is a registration and not a comment.
	//
	// Scoped to `ProbePaths` rather than applied to every operation, because
	// `HEAD` is how a health checker and an orchestrator ask, and a gateway that
	// answers 404 to `HEAD /healthz` is a process that looks dead to the tool
	// whose job is to notice it is alive. `TestTheHeadRoutesAreTheProbePaths`
	// holds the two sets equal, so adding a probe path without its `HEAD` route —
	// or the other way round — is a failing test rather than a difference only
	// the equivalence check would notice.
	router.Method(http.MethodHead, "/healthz", headOf(svc.Liveness))
	router.Method(http.MethodHead, "/readyz", headOf(svc.Readiness))

	if options.Routes == nil && options.VHosts == nil {
		// Nothing in front of the router to mount on, so `everyRequest`'s list is
		// already on chi (above, with the bearer gate in it) and this returns the
		// bare `*chi.Mux` — which `chi.Walk` can read, and which is why
		// `routes_test.go` can walk a gateway built from an empty configuration.
		return router, nil
	}

	// Validated AGAIN here rather than reusing `validate`'s result, and the reason
	// is that this is the copy the service reads: `ValidateRouteTable` returns a
	// fresh one, so the entry slices and the claim slices are not the caller's and
	// a caller cannot append to a table after the gateway was built. Refusing to
	// serve on the first pass and then forwarding on the second would leave a
	// gateway whose routing had never been checked.
	// Each validated only when configured: nil is the honest default for both —
	// no path routing, no hostname split — and `ValidateRouteTable` refuses an
	// empty table rather than blessing it, so an unconditional call here would
	// make a vhost-only gateway unconstructible.
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

	// The pass-through, and the credential gate in front of that — the same order
	// `src/index.ts` (removed at cutover) registers them, and the order is the property: a request is
	// authenticated *before* anything decides to spend an upstream call on it.
	//
	// ## WHY THE ROUTER IS WRAPPED RATHER THAN MOUNTED, AND WHAT THAT COSTS
	//
	// Hono registers `/v1/me` before `app.use(ROUTE_MOUNT, …)` and answers in
	// registration order, so the two never have to agree about precedence. chi has
	// no such order for a middleware and a route: the trie prefers the more specific
	// `/v1/me` and every middleware wraps whatever it matched, so a pass-through
	// mounted as chi middleware would see gateway's own route and — with the
	// permitted `/v1` prefix in the table — relay it.
	//
	// `routeProxy.handle` therefore names the exclusion itself (see its comment)
	// and the chain is assembled here as gate → limiter → pass-through → router,
	// with the header reduction outside both. Wrapping the router rather than
	// mounting into it costs one thing: the returned value is no longer a bare
	// `*chi.Mux`. It still *is* a `chi.Routes`, because `mount` embeds the router
	// and overrides only `ServeHTTP` — so `chi.Walk` still reads the generated
	// registrations, and `TestTheRouterServesExactlyWhatTheGeneratedDocument-
	// Declares` keeps working on a configured gateway as well as an empty one.
	proxied := newRouteProxy(proxyOptions{
		Routes:    table,
		Timeout:   options.UpstreamTimeout,
		Assertion: options.Assert,
	}).handle(router)

	// The chain in front of the pass-through, in the order the reference registers
	// them: the API-key gate, then the credential gate, then the scope gate, then
	// the limiter. The scope gate is the route's own declaration of what a caller
	// must hold to be forwarded — mounted after authentication and before the
	// limiter, so a caller refused for capability is counted against nothing, the
	// same rule an unverified token gets.
	gates := everyRequest(telemetryMiddleware, limiter,
		apiKeyGate(options.APIKeys),
		credentialGate(authentication(options), table),
		scopeGate(options.Verifier, table),
		vhostGate(vhosts, options.UpstreamTimeout, options.Assert),
	)
	return &mount{Router: router, handler: compose(proxied, gates...)}, nil
}

// everyRequest is the middleware every request passes through, in order: the span,
// then the repeated-header reduction, then each gate in the order given, then the
// limiter.
//
// ## WHY IT IS ONE LIST AND NOT THREE MOUNTS
//
// The order is the property — a span covers the whole request, a request refused by
// a gate is not counted, and the reduction rewrites what the gates read — and an
// order written out as three separate statements in two branches of `New` is an
// order one of the branches can forget. `New` registers this list with chi's `Use`
// when there is no pass-through and wraps the pass-through with it when there is;
// both are the same chain, so a fourth middleware added to gateway's request path is
// added in one place.
//
// The gates are variadic and run between the reduction and the limiter in the order
// given: the API-key gate, then the credential gate, then the scope gate. That order
// is the property — a credential is established before a capability is checked, and
// both are established before the limiter counts anything.
//
// ## THE SPAN IS IN EXACTLY ONE OF THE TWO PLACEMENTS, AND THAT IS MEASURED
//
// The limiter is mounted in one of them for a reason this paragraph repeats because
// the span has the same one: a middleware in BOTH runs twice for a request that
// passes through both — a path the proxy does not claim reaches the router, so the
// outer chain and chi's own `Use` chain both run. Two spans for one request is not a
// cosmetic doubling: a trace view renders it as a call that happened twice, and a
// request-counted dashboard is wrong by a factor of two on exactly the paths that
// are hardest to read.
//
// So `New` decides placement the same way it decides it for the limiter: the outer
// `compose` chain when there is a pass-through, chi's `Use` chain when there is
// none. Every request that reaches this process is in exactly one span, including a
// forwarded one and including a 404 that matches no route.
//
// ## THE LIMITER IS WRAPPED AROUND THE PASS-THROUGH, AND THAT IS THE WHOLE FIX
//
// chi's `Use` wraps the routes registered on the router it is called on. The
// pass-through is mounted on top of that router and, for a path the route table
// claims, never calls it — so a limiter mounted with `Use` counted gateway's own
// routes and forwarded nothing at all, which is the traffic that costs an upstream
// money. Wrapped here it runs on both, exactly once each.
//
// Once per request is why `New` passes the limiter to only one of the two
// placements; see the comment at the mount for what double counting measured like.
//
// ## A `nil` GATE IS NOT A GATE THAT REFUSES
//
// `credentialGate` returns nil when there is no `Authenticate`, and `New` passes a
// gate only when there are routes to gate, so `gate == nil` here means a gateway
// with no verifier rather than one that refuses everything. The same is true of the
// API-key and scope gates below.
func everyRequest(telemetry, limiter func(http.Handler) http.Handler, gates ...func(http.Handler) http.Handler) []func(http.Handler) http.Handler {
	chain := []func(http.Handler) http.Handler{collapseRepeatedHeaders}
	if telemetry != nil {
		chain = append([]func(http.Handler) http.Handler{telemetry}, chain...)
	}
	for _, gate := range gates {
		// A nil gate is not a gate that refuses — it is the absence of one, and
		// chi's `Use` panics on a nil middleware rather than skipping it.
		if gate != nil {
			chain = append(chain, gate)
		}
	}
	if limiter != nil {
		chain = append(chain, limiter)
	}
	return chain
}

// compose wraps `next` in `middlewares`, the first outermost — the order chi
// applies a `Use` list in, spelled out for the case where the chain is not chi's
// to build.
func compose(next http.Handler, middlewares ...func(http.Handler) http.Handler) http.Handler {
	for i := len(middlewares) - 1; i >= 0; i-- {
		next = middlewares[i](next)
	}
	return next
}

// bearerGate is the `/v1/*` token gate, or nil when no verifier is configured.
//
// Nil rather than a middleware that permits everything, because a gate that cannot
// refuse is not a gate and the honest spelling of "there is none" is the absence —
// the same reason `credentialGate` returns nil rather than `next`.
//
// It passes a request that already carries a verified principal. When a route table
// is configured the outer chain runs first and its credential gate (or API-key gate)
// has already authenticated the request; re-verifying here would either refuse an
// API key — its header is not a bearer token — or pay for a second verification of a
// token the first already checked.
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

// apiKeyGate is the API-key credential gate, or nil when no store is configured.
//
// Mounted before the bearer gate so a caller presenting a key is judged on the key,
// and scoped to the API surface so a key never authenticates a browser request. It
// passes any request whose `Authorization` is not an API key — a bearer token, a
// cookie and no credential at all are each a different gate's question.
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

// scopeGate is a route's own declaration of what a caller must hold to be forwarded,
// or nil when there is no verifier.
//
// This is the capabilities half of what the verifier proves about a caller, and the
// half that was implemented but mounted by nothing until this packet: without it, a
// route that declared scopes still forwarded any verified caller, so on a shared
// platform the forwarded traffic was by design able to act as any tenant.
//
// It is mounted after the credential gate and before the limiter, so the order the
// house rule names holds — a credential is established before a capability is
// checked, and a caller refused for capability is counted against nothing, exactly
// as a caller whose token does not verify is.
//
// Only a route that DECLARED scopes is checked, and only gateway's own routes are
// exempt: `/v1/me` and the `/v1/api-keys` management surface are answered by
// gateway, not forwarded, so a broad `/v1` table entry cannot scope-gate them.
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

			// The credential gate in front of this one has already put a verified
			// principal on the context (or refused 401), so `RequireScope`'s 401
			// branch is the wiring-mistake path, not a live one.
			handler := next
			for i := len(route.Scopes) - 1; i >= 0; i-- {
				middleware, err := verifier.RequireScope(writeAuthRefusal, route.Scopes[i])
				if err != nil {
					// Unreachable: the table validated every scope at boot, and an
					// empty one is a refusal to construct rather than a gate.
					next.ServeHTTP(w, r)
					return
				}
				handler = middleware(handler)
			}
			handler.ServeHTTP(w, r)
		})
	}
}

// middlewareOf is an optional limiter as an optional middleware.
func middlewareOf(limiter RateLimiter) func(http.Handler) http.Handler {
	if limiter == nil {
		return nil
	}
	return limiter.Wrap
}

// authentication is the gate the pass-through is mounted behind.
//
// # A VERIFIER SUPPLIES IT UNLESS SOMETHING ELSE ALREADY DID
//
// `Options.Authenticate` is the seam `gate.go` was built around, and until this
// packet arrived nothing in this repository could fill it — so `gate.go`'s own
// comment said the verifier packet would fill it and nothing else would change.
// This is that. `*auth.Verifier` is `Options.Verifier` here, so a gateway
// configured the way `RuntimeOptions` configures one verifies a token ONCE and both
// halves of the answer to the same question: `/v1/me` renders the principal and a
// private proxied route mints the assertion about it.
//
// The alternative — leaving `Authenticate` nil and letting the chi mount do the
// verifying — is a gateway that verifies `/v1/*` and then forwards private proxied
// requests with **no credential gate at all**, because `credentialGate(nil, …)` is
// a pass-through and not a refusal. That is the whole failure this line exists to
// prevent, and it is silent: nothing about a relayed anonymous request looks wrong.
//
// An explicit `Options.Authenticate` still wins, because a caller that supplied a
// gate has said what the gate is and this must not replace it.
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
			// The refusal's own words are NOT passed on, and that is not a discard:
			// `credentialGate` writes one 401 for every refusal this seam can return,
			// and the detail string is `src/middleware/jwt.ts` (removed at cutover)'s. A verifier's reason
			// can name an issuer, an audience or a `kid`, and a caller who cannot
			// authenticate is not entitled to the reason.
			return nil, errNotAuthenticated
		}
		return principal, nil
	}
}

// errNotAuthenticated is what this seam returns for every refusal, so a reader
// looking at the `err` branch does not go looking for a wrapped cause that is
// deliberately not there.
var errNotAuthenticated = errors.New("httpapi: the request carried no verified principal")

// browserSurface builds `Options.BFF`, or reports why it cannot.
//
// A nil `BFF` is the nil result and not an error: that is the "there is no
// identity to ask" configuration, and the reference serves probes only in it. A
// non-nil one with anything wrong in it is a refusal, because `/auth/*` answering
// `404` when an operator configured it is the failure this repository's rule
// names — "invalid config is an error, not a fallback".
func (o Options) browserSurface() (*Bff, error) {
	if o.BFF == nil {
		return nil, nil
	}
	return NewBff(*o.BFF)
}

// paramRefusal is what the generated router does when it cannot bind a header.
//
// # IT IS UNREACHABLE FOR THE TWO HEADERS THE CONTRACT DECLARES
//
// `collapseRepeatedHeaders` reduces a repeated value to its first before the router
// sees it, so the generator's "expected one value" refusal — the only way to reach
// this — does not fire for `Sec-Fetch-Site` or `Origin`. What it does for is a
// header parameter the document adds later and the middleware does not know about,
// and the answer here is the v0 `404` with the generator's own reason LOGGED rather
// than written: a body that names a header describes the gateway's internals to an
// unauthenticated caller, which is the one thing every other refusal here avoids.
//
// NOT the generator's default. That default is `http.Error`, which is `text/plain`
// — a body shape that appears nowhere in `openapi/v1.yaml`.
//
// `TestTheParameterRefusalIsUnreachableForTheDeclaredHeaders` is the tripwire: it
// doubles each declared header and asserts the request reaches its handler, so
// "unreachable" is a measured fact rather than a hope.
//
// The older reason this writer took a boolean — "mounted answers the gate's `403`,
// unmounted answers the v0 `404`" — is gone, because it rested on a measurement
// that was wrong: the reference does not refuse a repeated header at all. See
// `collapseRepeatedHeaders`.
func paramRefusal() func(http.ResponseWriter, *http.Request, error) {
	return func(w http.ResponseWriter, r *http.Request, err error) {
		log.Printf("gateway: a header the contract declares could not be read: %v. This is unreachable for Sec-Fetch-Site and Origin — collapseRepeatedHeaders reduces a repeated value to its first — so it means a header parameter this middleware does not know about arrived more than once.", err)
		notBuilt(w, r)
	}
}

// mount is the contract's router with the pass-through and the gate in front of
// it.
//
// The embedded `chi.Router` is not decoration: it is what keeps `chi.Walk` working
// through the wrapper, so core's account-scope checker and this repository's own
// router-to-document test can read the *generated* registrations off a configured
// gateway. Only `ServeHTTP` is overridden, and an interface's promoted method is
// shadowed by a method on the outer type, so the two never disagree.
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

// writeAuthRefusal renders a verifier refusal as core's problem document.
//
// One function rather than a closure built at every mount, because the envelope is
// `writeProblem`'s and the translation from `auth.Refusal`'s three fields to
// `Problem`'s four is the kind of thing that must not be re-spelled: a status
// defaulting to 401 because a caller forgot to set it is a `503` reported as a
// caller's fault, and `TestAProblemIsTheDocumentedEnvelope` cannot see that.
func writeAuthRefusal(w http.ResponseWriter, r *http.Request, refusal *auth.Refusal) {
	writeProblem(w, r, Problem{
		Status: refusal.Status,
		Code:   api.ProblemCode(refusal.Code),
		Detail: refusal.Detail,
	})
}

// writeRateLimitRefusal is `writeAuthRefusal` for the limiter's single `429`.
//
// It exists as its own name because the limiter's refusal carries a status and a
// code as strings — it is written by `internal/ratelimit`, which does not know
// about `api.ProblemCode` — and one place converts them is one place to check. The
// limiter has exactly one refusal and it is a constant: "The one 429 this
// repository writes. A fixed detail: nothing here varies."
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

// The two refusal writers are what `internal/auth` and `internal/ratelimit` are
// handed, asserted here so a signature drift is a compile error in this package
// rather than a `func(int, string, string)` mismatch at every mount.
var (
	_ auth.Refuser      = writeAuthRefusal
	_ ratelimit.Refuser = RateLimitRefuser
)

// headOf adapts a `GET` handler to answer a `HEAD`.
//
// `http.ResponseWriter` cannot un-write a body, so the body goes nowhere: the
// headers and the status are the answer, and that is what a `HEAD` answer is.
// The status comes from the real handler rather than from a constant, so a `GET`
// that starts failing starts failing on `HEAD` too — which is the property worth
// having, and the reason this is an adapter rather than a second handler that
// writes `200`.
func headOf(get http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		get(bodyless{ResponseWriter: w}, r)
	}
}

// bodyless is a `ResponseWriter` that drops the body. Three lines, and the
// standard Go idiom: it is what `net/http`'s own `ServeContent` does for `HEAD`.
type bodyless struct {
	http.ResponseWriter
}

func (bodyless) Write(body []byte) (int, error) { return len(body), nil }

// validate refuses a configuration that cannot be served as written.
//
// The rule is `src/index.ts` (removed at cutover)'s and it is a house convention rather than a
// gateway detail: *"Invalid config is an error, not a fallback."* A probe
// registered without a name would render as `{"deps":{"":"ok"}}`, a nil probe
// would answer `unavailable` forever — a readiness endpoint reporting a
// configuration mistake as an outage — and two probes under one name would be
// two dependencies of which `/readyz` can report one.
func (o Options) validate() error {
	// The route table, before anything else. `REDIS_URL=redis//redis` refusing to
	// boot is the precedent, and a table is the most expensive version of that
	// mistake: every prefix in it that forwards nothing answers 404 for a service
	// that exists, and nothing about that failure points at configuration.
	if o.Routes != nil {
		if _, err := ValidateRouteTable(o.Routes); err != nil {
			return err
		}
	}
	// The vhost table, by the same rule: a name in it that routes nowhere
	// answers 404 for a backend that exists, and nothing about that failure
	// points at configuration.
	if o.VHosts != nil {
		if _, err := ValidateVHostTable(o.VHosts); err != nil {
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

// server is the `api.ServerInterface` the generated router calls. It is the only
// place a handler is written.
//
// Each method below is ONE of three things, and the distinction is the whole
// shape of the port:
//
//   - the operation is served unconditionally (`Liveness`, `Readiness`), or
//   - the operation is served when its subsystem is configured and declines with
//     the reference's own `404` when it is not (the four `/auth` routes), or
//   - the operation is declared by the contract, needs a Wave 3 subsystem neither
//     packet ports, and declines (`GetCurrentPrincipal`).
//
// The second kind is the honest part and it is two-valued on purpose.
// `src/index.ts` (removed at cutover) does not register `/auth/*` unless there is an identity to ask,
// so a gateway built with nothing configured answers `404` on all four — and a
// gateway built WITH an identity has to answer exactly what the reference does
// with one, which is a different thing entirely. `decline` is the one writer for
// that shape, so the four methods below are one line each and the difference
// between "this is not here" and "this is here" is the `bff` field and nothing
// else.
type server struct {
	probes []NamedProbe

	// Nil means no browser surface, and every `/auth` method declines. It is set
	// by `New` from `Options.BFF` and cannot be nil-and-non-nil: the only
	// assignment is the one line there.
	bff *Bff

	// Nil means no bearer gate was mounted, which is what makes `/v1/me` decline
	// rather than answer. See `Options.Verifier`.
	verifier TokenVerifier

	// Nil means no API-key surface: the key gate is not mounted and the three
	// `/v1/api-keys` routes decline with the reference's `404`.
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
	// Encoded by hand rather than through `writeJSON`, because `encoding/json`
	// sorts map keys and `/readyz` renders `deps` in the order the caller wrote
	// the probes. `internal/equivalence` compared this body byte for byte against
	// the TypeScript reference, and a sorted map fails on a difference no client
	// would ever see — which is exactly the kind of difference an equivalence
	// check exists to find rather than to explain away.
	writeRawJSON(w, r, status, `{"deps":`+orderedDeps(s.probes, deps)+`}`)
}

// orderedDeps renders the `deps` object in the order the probes were registered,
// with every key and every value escaped by `encoding/json` rather than by hand.
//
// The values come from a closed two-value enum and the keys are validated
// non-empty at construction, so this is not a place a caller can inject a
// character into a body. It is still the one place this package builds JSON as
// text, so the braces and the comma are the only bytes written literally and the
// escaping is the encoder's job.
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
// defence, and a CSRF defence on a request that changes nothing protects a caller
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

// bffOr dispatches to a browser-surface handler, behind the origin gate, or
// declines.
//
// The `method` is an argument and not derived from the handler, because "is this
// route mutating" is a property of the CONTRACT and the contract is the generated
// document. Passing it means the gate's coverage is stated once, here, where a
// reader can see that a read is ungated on purpose; deriving it would mean asking
// the method off a request that the router has already matched.
//
// The handler is a method expression rather than a closure so no allocation
// happens per request and, more to the point, so the gate cannot be forgotten on
// one route by forgetting to wrap it in a `func`.
func (s *server) bffOr(w http.ResponseWriter, r *http.Request, method string, handler func(*Bff, http.ResponseWriter, *http.Request)) {
	if s.bff == nil {
		notBuilt(w, r)
		return
	}

	// `GET` is the only method on this surface that does not change anything, and
	// naming it is the whole exemption. A new method on `/auth` therefore gets the
	// gate by default, which is the direction to be wrong in: an ungated POST is a
	// CSRF hole and a gated GET is a read that 403s.
	if method == http.MethodGet {
		handler(s.bff, w, r)
		return
	}
	RequireSameOrigin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler(s.bff, w, r)
	})).ServeHTTP(w, r)
}

// notBuilt is the answer for an operation that is not here.
// notBuilt is the answer for an operation whose subsystem this packet does not
// port.
//
// It writes the v0 `404` envelope, and that is a decision rather than the obvious
// thing. The alternatives were each wrong in a way that would have cost a reader
// something:
//
//   - `501 Not Implemented` is the truthful answer about *this codebase*, and it
//     is not the contract's answer. `src/index.ts` (removed at cutover) does not register `/v1/me`
//     without a verifier and does not register `/auth/*` without an identity to
//     ask, so the reference answers `404` on all five with nothing configured —
//     and the packet rules that the TypeScript answer is the correct one.
//   - A `503` in the real handler's shape would make a deployment look broken in a
//     way `404` does not.
//   - Leaving the route unmounted would be indistinguishable from a path nobody
//     declared, and the router is generated, so there is no line here to leave
//     out: the document declares these operations and the generated router
//     registers all of them whatever this package does with them.
//
// One writer rather than five, because the answer is one answer. The method
// bodies above are what make it *visible* which operations are in this state, and
// `TestEveryOperationIsEitherServedOrDeclined` is what keeps the two in step with
// the document.
func notBuilt(w http.ResponseWriter, r *http.Request) {
	writeV0NotFound(w, r)
}

// writeV0NotFound writes the one non-problem body gateway still writes.
//
// This is open decision 5 in the document's header, and it is a conflict with
// core's conventions rather than an oversight: `404` and `500` answer
// `{ "error": …, "message": … }` with `application/json` because moving them onto
// the envelope needs trace-id propagation on every response first, which does not
// exist yet. `V0Error` is the generated type, so the body cannot carry a third
// error slug, and the message is a fixed string that names no path, no host and
// no query.
func writeV0NotFound(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, r, http.StatusNotFound, api.V0Error{
		Error:   api.V0ErrorErrorNotFound,
		Message: "no such route",
	})
}

// writeRawJSON writes a body this package has already encoded. It exists so the
// places that need key order have an honest name, rather than reaching for
// `writeJSON` and passing a string that reads like an oversight.
//
// The CONDITIONAL content type is the same rule `writeJSON` keeps, and it was
// FOUND HERE rather than assumed: a caller sets `application/problem+json` and
// then calls this, and an unconditional `Set` overwrote it with
// `application/json`. The body was byte-identical to the reference's and the media
// type was not, so every problem document in the service would have been served
// with the type that says "this is not a problem document" -- and a test that
// decodes the body and stops there never sees it. `internal/equivalence` did, as a
// `Content-Type` mismatch on otherwise identical bytes.
//
// THE COUNT IS TWO, and it is two because the two packets that each found this bug
// separately each added a caller: the BFF packet's `writeProblem` and the proxy
// packet's `writeProblemBody`. Both set a media type before calling this, and both
// would have had it overwritten. Neither packet could see the other's caller,
// which is why both reported the same defect with a comment claiming there was
// only one place -- and why this says two.
func writeRawJSON(w http.ResponseWriter, r *http.Request, status int, body string) {
	if w.Header().Get("Content-Type") == "" {
		w.Header().Set("Content-Type", "application/json")
	}
	w.WriteHeader(status)
	if _, err := w.Write([]byte(body)); err != nil {
		panic(fmt.Sprintf("httpapi: %s %s: response did not write: %v", r.Method, r.URL.Path, err))
	}
}
