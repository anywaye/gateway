package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/cafaye/gateway/internal/api"
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
// issuer serves probes only — and it is the shape `src/index.ts` documents for
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
	// hole this option opens and not one it closes — it is what the reference does,
	// and reproducing it is what lets `internal/equivalence` compare two
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
// `import.meta.main` in `src/index.ts` is the same boundary: importing this
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

	// Before the generated router, and the reason is in `collapseRepeatedHeaders`:
	// `oapi-codegen` refuses a header parameter sent twice with a `text/plain` 400,
	// the reference has no such refusal, and without this middleware the two answers
	// differ on status, in content type and in whether a cookie was set.
	router.Use(collapseRepeatedHeaders)

	svc := &server{probes: options.Probes, bff: bff}
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

	if options.Routes == nil {
		return router, nil
	}

	// Validated AGAIN here rather than reusing `validate`'s result, and the reason
	// is that this is the copy the service reads: `ValidateRouteTable` returns a
	// fresh one, so the entry slices and the claim slices are not the caller's and
	// a caller cannot append to a table after the gateway was built. Refusing to
	// serve on the first pass and then forwarding on the second would leave a
	// gateway whose routing had never been checked.
	table, err := ValidateRouteTable(options.Routes)
	if err != nil {
		return nil, err
	}

	// The pass-through, in front of the router, and the credential gate in front of
	// that — the same order `src/index.ts` registers them, and the order is the
	// property: a request is authenticated *before* anything decides to spend an
	// upstream call on it.
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
	// and the chain is assembled here as gate → pass-through → router. Wrapping the
	// router rather than mounting into it costs one thing: the returned value is no
	// longer a bare `*chi.Mux`. It still *is* a `chi.Routes`, because `mount`
	// embeds the router and overrides only `ServeHTTP` — so `chi.Walk` still reads
	// the generated registrations, and `TestTheRouterServesExactlyWhatTheGenerated-
	// DocumentDeclares` keeps working on a configured gateway as well as an empty
	// one.
	proxied := newRouteProxy(proxyOptions{
		Routes:    table,
		Timeout:   options.UpstreamTimeout,
		Assertion: options.Assert,
	}).handle(router)

	return &mount{Router: router, handler: credentialGate(options.Authenticate, table, proxied)}, nil
}

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
// The rule is `src/index.ts`'s and it is a house convention rather than a
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
// `src/index.ts` does not register `/auth/*` unless there is an identity to ask,
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
	// the probes. `internal/equivalence` compares this body byte for byte against
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
// from itself. `src/index.ts` mounts it per route for exactly this reason, and
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

// GetCurrentPrincipal is the one operation this packet does not serve, and it is
// bearer-token verification: a subsystem the auth packet owns.
//
// It stays a decline rather than a `401` for the reason `notBuilt` gives — the
// reference does not register `/v1/me` without a verifier, so the reference
// answers `404` here too. `grep notBuilt` therefore names exactly one operation
// now, which is what makes it a useful inventory rather than a decoration.
func (s *server) GetCurrentPrincipal(w http.ResponseWriter, r *http.Request) {
	notBuilt(w, r)
}

// notBuilt is the answer for an operation that is not here.
//
// It writes the v0 `404` envelope, and that is a decision rather than the obvious
// thing. The alternatives were each wrong in a way that would have cost a reader
// something:
//
//   - `501 Not Implemented` is the truthful answer about *this codebase*, and it
//     is not the contract's answer. `src/index.ts` does not register `/v1/me`
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
// decodes the body and stops there never sees it. `internal/equivalence` does, as a
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
