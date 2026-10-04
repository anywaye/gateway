package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

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
	// Nothing registers one by hand in this packet: the first dependency
	// gateway is given arrives with the packet that ports it, and it registers
	// here and nowhere else. See `NamedProbe` for why this is a slice.
	Probes []NamedProbe
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

	api.HandlerWithOptions(&server{probes: options.Probes}, api.ChiServerOptions{BaseRouter: router})

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
	svc := &server{probes: options.Probes}
	router.Method(http.MethodHead, "/healthz", headOf(svc.Liveness))
	router.Method(http.MethodHead, "/readyz", headOf(svc.Readiness))

	return router, nil
}

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
// Each method below is ONE of two things, and the distinction is the whole shape
// of this packet:
//
//   - the operation is served (`Liveness`, `Readiness`), or
//   - the operation is declared by the contract, needs a Wave 3 subsystem this
//     packet does not port, and answers the reference's own answer for an
//     operation that is not there (`notBuilt`).
//
// The second kind is the honest part. `src/index.ts` does not register `/v1/me`
// unless a verifier is configured, and does not register `/auth/*` unless there
// is an identity to ask — so a gateway built with nothing configured answers
// `404` on all five, and this one must too. `TestEveryOperationIsEitherServedOr
// Declined` reads the router and fails on an operation that is neither.
type server struct {
	probes []NamedProbe
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

// The five operations the contract declares that this packet does not serve.
//
// One paragraph is on `notBuilt`. Repeating it five times would be five places
// to update and one place a reader looks, and each of these is a bare name for
// `notBuilt` so `grep notBuilt` enumerates the Wave 3 surface.
func (s *server) GetCurrentPrincipal(w http.ResponseWriter, r *http.Request) {
	notBuilt(w, r)
}

func (s *server) RegisterUser(w http.ResponseWriter, r *http.Request, _ api.RegisterUserParams) {
	notBuilt(w, r)
}

func (s *server) CreateSession(w http.ResponseWriter, r *http.Request, _ api.CreateSessionParams) {
	notBuilt(w, r)
}

func (s *server) DeleteSession(w http.ResponseWriter, r *http.Request, _ api.DeleteSessionParams) {
	notBuilt(w, r)
}

func (s *server) GetCurrentUser(w http.ResponseWriter, r *http.Request) {
	notBuilt(w, r)
}

// notBuilt is the answer for an operation whose subsystem this packet does not
// port.
//
// It writes the v0 `404` envelope, and that is a decision rather than the
// obvious thing. The alternatives were each wrong in a way that would have cost
// a reader something:
//
//   - `501 Not Implemented` is the truthful answer about *this codebase*, and it
//     is not the contract's answer. `src/index.ts` does not register `/v1/me`
//     without a verifier, so the reference answers `404` there — and the packet
//     rules that the TypeScript answer is the correct one.
//   - A `503` in the real handler's shape would make a deployment look broken in
//     a way `404` does not.
//   - Leaving the route unmounted would be indistinguishable from a path nobody
//     declared, and the router is generated, so there is no line here to leave
//     out: the document declares these five operations and the generated router
//     registers all five whatever this package does with them.
//
// One writer rather than five, because the answer is one answer. The method
// bodies above are what make it *visible* which five operations are in this
// state, and `TestEveryOperationIsEitherServedOrDeclined` is what keeps the two
// in step with the document.
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
// one place that needs key order has an honest name, rather than reaching for
// `writeJSON` and passing a `json.RawMessage` that reads like an oversight.
func writeRawJSON(w http.ResponseWriter, r *http.Request, status int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if _, err := w.Write([]byte(body)); err != nil {
		panic(fmt.Sprintf("httpapi: %s %s: response did not write: %v", r.Method, r.URL.Path, err))
	}
}
