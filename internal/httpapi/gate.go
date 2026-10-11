package httpapi

import (
	"net/http"
	"strings"

	"github.com/cafaye/gateway/internal/api"
	"github.com/cafaye/gateway/internal/auth"
)

// The credential gate, and the one seam the pass-through needs from it.
//
// ## WHY THIS FILE EXISTS WHEN NOTHING IN IT VERIFIES A TOKEN
//
// The pass-through has to know two things about a request it did not verify:
// whether there is a **verified principal** to assert anything about, and whether
// the route it is about is one an anonymous caller may reach. Both are answers,
// and neither is a verification. `Authenticate` is the seam verification plugs
// into, and it is nil whenever no verifier is configured — which is the shape
// `internal/equivalence` compared the Go gateway against a reference configured
// with no `jwt` in, for exactly that reason. A configured `Options.Verifier` fills
// it; see `New` and `authentication`.
//
// ## WHY THE 401 LIVES HERE AND NOT IN THE PACKET THAT PORTED THE VERIFIER
//
// Because the placement is the property, and the placement is the pass-through's
// business. `assertionFor` reads a principal from the request context; something
// has to put one there, and something has to decide that a request with no
// principal on a private route is refused **before** the proxy runs rather than by
// the proxy noticing afterwards. Putting the refusal here — one writer, above both
// the pass-through and the contract's own operations — is what makes "an anonymous
// caller to a private route gets 401, and the upstream is never contacted" a
// property of the wiring rather than of a handler three files down.
//
// When the packet that ports RS256 verification arrived it filled in
// `Authenticate` and nothing else changed: the refusal, the detail string, the
// status and the envelope were already the reference's, and the equivalence
// comparison for the 401 already ran. That is what happened; this file did not
// change to accommodate it, which is the only evidence the seam was the right shape.

// Authenticate is the credential gate's contract: it establishes who a caller is,
// or that it cannot.
//
// The signature is chosen so the *refusal* is not the gate's to word. Returning
// `(nil, err)` and having one writer turn it into the reference's 401 means there
// is exactly one sentence for "no credential", and a verifier cannot accidentally
// answer 403 for a caller it never authenticated — which is the mistake
// `src/middleware/jwt.ts` (removed at cutover)'s `requireScope` documents when it answers 401 for a
// route with no auth in front of it.
//
// A non-nil error with a non-nil principal is a defect in the gate and is refused
// rather than preferred.
type Authenticate func(*http.Request) (*Principal, error)

// principalKey is the context key a verified principal travels under.
//
// Unexported and of an unexported type, so nothing outside this package can put a
// principal on a request — which is the whole point: a `context.WithValue` with a
// string key is forgeable by anything that imports `context`, and the assertion
// would then be a signed statement about a caller the gate never verified.
// withPrincipal returns a request carrying a verified principal.
//
// IT DELEGATES rather than keeping a key of its own, and that used to be
// different: this file had an unexported `principalKey{}` and wrote the principal
// under it. That was correct while `Authenticate` had no implementation — the gate
// and the reader were the only two parties. It stopped being correct when the
// verifier arrived, because `Require` writes the principal under `auth`'s key, and
// a pass-through gate that could not see it would verify a token the contract's own
// routes had already verified, or assert about a caller it had not itself checked.
//
// One key, reached through `auth.WithPrincipal`, and `PrincipalOf` is the read. The
// local key type is gone, which is the point: nothing outside `internal/auth` can
// write a principal at all any more, and that was always the property — the comment
// above `principalKey` said a string key would be forgeable by anything importing
// `context`, and this is the same argument with one fewer key to get wrong.
func withPrincipal(r *http.Request, principal Principal) *http.Request {
	return auth.WithPrincipal(r, &principal)
}

// PrincipalFrom is the verified principal on a request, if there is one.
//
// By value rather than by pointer, because the reader is `proxy.go`'s
// `assertionFor`, which copies a principal into an `AssertionSubject` and must not
// be able to hand the caller a pointer it could write through.
func PrincipalFrom(r *http.Request) (Principal, bool) {
	principal := auth.PrincipalOf(r)
	if principal == nil {
		return Principal{}, false
	}
	return *principal, true
}

// credentialGate answers 401 for a caller it cannot authenticate, and lets every
// other request through.
//
// It returns the MIDDLEWARE rather than a wrapped handler, because it is one
// element of `everyRequest`'s list and the order inside that list is the property
// this file exists to hold. Wrapping here would have meant deciding the position
// of the gate against the limiter at the call site instead of in the one list both
// are named in.
//
// `nil` when no gate is configured, which is **not** the same gate as one that
// refuses everything: `src/index.ts` (removed at cutover) does not register the middleware at all when
// `options.jwt` is absent, so a gateway built with a route table and no verifier
// relays an anonymous request to a private route. Reproducing that faithfully is
// what lets the equivalence check compare two gateways that are both
// unconfigured — and it is why this is a nil rather than an identity middleware
// somebody could set to the wrong answer by accident.
//
// The `nil` is the state every deployment that has not configured a verifier is in,
// and it is a documented one rather than an accident: `Options.Authenticate`'s own
// comment says what an unconfigured gateway forwards.
func credentialGate(authenticate Authenticate, routes RouteTable) func(http.Handler) http.Handler {
	if authenticate == nil {
		return nil
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			path := NormaliseRequestPath(r.URL.EscapedPath())

			// Mounted on `/v1/*` and nowhere else. `/healthz` and `/readyz` answer an
			// orchestrator that has no credential and must not be throttled into a
			// restart, and `/auth/*` is the browser surface, which answers with its own
			// gate. The mount is a prefix test rather than chi's `Use`, because the
			// pass-through and the contract's routes share one handler chain here and
			// `/v1/*` is the shape `RouteMount` already names.
			if !underRouteMount(path) {
				next.ServeHTTP(w, r)
				return
			}

			if _, already := PrincipalFrom(r); already {
				next.ServeHTTP(w, r)
				return
			}

			// MD18's exception, asked of the same resolver the pass-through asks.
			// `IsPublicRoute` reads `ResolveRoute`, so the prefix that mounts without a
			// credential is the prefix that forwards, and a change to the matching rule
			// cannot leave this gate and that mount disagree about which paths are open.
			if IsPublicRoute(routes, path) {
				next.ServeHTTP(w, r)
				return
			}

			principal, err := authenticate(r)
			if err != nil || principal == nil {
				writeProblem(w, r, Problem{
					Status: 401,
					Code:   api.ProblemCodeUnauthorized,
					// `src/middleware/jwt.ts` (removed at cutover)'s own words, and the reason this is a
					// fixed string rather than an interpolated error: the message can
					// carry a dependency host, a query or a token.
					Detail: "a bearer token is required",
				})
				return
			}

			next.ServeHTTP(w, withPrincipal(r, *principal))
		})
	}
}

// underRouteMount is what `RouteMount`'s `/v1/*` matches.
//
// ## `/v1` ON ITS OWN IS UNDER THE MOUNT, AND THAT WAS MEASURED
//
// The first draft of this function was `strings.HasPrefix(path, "/v1/")`, on the
// reading that a wildcard needs at least one character behind it. Measured against
// Bun 1.3.12 and Hono, it does not:
//
//	app.use("/v1/*", mw)   // mw runs for: /v1/me, /v1, /v1/, /v1/a/b
//	                      // mw does not run for: /healthz
//
// So `/v1` alone is gated. The consequence is worth stating because it is
// surprising in the other direction: a table carrying the `/v1` prefix forwards an
// anonymous request to `/v1` only if the gate is not registered, and the gate's
// mount and the pass-through's table therefore agree about which paths are open —
// which is the property `credentialGate` is built on. Recorded in the README's
// routing section so an operator reading it is not surprised.
func underRouteMount(path string) bool {
	return path == "/v1" || strings.HasPrefix(path, "/v1/")
}
