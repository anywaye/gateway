package httpapi

import (
	"net/http"
	"strings"

	"github.com/anywaye/gateway/internal/api"
	"github.com/anywaye/gateway/internal/auth"
)


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

func credentialGate(authenticate Authenticate, routes RouteTable, identity string) func(http.Handler) http.Handler {
	if authenticate == nil {
		return nil
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			path := NormaliseRequestPath(r.URL.EscapedPath())

			if !underRouteMount(path) {
				next.ServeHTTP(w, r)
				return
			}

			if _, already := PrincipalFrom(r); already {
				next.ServeHTTP(w, r)
				return
			}

			route, claimed := ResolveRoute(routes, path)
			if claimed && route.Public {
				next.ServeHTTP(w, r)
				return
			}

			if !claimed && identity != "" && isIdentityPublicRoute(r.Method, path) {
				next.ServeHTTP(w, r)
				return
			}

			principal, err := authenticate(r)
			if err != nil || principal == nil {
				writeProblem(w, r, Problem{
					Status: 401,
					Code:   api.ProblemCodeUnauthorized,
					Detail: "a bearer token is required",
				})
				return
			}

			next.ServeHTTP(w, withPrincipal(r, *principal))
		})
	}
}

func underRouteMount(path string) bool {
	return path == "/v1" || strings.HasPrefix(path, "/v1/")
}
