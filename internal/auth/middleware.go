package auth

import (
	"context"
	"fmt"
	"net/http"
	"strings"
)

type principalContextKey struct{}

func withPrincipal(r *http.Request, principal *Principal) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), principalContextKey{}, principal))
}

// PrincipalOf is the verified caller on a request, or nil.
//
// Nil is a real answer and not a bug: the only handlers that read it sit behind a
// gate that either sets it or answered 401, and `RequireScope` refuses a missing
// principal rather than assuming one.
func PrincipalOf(r *http.Request) *Principal {
	principal, _ := r.Context().Value(principalContextKey{}).(*Principal)
	return principal
}

// WithPrincipal returns a request carrying an already-verified principal.
//
// # WHY THIS IS EXPORTED
//
// `internal/httpapi` mounts its OWN credential gate — `Options.Authenticate`, the
// seam the pass-through asserts about a caller through — and that gate answers the
// same question `Require` answers. Two gates with two context keys would mean the
// second gate re-verifies a token the first already verified, or reads a context
// where the other gate put a principal under a key it cannot see.
//
// One key is the fix and this is how a caller outside the package reaches it. It is
// deliberately the only way: `internal/httpapi` cannot reach `principalContextKey{}`,
// so nothing can forge a principal under it except code that has actually verified
// one. A `context.WithValue` with a string key would be forgeable by anything
// importing `context`, and the assertion minted from it would be a signed
// statement about a caller nobody verified.
func WithPrincipal(r *http.Request, principal *Principal) *http.Request {
	return withPrincipal(r, principal)
}

type apiKeyContextKey struct{}

// WithAPIKeyID records the API key that authenticated a request.
func WithAPIKeyID(r *http.Request, id string) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), apiKeyContextKey{}, id))
}

// APIKeyIDOf is the authenticated key's id, or "".
func APIKeyIDOf(r *http.Request) string {
	id, _ := r.Context().Value(apiKeyContextKey{}).(string)
	return id
}

// Refuser is what writes a refusal. `internal/httpapi` supplies it, so that
// `internal/auth` does not depend on the package that renders the envelope — and
// the dependency runs one way, which is the direction that keeps the verifier
// testable without an HTTP surface.
type Refuser func(w http.ResponseWriter, r *http.Request, refusal *Refusal)

// Require is the bearer-token gate: 401 unless the request carries a token this
// verifier accepts.
//
// RFC 6750 §2.1 for the credential: the scheme is case-insensitive, the token is
// everything after it, and there is exactly one token.
func (v *Verifier) Require(refuse Refuser) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := BearerToken(r.Header.Get("Authorization"))
			if token == "" {
				refuse(w, r, unauthorized("a bearer token is required"))
				return
			}

			principal, refusal := v.Authenticate(r.Context(), token)
			if refusal != nil {
				refuse(w, r, refusal)
				return
			}

			next.ServeHTTP(w, withPrincipal(r, principal))
		})
	}
}

// RequireScope is 403 for a verified caller without this scope. Mount it after
// `Require`.
//
// A route with the scope gate and no auth in front of it is a wiring mistake, not
// an authorization decision: nothing has been proven yet, so the answer is 401
// and not 403. `src/middleware/jwt.ts` (removed at cutover) makes the same distinction and calls it
// out as a wiring mistake by name.
//
// It takes the refusal writer for the same reason `Require` does, and that is why
// it can answer 401 at all: a gate whose wiring mistake is unreachable is a gate
// whose wiring mistake is unfixed.
func (v *Verifier) RequireScope(refuse Refuser, scope string) (func(http.Handler) http.Handler, error) {
	required := strings.TrimSpace(scope)
	if required == "" {
		return nil, fmt.Errorf("%w: scope must be a non-empty string", ErrNotConfigured)
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			principal := PrincipalOf(r)
			if principal != nil && containsString(principal.Scope, required) {
				next.ServeHTTP(w, r)
				return
			}

			if principal == nil {
				refuse(w, r, unauthorized("a bearer token is required"))
				return
			}

			refuse(w, r, forbidden("token is missing the "+required+" scope"))
		})
	}, nil
}

func containsString(haystack []string, needle string) bool {
	for _, item := range haystack {
		if item == needle {
			return true
		}
	}
	return false
}

// bearerToken is RFC 6750 §2.1, and it is the same regular expression
// `bearerToken` in `src/middleware/jwt.ts` (removed at cutover) uses: `/^bearer +(\S+)$/i`.
//
// Case-insensitive scheme, one or more spaces after it, and a token with no
// whitespace in it — so `Authorization: Bearer a b` is not a credential and
// `Bearer` alone is not a credential. `\S+` in Go is `[^\s]+`, which is the same
// character class.
func BearerToken(authorization string) string {
	fields := strings.Fields(strings.TrimSpace(authorization))
	if len(fields) != 2 {
		return ""
	}
	if !strings.EqualFold(fields[0], "bearer") {
		return ""
	}
	return fields[1]
}
