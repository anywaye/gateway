package auth

import "net/http"


// WithPrincipalForTest attaches a verified principal to a request.
//
// It is the production writer with a name that says what it is. There is no way to
// reach it from outside this package's own tests except by calling it by name, and a
// caller that does is writing a test that needs a verified caller without a JWKS
// server.
func WithPrincipalForTest(r *http.Request, principal *Principal) *http.Request {
	return withPrincipal(r, principal)
}
