package auth

import "net/http"

// Test support, and it is in a non-test file for one reason.
//
// `internal/ratelimit`'s tests need a request carrying a verified principal, and the
// only writer of that is `withPrincipal`, which is unexported because the only
// production writer is `Require`. A `_test.go` file would be invisible to another
// package, so the alternative is exporting the production writer — which would put a
// function on the package's API whose whole purpose is to let a CALLER forge a
// verified identity, and that is a much worse thing to have on a security package's
// surface than one function with `ForTest` in its name and a comment saying why.
//
// # WHY IT IS NOT A `_test.go` FILE
//
// Go does not compile a package's `_test.go` files into the package for other
// packages to import, so `internal/ratelimit` cannot see one. The cost of this file
// is that it ships in the source tree rather than only in the test build; nothing
// outside a `_test.go` file calls it, so the linker drops it from `cmd/gateway`, and
// `Dockerfile` copies the whole context either way — recorded in that file's
// header rather than fixed here, because filtering a `COPY` is how a test double
// reaches a shipped image.

// WithPrincipalForTest attaches a verified principal to a request.
//
// It is the production writer with a name that says what it is. There is no way to
// reach it from outside this package's own tests except by calling it by name, and a
// caller that does is writing a test that needs a verified caller without a JWKS
// server.
func WithPrincipalForTest(r *http.Request, principal *Principal) *http.Request {
	return withPrincipal(r, principal)
}
