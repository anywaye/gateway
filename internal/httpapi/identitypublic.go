package httpapi

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
)

// Identity's public /v1 surface, as gateway enforces it.
//
// ## WHY THIS FILE EXISTS RATHER THAN FIFTEEN TABLE ENTRIES
//
// Identity marks 15 operations under /v1/* as `security: []` — the signup,
// login, password-reset, email-verification, session-link, agent-claim and
// OAuth-start operations, all of which a caller without a credential must
// reach. Gateway 401'd every one of them, because the credential gate only
// asked the ROUTE_TABLE, which names pantry alone (measured: POST
// /v1/signup-timestamp is 200 direct to identity and 401 through gateway).
//
// Two shapes were on the table, and the brief asked for the choice to be
// recorded. The table did NOT gain fifteen entries, for a reason the proxy
// makes structural: a table entry STRIPS its prefix before forwarding
// (`UpstreamPath`), so `/v1/users` with identity's base URL would forward to
// identity's `/`, which is a 404 with extra steps. Table prefixes rename a
// foreign namespace into gateway's (`/v1/pantry-writes/projects` becomes
// `/projects`); identity's public surface needs no renaming — gateway and
// identity share the /v1 namespace, so the caller's path IS the upstream
// path. The one prefix that would preserve it, `/v1`, claims the private
// routes too, and a gate that opened those to fix signup would be the defect
// pointed the other way.
//
// So the gate consults identity's declaration rather than the table for /v1
// paths the table does not own: `credentialGate` lets an identity-public
// operation through with no credential, and the pass-through forwards it to
// identity's base URL with the path intact. The table keeps meaning what it
// means — operator-owned prefixes — and neither shipped ROUTE_TABLE needed
// an edit: both stacks already set IDENTITY_URL, which is the base URL the
// fallback forwards to.
//
// ## WHERE THE LIST COMES FROM, AND WHAT KEEPS IT HONEST
//
// Identity's own openapi/v1.yaml is the authority, and this file is a compiled
// copy of what it declares — never the other way round, and never hand-grown:
// a seventeenth line added here by hand is the defect this packet exists to
// remove. `testdata/identity-public.txt` is the extraction (source commit and
// command in its header), `compareIdentityPublicRoutes` holds the two equal
// in both directions, and the drift fixture proves the comparison names a
// route identity opened that gateway did not. Refresh is re-run the command,
// replace the fixture body, update the list below, and commit all three.
//
// ## WHAT EACH ENTRY IS FOR (identity's own words, compressed)
//
//   - POST /v1/users — the signup itself. A browser arriving at the form holds
//     nothing but its address, so this is public exactly like signup-timestamp.
//   - POST /v1/signup-timestamp — the anti-fake-timestamp anchor the signup
//     form fetches first ("The endpoint is public and unauthenticated, exactly
//     as POST /v1/users is").
//   - POST /v1/session — the login: email and password for a session. There is
//     no credential to present because presenting one IS the operation.
//     DELETE /v1/session (logout) stays gated — same path, other method.
//   - POST /v1/session/mfa — the second step of a login that answered 202 with
//     an MFA challenge: the challenge, not a session, is presented.
//   - POST /v1/password-resets and POST /v1/password-resets/confirm — ask for
//     a reset mail, then spend the token. Both arrive with no session, or the
//     caller would not be resetting anything.
//   - POST /v1/email-verifications and POST /v1/email-verifications/confirm —
//     ask for a verification mail, then spend the token. Same shape as above.
//   - POST /v1/email-changes/current-address and
//     POST /v1/email-changes/new-address — the two confirmations of an address
//     change, each arriving by mail link with no session.
//   - POST /v1/agents and GET /v1/agents/claim/{token} — an agent registers
//     itself, then the claim link is opened (by a human, in a browser) to bind
//     it. The link carries the token, so there is nothing else to present.
//   - POST /v1/session-links/redeem — a magic-link redemption: the link IS the
//     credential. POST /v1/session-links (minting one) stays gated.
//   - GET /v1/auth/oauth/{provider} and GET /v1/auth/oauth/{provider}/callback
//     — the OAuth start (a 302 to the provider) and the provider's return. The
//     state cookie authenticates the round trip, not a bearer token.
//
// ## THE MATCHER IS METHOD-AWARE, AND THE TEMPLATES ARE EXACT
//
// `{name}` matches exactly one non-empty segment, and the segment count must
// agree — so /v1/agents/claim/{token} opens /v1/agents/claim/abc and never
// /v1/agents/claim, /v1/agents itself, or /v1/agents/claim/abc/extra. The
// method is part of every entry for the same reason: POST /v1/session is the
// login and DELETE /v1/session is the logout, and a path-only matcher would
// open the second to fix the first.

// identityPublicRoute is one operation identity declares public: a method and
// a path template in identity's own `/v1` namespace.
type identityPublicRoute struct {
	Method   string
	Template string
}

// identityPublicRoutes is the compiled copy of identity's declaration. Order
// is the fixture's (alphabetical by path) so a diff between the two reads as
// a diff rather than a shuffle.
var identityPublicRoutes = []identityPublicRoute{
	{Method: http.MethodPost, Template: "/v1/agents"},
	{Method: http.MethodGet, Template: "/v1/agents/claim/{token}"},
	{Method: http.MethodGet, Template: "/v1/auth/oauth/{provider}"},
	{Method: http.MethodGet, Template: "/v1/auth/oauth/{provider}/callback"},
	{Method: http.MethodPost, Template: "/v1/email-changes/current-address"},
	{Method: http.MethodPost, Template: "/v1/email-changes/new-address"},
	{Method: http.MethodPost, Template: "/v1/email-verifications"},
	{Method: http.MethodPost, Template: "/v1/email-verifications/confirm"},
	{Method: http.MethodPost, Template: "/v1/password-resets"},
	{Method: http.MethodPost, Template: "/v1/password-resets/confirm"},
	{Method: http.MethodPost, Template: "/v1/session"},
	{Method: http.MethodPost, Template: "/v1/session-links/redeem"},
	{Method: http.MethodPost, Template: "/v1/session/mfa"},
	{Method: http.MethodPost, Template: "/v1/signup-timestamp"},
	{Method: http.MethodPost, Template: "/v1/users"},
}

// isIdentityPublicRoute reports whether a request is one of identity's public
// operations.
//
// It reads the COMPILED list, not the fixture: the gate and the pass-through
// run per request and must not parse a file to answer. `compareIdentity-
// PublicRoutes` is what holds the compiled list to the declaration.
//
// `path` is the request line's spelling (query included): the match runs on
// the pathname, so the OAuth callback's `?code=&state=` neither helps nor
// hinders it. One trailing slash is forgiven — /v1/users/ is the same
// operation as /v1/users, and identity is the one that decides what either
// answers — and nothing else is: no case folding, no dot-segment resolution
// beyond what NormaliseRequestPath already did for the caller.
func isIdentityPublicRoute(method, path string) bool {
	target := pathname(path)
	if len(target) > 1 {
		target = strings.TrimSuffix(target, "/")
	}
	got := strings.Split(strings.TrimPrefix(target, "/"), "/")

	for _, route := range identityPublicRoutes {
		if method != route.Method {
			continue
		}
		want := strings.Split(strings.TrimPrefix(route.Template, "/"), "/")
		if len(got) != len(want) {
			continue
		}
		match := true
		for i := range want {
			if isTemplateSegment(want[i]) {
				if got[i] == "" {
					match = false
					break
				}
				continue
			}
			if got[i] != want[i] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// isTemplateSegment is `{name}`: one non-empty path segment, named for the
// reader rather than looked up anywhere. Identity's spec spells its parameters
// this way, so the compiled list keeps the spelling and this predicate keeps
// the meaning in one place.
func isTemplateSegment(segment string) bool {
	return len(segment) > 2 && strings.HasPrefix(segment, "{") && strings.HasSuffix(segment, "}")
}

// checkIdentityBaseURL reduces the identity fallback's base URL to an origin.
//
// The same rule the table's `checkBaseURL` applies to every entry, and for the
// same reason: the caller's path is appended to this origin, so a base carrying
// a path would put /v1/users somewhere identity does not serve it, and a URL
// carrying credentials would end up in a log line. It is its own function
// rather than a call to `checkBaseURL` because that one's refusals name the
// route table, and this value never came from one — a refusal that names the
// wrong field is a refusal nobody can act on.
func checkIdentityBaseURL(value string) (string, error) {
	parsed, err := parseAbsoluteURL(value)
	if err != nil {
		return "", fmt.Errorf("%w: identity: IdentityBaseURL must be an absolute http(s) URL, got %q", ErrNotConfigured, value)
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return "", fmt.Errorf("%w: identity: IdentityBaseURL must be a base URL with no path, got %q. The caller's path is appended to it", ErrNotConfigured, value)
	}
	if parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		return "", fmt.Errorf("%w: identity: IdentityBaseURL must carry no query or fragment, got %q", ErrNotConfigured, value)
	}
	if parsed.User != nil {
		return "", fmt.Errorf("%w: identity: IdentityBaseURL must not carry credentials, got %q. A credential belongs in a header, not in an authority that gets written to a log", ErrNotConfigured, redactUserinfo(value))
	}

	return originOf(parsed), nil
}

// compareIdentityPublicRoutes holds the compiled list to a declaration: one
// `METHOD /v1/path` string per entry, the fixture's own format.
//
// `missing` is what identity declares that gateway would refuse — the signup
// hole, as a value rather than an incident. `extra` is what gateway would open
// that identity never declared — the defect pointed the other way. Both are
// sorted, so the failure names routes rather than orders. Empty and empty is
// the only passing answer, and the drift fixture is what proves a non-empty
// one is reported rather than absorbed.
func compareIdentityPublicRoutes(declared []string) (missing, extra []string) {
	compiled := make(map[string]struct{}, len(identityPublicRoutes))
	for _, route := range identityPublicRoutes {
		compiled[route.Method+" "+route.Template] = struct{}{}
	}

	seen := make(map[string]struct{}, len(declared))
	for _, entry := range declared {
		seen[entry] = struct{}{}
		if _, ok := compiled[entry]; !ok {
			missing = append(missing, entry)
		}
	}
	for _, route := range identityPublicRoutes {
		entry := route.Method + " " + route.Template
		if _, ok := seen[entry]; !ok {
			extra = append(extra, entry)
		}
	}

	sort.Strings(missing)
	sort.Strings(extra)
	return missing, extra
}
