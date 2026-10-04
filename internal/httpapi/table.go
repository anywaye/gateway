package httpapi

import (
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Which path prefix goes to which service, in configuration rather than in code.
//
// Ported from `src/routes/table.ts`. A gateway that authenticates a caller and
// then has nowhere to send them is a gateway that terminates auth for its own
// sake. This file is the half of forwarding that can be decided without any of
// forwarding: the table of prefixes and upstreams, validated at construction,
// plus the one question a request asks of it — "who owns this path?".
//
// ## Why a static table and not a registry
//
// The set of services in a deployment is small, known, and changes with a deploy
// rather than at runtime, so a table read from configuration is the honest shape
// *now* rather than a simplification. Filling it from a registry is writing a
// different `RuntimeOptions` and changing nothing here — which is why there is no
// interface indirection waiting for a consumer that does not exist yet.
//
// ## What is validated, and why each one is a startup error
//
// `REDIS_URL=redis//redis` refusing to boot is the precedent, and every rule
// below is the same argument about a value an operator typed:
//
//   - a prefix outside `/v1/` could never match, because the pass-through is
//     mounted on the API surface — a route that silently forwards nothing;
//   - a glob (`*`, `?`) is a second matching language, and the only question a
//     route asks is "everything under here";
//   - a base URL carrying a path would put the caller's path somewhere nobody is
//     serving it — the same rule the identity URL applies to identity;
//   - `/v1/me` is gateway's own route, registered before the pass-through, so a
//     table claiming it describes a route that can never run;
//   - a token with a line break in it is header injection through configuration
//     rather than through a request, which is not a smaller problem;
//   - a `public` value that is not a boolean, and a `public` entry that also
//     carries a `token`, are both refusals for the same reason: a security field
//     an operator half-configured must not resolve to anything at all;
//   - a claim name that is not a claim name, one of the claims gateway owns
//     (`iss`, `aud`, `exp`…), and a `public` entry that also declares
//     `principal` — the last being the sharpest rule in the file.
//
// ## THE ONE PLACE GO IS NOT THE SAME SHAPE, AND WHY
//
// `RouteTarget` says `Token string`, `Public bool` and `Principal []string`, so
// Go's zero value is "no token, not public, no claims" and there is no way to
// spell the difference between an absent field and a field spelled `false` or
// `""`. TypeScript has three values for each and the distinction is load-bearing
// there: `{"principal": []}` is an operator mistake and `{"token": ""}` is an
// operator mistake, and both are refusals rather than the absence.
//
// The difference is kept where it can be observed and dropped where it cannot.
// `ParseRouteTable` reads the JSON's own types and refuses `[]`, `""` and
// `"true"` — so the operator mistake still stops the boot — and the typed struct
// is the *result* of that, where an absent and an empty field genuinely are the
// same answer. What a reader would lose is the ability to see which spelling an
// operator used, which is not a security property and is recorded in the
// operator-facing refusal messages instead.

// RouteTarget is one upstream, and the credential gateway attaches when it calls.
type RouteTarget struct {
	// The service's base URL: http(s), no path, no query, no fragment and no
	// credentials in the authority.
	//
	// No path is the load-bearing half. The caller's remaining path is appended to
	// it, so a base carrying one would put `/v1/items` under a prefix the operator
	// typed out of habit and nobody serves.
	BaseURL string

	// The credential gateway presents to this service, as a bearer token.
	//
	// Empty means the entry declares none, which is meaningful rather than
	// convenient: a service that authenticates nothing is reached with **no**
	// `Authorization` header at all, which is a different thing from reaching it
	// with one this process invented.
	//
	// It is *never* the caller's own credential. See `proxy.go` for why, and for
	// what would have to be true to change that.
	Token string

	// Whether this prefix is mounted with **no caller credential required**.
	//
	// False is the default because the safe reading of "I did not say" is the one
	// where nothing is opened by omission.
	//
	// It is about the CALLER and `Token` is about the SERVICE, which is the whole
	// distinction this field exists to be careful about — two credentials answering
	// two different questions, so an entry carrying both is refused rather than
	// resolved.
	//
	// One entry, named, in a table a human reads. There is no wildcard and no
	// prefix-independent switch, and `false` is what every existing entry already
	// means — the field is additive and no deployed route changes behaviour.
	Public bool

	// The claims this upstream is declared to need, and therefore the only claims
	// gateway will assert about the caller when it calls.
	//
	// Nil means **no assertion is minted at all** — not "an assertion with no
	// claims", which would be a token whose only content is which gateway minted
	// it. An upstream that has not declared what it needs has not asked, and the
	// alternative hands every service in a deployment a credential it never agreed
	// to hold.
	//
	// The names are claim names on the caller's verified token, read from the token
	// rather than from gateway's typed principal, so `scope` crosses as the string
	// identity signed and `github_id` — which is not a field gateway knows — crosses
	// without gateway being taught its name. A name the token does not carry is
	// omitted, never invented and never refused.
	Principal []string
}

// RouteTable is path prefix -> upstream. The whole of routing's configuration.
type RouteTable map[string]RouteTarget

// ResolvedRoute is one request's answer: the prefix that claimed it and where it
// goes.
//
// `public` and `principal` ride along on the resolved entry rather than being
// looked up again: the caller credential requirement and the destination are two
// properties of the *same winning entry*, and a resolver that returned the
// destination from one match and the openness from another would be two answers to
// "which prefix claimed this".
type ResolvedRoute struct {
	// The prefix that claimed the path, for the log line on a failure.
	Prefix  string
	BaseURL string
	Token   string
	Public  bool
	// Claims to assert about the caller, or nil when the entry declared none.
	Principal []string
}

// RouteMount is the prefix every routed path lives under.
//
// `/v1/` rather than anything else, and not for tidiness. The pass-through is
// mounted on `/v1/*`, which is where the token gate and the limiter already are,
// so a routed request is authenticated and counted without either this file
// knowing anything about either. It also means a configured prefix can never
// reach `/auth/*`, `/healthz` or `/readyz`: the browser surface and the probes
// are outside the API surface by construction rather than by a rule somebody has
// to remember.
const RouteMount = "/v1/*"

// gatewayOwned is the one path under the mount that gateway itself serves.
const gatewayOwned = "/v1/me"

// ValidateRouteTable checks a table and returns a fresh one.
//
// Returns a copy rather than the one it was handed, so a caller cannot reach in
// afterwards and add a prefix that was never checked — and so the caller's own
// `Principal` slices are not the ones the pass-through reads.
//
// Prefixes are checked in sorted order, which is the one place this file's shape
// departs from `Object.entries`. Go's map iteration is randomised per range, so
// iterating the map directly would mean a table with two bad entries names a
// different one on every run — a refusal that is not reproducible is a refusal
// nobody can act on, and a test asserting on it would flake rather than fail.
func ValidateRouteTable(table RouteTable) (RouteTable, error) {
	if len(table) == 0 {
		return nil, fmt.Errorf("%w: a route table must name at least one prefix. An empty one forwards nothing, and an operator who meant to configure routing would never find out from a 404", ErrNotConfigured)
	}

	prefixes := make([]string, 0, len(table))
	for prefix := range table {
		prefixes = append(prefixes, prefix)
	}
	sort.Strings(prefixes)

	checked := make(RouteTable, len(table))
	for _, prefix := range prefixes {
		target := table[prefix]

		if err := checkPrefix(prefix); err != nil {
			return nil, err
		}
		base, err := checkBaseURL(prefix, target.BaseURL)
		if err != nil {
			return nil, err
		}
		if err := checkToken(prefix, target.Token); err != nil {
			return nil, err
		}

		// The contradiction, refused rather than resolved. Both resolutions are
		// wrong in a way an operator cannot see from the running service: honouring
		// `public` hands an anonymous caller an upstream that may be authenticating
		// gateway's calls, and honouring `Token` quietly answers 401 to a route the
		// table says is open. What is certain is that nobody reading this table can
		// say which of the two was meant, so it does not boot and the message names
		// both ways out.
		if target.Public && target.Token != "" {
			return nil, fmt.Errorf("%w: routeTable: %s is declared public AND carries an upstream token, which are two different credentials answering two different questions. \"public\" is about the CALLER: the prefix is mounted with no caller credential required. \"token\" is gateway's own credential to the SERVICE, attached on every call it makes. An entry carrying both is an operator who has not decided which of the two they meant, and choosing here would either hand an anonymous caller a credential-protected upstream or silently require a credential the table says is not required. Drop \"token\" if the route is meant to be caller-anonymous and the service takes nothing from gateway; drop \"public\" if the caller must present a credential", ErrNotConfigured, prefix)
		}

		// THE SHARPEST RULE IN THIS FILE, and the one that makes MD19's first
		// property structural rather than conditional: **a public route gets no
		// assertion, ever.** Declaring the claims a public route needs is an operator
		// who has not noticed that a public route has no caller to assert one about —
		// and it is the exact shape of the bug this field could introduce, because
		// the machinery to mint one would be configured, present and correct.
		// Honouring it would mint a signed token saying who sent a request that
		// nobody was required to send.
		//
		// Refused rather than ignored, and refused at BOOT rather than at the send
		// site: an entry that says this and does not get it is a table that lies
		// about what is on the wire. `proxy.go` also refuses to mint for a public
		// entry, because a security property that depends only on a validation in
		// another file is one refactor from being decorative.
		if target.Public && target.Principal != nil {
			return nil, fmt.Errorf("%w: routeTable: %s is declared public AND declares principal claims, and a public route carries no assertion about a caller. \"public\" means the prefix is mounted with no caller credential required, so there is no verified caller to assert anything about: an assertion here would be a signed statement about a request that nobody was required to make. Drop \"principal\" if the route really is anonymous, or drop \"public\" if the upstream really does need to know who the caller is — a private prefix is what carries the assertion", ErrNotConfigured, prefix)
		}

		var claims []string
		if target.Principal != nil {
			claims = make([]string, len(target.Principal))
			copy(claims, target.Principal)
		}

		checked[prefix] = RouteTarget{BaseURL: base, Token: target.Token, Public: target.Public, Principal: claims}
	}

	return checked, nil
}

// IsPublicRoute answers whether a path is mounted with no caller credential
// required.
//
// Reads `ResolveRoute` rather than scanning for a public entry itself, and that is
// the property worth having: the credential gate asks this question, and the
// pass-through asks `ResolveRoute` the same one a few lines later. Two scans
// would be two spellings of "which prefix claims this path", and a routing rule
// tightened in one of them would leave the other deciding who may reach it.
//
// `public` is on the *entry*, not on the prefix as a name, so this is decided by
// the longest match exactly like the destination is: a public `/v1/catalog` and a
// private `/v1/catalog/imports` are a public read surface and a private write
// surface, and the longer prefix wins for both questions at once.
func IsPublicRoute(table RouteTable, path string) bool {
	route, ok := ResolveRoute(table, path)
	return ok && route.Public
}

// ResolveRoute returns the upstream for one path, or false when nothing claims it.
//
// Longest matching prefix wins, on a path-segment boundary — the same rule the
// rate-limit table applies, and deliberately the same *rule* rather than the same
// code: the two tables answer the same question about the same prefixes, and a
// route that is rate limited under one reading and not under the other is a limit
// nobody can reason about. `/v1/pantry` claims `/v1/pantry` and
// `/v1/pantry/items` and not `/v1/pantryx`, so a new service cannot inherit a
// mount by sharing a name with an old one.
//
// A prefix of exactly `/v1` claims everything under the API surface, including
// gateway's own `/v1/me`. That is allowed, and `/v1/me` is still served by
// gateway — see `New` for why that has to be said out loud in Go rather than
// coming from registration order the way it does in Hono.
func ResolveRoute(table RouteTable, path string) (ResolvedRoute, bool) {
	target := pathname(path)

	var best ResolvedRoute
	bestLength := -1

	for prefix, upstream := range table {
		if len(prefix) <= bestLength || !claims(prefix, target) {
			continue
		}

		best = ResolvedRoute{
			Prefix:  prefix,
			BaseURL: upstream.BaseURL,
			Token:   upstream.Token,
			Public:  upstream.Public,
		}
		if upstream.Principal != nil {
			best.Principal = make([]string, len(upstream.Principal))
			copy(best.Principal, upstream.Principal)
		}
		bestLength = len(prefix)
	}

	return best, bestLength >= 0
}

// pathname is the path, without the query or the fragment.
func pathname(path string) string {
	if cut := strings.IndexAny(path, "?#"); cut >= 0 {
		return path[:cut]
	}
	return path
}

// claims reports whether a prefix owns a path, on a segment boundary.
func claims(prefix, path string) bool {
	if prefix == "/" {
		return path == "/"
	}
	if strings.HasSuffix(prefix, "/") {
		return strings.HasPrefix(path, prefix)
	}
	return path == prefix || strings.HasPrefix(path, prefix+"/")
}

// checkPrefix refuses a prefix that is not a path under the API surface.
//
// The trailing slash is left alone because it is meaningful to the matcher, and
// `/v1` is allowed because it is the whole surface. What is refused is anything
// that could not be reached, could match more than a subtree, or could carry a
// traversal out of the mount before a request is ever made.
func checkPrefix(prefix string) error {
	if prefix == "" {
		return fmt.Errorf("%w: routeTable: route prefixes must be non-empty strings", ErrNotConfigured)
	}
	if !strings.HasPrefix(prefix, "/") {
		return fmt.Errorf("%w: routeTable: route prefixes must be absolute paths, got %q", ErrNotConfigured, prefix)
	}
	if strings.ContainsAny(prefix, "*?") {
		return fmt.Errorf("%w: routeTable: route prefixes must be paths and not patterns, got %q. The whole subtree under a prefix is routed; a glob would be a second matching language to get wrong", ErrNotConfigured, prefix)
	}
	if prefix != "/v1" && !strings.HasPrefix(prefix, "/v1/") {
		return fmt.Errorf("%w: routeTable: route prefixes must live under %s, got %q. The pass-through is mounted there, so a prefix elsewhere could never match — a route that silently forwards nothing", ErrNotConfigured, RouteMount, prefix)
	}
	if prefix == gatewayOwned {
		return fmt.Errorf("%w: routeTable: %s is gateway's own route and is served before the pass-through, so a table claiming it describes a route that can never run", ErrNotConfigured, gatewayOwned)
	}
	for _, segment := range strings.Split(prefix, "/") {
		if segment == "." || segment == ".." {
			return fmt.Errorf("%w: routeTable: route prefixes must not contain a traversal segment, got %q", ErrNotConfigured, prefix)
		}
		// `%2e%2e` is `..`, and a prefix carrying it is a traversal that has not
		// happened yet: the pass-through rebuilds the upstream path from decoded
		// segments, so a configured prefix is checked in the same notation a
		// caller's path arrives in.
		if decoded, ok := decodeSegment(segment); ok && decoded == ".." {
			return fmt.Errorf("%w: routeTable: route prefixes must not contain a traversal segment, got %q", ErrNotConfigured, prefix)
		}
	}

	return nil
}

// checkBaseURL reduces an upstream's base URL to an origin.
//
// No path (the caller's path is appended), no trailing slash (it would join into
// `//v1/items`), and credentials in the authority are refused because a URL that
// carries a password is a URL that ends up in a log line.
func checkBaseURL(prefix, value string) (string, error) {
	if value == "" {
		return "", fmt.Errorf("%w: routeTable: %s baseUrl must be a non-empty string", ErrNotConfigured, prefix)
	}

	parsed, err := url.Parse(value)
	if err != nil {
		return "", fmt.Errorf("%w: routeTable: %s baseUrl must be an absolute URL, got %q", ErrNotConfigured, prefix, value)
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return "", fmt.Errorf("%w: routeTable: %s baseUrl must be http(s), got %q", ErrNotConfigured, prefix, value)
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return "", fmt.Errorf("%w: routeTable: %s baseUrl must be a base URL with no path, got %q. The caller's path is appended to it", ErrNotConfigured, prefix, value)
	}
	if parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		return "", fmt.Errorf("%w: routeTable: %s baseUrl must carry no query or fragment, got %q", ErrNotConfigured, prefix, value)
	}
	if parsed.User != nil {
		return "", fmt.Errorf("%w: routeTable: %s baseUrl must not carry credentials, got %q. A credential belongs in the table's token, not in an authority that gets written to a log", ErrNotConfigured, prefix, redactUserinfo(value))
	}

	return originOf(parsed), nil
}

// parseAbsoluteURL parses an absolute http(s) URL, or reports that it is not one.
//
// Shared by the base URL and the assertion issuer, which are the same rule twice:
// both are operator-typed origins, both end up in a signed claim or a request line,
// and both have to be a startup refusal rather than a 503 later.
func parseAbsoluteURL(value string) (*url.URL, error) {
	parsed, err := url.Parse(value)
	if err != nil {
		return nil, fmt.Errorf("%q is not a URL: %w", value, err)
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return nil, fmt.Errorf("%q is not http(s)", value)
	}
	if parsed.Host == "" {
		return nil, fmt.Errorf("%q has no host", value)
	}
	return parsed, nil
}

// originOf is `scheme://host[:port]` with the default port dropped and the host
// lowercased, which is what `URL.origin` is.
//
// The default port is the half that matters and it is not cosmetic: it is the
// `aud` claim on every principal assertion (see `assertion.go`), so a table
// naming `http://pantry:80` and one naming `http://pantry` would mint two
// assertions whose audiences are two different strings for the same service, and
// an upstream that verified `aud` would refuse one of them for no reason a reader
// could find.
func originOf(parsed *url.URL) string {
	host := strings.ToLower(parsed.Hostname())
	if port := parsed.Port(); port != "" && !isDefaultPort(parsed.Scheme, port) {
		host += ":" + port
	}

	return parsed.Scheme + "://" + host
}

func isDefaultPort(scheme, port string) bool {
	return (scheme == "http" && port == "80") || (scheme == "https" && port == "443")
}

// checkToken refuses a bearer token, or accepts one.
//
// Whitespace and control characters are refused rather than escaped. This value
// is written into a request header verbatim, so a newline here is header
// injection configured on purpose — the same class of defect as a caller's CRLF,
// arriving from the one place an operator trusts.
func checkToken(prefix, value string) error {
	if value == "" {
		return nil
	}
	if hasHeaderUnsafe(value) {
		return fmt.Errorf("%w: routeTable: %s token must not contain whitespace or control characters. It is written into an Authorization header verbatim", ErrNotConfigured, prefix)
	}
	return nil
}

// hasHeaderUnsafe is the one definition of "a byte that must never reach a header
// value", shared by the token and by a claim name. Go's `http.Header.Set` would
// let a newline through into a value, and `net/http` would then refuse the
// request with an error the caller never sees — so this is a startup refusal
// rather than a runtime surprise.
func hasHeaderUnsafe(value string) bool {
	for _, r := range value {
		if r <= 0x1f || r == 0x7f || unicode.IsSpace(r) {
			return true
		}
	}
	return false
}

// redactUserinfo removes the credentials from a URL before it appears in an
// error message.
//
// The refusal has to *name* the URL, and a URL that carries a password in it is
// the case: quoting it back verbatim would put the password in the log line the
// message goes to, which is the whole reason the field is refused.
func redactUserinfo(value string) string {
	if at := strings.LastIndex(value, "@"); at >= 0 {
		if scheme := strings.Index(value, "://"); scheme >= 0 && scheme+3 < at {
			return value[:scheme+3] + "…" + value[at:]
		}
	}
	return value
}

// --------------------------------------------------------------------------
// the path, before anything reads it
// --------------------------------------------------------------------------

// NormaliseRequestPath is the dot-segment removal a URL parser performs, applied
// to the request line's own spelling of the path.
//
// ## WHY THIS IS HERE AT ALL, AND WHY IT IS THE PORT THAT MATTERS
//
// The reference asks the URL parser: `new URL(c.req.url).pathname`. A WHATWG URL
// parser resolves `.` and `..` — and the *percent-encoded spellings* of them — as
// path segments, before `upstreamPath` is ever called. So in the reference,
// `/v1/pantry/./x` reaches the pass-through as `/v1/pantry/x`, and
// `/v1/pantry/x/..` reaches it as `/v1/pantry/`.
//
// Go's `net/url` does **no** path normalisation at all: `Request.URL.Path` is the
// decoded path and `RawPath` is what the client sent, with no dot-segment
// resolution in either. So without this function the two gateways disagree about
// every request carrying a dot segment, and the disagreement is not a difference
// in the pass-through's own rules — it is a difference about **which route claims
// the path**. `/v1/pantry/../secret` is an unrouted 404 in the reference and a
// refused rebuild in a Go port that does not normalise; `/v1/pantry/./x` is a
// relayed 200 in the reference and a 404 in a Go port that does not normalise.
//
// The packet rules that the TypeScript answer is the correct one, so the parser's
// behaviour is ported rather than argued with. `TestTheNormalisedPathIsTheURL
// ParsersOwn` is not a claim about this function's intent — it is a claim that it
// agrees with the reference on a corpus of paths the equivalence check drives
// end to end.
//
// ## WHAT THIS DOES *NOT* DO, AND WHERE THE DEFENCE ACTUALLY IS
//
// It removes `.` and `..`. It does not decode anything, and in particular it does
// not decode `%2f`. So `/v1/pantry/a%2f..%2f..%2fsecret` survives this function
// whole — and `UpstreamPath` is what refuses it, because a segment that decodes
// to something containing a separator is not a segment.
//
// ## A CORRECTION TO THE REFERENCE'S OWN COMMENT
//
// `src/routes/proxy.ts:24` says: *"`%2e%2e` survives WHATWG URL normalisation, so
// this is the check that matters."* Measured against Bun 1.3.12, it does not:
//
//	new URL("http://h/v1/pantry/%2e%2e/secret").pathname  ===  "/v1/secret"
//
// So the sentence is wrong about the mechanism. The **defence** it describes is
// real and this port keeps it — a traversal is not expressible in what reaches an
// upstream — but it is `UpstreamPath`'s refusal of a decoded separator, plus the
// parser's dot-segment removal, and not a `%2e%2e` that arrives intact. A future
// reader who believes the comment will not look for the encoded-separator case,
// which is the one that is actually reachable. Reported in
// `REPORT-gateway-go-proxy-01.md`; the reference is not changed here, because it is
// the implementation this port is measured against.
//
// ## THE ALGORITHM, AND WHY IT IS NOT `path.Clean`
//
// `path.Clean` also removes dot segments and answers differently on every one of
// these: it collapses `//`, it drops a trailing slash, and it produces `.` for an
// empty path. The reference's answers were measured — `/a/b/../` is `/a/`,
// `/a//b/..` is `/a//`, `/a/b/..//c` is `/a//c` — and this function reproduces
// them by keeping the segment list rather than by rewriting a string. The empty
// segments survive because an empty segment is not a dot segment, and the trailing
// slash appears because a `..` that pops a segment leaves the separator that
// preceded it.
func NormaliseRequestPath(path string) string {
	// Fast path, and it is the overwhelmingly common one: a path with no dot in the
	// first position of any segment cannot contain a dot segment, and this is the
	// function every request in the deployment goes through.
	if !strings.Contains(path, ".") && !strings.Contains(path, "2e") && !strings.Contains(path, "2E") {
		return path
	}

	segments := strings.Split(strings.TrimPrefix(path, "/"), "/")

	out := make([]string, 0, len(segments))
	// Whether a segment that was consumed — `.` or `..` — leaves a separator
	// behind. `/a/b/..` is `/a/` rather than `/a`, and that trailing `/` is the
	// difference between a path a service routes and a path it refuses.
	separatorPending := false

	for i, segment := range segments {
		switch {
		case isDoubleDotSegment(segment):
			// Never past the root: `/..` is `/`, and popping it would produce the
			// empty string, which is not a path.
			if len(out) > 0 {
				out = out[:len(out)-1]
			}
			separatorPending = true

		case isSingleDotSegment(segment):
			separatorPending = true

		default:
			out = append(out, segment)
			_ = i
			separatorPending = false
		}
	}

	joined := strings.Join(out, "/")
	if separatorPending && joined != "" {
		joined += "/"
	}

	return "/" + joined
}

// isDoubleDotSegment is the segment a URL parser treats as `..`: the literal, and
// every spelling of it that percent-encodes one or both dots.
//
// The `%2e` forms are case-insensitive and the mixtures matter — `.%2e` and
// `%2e.` are both `..` — because a filter that only knew `..` would be bypassed by
// a two-character change to a request line, which is the cheapest possible attack
// against a check written by someone who did not measure the parser.
func isDoubleDotSegment(segment string) bool {
	switch strings.ToLower(segment) {
	case "..", ".%2e", "%2e.", "%2e%2e":
		return true
	}
	return false
}

// isSingleDotSegment is the segment a URL parser treats as `.`.
func isSingleDotSegment(segment string) bool {
	return segment == "." || strings.EqualFold(segment, "%2e")
}

// --------------------------------------------------------------------------
// the path, rebuilt rather than forwarded
// --------------------------------------------------------------------------

// UpstreamPath rebuilds the service's path from the caller's segments.
//
// Structural rather than filtered, which is the property: each segment is
// decoded, refused if it is `.`, `..`, an empty segment or one that contains a
// separator, and re-encoded. A traversal, an absolute URL in a segment and a
// doubled slash are not rejected by a list here — after this function they are
// not expressible. `%2e%2e` is the case that matters, because a percent-encoded
// dot segment survives URL parsing and reaches gateway as three ordinary
// characters.
//
// False means "not a path this gateway serves", which the caller is told by the
// same 404 an unrouted path gets.
//
// ## WHY `path.Clean` IS NOT THIS FUNCTION, AND THE DIFFERENCE IS THE DEFENCE
//
// `path.Clean("/a/../../b")` answers `/b`. That is a *normaliser*: it takes a
// path that was already expressible and rewrites it into the shortest spelling of
// the same place. The traversal was already in the string, already parsed, and
// the answer is a path that exists elsewhere on the upstream. A filter that
// compares the cleaned result against the original catches the escape and does
// nothing about `/a//b`, about `%2f` inside a segment, or about a base URL the
// operator wrote with a path in it.
//
// Reconstructing is a different shape: there is no input from which a traversal
// can be spelled, because every segment is decoded and then *re-encoded* with
// only its unreserved characters, so a separator inside a segment is refused
// rather than concatenated, and a `.`/`..` segment is refused rather than
// resolved. `path.Clean` is called nowhere in this file and must not be.
//
// ## THE PATH IS THE RAW ONE, NOT `URL.Path`
//
// Go's `net/url` decodes `Request.URL.Path` and keeps the original in `RawPath`,
// and this function needs the original: `%2e%2e` is three ordinary characters in
// `Path` after decoding and a traversal before it, and decoding first would be
// the traversal arriving already resolved. Callers pass `EscapedPath()`, which
// returns the request line's own spelling.
func UpstreamPath(prefix, path string) (string, bool) {
	if !strings.HasPrefix(path, prefix) {
		return "", false
	}

	rest := path[len(prefix):]
	if rest == "" {
		return "/", true
	}
	if rest[0] != '/' {
		return "", false
	}

	// A trailing slash is not a segment. `/v1/pantry/items/` and
	// `/v1/pantry/items` are the same question and every service this platform has
	// answers them the same way; an *interior* empty segment is a doubled slash,
	// which is not a path and is refused below rather than quietly collapsed.
	segments := strings.Split(rest[1:], "/")
	if segments[len(segments)-1] == "" {
		segments = segments[:len(segments)-1]
	}

	out := make([]string, 0, len(segments))
	for _, raw := range segments {
		segment, ok := decodeSegment(raw)
		if !ok || segment == "" || segment == "." || segment == ".." || strings.ContainsAny(segment, `/\`) {
			return "", false
		}

		out = append(out, encodeURIComponent(segment))
	}

	if len(out) == 0 {
		return "/", true
	}
	return "/" + strings.Join(out, "/"), true
}

// decodeSegment percent-decodes one segment, or reports that it is not valid.
//
// ## THE UTF-8 CHECK IS THE PART GO DOES NOT GIVE YOU
//
// `url.PathUnescape` returns a string and an error, and the error is only about
// the *syntax* of the escape: `%ff` is a perfectly well-formed escape of a byte
// that is not a character, and `PathUnescape` hands it back as an invalid string
// with `err == nil`. `decodeURIComponent` throws on it, and the reference's
// answer for a path carrying one is therefore a 404 from the refusal below rather
// than a relay of a path whose last segment is not text. Without the
// `utf8.ValidString` check the two implementations disagree on `%ff` — and on
// every overlong encoding and every surrogate half, which is the same class.
func decodeSegment(segment string) (string, bool) {
	decoded, err := url.PathUnescape(segment)
	if err != nil {
		return "", false
	}
	if !utf8.ValidString(decoded) {
		return "", false
	}
	return decoded, true
}

// encodeURIComponent percent-encodes a string the way `encodeURIComponent` does.
//
// ## NOT `url.PathEscape`, AND NOT `url.QueryEscape`
//
// Neither matches. `url.PathEscape` leaves `$&+,:;=@` alone — a `?` and a `=` in
// a path segment would survive into the upstream's query string — and
// `url.QueryEscape` writes a space as `+`, which is a form encoding and means
// nothing in a path. The set kept here is ECMA-262's: `A-Za-z0-9-_.!~*'()`, and
// everything else is `%XX` over the UTF-8 bytes, upper-case hex.
//
// Getting this wrong is a path-integrity bug rather than a cosmetic one: a
// segment carrying `?` or `#` that reached the upstream unescaped would truncate
// the path there and move the rest of it into the query string.
func encodeURIComponent(value string) string {
	const hex = "0123456789ABCDEF"

	var b strings.Builder
	b.Grow(len(value))
	for i := 0; i < len(value); i++ {
		c := value[i]
		if isURIComponentUnreserved(c) {
			b.WriteByte(c)
			continue
		}

		b.WriteByte('%')
		b.WriteByte(hex[c>>4])
		b.WriteByte(hex[c&0x0f])
	}

	return b.String()
}

// isURIComponentUnreserved is ECMA-262's unreserved set, over bytes.
//
// The seven characters beyond `A-Za-z0-9-_.` are the ones `encodeURIComponent`
// has always left alone and that a segment legitimately carries: `!~*'()`. Note
// that it leaves `*` alone, which is safe here only because the segments are
// re-encoded into a path *after* `checkPrefix` has refused globs in the prefix —
// a `*` in a caller's segment is a literal segment character here, never a
// wildcard.
func isURIComponentUnreserved(c byte) bool {
	switch {
	case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		return true
	case c == '-' || c == '_' || c == '.' || c == '!' || c == '~' || c == '*' || c == '\'' || c == '(' || c == ')':
		return true
	}
	return false
}

// --------------------------------------------------------------------------
// the JSON a deployment writes
// --------------------------------------------------------------------------

// rawTarget is one entry as the JSON carries it, with the two security fields
// left raw.
//
// `json.RawMessage` rather than `bool` and `[]string` because the refusals this
// port has to keep are refusals about **the JSON's own types**: `{"public":
// "true"}` is exactly what an operator writes when they mean it to be public and
// have not checked that JSON has no booleans-as-strings, and a Go field of type
// `bool` would either refuse it with a type error that names no field, or — if
// someone reached for `,string` — coerce it, which is the one outcome on this
// field that a silent default must never produce.
type rawTarget struct {
	BaseURL   string          `json:"baseUrl"`
	Token     *string         `json:"token"`
	Public    json.RawMessage `json:"public"`
	Principal json.RawMessage `json:"principal"`
}

// ParseRouteTable reads the table an operator wrote and validates it.
//
// The refusals live here rather than only in `ValidateRouteTable` because two of
// them are about a spelling that only the JSON has: `"public": "true"`,
// `"principal": "sub"`, `"principal": []` and `"token": ""` are all mistakes a
// typed `RouteTarget` cannot express and an operator can make on a Tuesday
// afternoon. Every one of them stops the boot.
//
// A value that is not JSON, or JSON of the wrong shape, is a refusal to boot —
// the same rule as every other variable `RuntimeOptions` reads, and for the same
// reason: a typo'd route table is a gateway that answers 404 for a service that
// exists.
func ParseRouteTable(document string) (RouteTable, error) {
	trimmed := trimSpace(document)
	if trimmed == "" {
		return nil, nil
	}

	var entries map[string]json.RawMessage
	if err := json.Unmarshal([]byte(trimmed), &entries); err != nil {
		return nil, fmt.Errorf("%w: gateway: ROUTE_TABLE must be a JSON object mapping a path prefix to {\"baseUrl\": …, \"token\"?: …, \"public\"?: true|false, \"principal\"?: [\"…\"]}, and it is not one. It names %q", ErrNotConfigured, document)
	}

	table := make(RouteTable, len(entries))
	for prefix, raw := range entries {
		target, err := rawTargetOf(prefix, raw)
		if err != nil {
			return nil, err
		}
		table[prefix] = target
	}

	return ValidateRouteTable(table)
}

// rawTargetOf turns one entry's JSON into a typed one, refusing the spellings
// that mean something other than what they say.
func rawTargetOf(prefix string, raw json.RawMessage) (RouteTarget, error) {
	var decoded rawTarget
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return RouteTarget{}, fmt.Errorf("%w: routeTable: %s must be an object with a baseUrl, got %q", ErrNotConfigured, prefix, string(raw))
	}

	target := RouteTarget{BaseURL: decoded.BaseURL}

	if decoded.Token != nil {
		if *decoded.Token == "" {
			return RouteTarget{}, fmt.Errorf("%w: routeTable: %s token must be a non-empty string. An empty token is not a service that takes no credential — omit the field for that, so the difference between the two spellings survives", ErrNotConfigured, prefix)
		}
		target.Token = *decoded.Token
	}

	if len(decoded.Public) > 0 {
		public, err := checkPublicField(prefix, decoded.Public)
		if err != nil {
			return RouteTarget{}, err
		}
		target.Public = public
	}

	if len(decoded.Principal) > 0 {
		claims, err := checkPrincipalField(prefix, decoded.Principal)
		if err != nil {
			return RouteTarget{}, err
		}
		target.Principal = claims
	}

	return target, nil
}

// checkPublicField accepts `true` and `false` and refuses everything else.
//
// The case that earns the rule is the string: `ROUTE_TABLE` is JSON, and
// `{"public":"true"}` is exactly what an operator writes. Coerced, that is a
// route serving anyone, which is the one outcome on this field that a silent
// default must never produce — so it refuses to boot and the message says what to
// type instead.
func checkPublicField(prefix string, raw json.RawMessage) (bool, error) {
	var public bool
	if err := json.Unmarshal(raw, &public); err != nil {
		return false, fmt.Errorf("%w: routeTable: %s public must be true or false, got %s. It is a boolean in JSON and not a string: {\"public\":\"true\"} is a route that does not mean what it says, and the string a reader would take for permission is the one value that must never be coerced into it. Write true or false without quotes, or omit the field — an entry with no public field requires a caller credential", ErrNotConfigured, prefix, string(raw))
	}
	return public, nil
}

// checkPrincipalField accepts a non-empty list of claim names, and refuses four
// things, each of which is a value an operator can type in JSON and believe has
// been honoured:
//
//   - **Not an array.** `{"principal": "sub"}` is a string where a list was
//     wanted. Coerced it would be one claim named `s`,`u`,`b`.
//   - **An empty array.** Which is *not* the same as omitting the field, and the
//     difference is the whole contract: omitted means "no assertion", and an empty
//     list can only mean "an assertion carrying no claims" — a token whose entire
//     content is which gateway minted it.
//   - **A name gateway owns.** `iss`, `aud`, `exp`, `nbf`, `iat`, `jti` are the
//     envelope, and honouring one would produce a token whose audience or lifetime
//     the operator chose rather than gateway.
//   - **A name with whitespace, a control character or a wildcard.** `"*"` in
//     particular is the shape that would quietly turn "minimal claims" into "the
//     whole JWT", which is the one outcome the field exists to prevent.
//
// A repeat is deduplicated rather than refused: two spellings of the same name is
// an operator's editor and not an undecided question, and refusing it would train
// a reader to ignore a rule that matters.
func checkPrincipalField(prefix string, raw json.RawMessage) ([]string, error) {
	var names []string
	if err := json.Unmarshal(raw, &names); err != nil {
		return nil, fmt.Errorf("%w: routeTable: %s principal must be an array of claim names, got %s. It is a list in JSON, not a string: {\"principal\":\"sub\"} is a configuration that does not mean what it says. Write [\"sub\"], or omit the field to declare that this upstream needs no assertion at all", ErrNotConfigured, prefix, string(raw))
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("%w: routeTable: %s principal is an empty array, which is not the same as leaving the field out. An empty list can only mean an assertion carrying no claims — a signed statement about the caller that says nothing, at the cost of a signature on every request. Omit \"principal\" if this upstream needs no assertion; write the claim names if it does", ErrNotConfigured, prefix)
	}

	seen := make(map[string]struct{}, len(names))
	out := make([]string, 0, len(names))
	for _, name := range names {
		if err := checkClaimName(prefix, name); err != nil {
			return nil, err
		}
		if _, dup := seen[name]; dup {
			continue
		}

		seen[name] = struct{}{}
		out = append(out, name)
	}

	return out, nil
}

// checkClaimName refuses one claim name, or accepts it.
func checkClaimName(prefix, name string) error {
	if name == "" {
		return fmt.Errorf("%w: routeTable: %s principal must hold claim names as non-empty strings, got \"\"", ErrNotConfigured, prefix)
	}
	if name == "*" {
		return fmt.Errorf("%w: routeTable: %s principal may not name \"*\". The list is what this upstream is declared to need, and a wildcard is the one entry that would turn \"minimal claims\" into the caller's whole JWT — which is exactly what the field exists to prevent. Name the claims", ErrNotConfigured, prefix)
	}
	if hasHeaderUnsafe(name) {
		return fmt.Errorf("%w: routeTable: %s principal claim names may not contain whitespace or control characters, got %q. A claim name is one token from a signed payload, so a name with a space in it is a name no upstream can look up", ErrNotConfigured, prefix, name)
	}
	if isReservedClaim(name) {
		return fmt.Errorf("%w: routeTable: %s principal may not name %q, which is gateway's own and not the caller's. The issuer, the audience that binds the assertion to this upstream, the lifetime and the correlation id are set by gateway from the route it is calling; an entry that chose them would be minting an assertion that verifies for a route it was never minted for. Declare the caller's own claims instead — \"sub\", \"account_id\", \"github_id\" — and gateway will bind and date it", ErrNotConfigured, prefix, name)
	}
	return nil
}
