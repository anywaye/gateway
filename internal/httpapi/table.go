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


// RouteTarget is one upstream, and the credential gateway attaches when it calls.
type RouteTarget struct {
	BaseURL string

	Token string

	Public bool

	Principal []string

	Scopes []string
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
	Prefix  string
	BaseURL string
	Token   string
	Public  bool
	Principal []string
	Scopes []string
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

const gatewayOwned = "/v1/me"

func isGatewayOwned(path string) bool {
	if path == gatewayOwned {
		return true
	}
	return path == "/v1/api-keys" || strings.HasPrefix(path, "/v1/api-keys/")
}

// ValidateRouteTable checks a table and returns a fresh one.
//
// Returns a copy rather than the one it was handed, so a caller cannot reach in
// afterwards and add a prefix that was never checked — and so the caller's own
// `Principal` slices are not the ones the pass-through reads.
//
// Prefixes are checked in sorted order, which is the one place this file's shape
// departs from `Object.entries`. Go's map iteration is randomized per range, so
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

		if target.Public && target.Token != "" {
			return nil, fmt.Errorf("%w: routeTable: %s is declared public AND carries an upstream token, which are two different credentials answering two different questions. \"public\" is about the CALLER: the prefix is mounted with no caller credential required. \"token\" is gateway's own credential to the SERVICE, attached on every call it makes. An entry carrying both is an operator who has not decided which of the two they meant, and choosing here would either hand an anonymous caller a credential-protected upstream or silently require a credential the table says is not required. Drop \"token\" if the route is meant to be caller-anonymous and the service takes nothing from gateway; drop \"public\" if the caller must present a credential", ErrNotConfigured, prefix)
		}

		if target.Public && target.Principal != nil {
			return nil, fmt.Errorf("%w: routeTable: %s is declared public AND declares principal claims, and a public route carries no assertion about a caller. \"public\" means the prefix is mounted with no caller credential required, so there is no verified caller to assert anything about: an assertion here would be a signed statement about a request that nobody was required to make. Drop \"principal\" if the route really is anonymous, or drop \"public\" if the upstream really does need to know who the caller is — a private prefix is what carries the assertion", ErrNotConfigured, prefix)
		}

		if target.Public && target.Scopes != nil {
			return nil, fmt.Errorf("%w: routeTable: %s is declared public AND declares scopes, and a public route has no verified caller to check a scope against. \"public\" means the prefix is mounted with no caller credential required, so a scope here would be a check that never runs — or worse, a route that silently forwards everyone. Drop \"scopes\" if the route really is anonymous, or drop \"public\" if the upstream really does need a capable caller", ErrNotConfigured, prefix)
		}

		var claims []string
		if target.Principal != nil {
			claims = make([]string, len(target.Principal))
			copy(claims, target.Principal)
		}

		var scopes []string
		if target.Scopes != nil {
			scopes = make([]string, len(target.Scopes))
			copy(scopes, target.Scopes)
		}

		checked[prefix] = RouteTarget{BaseURL: base, Token: target.Token, Public: target.Public, Principal: claims, Scopes: scopes}
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
		if upstream.Scopes != nil {
			best.Scopes = make([]string, len(upstream.Scopes))
			copy(best.Scopes, upstream.Scopes)
		}
		bestLength = len(prefix)
	}

	return best, bestLength >= 0
}

func pathname(path string) string {
	if cut := strings.IndexAny(path, "?#"); cut >= 0 {
		return path[:cut]
	}
	return path
}

func claims(prefix, path string) bool {
	if prefix == "/" {
		return path == "/"
	}
	if strings.HasSuffix(prefix, "/") {
		return strings.HasPrefix(path, prefix)
	}
	return path == prefix || strings.HasPrefix(path, prefix+"/")
}

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
		if decoded, ok := decodeSegment(segment); ok && decoded == ".." {
			return fmt.Errorf("%w: routeTable: route prefixes must not contain a traversal segment, got %q", ErrNotConfigured, prefix)
		}
	}

	return nil
}

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

func checkToken(prefix, value string) error {
	if value == "" {
		return nil
	}
	if hasHeaderUnsafe(value) {
		return fmt.Errorf("%w: routeTable: %s token must not contain whitespace or control characters. It is written into an Authorization header verbatim", ErrNotConfigured, prefix)
	}
	return nil
}

func hasHeaderUnsafe(value string) bool {
	for _, r := range value {
		if r <= 0x1f || r == 0x7f || unicode.IsSpace(r) {
			return true
		}
	}
	return false
}

func redactUserinfo(value string) string {
	if at := strings.LastIndex(value, "@"); at >= 0 {
		if scheme := strings.Index(value, "://"); scheme >= 0 && scheme+3 < at {
			return value[:scheme+3] + "…" + value[at:]
		}
	}
	return value
}


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
// behavior is ported rather than argued with. `TestTheNormalisedPathIsTheURL
// ParsersOwn` is not a claim about this function's intent — it is a claim that it
// agrees with the reference on a corpus of paths the equivalence check drives
// end to end.
//
// ## WHAT THIS DOES *NOT* DO, AND WHERE THE DEFENSE ACTUALLY IS
//
// It removes `.` and `..`. It does not decode anything, and in particular it does
// not decode `%2f`. So `/v1/pantry/a%2f..%2f..%2fsecret` survives this function
// whole — and `UpstreamPath` is what refuses it, because a segment that decodes
// to something containing a separator is not a segment.
//
// ## A CORRECTION TO THE REFERENCE'S OWN COMMENT
//
// `src/routes/proxy.ts:24` (removed at cutover) says: *"`%2e%2e` survives WHATWG URL normalisation, so
// this is the check that matters."* Measured against Bun 1.3.12, it does not:
//
//	new URL("http://h/v1/pantry/%2e%2e/secret").pathname  ===  "/v1/secret"
//
// So the sentence is wrong about the mechanism. The **defense** it describes is
// real and this port keeps it — a traversal is not expressible in what reaches an
// upstream — but it is `UpstreamPath`'s refusal of a decoded separator, plus the
// parser's dot-segment removal, and not a `%2e%2e` that arrives intact. A future
// reader who believes the comment will not look for the encoded-separator case,
// which is the one that is actually reachable. Reported in
// `REPORT-gateway-go-proxy-01`; the reference is not changed here, because it is
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
	if !strings.Contains(path, ".") && !strings.Contains(path, "2e") && !strings.Contains(path, "2E") {
		return path
	}

	segments := strings.Split(strings.TrimPrefix(path, "/"), "/")

	out := make([]string, 0, len(segments))
	separatorPending := false

	for i, segment := range segments {
		switch {
		case isDoubleDotSegment(segment):
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

func isDoubleDotSegment(segment string) bool {
	switch strings.ToLower(segment) {
	case "..", ".%2e", "%2e.", "%2e%2e":
		return true
	}
	return false
}

func isSingleDotSegment(segment string) bool {
	return segment == "." || strings.EqualFold(segment, "%2e")
}


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
// ## WHY `path.Clean` IS NOT THIS FUNCTION, AND THE DIFFERENCE IS THE DEFENSE
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

func isURIComponentUnreserved(c byte) bool {
	switch {
	case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		return true
	case c == '-' || c == '_' || c == '.' || c == '!' || c == '~' || c == '*' || c == '\'' || c == '(' || c == ')':
		return true
	}
	return false
}


type rawTarget struct {
	BaseURL   string          `json:"baseUrl"`
	Token     *string         `json:"token"`
	Public    json.RawMessage `json:"public"`
	Principal json.RawMessage `json:"principal"`
	Scopes    json.RawMessage `json:"scopes"`
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

	if len(decoded.Scopes) > 0 {
		scopes, err := checkScopesField(prefix, decoded.Scopes)
		if err != nil {
			return RouteTarget{}, err
		}
		target.Scopes = scopes
	}

	return target, nil
}

func checkPublicField(prefix string, raw json.RawMessage) (bool, error) {
	var public bool
	if err := json.Unmarshal(raw, &public); err != nil {
		return false, fmt.Errorf("%w: routeTable: %s public must be true or false, got %s. It is a boolean in JSON and not a string: {\"public\":\"true\"} is a route that does not mean what it says, and the string a reader would take for permission is the one value that must never be coerced into it. Write true or false without quotes, or omit the field — an entry with no public field requires a caller credential", ErrNotConfigured, prefix, string(raw))
	}
	return public, nil
}

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

func checkScopesField(prefix string, raw json.RawMessage) ([]string, error) {
	var names []string
	if err := json.Unmarshal(raw, &names); err != nil {
		return nil, fmt.Errorf("%w: routeTable: %s scopes must be an array of scope names, got %s. It is a list in JSON, not a string: {\"scopes\":\"pantry:read\"} is a configuration that does not mean what it says. Write [\"pantry:read\"], or omit the field to declare that this route forwards any verified caller", ErrNotConfigured, prefix, string(raw))
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("%w: routeTable: %s scopes is an empty array, which is not the same as leaving the field out. An empty list can only mean a gate that refuses every caller with a message naming nothing. Omit \"scopes\" if this route needs no scope check; write the scope names if it does", ErrNotConfigured, prefix)
	}

	seen := make(map[string]struct{}, len(names))
	out := make([]string, 0, len(names))
	for _, name := range names {
		if name == "" {
			return nil, fmt.Errorf("%w: routeTable: %s scopes must hold scope names as non-empty strings, got \"\"", ErrNotConfigured, prefix)
		}
		if hasHeaderUnsafe(name) {
			return nil, fmt.Errorf("%w: routeTable: %s scope names may not contain whitespace or control characters, got %q. A scope is one token from a space-separated claim, so a name with a space in it is a name no token can match", ErrNotConfigured, prefix, name)
		}
		if _, dup := seen[name]; dup {
			continue
		}

		seen[name] = struct{}{}
		out = append(out, name)
	}

	return out, nil
}
