package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/cafaye/gateway/internal/api"
)

// stderr is where this service's operational log lines go.
//
// A package variable rather than a call to `os.Stderr` in each of the six places
// that logs, so a test can read what gateway said about a failed upstream without
// a relay redirecting the process's own descriptor. It is swapped and restored
// inside a test and never by production code, which is the same seam `bff/auth.go`
// keeps in the reference.
//
// The content is deliberately not a response body: a dependency's URL, a status
// and the *shape* of an answer go here, and the answer itself never does — a
// service's error page is exactly where a credential turns up, and this repository
// never writes one down.
var stderr io.Writer = os.Stderr

// The pass-through: a path prefix, an upstream, and gateway's own credential.
//
// Ported from `src/routes/proxy.ts` (removed at cutover). This is the half of routing that touches the
// network, and it is deliberately thin. `net/http`'s own client is the tool — a
// proxy library would be a dependency with no cause, in a repository whose rule is
// that a dependency has to earn itself — and there is no retry, no circuit breaker
// and no health check, because each of those is a packet that says what it costs
// and this one is not.
//
// ## THE FOUR THINGS A FORWARDER HAS TO GET RIGHT
//
//   1. ONE CONFIGURED DESTINATION, NEVER A CALLER-SUPPLIED HOST. The upstream
//      comes out of the validated table and the remainder of the path is appended
//      to it. There is no code path that could build a request out of a header, a
//      query, a body or a segment.
//   2. THE UPSTREAM PATH IS REBUILT, NEVER FORWARDED AS RECEIVED. Every segment
//      is decoded, checked and re-encoded (`UpstreamPath`), so a traversal is not
//      filtered — it is not expressible. `%2e%2e` survives URL normalisation, so
//      this is the check that matters.
//   3. AN UPSTREAM FAILURE IS GATEWAY'S TO TRANSLATE. A 5xx, a 3xx or a dead
//      socket becomes a fixed 503 and nothing else. `connect: connection refused`
//      against an internal address is the topology of a fleet and it must not reach
//      whoever asked.
//   4. THE CREDENTIAL IS GATEWAY'S. See below.
//
// ## THE CREDENTIAL RULE, WHICH IS THE SECURITY CONTENT HERE
//
// gateway attaches the credential for the upstream it is calling. The caller's
// inbound `Authorization` is **never** copied to an internal service, and neither
// is their `Cookie`.
//
// The reason is what forwarding it would turn gateway into. If a caller can set
// an arbitrary `Authorization` and have it reach pantry, then gateway is a
// confused deputy: the caller authenticates *to gateway* and then chooses who they
// are *downstream*. Every property "gateway is the only door" rests on — that the
// credential a service sees is one gateway issued or verified — is gone, and an
// attacker does not need a token for the service at all, only a valid one for the
// edge and a target of their choosing.
//
// So the outbound header set is an allowlist of two (`content-type`, `accept`)
// plus whatever the table's entry carries. A header this file does not name cannot
// be a smuggling channel, which is a property a deny list never has: a deny list
// has to have thought of `Authorization`, `Cookie`, `X-Forwarded-For` and every
// header a future proxy invents.
//
// What that costs, stated plainly because it is what the assertion exists to buy:
// the per-upstream `Token` is a service credential, not a delegation, and on its
// own an upstream cannot tell which caller sent a request. `AssertionHeader` is the
// half of the answer that is additive rather than a change to the rule above.
//
// Two things it deliberately is NOT, both because MD19 ruled them:
//
//   - **Never on a public entry.** That is what makes a route public, and it is
//     enforced twice — refused at boot in `ValidateRouteTable`, and refused again
//     at the send site below. The duplication is the point: a security property
//     that depends only on a validation in another file is one refactor from gone.
//   - **Never a wildcard.** An upstream that declared nothing gets no assertion at
//     all. An entry that names claims gets exactly those, so a service in a
//     deployment can never be handed a credential it did not ask for.

// ForwardedRequestHeaders are the caller headers that cross to a service.
//
// Two, and the list is the control: `accept` so a service that answers
// `application/problem+json` is asked for it, and `content-type` so a body stays
// the shape it was sent as. Everything else the caller sent is dropped —
// `authorization` and `cookie` by the rule above, and `host`, `x-forwarded-for`
// and the rest because a caller-chosen header that reaches an internal service is
// an input to something nobody has read yet.
//
// Exported because the equivalence check reads it rather than restating it, and
// because a check that hardcodes its own copy of the allowlist stops being a check
// the day somebody widens it.
var ForwardedRequestHeaders = []string{"content-type", "accept"}

// ForwardedResponseHeaders are the upstream headers that cross back. One, for the
// same reason.
var ForwardedResponseHeaders = []string{"content-type"}

// DefaultUpstreamTimeout is where a routed request goes when nothing says
// otherwise: five seconds.
const DefaultUpstreamTimeout = 5 * time.Second

// relayedUntyped is the content type a relayed answer carries when the service
// sent none. See `relayUpstream`.
const relayedUntyped = "application/octet-stream"

// upstreamClient is the one `http.Client` every relayed request goes out on.
//
// `CheckRedirect` is the load-bearing line and it is the reason this is a named
// value rather than `http.DefaultClient`:
//
//	err := http.ErrUseLastResponse
//
// returns the 3xx as the answer instead of following it. The default follows, and
// a `Location` an internal service answers with is an address that is not on the
// internet — so a followed redirect is a way out of the route table, and the
// `isRelayable` predicate below would then be deciding about a *different*
// upstream's answer.
//
// Nothing sets a client-wide `Timeout`: the bound is per request and comes from
// the request's own context, so one slow service cannot shorten another's window
// and a `Timeout` here would be a second, invisible bound.
var upstreamClient = &http.Client{
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// routeProxy relays one request to one upstream, or refuses.
type routeProxy struct {
	table     RouteTable
	timeout   time.Duration
	assertion *AssertionMinter
}

// proxyOptions is what the pass-through is built from. An argument rather than
// three package-level values, for `guard/AGENTS.md`'s reason: a test can build two
// differently-configured gateways in one process, which is exactly what
// `internal/equivalence` did.
type proxyOptions struct {
	Routes    RouteTable
	Timeout   time.Duration
	Assertion *AssertionMinter
}

func newRouteProxy(options proxyOptions) *routeProxy {
	timeout := options.Timeout
	if timeout == 0 {
		timeout = DefaultUpstreamTimeout
	}

	return &routeProxy{table: options.Routes, timeout: timeout, assertion: options.Assertion}
}

// handle wraps `next`, the rest of the gateway.
//
// A path nothing claims calls `next()` rather than refusing, which is what lets
// gateway's own `/v1/me` and every unrouted path keep behaving exactly as they did
// before routing existed. A path that cannot be rebuilt into a service path also
// calls `next()`, and lands on the same 404 an unrouted path does: it is not a
// route this gateway serves, which is a truer sentence than one invented here.
//
// ## `/v1/me` IS EXCLUDED BY NAME HERE, AND IN HONO IT IS EXCLUDED BY ORDER
//
// The reference registers `app.get("/v1/me")` *before* `app.use(ROUTE_MOUNT, …)`,
// and Hono answers in registration order, so gateway's own route is served and the
// mount never runs. chi has no such order: middlewares wrap whatever the trie
// matched, and the trie prefers the more specific `/v1/me`. So the pass-through
// would see it — and a table carrying the `/v1` prefix, which is allowed and
// claims everything under the mount, would relay gateway's own route to a service.
//
// So the exclusion is written down rather than inherited. It is an exact match and
// not a prefix: `/v1/me/` is a different path, and in the reference it *is*
// relayed by a `/v1` entry, which is the correct answer — it is not gateway's own
// route. `TestGatewayOwnsItsOwnRouteEvenUnderTheBroadestPrefix` is what holds the
// two readings together.
func (p *routeProxy) handle(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The raw spelling, never `URL.Path`: `%2e%2e` is a traversal before it is
		// decoded and three ordinary characters after, and decoding first would be
		// the traversal arriving already resolved.
		path := NormaliseRequestPath(r.URL.EscapedPath())
		if isGatewayOwned(path) {
			next.ServeHTTP(w, r)
			return
		}

		route, ok := ResolveRoute(p.table, path)
		if !ok {
			next.ServeHTTP(w, r)
			return
		}

		upstream, ok := UpstreamPath(route.Prefix, path)
		if !ok {
			next.ServeHTTP(w, r)
			return
		}

		target := route.BaseURL + upstream + searchOf(r.URL)
		response := p.call(r, route, target)

		// A 2xx or a 4xx is the service's own contract and crosses unchanged: a 401
		// that became a 200 would report a refusal as a success, and a 422 that
		// became a 400 would drop the field errors a form turns into sentences.
		// Everything else — 3xx and 5xx — is a `Location` or an error page from
		// behind the edge, and it is translated.
		if response == nil {
			writeProblem(w, r, unreachableUpstream())
			return
		}
		if IsRelayableStatus(response.status) {
			relayUpstream(w, response)
			return
		}

		writeProblem(w, r, unusableUpstream(target, response))
	})
}

// call makes one request to a service, or returns nil when there was no answer to
// have.
//
// The context carries the deadline, which bounds the handler even if the transport
// ignores it — the difference between a request that fails and a process that
// stops answering. No retry: a retry multiplies load on a service that is already
// failing, and the limiter counts one attempt, so a retry would make the
// accounting describe traffic gateway never refused.
//
// The assertion is built **before** the request rather than after, so a signing
// failure is reported as gateway's own 503 and never as a request the service saw
// and answered. It is the only fallible step between deciding to call and calling,
// and putting it last would mean an upstream had done the work of a request
// gateway then failed to describe.
func (p *routeProxy) call(r *http.Request, route ResolvedRoute, target string) *upstreamAnswer {
	headers, err := p.outboundHeaders(r, route)
	if err != nil {
		// The only way here is a signing failure, which is this process's problem
		// and not the caller's: the credential is configured and cannot be used.
		// The same 503 a dead socket gets, because from the caller's side they are
		// the same sentence — gateway cannot answer right now — and the detail goes
		// to the log so the operator can tell them apart at 3am.
		fmt.Fprintf(stderr, "gateway: could not mint the principal assertion for %s: %v\n", route.Prefix, err)
		return nil
	}

	ctx, cancel := context.WithTimeout(r.Context(), p.timeout)
	defer cancel()

	outgoing, err := http.NewRequestWithContext(ctx, r.Method, target, bodyOf(r))
	if err != nil {
		fmt.Fprintf(stderr, "gateway: upstream %s could not be reached: %v\n", target, err)
		return nil
	}
	// A fresh header set rather than a copy of the request's, and the reason the
	// allowlist above is a *construction* rather than a subtraction: there is no
	// starting set to leak from, so "forward everything except N" is not a shape
	// this code can be written in.
	outgoing.Header = headers

	// `Host` is deliberately left unset, which is what makes `net/http` send the
	// target's own host. The caller's `Host` header would otherwise be the one
	// reaching the upstream, and it is caller-chosen.
	response, err := upstreamClient.Do(outgoing)
	if err != nil {
		// The URL, the socket error and the stack go to the log. They are the
		// platform's to know and an authenticated caller is not to be told.
		fmt.Fprintf(stderr, "gateway: upstream %s could not be reached: %v\n", target, err)
		return nil
	}

	return &upstreamAnswer{status: response.StatusCode, header: response.Header, body: response.Body}
}

// outboundHeaders are the headers gateway sends, built from an allowlist and its
// own credentials.
//
// The service credential is `Bearer` with the table's token and never the
// caller's: when a table entry has no token, no `Authorization` header is sent at
// all, which is a different thing from sending one this process invented.
//
// The assertion is a **third** header rather than a second value in the first, and
// `assertionFor` is where the decision to add it is made.
func (p *routeProxy) outboundHeaders(r *http.Request, route ResolvedRoute) (http.Header, error) {
	headers := make(http.Header, len(ForwardedRequestHeaders)+2)

	for _, name := range ForwardedRequestHeaders {
		if value, present := headerValue(r.Header, name); present {
			headers.Set(name, value)
		}
	}
	if route.Token != "" {
		headers.Set("Authorization", "Bearer "+route.Token)
	}

	asserted, err := p.assertionFor(r, route)
	if err != nil {
		return nil, err
	}
	if asserted != "" {
		headers.Set(AssertionHeader, asserted)
	}

	return headers, nil
}

// assertionFor returns the assertion for this request, or the empty string.
//
// ## THE FOUR CONDITIONS, AND WHICH OF THEM IS LOAD-BEARING
//
//  1. a minter is configured — absent means no assertion on any route, which is
//     what every deployment that has not configured a key is in;
//  2. **the entry is not `public`** — MD19's first property, and the only
//     condition here that is a security rule rather than a convenience;
//  3. the entry **declared** claims — an upstream that has not said what it needs
//     gets nothing, which is the "no wildcard" half of the rule and the reason an
//     undeclared route cannot be handed a credential it did not ask for;
//  4. there is a **verified principal** — which is absent when no credential gate
//     is configured, and in that case the pass-through has been serving anyone all
//     along. There is nothing to assert and nothing to assert *about*, so the
//     header is simply not set. That is not a new hole and not a closed one: a
//     gateway with routes and no verifier forwards with no credential, and this
//     packet does not change that.
//
// ## WHY CONDITION 2 IS CHECKED HERE AND NOT ONLY IN `ValidateRouteTable`
//
// `ValidateRouteTable` already refuses `public` together with `principal`, so
// condition 2 is unreachable through `New`. It is written out anyway, and that is
// not redundancy for its own sake: the two live in different files, only one of
// them is a validation a reader will think to look at when changing the other, and
// a security property that rests entirely on a rule three files away is one
// refactor from being decorative.
//
// `TestAPublicEntryIsRefusedAnAssertionEvenByATableThatBootWouldHaveRefused` is
// what holds it, and it builds the proxy directly rather than through `New` — the
// only way to reach a table the validator would refuse, and the only way this line
// is not a green by omission.
func (p *routeProxy) assertionFor(r *http.Request, route ResolvedRoute) (string, error) {
	if p.assertion == nil {
		return "", nil
	}
	if route.Public {
		return "", nil
	}
	if route.Principal == nil {
		return "", nil
	}

	principal, ok := PrincipalFrom(r)
	if !ok {
		return "", nil
	}

	return p.assertion.Mint(principal, AssertionSubject{Audience: route.BaseURL, Claims: route.Principal})
}

// upstreamAnswer is what the service said, and the body still unread.
type upstreamAnswer struct {
	status int
	header http.Header
	body   io.ReadCloser
}

// bodyOf is the caller's body, streamed, or nothing for a method that cannot carry
// one.
//
// Streamed rather than buffered because a proxy that reads a body in order to hand
// it straight on is holding a caller's megabytes in memory for no reason.
//
// The inbound `Content-Length` is deliberately NOT copied, and the equivalence
// check is why: the reference hands the caller's body to `fetch` as a **stream**,
// and Bun then relays it with no `Content-Length` and a chunked framing. Copying
// it would give the upstream a different request shape than the caller sent *and*
// different from the reference's — and a service that reads exactly
// `Content-Length` bytes would see two different framings depending on which
// implementation forwarded to it. `http.NewRequestWithContext` is therefore left
// to infer the framing from the reader, which is chunked, which is what the
// reference does.
func bodyOf(r *http.Request) io.Reader {
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		return nil
	}
	if r.Body == nil {
		return nil
	}
	return r.Body
}

// IsRelayableStatus reports whether a status crosses, or is translated.
//
// A 2xx or a 4xx is the service's own contract and reaches the caller as it is: a
// 401 that became a 200 reports a refusal as a success, and a 422 that became a
// 400 drops the field errors a form turns into sentences. A 3xx and a 5xx are a
// `Location` and an error page from behind the edge, and neither belongs to the
// caller.
//
// Stated as its own predicate because it was a range check once, and a range check
// that reads "300 to 499" is a 200 translated into a 503 — which the first run of
// `src/routes/proxy.test.ts` (removed at cutover) did, in the one sentence this comment is about.
//
// Exported so the tests can hold the boundary from both sides: a table over every
// status class, and the same table again through a real upstream.
func IsRelayableStatus(status int) bool {
	return status < 300 || (status >= 400 && status < 500)
}

// relayUpstream writes the service's answer, with only the header that says what
// it is.
//
// `set-cookie` is dropped and that is not tidiness: a service answering
// `Set-Cookie: __Host-bff-session=…` would be writing the browser's BFF session from
// behind the edge, which is session fixation arriving through the gateway on an
// origin where the `__Host-` prefix is honoured. `cache-control: no-store` is the
// one header added rather than forwarded — proxied traffic is authenticated, and a
// response held in a shared cache between here and the caller is an account's data
// at rest.
//
// The relay is an allowlist in the response direction too, for the same reason the
// request one is: a header this function does not name cannot be a cookie the
// gateway did not decide to drop, which is what makes "it drops `set-cookie`" a
// property rather than a line somebody maintains.
func relayUpstream(w http.ResponseWriter, response *upstreamAnswer) {
	defer response.body.Close()

	for _, name := range ForwardedResponseHeaders {
		if value, present := headerValue(response.header, name); present {
			w.Header().Set(name, value)
		}
	}
	if _, present := headerValue(response.header, "Content-Type"); !present {
		w.Header().Set("Content-Type", relayedUntyped)
	}
	// An upstream that answered without a content type gets `application/octet-stream`,
	// and that is measured rather than chosen. The reference builds
	// `new Response(upstream.body, {status, headers})` with no content type in
	// `headers`, and Bun answers the caller `application/octet-stream`; the first
	// run of the equivalence check said `octet-stream` on one side and nothing on
	// the other, and the TypeScript answer is the correct one.
	//
	// Go's writer would otherwise *sniff* — `net/http` reads the first 512 bytes of
	// a body whose type is unset and labels it `text/plain; charset=utf-8` — so this
	// is a third possible answer and the only one neither side chose.
	w.Header().Set("Cache-Control", "no-store")

	w.WriteHeader(response.status)
	if _, err := io.Copy(w, response.body); err != nil {
		fmt.Fprintf(stderr, "gateway: relaying a %d from an upstream did not write: %v\n", response.status, err)
	}
}

// Two 503s, deliberately not one, and the same split the BFF draws.
//
// A service that cannot be reached is logged by `call`, which is where the socket
// error is; a service that answered something unusable is logged here, with the
// target, the status and the *shape* of the body — never the body itself, because a
// service's error page is exactly where a credential turns up and this repository
// never writes one down. An operator reading a log at 3am has to be able to tell
// "the service is down" from "the service is broken", and that difference only
// exists if it is written down.
func unreachableUpstream() Problem {
	return Problem{Status: 503, Code: api.ProblemCodeUnavailable, Detail: "the service this request needs could not be reached"}
}

// unusableUpstream reads what the answer looked like, for a log line and nothing
// else, and reports the same sentence as an unreachable service.
//
// The body is read here rather than streamed because it is about to be thrown
// away: an error page nobody may relay and nobody may log is a body this process
// holds only to decide whether it was JSON. It is bounded by the same deadline as
// the request, so an upstream streaming a 5xx forever ends at the timeout rather
// than filling memory.
func unusableUpstream(target string, response *upstreamAnswer) Problem {
	shape := shapeOf(response)
	_ = response.body.Close()

	fmt.Fprintf(stderr, "gateway: upstream %s answered %d (%s), which this contract does not relay\n", target, response.status, shape)

	return Problem{Status: 503, Code: api.ProblemCodeUnavailable, Detail: "the service this request needs did not answer"}
}

// shapeOf is what an answer looked like, for a log line and nothing else.
//
// `null` is separated from a document on purpose: `json.Unmarshal` into `any`
// leaves a literal `null` as a nil interface, so the obvious test reports an HTML
// error page as a JSON document.
func shapeOf(response *upstreamAnswer) string {
	body, err := io.ReadAll(response.body)
	if err != nil {
		return "not JSON"
	}

	var document any
	if err := json.Unmarshal(body, &document); err != nil {
		return "not JSON"
	}
	switch document.(type) {
	case nil:
		return "not JSON"
	case map[string]any, []any:
		return "a JSON document"
	}

	return "a JSON scalar"
}

// headerValue reads one header and says whether it was there at all.
//
// `Header.Get` collapses "absent" and "present and empty" into the same string, and
// the difference is load-bearing on the request side: a caller who sent
// `Content-Type:` with no value sent a header, and forwarding it as absent is a
// different answer from forwarding it as empty. The reference's `c.req.header()`
// has the same three-way result and this reproduces it.
func headerValue(headers http.Header, name string) (string, bool) {
	values, present := headers[http.CanonicalHeaderKey(name)]
	if !present || len(values) == 0 {
		return "", false
	}
	return values[0], true
}

// searchOf is the caller's query string, verbatim.
//
// `RawQuery`, not a re-encoding: the caller chose this spelling and an upstream
// that parses a query does not care which of two equivalent spellings produced it,
// whereas a re-encoded one could differ in a way that changes a parameter's name.
// A bare `?` with nothing after it is preserved, because the reference's `url.search`
// is `"?"` there and dropping it is a different request.
func searchOf(target *url.URL) string {
	if target.RawQuery == "" && !target.ForceQuery {
		return ""
	}
	return "?" + target.RawQuery
}
