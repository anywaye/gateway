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

	"github.com/anywaye/gateway/internal/api"
)

var stderr io.Writer = os.Stderr


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

const relayedUntyped = "application/octet-stream"

var upstreamClient = &http.Client{
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

type routeProxy struct {
	table     RouteTable
	timeout   time.Duration
	assertion *AssertionMinter

	identity string
}

type proxyOptions struct {
	Routes    RouteTable
	Timeout   time.Duration
	Assertion *AssertionMinter

	IdentityBaseURL string
}

func newRouteProxy(options proxyOptions) *routeProxy {
	timeout := options.Timeout
	if timeout == 0 {
		timeout = DefaultUpstreamTimeout
	}

	return &routeProxy{table: options.Routes, timeout: timeout, assertion: options.Assertion, identity: options.IdentityBaseURL}
}

func (p *routeProxy) handle(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := NormaliseRequestPath(r.URL.EscapedPath())
		if isGatewayOwned(path) {
			next.ServeHTTP(w, r)
			return
		}

		route, ok := ResolveRoute(p.table, path)
		var upstream string
		if ok {
			var uok bool
			upstream, uok = UpstreamPath(route.Prefix, path)
			if !uok {
				next.ServeHTTP(w, r)
				return
			}
		} else {
			var fok bool
			route, upstream, fok = p.identityRoute(r, path)
			if !fok {
				next.ServeHTTP(w, r)
				return
			}
		}

		target := route.BaseURL + upstream + searchOf(r.URL)
		response := p.call(r, route, target)

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

func (p *routeProxy) identityRoute(r *http.Request, path string) (ResolvedRoute, string, bool) {
	if p.identity == "" {
		return ResolvedRoute{}, "", false
	}
	if !underRouteMount(path) {
		return ResolvedRoute{}, "", false
	}
	if !isIdentityPublicRoute(r.Method, path) {
		return ResolvedRoute{}, "", false
	}

	upstream, ok := UpstreamPath("", path)
	if !ok {
		return ResolvedRoute{}, "", false
	}
	return ResolvedRoute{Prefix: path, BaseURL: p.identity, Public: true}, upstream, true
}

func (p *routeProxy) call(r *http.Request, route ResolvedRoute, target string) *upstreamAnswer {
	headers, err := p.outboundHeaders(r, route)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "gateway: could not mint the principal assertion for %s: %v\n", route.Prefix, err)
		return nil
	}

	ctx, cancel := context.WithTimeout(r.Context(), p.timeout)
	defer cancel()

	outgoing, err := http.NewRequestWithContext(ctx, r.Method, target, bodyOf(r))
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "gateway: upstream %s could not be reached: %v\n", target, err)
		return nil
	}
	outgoing.Header = headers

	// `Host` is deliberately left unset, which is what makes `net/http` send the
	// target's own host. The caller's `Host` header would otherwise be the one
	// reaching the upstream, and it is caller-chosen.
	response, err := upstreamClient.Do(outgoing) //nolint:bodyclose // the body is carried in upstreamAnswer and closed by relayUpstream.
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "gateway: upstream %s could not be reached: %v\n", target, err)
		return nil
	}

	return &upstreamAnswer{status: response.StatusCode, header: response.Header, body: response.Body}
}

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

type upstreamAnswer struct {
	status int
	header http.Header
	body   io.ReadCloser
}

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

func relayUpstream(w http.ResponseWriter, response *upstreamAnswer) {
	defer func() { _ = response.body.Close() }()

	for _, name := range ForwardedResponseHeaders {
		if value, present := headerValue(response.header, name); present {
			w.Header().Set(name, value)
		}
	}
	if _, present := headerValue(response.header, "Content-Type"); !present {
		w.Header().Set("Content-Type", relayedUntyped)
	}
	w.Header().Set("Cache-Control", "no-store")

	w.WriteHeader(response.status)
	if _, err := io.Copy(w, response.body); err != nil {
		_, _ = fmt.Fprintf(stderr, "gateway: relaying a %d from an upstream did not write: %v\n", response.status, err)
	}
}

func unreachableUpstream() Problem {
	return Problem{Status: 503, Code: api.ProblemCodeUnavailable, Detail: "the service this request needs could not be reached"}
}

func unusableUpstream(target string, response *upstreamAnswer) Problem {
	shape := shapeOf(response)
	_ = response.body.Close()

	_, _ = fmt.Fprintf(stderr, "gateway: upstream %s answered %d (%s), which this contract does not relay\n", target, response.status, shape)

	return Problem{Status: 503, Code: api.ProblemCodeUnavailable, Detail: "the service this request needs did not answer"}
}

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

func headerValue(headers http.Header, name string) (string, bool) {
	values, present := headers[http.CanonicalHeaderKey(name)]
	if !present || len(values) == 0 {
		return "", false
	}
	return values[0], true
}

func searchOf(target *url.URL) string {
	if target.RawQuery == "" && !target.ForceQuery {
		return ""
	}
	return "?" + target.RawQuery
}
