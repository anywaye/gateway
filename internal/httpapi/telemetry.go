package httpapi

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"go.opentelemetry.io/otel/trace"

	"github.com/anywaye/gateway/internal/telemetry"
)

// The span every inbound request produces, and the arguments for what goes in it.
//
// # ONE NAME, AND THE ROUTE IS NOT IN IT
//
// A span name is the grouping key in every trace UI, so anything in the name is
// something an operator cannot filter out of the grouping. Naming this after the
// concrete route gives one series per endpoint and a fleet-wide request count that
// cannot be read without a client-side aggregation every reader would have to write
// separately — and it is worse than that here, because a route that ends in an
// identifier is a series per value, which is the cardinality failure core's span
// grammar exists to make unspellable: each segment is at most fifteen characters,
// and no ULID is fifteen characters.
//
// So the name is the OPERATION (`gateway.request`, one series for every request the
// service answers) and the route template is an ATTRIBUTE (`http.route`), where it
// is bounded, filterable, and allowlisted. The name is built at init from a
// constant, so the generated `SpanName`'s error path is unreachable here — a
// constant outside core's grammar is a programming error, and
// `TestTheRequestSpanNameIsInTheFleetsGrammar` is what proves it rather than a
// check on every request.
var requestSpanName = mustRequestSpanName()

func mustRequestSpanName() string {
	return telemetry.MustSpanName("request")
}

// telemetryMiddleware opens the server span for a request and records how it ended.
//
// # WHY NOT `otelhttp.NewHandler`
//
// It is the obvious choice and it does the propagation and the span for you. It
// also records `url.path`, `url.full`, `url.query`, `user_agent.original`,
// `server.address` and the request headers as span attributes.
//
// Every one of those is dropped by kit's collector, so shipping them would not be a
// leak today. It would mean this service EXPORTS a span carrying a caller's
// concrete path and query string and relies on the collector to take them back out,
// and the fleet's rule is the opposite: the collector's allowlist is a backstop and
// the service is the design. One control that needs a misconfiguration elsewhere to
// fail is not two controls.
//
// So this records three attributes, all bounded, all on core's trace allowlist, and
// all through `telemetry.Record` — the one path to a span, and the one that asks the
// GENERATED contract whether each value may be recorded:
//
//	http.request.method         the method
//	http.route                  the matched route TEMPLATE
//	http.response.status_code   the status
//
// plus `error.type` and a failed status on a 5xx, which `recordRequestFailure`
// owns.
//
// # IT IS MOUNTED OUTERMOST, IN BOTH PLACEMENTS, AND THAT IS THE POINT
//
// `everyRequest` builds one chain and `New` mounts it in two places — chi's `Use`
// when there is no pass-through, and `compose` around the pass-through when there
// is. First in that list is therefore first in both, so a forwarded request is
// spanned too: the upstream call gateway makes on somebody's behalf is the most
// expensive thing this process does, and a service that traces its own routes and
// not its own forwarding has traced the cheap half.
func telemetryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, span := telemetry.StartServer(r.Context(), r.Header, requestSpanName)

		// Recorded HERE, outside the router, because a 404 and a 405 never reach a
		// route handler — so a method recorded only where the route is would be
		// missing from exactly the requests where knowing what was asked for matters
		// most. Eight methods, so it is free to carry.
		telemetry.Record(span, map[string]any{"http.request.method": r.Method})

		// Wrapped BEFORE anything can write, so the status is observed whichever
		// layer commits the response.
		tracked := &statusWriter{ResponseWriter: w, status: http.StatusOK}

		// The status is recorded EXACTLY ONCE, from this wrapper, on the way out.
		// The OpenTelemetry SDK's `SetAttributes` REPLACES a key rather than
		// appending, so a second record of the same attribute anywhere in the chain
		// would not add a duplicate — it would silently overwrite this one, and
		// whichever writer ran last would be the one a reader believes.
		defer func() {
			telemetry.Record(span, map[string]any{
				"http.response.status_code": tracked.status,
				"http.route":                routeTemplate(r),
			})
			recordRequestFailure(span, tracked.status)
			span.End()
		}()

		next.ServeHTTP(tracked, r.WithContext(ctx))
	})
}

// routeTemplate is the matched route, read on the way OUT.
//
// chi fills `RoutePattern` in as the request walks its routing tree, and it puts
// that tree into the request's context BEFORE it runs the middleware chain — so a
// middleware sees the pattern only after the handler has returned. Reading it before
// `next` returns "" for every request, which is what an earlier version of this did.
//
// The measured answer for a matched route is a chi URL pattern with its wildcards
// as `{name}` — `/v1/me`, `/healthz` — which is a TEMPLATE and not a caller's path.
// An unmatched request has none, and that gap is deliberate: putting the unmatched
// path in `http.route` would put caller-controlled text into a span attribute, and
// core's generated `Check` would refuse it as well as deserve it.
func routeTemplate(r *http.Request) string {
	routeContext := chi.RouteContext(r.Context())
	if routeContext == nil {
		return ""
	}
	return routeContext.RoutePattern()
}

// statusWriter remembers the status the response was committed with.
//
// `http.ResponseWriter` is committed exactly once and the only way to learn the
// status from outside is to watch for it. The default is 200 rather than 0 because a
// handler that returns without writing produces a 200 — net/http sends one — and a
// span saying status 0 for a successful request is a span no status filter reads
// correctly. `Unwrap` matters: it is how `http.ResponseController` reaches the
// underlying writer, so Flush and Hijack still work through this wrapper.
type statusWriter struct {
	http.ResponseWriter
	status  int
	written bool
}

func (w *statusWriter) WriteHeader(status int) {
	if !w.written {
		w.status = status
		w.written = true
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	w.written = true
	return w.ResponseWriter.Write(b)
}

func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// recordRequestFailure records the bounded error class for a failed request, and
// nothing at all for a successful one.
//
// # THE BICONDITIONAL, AND WHY BOTH HALVES HAPPEN HERE
//
// core's traces schema constrains it in both directions: a span whose status is
// `error` must carry an `error.type`, and a span that carries one must have failed.
// The ABSENCE of a class is therefore the load-bearing "this was not an error"
// marker — on a duration histogram the samples carrying the class are the errors and
// every other sample is a success, which is how an error rate is computable without
// a message in a label. So a success records no class at all: not `_OTHER`, and not
// a class a filter has to special-case.
//
// # WHY 4xx IS NOT HERE, AND IT IS THE MORE INTERESTING HALF
//
// A 401 on `/auth/session` is a wrong password and a 404 on a proxied route is
// somebody guessing an id. Both are a caller doing something the API answers by
// refusing, and both are the service working. A span marked ERROR for every rejected
// login is an error rate that is a function of how much credential stuffing the
// gateway is absorbing, and an alert on it pages somebody towards disabling the
// protection that is doing its job. The fleet's error view is about the service
// failing, not about the service refusing. A 5xx is the service failing.
//
// `internal_error` rather than a class derived from the status: the class is a
// grouping key shared with the other services, and a class invented per status code
// is a class nobody else emits — which is how one place to see all errors becomes
// six places. The status is already on the span, so the pair says everything it can,
// and `_OTHER` is not warranted either, because an unhandled 5xx IS this class.
func recordRequestFailure(span trace.Span, status int) {
	if status < 500 {
		return
	}
	// A fixed description, and the reason it is fixed is the same reason the status
	// is not in it: this string is exported to a backend that anyone with access to
	// the telemetry can read, and a handler's error text is the one thing on a
	// request that can carry a token, a path or a query.
	_ = telemetry.RecordFailure(span, "internal_error", "the handler returned a server error")
}
