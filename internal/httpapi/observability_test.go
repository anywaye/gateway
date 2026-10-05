package httpapi_test

// The narrow proof, and it is narrow on purpose.
//
// Four properties, each one a claim about the SERVING PATH rather than about a
// function called directly:
//
//  1. with telemetry OFF, a request is answered exactly as it was before this packet
//     existed — same status, same body, same content type — and no span is recorded;
//  2. with telemetry ON, one server span per request, named in core's grammar,
//     carrying the method, the route TEMPLATE and the status, with the process
//     identity on the RESOURCE and `error.type` plus a failed status on a 5xx;
//  3. an inbound W3C `traceparent` is CONTINUED — same trace id — and a missing or
//     malformed one starts a new trace without answering 4xx;
//  4. the span name is core's grammar and cannot be a caller's path.
//
// The exporter is in-memory and installed through the seam `Install` takes, so what
// is asserted is a real exported `ReadOnlySpan` rather than a mock's idea of one. A
// test that could only reach the network would either be skipped or would make this
// suite phone an observability backend.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"

	"github.com/cafaye/gateway/internal/httpapi"
	"github.com/cafaye/gateway/internal/telemetry"
)

// recordingExporter collects spans in memory. A test seam, not a second
// implementation of anything.
type recordingExporter struct{ spans *[]sdktrace.ReadOnlySpan }

func (r recordingExporter) ExportSpans(_ context.Context, spans []sdktrace.ReadOnlySpan) error {
	*r.spans = append(*r.spans, spans...)
	return nil
}

func (r recordingExporter) Shutdown(context.Context) error { return nil }

// recorded is the recorder a test reads, plus the install that made it current.
//
// The global provider is not a shortcut. It is the OpenTelemetry specification's own
// design — the propagator and the provider are process-wide singletons — and the
// middleware resolves its tracer through `otel.Tracer`, so a test that installed a
// provider any other way would be asserting against a span the request path never
// touched. The restore is not optional bookkeeping: these tests share one process,
// and a provider left behind by one test is a provider the next test exports into.
type recorded struct {
	spans    *[]sdktrace.ReadOnlySpan
	lookup   func(string) string
	shutdown telemetry.Shutdown
	once     sync.Once
}

// flushSpans makes every span recorded so far visible, and is the reason this
// fixture exists in this shape.
//
// The SDK's Batcher is asynchronous — a span reaches the exporter on a background
// goroutine, in batches, which is the correct production behaviour and the wrong
// thing to assert against. A test that reads the recorder straight after a request
// sees an empty slice and concludes the middleware spans nothing, which is a false
// negative on the one property this file exists to prove. So the test flushes, and
// the flush is the same call the binary makes on SIGTERM.
func (r *recorded) flushSpans() { r.once.Do(func() { _ = r.shutdown(context.Background()) }) }

// installTelemetry turns telemetry on or off for one test, over a recorder.
//
// `disabled` is passed through rather than inferred from the environment, because
// the property under test in the off case is that the no-op answers requests
// identically — and a test that turned telemetry off by exporting a variable would
// be testing the environment's precedence rules as well.
func installTelemetry(t *testing.T, disabled bool, lookup func(string) string) *recorded {
	t.Helper()
	spans := &[]sdktrace.ReadOnlySpan{}
	previous := otel.GetTracerProvider()
	t.Cleanup(func() { otel.SetTracerProvider(previous) })

	shutdown, err := telemetry.Install(context.Background(), telemetry.Options{
		// The endpoint is never dialled: the exporter below is the one that runs, and
		// this string is here so the "configured" and "disabled" cases differ in
		// exactly one field.
		Endpoint: "http://otel-collector:4317",
		Disabled: disabled,
		NewExporter: func(context.Context, string) (telemetry.Exporter, error) {
			return recordingExporter{spans: spans}, nil
		},
		LookupEnv: lookup,
	})
	if err != nil {
		t.Fatalf("installing telemetry (disabled=%t): %v", disabled, err)
	}
	recorder := &recorded{spans: spans, lookup: lookup, shutdown: shutdown}
	t.Cleanup(recorder.flushSpans)
	return recorder
}

// aGateway is the smallest gateway that serves a request: `New(Options{})`, the two
// probes and nothing else, which this package documents as a working gateway rather
// than a stub.
func aGateway(t *testing.T, options httpapi.Options) http.Handler {
	t.Helper()
	handler, err := httpapi.New(options)
	if err != nil {
		t.Fatalf("building a gateway: %v", err)
	}
	return handler
}

// ask sends one request and returns what the caller saw.
func ask(handler http.Handler, method, target string, header http.Header) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, target, nil)
	for name, values := range header {
		request.Header[name] = values
	}
	recorded := httptest.NewRecorder()
	handler.ServeHTTP(recorded, request)
	return recorded
}

// attributesOf is one exported span's attributes as a map, so an assertion reads as
// "carries exactly this" rather than as a walk.
func attributesOf(span sdktrace.ReadOnlySpan) map[string]any {
	carried := map[string]any{}
	for _, kv := range span.Attributes() {
		carried[string(kv.Key)] = kv.Value.AsInterface()
	}
	return carried
}

// resourceString reads one resource attribute.
func resourceString(span sdktrace.ReadOnlySpan, name string) (string, bool) {
	value, found := span.Resource().Set().Value(attribute.Key(name))
	if !found {
		return "", false
	}
	return value.AsString(), true
}

// # 1. THE NO-OP PATH
//
// An app with telemetry off must be the gateway it was before this packet: the
// middleware still runs, `StartServer` still returns a span, and every one of those
// spans is non-recording and goes nowhere. That is core's otel-endpoint schema's
// demand — nothing dials, nothing allocates — and it is asserted on the RESPONSE,
// because a no-op that changed a status code would be a gateway nobody could deploy
// unobserved.

func TestWithTelemetryOffARequestIsAnsweredAsBeforeAndNothingIsRecorded(t *testing.T) {
	off := installTelemetry(t, true, func(string) string { return "" })
	handler := aGateway(t, httpapi.Options{})

	response := ask(handler, http.MethodGet, "/healthz", nil)
	if response.Code != http.StatusOK {
		t.Errorf("/healthz answered %d with telemetry off, want 200", response.Code)
	}
	if got := response.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("/healthz answered Content-Type %q with telemetry off, want application/json. The span middleware must not be able to change a header.", got)
	}
	if body := response.Body.String(); !strings.Contains(body, `"status":"ok"`) {
		t.Errorf("/healthz answered %s with telemetry off, want the same liveness document", body)
	}
	if len(*off.spans) != 0 {
		t.Errorf("telemetry is off and %d span(s) were recorded. The disabled path installs the SDK's noop provider, which records nothing at all — a provider pointed at nowhere would still allocate a span and a batch timer per request.", len(*off.spans))
	}
}

// # 2. THE SPAN, ITS NAME AND ITS ATTRIBUTES

func TestTheRequestOpensOneServerSpanNamedByTheFleetsGrammar(t *testing.T) {
	on := installTelemetry(t, false, func(string) string { return "" })

	response := ask(aGateway(t, httpapi.Options{}), http.MethodGet, "/healthz", nil)
	if response.Code != http.StatusOK {
		t.Fatalf("/healthz answered %d, want 200. The assertions below are about a served request, not about one that failed.", response.Code)
	}

	on.flushSpans()
	if len(*on.spans) != 1 {
		t.Fatalf("one request produced %d spans, want exactly 1. A middleware that opens a span and never ends it, or one mounted in both of New's places, is both of those failures at once.", len(*on.spans))
	}
	span := (*on.spans)[0]

	// THE NAME, asserted rather than trusted. `telemetry.SpanName` refuses anything
	// outside core's grammar, and this reads that from the outside: the name is
	// `gateway.<operation>`, never a route and never a caller's path — a name
	// carrying an identifier is one series per request, which is what core's
	// fifteen-character segments exist to make unspellable.
	if span.Name() != "gateway.request" {
		t.Errorf("span name = %q, want %q. A name is the grouping key in a trace UI, so it must be the operation and never a route or a path.", span.Name(), "gateway.request")
	}
	if !telemetry.SpanNamePattern.MatchString(span.Name()) {
		t.Errorf("span name %q is not in core's span-name grammar (%s)", span.Name(), telemetry.SpanNamePattern)
	}
	if strings.Contains(span.Name(), "/") {
		t.Errorf("span name %q contains a slash; the route is an attribute", span.Name())
	}

	attributes := attributesOf(span)
	for name, want := range map[string]any{
		"http.request.method":       "GET",
		"http.route":                "/healthz",
		"http.response.status_code": int64(200),
	} {
		got, carried := attributes[name]
		if !carried {
			t.Errorf("the span carries no %q. Every value goes through the generated Check, so a missing attribute here is the allowlist refusing a value rather than the middleware forgetting to record one.", name)
			continue
		}
		if got != want {
			t.Errorf("span attribute %s = %#v, want %#v", name, got, want)
		}
	}

	// What the SDK would have added and this must not: `otelhttp` records
	// `http.target`, `url.full`, `url.path`, `user_agent.original` and the headers.
	// kit's collector drops them all, so shipping them would mean this service
	// exports a caller's concrete path and relies on the collector to take it back
	// out — the collector is the backstop, the service is the design.
	for _, forbidden := range []string{"http.target", "url.full", "url.path", "url.query", "user_agent.original", "http.request.headers"} {
		if _, carried := attributes[forbidden]; carried {
			t.Errorf("the span carries %q, which is on nobody's allowlist and carries a caller's concrete path", forbidden)
		}
	}
}

// The RESOURCE half of property 2: the process identity, on the resource and only
// there. The values come from a `LookupEnv` rather than from the process
// environment, which is what makes the assertion about the wiring rather than about
// whoever ran the test.
func TestTheProcessIdentityIsOnTheResourceAndNotOnTheSpan(t *testing.T) {
	on := installTelemetry(t, false, func(key string) string {
		switch key {
		case "OTEL_SERVICE_VERSION":
			return "1.2.3"
		case "DEPLOYMENT_ENVIRONMENT":
			return "test"
		case "GATEWAY_TENANT_ID":
			return "tenant-abc"
		default:
			return ""
		}
	})

	ask(aGateway(t, httpapi.Options{}), http.MethodGet, "/healthz", nil)
	on.flushSpans()
	if len(*on.spans) != 1 {
		t.Fatalf("one request produced %d spans, want 1", len(*on.spans))
	}
	span := (*on.spans)[0]

	for name, want := range map[string]string{
		"service.name":           "gateway",
		"service.namespace":      "cafaye",
		"service.version":        "1.2.3",
		"deployment.environment": "test",
		"tenant_id":              "tenant-abc",
	} {
		got, found := resourceString(span, name)
		if !found {
			t.Errorf("the RESOURCE carries no %q. Resource attributes are attached once per process and are exempt from the 2000-combination metric cap, which is exactly why an identity belongs here.", name)
			continue
		}
		if got != want {
			t.Errorf("resource attribute %s = %q, want %q", name, got, want)
		}
	}

	// The same identity is NOT on the span. core refuses `tenant_id` on a
	// measurement by name, and the generated `Check` is what stops one being added
	// here by a later packet: a tenant on a measurement renders a dashboard whose
	// totals are right and whose per-tenant breakdown silently undercounts.
	if _, carried := attributesOf(span)["tenant_id"]; carried {
		t.Error("the SPAN carries tenant_id; it belongs on the resource")
	}
}

// The failure half of property 2, in both directions: a refused request is not a
// failed one, and a failed request is a status plus a class from core's vocabulary.
//
// The 5xx is gateway's OWN, from the pass-through: a routed request whose upstream
// cannot be reached is translated into a 503 by `proxy.go` — a dependency answering
// 5xx is not an outage gateway can be quiet about, and it is exactly the case a
// trace has to make visible. The upstream is an ADDRESS that refuses, not a socket
// this test opens: `TestNoFileInThisPackageTalksToARealSocket` is right that this
// package opens none, and a test that opened one would put the network's opinions
// into an assertion about what gateway records.
func TestAFailureCarriesCoreErrorVocabularyAndARefusalDoesNot(t *testing.T) {
	on := installTelemetry(t, false, func(string) string { return "" })
	handler := aGateway(t, httpapi.Options{
		Routes: httpapi.RouteTable{"/v1/upstream": {BaseURL: "http://127.0.0.1:1"}},
	})

	// A 404 first: not a failure, so no class and no failed status.
	refused := ask(handler, http.MethodGet, "/nothing-here", nil)
	if refused.Code != http.StatusNotFound {
		t.Fatalf("an unmatched path answered %d, want 404", refused.Code)
	}
	// Then a routed request to an upstream that is not there.
	failed := ask(handler, http.MethodGet, "/v1/upstream/thing", nil)
	if failed.Code < 500 {
		t.Fatalf("a routed request to an unreachable upstream produced %d, want a 5xx. Read proxy.go before changing this: the translation is the pass-through's and this test is about the span rather than about it.", failed.Code)
	}

	on.flushSpans()
	if len(*on.spans) != 2 {
		t.Fatalf("two requests produced %d spans, want 2", len(*on.spans))
	}
	refusedSpan, failedSpan := (*on.spans)[0], (*on.spans)[1]

	// THE BICONDITIONAL. core's traces schema constrains it both ways, so the
	// ABSENCE of a class is the load-bearing "this was not an error" marker: on a
	// duration histogram the samples carrying the class are the errors and every
	// other sample is a success.
	if _, carried := attributesOf(refusedSpan)["error.type"]; carried {
		t.Error("a 404 span carries error.type. The fleet's error view is about the service FAILING, not about the service refusing — a span marked ERROR for every rejected request makes the error rate a function of how much credential stuffing the gateway absorbs.")
	}
	if got := refusedSpan.Status().Code.String(); got != "Unset" {
		t.Errorf("a 404 span has status %s, want Unset", got)
	}

	attributes := attributesOf(failedSpan)
	carriedClass, carried := attributes["error.type"]
	if !carried {
		t.Fatalf("a 5xx span carries no error.type. core's schema obliges a class on a failed status, so this span fails the contract the collector enforces.")
	}
	if class, isString := carriedClass.(string); !isString || !telemetry.IsErrorType(class) {
		t.Errorf("error.type = %#v, which is not in core's closed vocabulary (%s)", carriedClass, strings.Join(telemetry.ErrorTypes(), ", "))
	}
	if got := failedSpan.Status().Code.String(); got != "Error" {
		t.Errorf("a 5xx span has status %s, want Error", got)
	}
	if _, carried := attributes["error.message"]; carried {
		t.Error("the span carries error.message. It is the one attribute every SDK adds by default and the one that could carry a token or a caller's path; a span that records only the class cannot carry the message at all.")
	}
}

// # 3. PROPAGATION
//
// The caller's trace is continued: same trace id, this hop's span under it. And a
// header that is absent or garbage starts a new trace and answers exactly as it
// would have — W3C §4.2 says an unparseable traceparent is ignored, and a request
// must not become an error because its trace header was malformed.

func TestAValidTraceparentIsContinuedAndAGarbageOneIsIgnored(t *testing.T) {
	const callerTraceID = "4bf92f3577b34da6a3ce929d0e0e4736"
	valid := "00-" + callerTraceID + "-00f067aa0ba902b7-01"

	for _, testCase := range []struct {
		name        string
		header      string
		wantTraceID string
		wantStatus  int
	}{
		{name: "a valid traceparent is continued", header: valid, wantTraceID: callerTraceID, wantStatus: http.StatusOK},
		{name: "no traceparent starts a new trace", header: "", wantTraceID: "", wantStatus: http.StatusOK},
		{name: "a malformed traceparent is ignored", header: "not-a-traceparent", wantTraceID: "", wantStatus: http.StatusOK},
		{name: "an all-zero trace id is invalid", header: "00-00000000000000000000000000000000-00f067aa0ba902b7-01", wantTraceID: "", wantStatus: http.StatusOK},
		{name: "a version ff is invalid", header: "ff-" + callerTraceID + "-00f067aa0ba902b7-01", wantTraceID: "", wantStatus: http.StatusOK},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			on := installTelemetry(t, false, func(string) string { return "" })
			handler := aGateway(t, httpapi.Options{})

			header := http.Header{}
			if testCase.header != "" {
				header.Set("traceparent", testCase.header)
			}
			response := ask(handler, http.MethodGet, "/healthz", header)

			// NEVER a 4xx. A request is not an error because its trace header was
			// garbage, and an answer that varied with the header would make
			// observability a way to break a gateway.
			if response.Code != testCase.wantStatus {
				t.Fatalf("/healthz with traceparent %q answered %d, want %d", testCase.header, response.Code, testCase.wantStatus)
			}
			on.flushSpans()
			if len(*on.spans) != 1 {
				t.Fatalf("one request produced %d spans, want 1", len(*on.spans))
			}
			spanContext := (*on.spans)[0].SpanContext()

			if testCase.wantTraceID == "" {
				if !spanContext.IsValid() {
					// A span with no parent and no recorded remote context is the
					// root of a NEW trace, which is what "ignored" means.
					return
				}
				if got := spanContext.TraceID().String(); got == callerTraceID {
					t.Errorf("traceparent %q was ignored as required, but the span continued trace %s", testCase.header, got)
				}
				return
			}
			if got := spanContext.TraceID().String(); got != testCase.wantTraceID {
				t.Errorf("trace id = %q, want the caller's %q. A request that enters one cafaye service and leaves it another has to read as ONE trace, and the continuation is this hop's span under the caller's trace id.", got, testCase.wantTraceID)
			}
			// The parent is where the caller's context lives: this hop's own span
			// context is local by definition, so asserting on it would assert that
			// gateway is its own parent. `IsRemote` on the PARENT is what says the
			// trace arrived from another process, and the sampled flag is the
			// caller's decision preserved (§3.2.2.5.1).
			parent := (*on.spans)[0].Parent()
			if !parent.IsValid() {
				t.Fatalf("trace id = %q matches the caller, but the span has no parent. The trace id was carried by something other than a continued span context.", spanContext.TraceID())
			}
			if !parent.IsRemote() {
				t.Error("the parent span context is not remote, so this trace did not arrive from another process")
			}
			if !parent.IsSampled() {
				t.Error("the parent's sampled flag is false; the caller's decision must be preserved (§3.2.2.5.1)")
			}
		})
	}
}
