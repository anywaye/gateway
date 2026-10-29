package httpapi_test


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

	"github.com/anywaye/gateway/internal/httpapi"
	"github.com/anywaye/gateway/internal/telemetry"
)

type recordingExporter struct{ spans *[]sdktrace.ReadOnlySpan }

func (r recordingExporter) ExportSpans(_ context.Context, spans []sdktrace.ReadOnlySpan) error {
	*r.spans = append(*r.spans, spans...)
	return nil
}

func (r recordingExporter) Shutdown(context.Context) error { return nil }

type recorded struct {
	spans    *[]sdktrace.ReadOnlySpan
	lookup   func(string) string
	shutdown telemetry.Shutdown
	once     sync.Once
}

func (r *recorded) flushSpans() { r.once.Do(func() { _ = r.shutdown(context.Background()) }) }

func installTelemetry(t *testing.T, disabled bool, lookup func(string) string) *recorded {
	t.Helper()
	spans := &[]sdktrace.ReadOnlySpan{}
	previous := otel.GetTracerProvider()
	t.Cleanup(func() { otel.SetTracerProvider(previous) })

	shutdown, err := telemetry.Install(context.Background(), telemetry.Options{
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

func aGateway(t *testing.T, options httpapi.Options) http.Handler {
	t.Helper()
	handler, err := httpapi.New(options)
	if err != nil {
		t.Fatalf("building a gateway: %v", err)
	}
	return handler
}

func ask(handler http.Handler, method, target string, header http.Header) *httptest.ResponseRecorder {
	request := httptest.NewRequestWithContext(context.Background(), method, target, nil)
	for name, values := range header {
		request.Header[name] = values
	}
	recorded := httptest.NewRecorder()
	handler.ServeHTTP(recorded, request)
	return recorded
}

func attributesOf(span sdktrace.ReadOnlySpan) map[string]any {
	carried := map[string]any{}
	for _, kv := range span.Attributes() {
		carried[string(kv.Key)] = kv.Value.AsInterface()
	}
	return carried
}

func resourceString(span sdktrace.ReadOnlySpan, name string) (string, bool) {
	value, found := span.Resource().Set().Value(attribute.Key(name))
	if !found {
		return "", false
	}
	return value.AsString(), true
}


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

	for _, forbidden := range []string{"http.target", "url.full", "url.path", "url.query", "user_agent.original", "http.request.headers"} {
		if _, carried := attributes[forbidden]; carried {
			t.Errorf("the span carries %q, which is on nobody's allowlist and carries a caller's concrete path", forbidden)
		}
	}
}

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
		"service.namespace":      "anywaye",
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

	if _, carried := attributesOf(span)["tenant_id"]; carried {
		t.Error("the SPAN carries tenant_id; it belongs on the resource")
	}
}

func TestAFailureCarriesCoreErrorVocabularyAndARefusalDoesNot(t *testing.T) {
	on := installTelemetry(t, false, func(string) string { return "" })
	handler := aGateway(t, httpapi.Options{
		Routes: httpapi.RouteTable{"/v1/upstream": {BaseURL: "http://127.0.0.1:1"}},
	})

	refused := ask(handler, http.MethodGet, "/nothing-here", nil)
	if refused.Code != http.StatusNotFound {
		t.Fatalf("an unmatched path answered %d, want 404", refused.Code)
	}
	failed := ask(handler, http.MethodGet, "/v1/upstream/thing", nil)
	if failed.Code < 500 {
		t.Fatalf("a routed request to an unreachable upstream produced %d, want a 5xx. Read proxy.go before changing this: the translation is the pass-through's and this test is about the span rather than about it.", failed.Code)
	}

	on.flushSpans()
	if len(*on.spans) != 2 {
		t.Fatalf("two requests produced %d spans, want 2", len(*on.spans))
	}
	refusedSpan, failedSpan := (*on.spans)[0], (*on.spans)[1]

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
					return
				}
				if got := spanContext.TraceID().String(); got == callerTraceID {
					t.Errorf("traceparent %q was ignored as required, but the span continued trace %s", testCase.header, got)
				}
				return
			}
			if got := spanContext.TraceID().String(); got != testCase.wantTraceID {
				t.Errorf("trace id = %q, want the caller's %q. A request that enters one anywaye service and leaves it another has to read as ONE trace, and the continuation is this hop's span under the caller's trace id.", got, testCase.wantTraceID)
			}
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
