package telemetry


import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"go.opentelemetry.io/otel"
	metricnoop "go.opentelemetry.io/otel/metric/noop"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
)

// TenantVariable is the one fleet-specific variable this package adds: the tenant
// this process serves.
//
// It is a RESOURCE attribute, and `tenant_id` is on core's resource allowlist and
// on nobody's measurement allowlist. That placement is not a preference. The
// OpenTelemetry SDK folds a metric stream at two thousand attribute
// combinations, and on the overflow point it drops every measurement attribute and
// keeps the total — so a tenant on a measurement renders a dashboard whose totals
// are right and whose per-tenant breakdown silently undercounts. On the resource it
// is exempt from that count entirely and survives the fold.
const TenantVariable = "GATEWAY_TENANT_ID"

const shutdownWait = 5 * time.Second

// exportTimeout bounds one export. The collector is a container on the compose
// network, and a slow export is a latency bug in development caused by an
// observability tool.
const exportTimeout = 5 * time.Second

// Resource is this process's identity, attached once per process rather than once
// per span.
//
// Appended only when set, and the reason is the same in both cases: an empty
// `service.version=""` is not a tidier version than no version. A backend that
// groups by it shows the same service twice, once with no builds, and an operator
// looking at a service list reads that as two deployments rather than as one
// without a version.
func Resource(lookup func(string) string) *resource.Resource {
	attributes := []attribute.KeyValue{
		semconv.ServiceName(ServiceName),

	}
	if version := lookup("OTEL_SERVICE_VERSION"); version != "" {
		attributes = append(attributes, semconv.ServiceVersion(version))
	}
	if environment := lookup("DEPLOYMENT_ENVIRONMENT"); environment != "" {
		attributes = append(attributes, semconv.DeploymentEnvironment(environment))
	}
	if instance := lookup("OTEL_SERVICE_INSTANCE_ID"); instance != "" {
		attributes = append(attributes, semconv.ServiceInstanceID(instance))
	}
	if tenant := lookup(TenantVariable); tenant != "" {
		attributes = append(attributes, attribute.String("tenant_id", tenant))
	}
	return resource.NewWithAttributes(semconv.SchemaURL, attributes...)
}

// Exporter is where finished spans go. Production builds an OTLP exporter; a test
// builds one over an in-memory recorder.
//
// It is a parameter to `Install` rather than something `Install` reaches for, and
// that is what lets a test in this repository assert a REAL exported span — the
// check below is a claim about what leaves the process, not about what a mock was
// handed. A test that could only reach the network would either be skipped or would
// make the suite phone an observability backend.
type Exporter interface {
	ExportSpans(ctx context.Context, spans []sdktrace.ReadOnlySpan) error
	Shutdown(ctx context.Context) error
}

// NewExporter builds an exporter for an endpoint.
type NewExporter func(ctx context.Context, endpoint string) (Exporter, error)

// Options is everything `Install` needs, every field explicit. `Install` runs once
// at boot, and a value it read from a global is a value nobody can find when a
// deployment is misconfigured.
type Options struct {
	Endpoint string

	Disabled bool

	ServiceName string

	NewExporter NewExporter
	LookupEnv   func(string) string

	ShutdownWait time.Duration
}

// Shutdown flushes and stops the provider. Missing it loses the last batch, which
// is usually the batch holding the error the operator is restarting to look at.
type Shutdown func(context.Context) error

// Install sets the propagator and the tracer provider, and returns one `Shutdown`.
//
// # A NO-OP PROVIDER WHEN TELEMETRY IS OFF, NEVER A PROVIDER POINTED AT NOTHING
//
// A provider with an exporter that has nowhere to go still allocates a span per
// request, still computes attributes nobody reads, and still costs a goroutine
// and a batch timer for the life of the process. Core's otel-endpoint schema asks
// for a no-op that allocates nothing, and `noop.NewTracerProvider()` is the SDK's
// own answer rather than a anywaye reimplementation of "disabled".
//
// # THE PROPAGATOR IS NAMED, NOT INHERITED
//
// `otel.SetTextMapPropagator` is process-wide and any package may call it. Naming
// W3C TraceContext here means this service's propagation is a line in this file
// rather than a fact about whichever library happened to be initialized first.
func Install(ctx context.Context, options Options) (Shutdown, error) {
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	if options.ServiceName == "" {
		options.ServiceName = ServiceName
	}
	if options.LookupEnv == nil {
		options.LookupEnv = func(string) string { return "" }
	}
	if options.NewExporter == nil {
		options.NewExporter = OTLPExporter
	}
	if options.ShutdownWait == 0 {
		options.ShutdownWait = shutdownWait
	}

	if options.Disabled {
		otel.SetTracerProvider(noop.NewTracerProvider())
		otel.SetMeterProvider(metricnoop.NewMeterProvider())
		return func(context.Context) error { return nil }, nil
	}

	exporter, err := options.NewExporter(ctx, options.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("building the otlp span exporter for %s: %w", redactEndpoint(options.Endpoint), err)
	}

	provider := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.AlwaysSample())),
		sdktrace.WithResource(Resource(options.LookupEnv)),
	)
	otel.SetTracerProvider(provider)

	target, err := normaliseEndpoint(options.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("building the otlp metric exporter for %s: %w", redactEndpoint(options.Endpoint), err)
	}
	metricExporter, err := otlpmetricgrpc.New(ctx, otlpmetricgrpc.WithEndpointURL(target))
	if err != nil {
		return nil, fmt.Errorf("building the otlp metric exporter for %s: %w", redactEndpoint(options.Endpoint), err)
	}
	meterProvider := sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(sdkmetric.NewPeriodicReader(metricExporter)),
		sdkmetric.WithResource(Resource(options.LookupEnv)),
	)
	otel.SetMeterProvider(meterProvider)

	return func(shutdownCtx context.Context) error {
		flushCtx, cancel := context.WithTimeout(shutdownCtx, options.ShutdownWait)
		defer cancel()
		err1 := provider.Shutdown(flushCtx)
		err2 := meterProvider.Shutdown(flushCtx)
		if err1 != nil { return err1 }
		return err2
	}, nil
}

// OTLPExporter is the production exporter: OTLP over gRPC.
//
// gRPC because that is the address the generated contract already names —
// `DefaultEndpoint` is `http://otel-collector:4317`, the collector's gRPC
// receiver — and the contract is a generated file this repository may not edit. An
// HTTP exporter pointed at the generated default would be a service that exports
// nowhere while appearing configured, which is the failure the boot error above
// exists to catch.
//
// No retry and no queue, for the reason kit's collector config states: a retry
// loop against a dead collector is a goroutine waking on a timer for the life of
// the process, invisible in every dashboard because nothing is being recorded, and
// a queue that accepts spans and holds them is a memory leak with a
// telemetry-shaped trigger. Losing a span is strictly better than becoming a slow
// service. The SDK's defaults are `retry_on_failure: enabled` and
// `sending_queue: enabled`, so both are stated as off rather than left to a default
// that is the opposite of the fleet's rule.
func OTLPExporter(ctx context.Context, endpoint string) (Exporter, error) {
	target, err := normaliseEndpoint(endpoint)
	if err != nil {
		return nil, err
	}
	return otlptracegrpc.New(ctx,
		otlptracegrpc.WithEndpointURL(target),
		otlptracegrpc.WithRetry(otlptracegrpc.RetryConfig{Enabled: false}),
		otlptracegrpc.WithTimeout(exportTimeout),
	)
}

func normaliseEndpoint(endpoint string) (string, error) {
	trimmed := strings.TrimSpace(endpoint)
	if trimmed == "" {
		return "", fmt.Errorf("telemetry: the OTLP endpoint is empty")
	}
	if !strings.Contains(trimmed, "://") {
		trimmed = "http://" + trimmed
	}
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return "", fmt.Errorf("telemetry: %q is not a usable OTLP endpoint: %w", redactEndpoint(endpoint), err)
	}
	if parsed.Host == "" {
		return "", fmt.Errorf("telemetry: the OTLP endpoint has no host")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", fmt.Errorf("telemetry: the OTLP endpoint has scheme %q; an OTLP endpoint is http or https", parsed.Scheme)
	}
	return parsed.String(), nil
}

func redactEndpoint(endpoint string) string {
	parsed, err := url.Parse(strings.TrimSpace(endpoint))
	if err != nil || parsed.Host == "" {
		return "<unparseable endpoint>"
	}
	return parsed.Scheme + "://" + parsed.Host
}

var _ Exporter = (*otlptrace.Exporter)(nil)

// StartServer begins a span for an inbound request, continuing the caller's trace.
//
// THE PROPAGATOR CANNOT FAIL, and that is the contract rather than an omission. A
// malformed `traceparent` is extracted as no parent at all, so the result is a
// fresh root span and the request is served exactly as it would have been — W3C
// §4.2 says an unparseable header is ignored, and a request is not an error because
// its trace header was garbage. There is no return value here that could turn a bad
// header into a 4xx, which is the property worth having.
func StartServer(ctx context.Context, header http.Header, name string) (context.Context, trace.Span) {
	ctx = otel.GetTextMapPropagator().Extract(ctx, propagation.HeaderCarrier(header))
	tracer := otel.Tracer(ServiceName)
	return tracer.Start(ctx, name, trace.WithSpanKind(trace.SpanKindServer))
}

// Inject writes the current trace onto an outbound header map, so a service-to-
// service call continues this trace rather than starting a new one.
//
// Not called by gateway itself today — the pass-through hands the upstream a
// credential, not a trace — and it is here because the moment a second outbound
// call exists, the alternative is a trace that silently breaks at that hop with no
// error anywhere to grep for.
func Inject(ctx context.Context, header http.Header) {
	otel.GetTextMapPropagator().Inject(ctx, propagation.HeaderCarrier(header))
}

// TraceID is the current trace id for a log line.
//
// "unknown" rather than an error: this is called from a formatting path, and a 500
// on a log-formatting path is worse than a missing id.
func TraceID(ctx context.Context) string {
	spanContext := trace.SpanContextFromContext(ctx)
	if !spanContext.HasTraceID() {
		return "unknown"
	}
	return spanContext.TraceID().String()
}

// MustSpanName is `SpanName` for a name built from constants.
//
// The panic is the point rather than an inconvenience: the generated function
// refuses anything outside core's grammar, and the only callers here pass
// constants. A name that cannot be built is a programming error, and a constant
// checked on every request would be a check that costs a request to discover what
// a build could have refused.
func MustSpanName(operation string, targetAndQualifier ...string) string {
	name, err := SpanName(operation, targetAndQualifier...)
	if err != nil {
		panic("telemetry: " + err.Error())
	}
	return name
}

// Record is the ONE path to a span attribute in this repository.
//
// # EVERY VALUE GOES THROUGH THE GENERATED `Check`, AND NOTHING ELSE
//
// `Check` carries the per-signal allowlist, the closed vocabularies, the route
// pattern, the integer bounds and the refusal for a name core names in its
// measurements `not` clause. Consulting it from here means this file holds no
// second copy of any of that: a core release that adds a method to the enum or
// tightens a pattern reaches this service through the generator and not through a
// table somebody remembered to update.
//
// A refused attribute is DROPPED, not recorded and not fatal. The refusal is
// deliberately quiet at the call site — a gateway must not turn a diagnostic into
// an outage — and the drop is visible in exactly one place: an attribute nobody
// reads. That is the trade core's default-deny is for.
//
// `float64` and anything with a `String()` method are refused without consulting
// `Check`, because no attribute on the traces allowlist is a float and an object's
// `String()` can be anything at all — on a service that verifies credentials, it
// can be a list of callers' email addresses.
func Record(span trace.Span, attributes map[string]any) {
	if span == nil || !span.IsRecording() {
		return
	}
	for _, name := range sortedKeys(attributes) {
		value, ok := attributeValue(name, attributes[name])
		if !ok {
			continue
		}
		span.SetAttributes(value)
	}
}

// RecordFailure says a span failed, and which CLASS of failure it was.
//
// Two decisions, and the second is the one that gets made wrong:
//
//  1. "This is an error" is the span's STATUS, not `error.type`. core's traces
//     schema constrains both directions — a failed status obliges a class and a
//     class obliges a failed status — so a span that carries one without the other
//     is a span two queries read differently. Both are set here so they cannot come
//     apart.
//
//  2. `error.type` is the CLASS and never the message. The SDK's `RecordError` is
//     deliberately not called: it writes `exception.message` and
//     `exception.stacktrace`, which are unbounded, are on nobody's allowlist, and
//     on a service that verifies tokens are a path to whatever the failing handler
//     had in hand. A class outside core's vocabulary collapses to `_OTHER` and
//     returns an error saying so, so the instrumentation is never silently wrong
//     about a failure it could not classify.
func RecordFailure(span trace.Span, class string, description string) error {
	if span == nil {
		return nil
	}
	resolved := class
	if !IsErrorType(resolved) {
		resolved = "_OTHER"
	}
	span.SetStatus(codes.Error, description)
	span.SetAttributes(
		attribute.String("error.type", resolved),
		attribute.String("otel.status_code", "ERROR"),
	)
	if resolved != class {
		return fmt.Errorf("telemetry: %q is not in core's error vocabulary; recorded as _OTHER", class)
	}
	return nil
}

func attributeValue(name string, value any) (attribute.KeyValue, bool) {
	switch typed := value.(type) {
	case string:
		if typed == "" {
			return attribute.KeyValue{}, false
		}
		if err := Check(SignalTraces, name, typed); err != nil {
			return attribute.KeyValue{}, false
		}
		return attribute.String(name, typed), true
	case int:
		return checkedInt64(name, int64(typed))
	case int8:
		return checkedInt64(name, int64(typed))
	case int16:
		return checkedInt64(name, int64(typed))
	case int32:
		return checkedInt64(name, int64(typed))
	case int64:
		return checkedInt64(name, typed)
	case uint:
		return checkedUint64(name, uint64(typed))
	case uint8:
		return checkedInt64(name, int64(typed))
	case uint16:
		return checkedInt64(name, int64(typed))
	case uint32:
		return checkedInt64(name, int64(typed))
	case uint64:
		return checkedUint64(name, typed)
	default:
		return attribute.KeyValue{}, false
	}
}

func checkedInt64(name string, value int64) (attribute.KeyValue, bool) {
	if err := Check(SignalTraces, name, strconv.FormatInt(value, 10)); err != nil {
		return attribute.KeyValue{}, false
	}
	return attribute.Int64(name, value), true
}

func checkedUint64(name string, value uint64) (attribute.KeyValue, bool) {
	if value > MaxSafeJSONInteger {
		return attribute.KeyValue{}, false
	}
	return checkedInt64(name, int64(value))
}

func sortedKeys(attributes map[string]any) []string {
	names := make([]string, 0, len(attributes))
	for name := range attributes {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
