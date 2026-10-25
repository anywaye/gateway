package telemetry

import (
	"context"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

var (
	requestCount   metric.Int64Counter
	requestDur     metric.Float64Histogram
	metricsInited  bool
)

func initMetrics() {
	if metricsInited {
		return
	}
	meter := otel.Meter(ServiceName)
	c, _ := meter.Int64Counter("http.server.request.count",
		metric.WithDescription("Number of HTTP requests"))
	h, _ := meter.Float64Histogram("http.server.request.duration",
		metric.WithDescription("HTTP request duration in seconds"),
		metric.WithUnit("s"))
	requestCount = c
	requestDur = h
	metricsInited = true
}

// RecordRequest records application-level HTTP metrics for one request.
func RecordRequest(ctx context.Context, method, route string, status int, dur time.Duration) {
	initMetrics()
	attrs := []attribute.KeyValue{
		attribute.String("http.request.method", method),
		attribute.String("http.route", route),
		attribute.Int("http.response.status_code", status),
	}
	if requestCount != nil {
		requestCount.Add(ctx, 1, metric.WithAttributes(attrs...))
	}
	if requestDur != nil {
		requestDur.Record(ctx, dur.Seconds(), metric.WithAttributes(attrs...))
	}
}
