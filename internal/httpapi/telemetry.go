package httpapi

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"go.opentelemetry.io/otel/trace"

	"github.com/anywaye/gateway/internal/telemetry"
)

var requestSpanName = mustRequestSpanName()

func mustRequestSpanName() string {
	return telemetry.MustSpanName("request")
}

func telemetryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, span := telemetry.StartServer(r.Context(), r.Header, requestSpanName)

		telemetry.Record(span, map[string]any{"http.request.method": r.Method})

		tracked := &statusWriter{ResponseWriter: w, status: http.StatusOK}
	start := time.Now()

		defer func() {
			telemetry.Record(span, map[string]any{
				"http.response.status_code": tracked.status,
				"http.route":                routeTemplate(r),
			})
			recordRequestFailure(span, tracked.status)
			telemetry.RecordRequest(r.Context(), r.Method, routeTemplate(r), tracked.status, time.Since(start))
			span.End()
		}()

		next.ServeHTTP(tracked, r.WithContext(ctx))
	})
}

func routeTemplate(r *http.Request) string {
	routeContext := chi.RouteContext(r.Context())
	if routeContext == nil {
		return ""
	}
	return routeContext.RoutePattern()
}

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

func recordRequestFailure(span trace.Span, status int) {
	if status < 500 {
		return
	}
	_ = telemetry.RecordFailure(span, "internal_error", "the handler returned a server error")
}
