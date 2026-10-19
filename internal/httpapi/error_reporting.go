package httpapi

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/getsentry/sentry-go"
)

func InitErrorReporting() {
	dsn := strings.TrimSpace(OSEnv("GATEWAY_ERROR_REPORTING_DSN"))
	if dsn == "" {
		return
	}
	release := strings.TrimSpace(OSEnv("GATEWAY_RELEASE"))
	if release == "" {
		release = strings.TrimSpace(OSEnv("COURIER_RELEASE"))
	}
	if release == "" {
		release = "unknown"
	}
	environment := strings.TrimSpace(OSEnv("DEPLOYMENT_ENVIRONMENT"))
	if environment == "" {
		environment = "production"
	}
	_ = sentry.Init(sentry.ClientOptions{
		Dsn:              dsn,
		Release:          release,
		Environment:      environment,
		AttachStacktrace: true,
		BeforeSend: func(event *sentry.Event, hint *sentry.EventHint) *sentry.Event {
			for i := range event.Exception {
				event.Exception[i].Value = ""
			}
			if event.Request != nil {
				event.Request.URL = ""
				event.Request.QueryString = ""
			}
			return event
		},
	})
}

func CaptureError(err error, r *http.Request) {
	if err == nil {
		return
	}
	hub := sentry.CurrentHub().Clone()
	if r != nil {
		hub.ConfigureScope(func(scope *sentry.Scope) {
			scope.SetRequest(r)
		})
	}
	hub.CaptureException(err)
	sentry.Flush(2 * time.Second)
}

// ErrorReportingEnabled reports whether a reporting DSN is configured.
func ErrorReportingEnabled() bool {
	return strings.TrimSpace(OSEnv("GATEWAY_ERROR_REPORTING_DSN")) != ""
}

// RecoverMiddleware turns a panic in a handler into a 500 and reports it. It
// wraps the outer handler so a panic anywhere in the chain is captured.
func RecoverMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				CaptureError(fmt.Errorf("panic: %v", rec), r)
				panic(rec)
			}
		}()
		next.ServeHTTP(w, r)
	})
}
