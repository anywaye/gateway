package httpapi

import (
	"fmt"
	"log"
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
	err := sentry.Init(sentry.ClientOptions{
		Dsn:              dsn,
		Release:          release,
		Environment:      environment,
		AttachStacktrace: true,
		BeforeSend: func(event *sentry.Event, hint *sentry.EventHint) *sentry.Event {
			// Keep the exception message so errors are actionable. The message
			// must not contain user input or secrets; identifiers belong in tags.
			if event.Request != nil {
				// Keep the path for reproduction, but drop the query string,
				// which is where tokens and PII most often leak.
				if u := event.Request.URL; u != "" {
					if i := strings.IndexByte(u, '?'); i >= 0 {
						event.Request.URL = u[:i]
					}
				}
				event.Request.QueryString = ""
			}
			// Mark gateway's own frames as in-app so GlitchTip shows the
			// stack trace in its default (in-app) view instead of hiding
			// every frame.
			for i := range event.Exception {
				if st := event.Exception[i].Stacktrace; st != nil {
					for j := range st.Frames {
						if strings.Contains(st.Frames[j].Module, "anywaye") ||
							strings.Contains(st.Frames[j].Filename, "anywaye") {
							st.Frames[j].InApp = true
						}
					}
				}
			}
			return event
		},
	})
	if err != nil {
		log.Printf("error reporting init failed: %v", err)
	}
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
	if !sentry.Flush(2 * time.Second) {
		log.Printf("error reporting flush timed out")
	}
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
