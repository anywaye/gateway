package auth

import (
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/getsentry/sentry-go"
)

func InitErrorReporting() {
	dsn := strings.TrimSpace(os.Getenv("GATEWAY_ERROR_REPORTING_DSN"))
	if dsn == "" {
		return
	}
	release := strings.TrimSpace(os.Getenv("GATEWAY_RELEASE"))
	if release == "" {
		release = "unknown"
	}
	environment := strings.TrimSpace(os.Getenv("DEPLOYMENT_ENVIRONMENT"))
	if environment == "" {
		environment = "production"
	}
	err := sentry.Init(sentry.ClientOptions{
		Dsn:              dsn,
		Release:          release,
		Environment:      environment,
		AttachStacktrace: true,
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
