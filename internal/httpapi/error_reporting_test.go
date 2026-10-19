package httpapi

import "testing"

func TestErrorReportingOffByDefault(t *testing.T) {
	t.Setenv("GATEWAY_ERROR_REPORTING_DSN", "")
	if ErrorReportingEnabled() {
		t.Fatal("reporting should be off when DSN is unset")
	}
}
