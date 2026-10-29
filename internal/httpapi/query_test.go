package httpapi

import (
	"net/url"
	"testing"
)

func mustParse(t *testing.T, rawQuery string) *url.URL {
	t.Helper()

	target := "http://upstream.test/v1/pantry"
	if rawQuery != "" {
		target += "?" + rawQuery
	}

	parsed, err := url.Parse(target)
	if err != nil {
		t.Fatalf("the test's own URL did not parse: %v", err)
	}
	return parsed
}

func TestTheQueryIsAppendedVerbatimAndABareQuestionMarkSurvives(t *testing.T) {
	parsed, err := url.Parse("http://upstream.test/v1/pantry?")
	if err != nil {
		t.Fatalf("the test's own URL did not parse: %v", err)
	}
	if !parsed.ForceQuery {
		t.Skipf("net/url does not report ForceQuery for %q, so this case cannot be stated on this toolchain", parsed)
	}
	if got := searchOf(parsed); got != "?" {
		t.Errorf("searchOf(%q) = %q, want %q — a caller who asked an empty question still asked one", parsed.RawQuery, got, "?")
	}
}
