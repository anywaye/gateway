package httpapi

import (
	"net/url"
	"testing"
)

// mustParse is `url.Parse` for a query string, failing the test rather than
// returning an error: the inputs are literals in a table, so a parse failure is a
// defect in this file and not a thing the code under test has to answer for.
func mustParse(t *testing.T, rawQuery string) *url.URL {
	t.Helper()

	// No `?` is appended when there is no query: a URL with a bare question mark is
	// a *different* request, and this helper builds the no-query case rather than
	// asserting the bare-`?` one, which the test below owns.
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

// TestTheQueryIsAppendedVerbatimAndABareQuestionMarkSurvives is the third case the
// two-row version above could not state.
//
// `?` with nothing after it is a request the caller made; the reference's
// `url.search` is `"?"` there, and dropping it would be a different request. Go's
// `url.URL` says so with `ForceQuery` rather than by leaving an empty `RawQuery`,
// so this is the one row that needs the flag to be read at all.
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
