package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/cafaye/gateway/internal/api"
)

// This file holds core's error envelope — the one every rejection in gateway
// goes through, ported from `src/problem.ts` (removed at cutover).
//
// Nothing in this packet writes a problem yet: the two refusals the substrate
// serves are the v0 `404` and the v0 `500`, both of which are the other
// envelope (`V0Error`). So every case here drives the writer directly, and that
// is worth saying plainly rather than letting a reader assume the suite is
// covering a live path — it is covering the floor the first Wave 3 handler
// stands on, and the first thing that handler must not get wrong is the shape.

// write drives one problem through the writer and returns what it wrote.
func write(t *testing.T, p Problem) *httptest.ResponseRecorder {
	t.Helper()

	rec := httptest.NewRecorder()
	writeProblem(rec, httptest.NewRequest(http.MethodPost, "/v1/whatever", nil), p)
	return rec
}

// A problem is RFC 9457 with core's two extensions, and the whole envelope is
// asserted rather than the fields a struct happens to decode.
func TestAProblemIsTheDocumentedEnvelope(t *testing.T) {
	rec := write(t, Problem{
		Status: api.N401,
		Code:   api.ProblemCodeUnauthorized,
		Detail: "bearer token is not acceptable",
	})

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status is %d, want 401", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/problem+json" {
		t.Errorf("Content-Type is %q, want application/problem+json — a client that switches on it is the entire reason RFC 9457 exists", got)
	}

	var body map[string]any
	decode(t, rec, &body)

	want := map[string]any{
		"type":     "https://errors.cafaye.com/unauthorized",
		"title":    "Unauthorized",
		"status":   float64(401),
		"detail":   "bearer token is not acceptable",
		"instance": "/v1/whatever",
		"code":     "unauthorized",
	}
	for name, expected := range want {
		if body[name] != expected {
			t.Errorf("%s is %v, want %v", name, body[name], expected)
		}
	}

	// And nothing else: the document's `Problem` has seven required fields and
	// one optional `errors`, so an eighth key is a field the contract does not
	// declare. Key-by-key equality is the assertion; a decode into a struct would
	// have dropped the extra silently. `trace_id` is the seventh and is asserted
	// by the next test, so it is counted here rather than listed above.
	var keys []string
	for name := range body {
		keys = append(keys, name)
	}
	sort.Strings(keys)

	if len(body) != len(want)+1 {
		t.Errorf("the problem has %d keys (%v), want %d: no service invents its own error body", len(body), keys, len(want)+1)
	}
}

// The trace id is the correlation handle, and the two halves have to agree: a
// support engineer starts from the header and searches the log, and a body
// carrying an id the header does not have sends them nowhere.
func TestTheTraceIdHeaderEqualsTheBodyAndLooksLikeOne(t *testing.T) {
	// Ten of them, because one that matches by luck is not a check.
	shape := regexp.MustCompile(`^[0-9a-f]{32}$`)
	seen := map[string]bool{}

	for i := 0; i < 10; i++ {
		rec := write(t, Problem{Status: api.N401, Code: api.ProblemCodeUnauthorized, Detail: "no"})

		header := rec.Header().Get("X-Trace-Id")
		var body struct {
			TraceID string `json:"trace_id"`
		}
		decode(t, rec, &body)

		if header != body.TraceID {
			t.Fatalf("X-Trace-Id is %q and trace_id is %q; they are the same id and a support search starts from one of them", header, body.TraceID)
		}
		if !shape.MatchString(header) {
			t.Errorf("trace id %q is not 32 hex characters, which is the shape openapi/v1.yaml's pattern requires", header)
		}
		if seen[header] {
			t.Errorf("trace id %q was minted twice in ten problems", header)
		}
		seen[header] = true
	}
}

// `errors` is scoped to a 422 by core's convention, and the renderer has to hold
// that on its own: a caller that passes field errors at a 401 must not widen the
// rule. The key is ABSENT rather than empty for the same reason — a client
// rendering `errors` must be able to tell "no fields failed" from "this response
// is not about fields".
func TestFieldErrorsAppearOnlyOnA422(t *testing.T) {
	fields := []api.FieldError{{Field: "password", Code: "too_short"}}

	// A FRESH map per case, every time. Decoding into one map declared above the
	// loop merges rather than replaces, so an `errors` key left by the 422 case
	// would still be there for the 401 case and this test would report every
	// status as carrying field errors. It did, until it was caught by the 422
	// case itself — which is the argument for asserting on decoded shapes at all.
	for _, status := range []api.ProblemStatus{api.N400, api.N401, api.N403, api.N409, api.N413, api.N423, api.N429, api.N503} {
		var body map[string]any
		decode(t, write(t, Problem{Status: status, Code: api.ProblemCodeValidationFailed, Detail: "no", Errors: fields}), &body)

		if _, present := body["errors"]; present {
			t.Errorf("a %d carries errors[]: core scopes it to a 422", status)
		}
	}

	var body map[string]any
	decode(t, write(t, Problem{Status: api.N422, Code: api.ProblemCodeValidationFailed, Detail: "no", Errors: fields}), &body)
	if _, present := body["errors"]; !present {
		t.Errorf("a 422 with field errors has no errors[]: %v", body)
	}

	// And an empty list on a 422 is also absent, for the same reason.
	body = nil
	decode(t, write(t, Problem{Status: api.N422, Code: api.ProblemCodeValidationFailed, Detail: "no"}), &body)
	if _, present := body["errors"]; present {
		t.Errorf("a 422 with no field errors carries errors[]: %v", body)
	}
}

// `detail` is written by the caller and is never an internal reason. This is the
// one assertion in the file that is about a property rather than a shape, and it
// is the reason `Problem.Detail` has no constructor: a caller that interpolated
// an error into it would be writing a dependency's host into a document an
// unauthenticated caller reads.
func TestTheInstanceIsThePathAndTheQueryNeverReachesTheBody(t *testing.T) {
	rec := httptest.NewRecorder()
	writeProblem(rec, httptest.NewRequest(http.MethodGet, "/v1/me?token=caf_secret_value&x=1", nil), Problem{
		Status: api.N401,
		Code:   api.ProblemCodeUnauthorized,
		Detail: "no credential presented",
	})

	var body map[string]any
	decode(t, rec, &body)

	if body["instance"] != "/v1/me" {
		t.Errorf("instance is %v, want /v1/me — the path and never the query", body["instance"])
	}
	if strings.Contains(rec.Body.String(), "caf_secret_value") {
		t.Errorf("the query reached the body: %s", rec.Body.String())
	}
}

// A code with no title is a defect in this repository, and the writer refuses
// rather than rendering a document the contract does not describe.
//
// The alternative — a lookup with a fallback, which is what `src/problem.ts` (removed at cutover)
// does and which renders `title: undefined` into the JSON — produces a body that
// looks like a problem document and is not one. So an unknown code is rewritten
// to a code this file can justify, with the status that code is for, and
// `TestEveryProblemCodeHasATitle` below is what makes the branch unreachable.
func TestACodeWithNoTitleIsRefusedRatherThanRendered(t *testing.T) {
	rec := write(t, Problem{Status: api.N401, Code: api.ProblemCode("invented_here"), Detail: "no"})

	var body map[string]any
	decode(t, rec, &body)

	if body["code"] != "unavailable" {
		t.Errorf("code is %v, want unavailable — an undeclared code is not rendered as itself", body["code"])
	}
	if body["status"] != float64(503) {
		t.Errorf("status is %v, want 503 — the status is not carried over from a code that does not exist", body["status"])
	}
	if _, absent := titles[api.ProblemCode("invented_here")]; absent {
		if title, _ := body["title"].(string); title == "" {
			t.Errorf("title is %v, want a summary: the envelope must stay readable", body["title"])
		}
	}
}

// The titles map is total over the document's `Problem.code` enum, and this is
// what makes the branch above unreachable.
//
// The enum is read out of the GENERATED file rather than transcribed: the list is
// `api.ProblemCode`'s constants, and a hand-written copy is a second inventory of
// the document that goes stale silently — a code added to `openapi/v1.yaml`
// would produce a problem document with no title and no failing test.
func TestEveryProblemCodeHasATitle(t *testing.T) {
	declared := declaredProblemCodes(t)

	for code := range declared {
		if _, ok := titles[code]; !ok {
			t.Errorf("%q is in openapi/v1.yaml's Problem.code enum and has no title in problem.go, so a response carrying it would fall through to the refusal branch.", code)
		}
	}

	// The other direction. A title for a code the document does not name is a
	// title nothing can reach, and `TestACodeWithNoTitleIsRefusedRatherThanRendered`
	// is the only place it could be reached — through a code that does not exist.
	for code := range titles {
		if !declared[code] {
			t.Errorf("problem.go has a title for %q, which the document does not declare", code)
		}
	}
}

// declaredProblemCodes reads `ProblemCode`'s constants out of the generated file.
var problemCodeConst = regexp.MustCompile(`(?m)^\s*ProblemCode([A-Za-z]+)\s+ProblemCode = "([a-z_]+)"$`)

func declaredProblemCodes(t *testing.T) map[api.ProblemCode]bool {
	t.Helper()

	source := read(t, "../api/api.gen.go")

	codes := map[api.ProblemCode]bool{}
	for _, match := range problemCodeConst.FindAllStringSubmatch(source, -1) {
		codes[api.ProblemCode(match[2])] = true
	}

	// A reader that found nothing would make the loop above vacuous, which is the
	// failure mode `noSkips.test.ts` calls "a check that covers nothing".
	if len(codes) != 9 {
		t.Fatalf("this test reads %d problem codes and openapi/v1.yaml declares nine. If the generator changed how it writes them, this test has stopped checking anything.", len(codes))
	}
	if len(codes) == 0 {
		t.Fatal("no problem codes were read from ../api/api.gen.go, so the check above passed without looking at anything")
	}

	return codes
}

// The v0 envelope is the OTHER shape, and holding it to the document's `V0Error`
// is what stops a second error body being invented.
func TestTheV0EnvelopeCarriesOnlyTheTwoFieldsTheDocumentDeclares(t *testing.T) {
	rec := ask(t, bare(t), http.MethodGet, "/nope", nil)

	var body map[string]any
	decode(t, rec, &body)

	if len(body) != 2 || body["error"] != "not_found" || body["message"] != "no such route" {
		t.Errorf("body is %s, want exactly {\"error\":\"not_found\",\"message\":\"no such route\"}", rec.Body.String())
	}

	// And it is `application/json`, not the problem media type: that difference is
	// how a client tells the two envelopes apart, and open decision 5 in the
	// document's header says nothing else does.
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type is %q, want application/json", got)
	}

	// The generated type is what makes the third slug unreachable.
	if !api.V0ErrorErrorNotFound.Valid() || api.V0ErrorError("something_else").Valid() {
		t.Error("V0ErrorError does not validate its own enum, so the body could carry a slug the document does not declare")
	}
}

// json.Marshal is used by `orderedDeps`, so this file's import is not decorative:
// a key that needed escaping would otherwise be a byte-corrupting bug nobody had
// tested. Names are validated non-empty at construction, but a name with a quote
// in it is not refused, and it should not corrupt the document either.
func TestADependencyNameWithAwkwardCharactersIsEscaped(t *testing.T) {
	const name = `we"ird\name`

	rec := ask(t, Options{Probes: []NamedProbe{{Name: name, Probe: alwaysOK}}}, http.MethodGet, "/readyz", nil)

	var body struct {
		Deps map[string]string `json:"deps"`
	}
	decode(t, rec, &body)

	if body.Deps[name] != "ok" {
		t.Errorf("deps is %v; the name did not survive a round trip through the hand-written JSON", rec.Body.String())
	}

	// And the raw bytes are still one object, not two: a missing escape would
	// have split the key and made this unmarshal fail rather than produce a
	// wrong map.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("the body is not a single JSON object: %v\n%s", err, rec.Body.String())
	}
}
