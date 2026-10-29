package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/anywaye/gateway/internal/api"
)


func write(t *testing.T, p Problem) *httptest.ResponseRecorder {
	t.Helper()

	rec := httptest.NewRecorder()
	writeProblem(rec, httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/whatever", nil), p)
	return rec
}

func TestAProblemIsTheDocumentedEnvelope(t *testing.T) {
	rec := write(t, Problem{
		Status: 401,
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
		"type":     "https://docs.anywaye.com/errors/unauthorized",
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

	var keys []string
	for name := range body {
		keys = append(keys, name)
	}
	sort.Strings(keys)

	if len(body) != len(want)+1 {
		t.Errorf("the problem has %d keys (%v), want %d: no service invents its own error body", len(body), keys, len(want)+1)
	}
}

func TestTheTraceIdHeaderEqualsTheBodyAndLooksLikeOne(t *testing.T) {
	shape := regexp.MustCompile(`^[0-9a-f]{32}$`)
	seen := map[string]bool{}

	for i := 0; i < 10; i++ {
		rec := write(t, Problem{Status: 401, Code: api.ProblemCodeUnauthorized, Detail: "no"})

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

func TestFieldErrorsAppearOnlyOnA422(t *testing.T) {
	fields := []api.FieldError{{Field: "password", Code: "too_short"}}

	for _, status := range []int{400, 401, 403, 409, 413, 423, 429, 503} {
		var body map[string]any
		decode(t, write(t, Problem{Status: status, Code: api.ProblemCodeValidationFailed, Detail: "no", Errors: fields}), &body)

		if _, present := body["errors"]; present {
			t.Errorf("a %d carries errors[]: core scopes it to a 422", status)
		}
	}

	var body map[string]any
	decode(t, write(t, Problem{Status: 422, Code: api.ProblemCodeValidationFailed, Detail: "no", Errors: fields}), &body)
	if _, present := body["errors"]; !present {
		t.Errorf("a 422 with field errors has no errors[]: %v", body)
	}

	body = nil
	decode(t, write(t, Problem{Status: 422, Code: api.ProblemCodeValidationFailed, Detail: "no"}), &body)
	if _, present := body["errors"]; present {
		t.Errorf("a 422 with no field errors carries errors[]: %v", body)
	}
}

func TestTheInstanceIsThePathAndTheQueryNeverReachesTheBody(t *testing.T) {
	rec := httptest.NewRecorder()
	writeProblem(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/v1/me?token=caf_secret_value&x=1", nil), Problem{
		Status: 401,
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

func TestACodeWithNoTitleIsRefusedRatherThanRendered(t *testing.T) {
	rec := write(t, Problem{Status: 401, Code: api.ProblemCode("invented_here"), Detail: "no"})

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

func TestEveryProblemCodeHasATitle(t *testing.T) {
	declared := declaredProblemCodes(t)

	for code := range declared {
		if _, ok := titles[code]; !ok {
			t.Errorf("%q is in openapi/v1.yaml's Problem.code enum and has no title in problem.go, so a response carrying it would fall through to the refusal branch.", code)
		}
	}

	for code := range titles {
		if !declared[code] {
			t.Errorf("problem.go has a title for %q, which the document does not declare", code)
		}
	}
}

var problemCodeConst = regexp.MustCompile(`(?m)^\s*ProblemCode([A-Za-z]+)\s+ProblemCode = "([a-z_]+)"$`)

func declaredProblemCodes(t *testing.T) map[api.ProblemCode]bool {
	t.Helper()

	source := read(t, "../api/api.gen.go")

	codes := map[api.ProblemCode]bool{}
	for _, match := range problemCodeConst.FindAllStringSubmatch(source, -1) {
		codes[api.ProblemCode(match[2])] = true
	}

	if len(codes) != 9 {
		t.Fatalf("this test reads %d problem codes and openapi/v1.yaml declares nine. If the generator changed how it writes them, this test has stopped checking anything.", len(codes))
	}
	if len(codes) == 0 {
		t.Fatal("no problem codes were read from ../api/api.gen.go, so the check above passed without looking at anything")
	}

	return codes
}

func TestTheV0EnvelopeCarriesOnlyTheTwoFieldsTheDocumentDeclares(t *testing.T) {
	rec := ask(t, bare(t), http.MethodGet, "/nope", nil)

	var body map[string]any
	decode(t, rec, &body)

	if len(body) != 2 || body["error"] != "not_found" || body["message"] != "no such route" {
		t.Errorf("body is %s, want exactly {\"error\":\"not_found\",\"message\":\"no such route\"}", rec.Body.String())
	}

	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type is %q, want application/json", got)
	}

	if !api.V0ErrorErrorNotFound.Valid() || api.V0ErrorError("something_else").Valid() {
		t.Error("V0ErrorError does not validate its own enum, so the body could carry a slug the document does not declare")
	}
}

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

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("the body is not a single JSON object: %v\n%s", err, rec.Body.String())
	}
}
