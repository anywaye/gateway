package httpapi

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/anywaye/gateway/internal/api"
)


const problemTypeBase = "https://docs.anywaye.com/errors/"

var titles = map[api.ProblemCode]string{
	api.ProblemCodeUnauthorized:     "Unauthorized",
	api.ProblemCodeForbidden:        "Forbidden",
	api.ProblemCodeUnavailable:      "Service unavailable",
	api.ProblemCodeInvalidJSON:      "Invalid request",
	api.ProblemCodeConflict:         "Conflict",
	api.ProblemCodeValidationFailed: "Validation failed",
	api.ProblemCodeAccountLocked:    "Account locked",
	api.ProblemCodePayloadTooLarge:  "Payload too large",
	api.ProblemCodeRateLimited:      "Too many requests",
}

const problemContentType = "application/problem+json"

// A problem to write. The status is an argument rather than something derived
// from the code, because the two halves a client switches on are the slug and
// the status: deriving one from the other would make `unauthorized` reachable at
// a status nobody documented.
type Problem struct {
	Status int

	Code api.ProblemCode

	Detail string

	Errors []api.FieldError
}

func writeProblem(w http.ResponseWriter, r *http.Request, p Problem) {
	title, ok := titles[p.Code]
	if !ok {
		title = titles[api.ProblemCodeUnavailable]
		p.Code = api.ProblemCodeUnavailable
		p.Status = 503
	}

	traceID := newTraceID()

	body := api.Problem{
		Type:   problemTypeBase + string(p.Code),
		Title:  title,
		Status: p.Status,
		Detail: p.Detail,
		Instance: instanceOf(r),
		Code:     p.Code,
		TraceID:  traceID,
	}
	if p.Status == 422 && len(p.Errors) > 0 {
		fields := p.Errors
		body.Errors = &fields
	}

	w.Header().Set("Content-Type", problemContentType)
	w.Header().Set("X-Trace-Id", traceID)
	writeProblemBody(w, r, body)
}

func instanceOf(r *http.Request) string {
	return NormaliseRequestPath(r.URL.EscapedPath())
}

func writeProblemBody(w http.ResponseWriter, r *http.Request, body api.Problem) {
	members := []string{
		jsonStringMember("type", body.Type),
		jsonStringMember("title", body.Title),
		jsonNumberMember("status", body.Status),
		jsonStringMember("detail", body.Detail),
		jsonStringMember("instance", body.Instance),
		jsonStringMember("code", string(body.Code)),
		jsonStringMember("trace_id", body.TraceID),
	}
	if body.Status == 422 && body.Errors != nil && len(*body.Errors) > 0 {
		members = append(members, `"errors":`+encodeFieldErrors(*body.Errors))
	}

	writeRawJSON(w, r, body.Status, "{"+strings.Join(members, ",")+"}")
}

func jsonStringMember(name, value string) string {
	encodedName, _ := json.Marshal(name)
	encodedValue, _ := json.Marshal(value)
	return string(encodedName) + ":" + string(encodedValue)
}

func encodeFieldErrors(fields []api.FieldError) string {
	entries := make([]string, 0, len(fields))
	for _, field := range fields {
		entries = append(entries, "{"+jsonStringMember("field", field.Field)+","+jsonStringMember("code", field.Code)+"}")
	}
	return "[" + strings.Join(entries, ",") + "]"
}

func jsonNumberMember(name string, value int) string {
	encodedName, _ := json.Marshal(name)
	return string(encodedName) + ":" + strconv.Itoa(value)
}

func writeJSON(w http.ResponseWriter, r *http.Request, status int, body any) {
	encoded, err := json.Marshal(body)
	if err != nil {
		panic(fmt.Sprintf("httpapi: %s %s: response did not encode: %v", r.Method, r.URL.Path, err))
	}

	if w.Header().Get("Content-Type") == "" {
		w.Header().Set("Content-Type", "application/json")
	}
	w.WriteHeader(status)

	if _, err := w.Write(encoded); err != nil {
		panic(fmt.Sprintf("httpapi: %s %s: response did not write: %v", r.Method, r.URL.Path, err))
	}
}

func newTraceID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("httpapi: crypto/rand is unavailable: " + err.Error())
	}
	return hex.EncodeToString(b[:])
}
