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

// core's error envelope, ported from `src/problem.ts` (removed at cutover): RFC 9457 problem+json
// with anywaye's extensions (`core/docs/openapi-conventions.md`, "Error
// envelope"). No service invents its own error body, and this is the one every
// rejection in gateway goes through.
//
// Only the codes gateway can actually produce, and the list is the generated
// one rather than a hand-written copy: `openapi/v1.yaml`'s `Problem.code`
// enumerates them, so a code the document does not name cannot be written and a
// code the document adds is a missing row here that `TestEveryProblemCodeHasATitle`
// names. `src/problem.ts` (removed at cutover) carries the same list with the same note — the
// reserved list is longer, and the codes here are not a closed set for the
// platform, only for this repository.
//
// `invalid_json`, `account_locked` and `payload_too_large` are not on core's
// reserved list. They are the slugs identity already answers with
// (`identity/internal/httpapi/problem.go`), and one vocabulary across the
// platform beats a gateway-private synonym for the same failure. Recorded as a
// DECISION NEEDED in anywaye.yml, and carried over unchanged.

// problemTypeBase is where every problem's `type` lives. The document pins it:
// the type is a stable URI and the `code` is the slug under it, so a client can
// switch on one and print the other.
const problemTypeBase = "https://docs.anywaye.com/errors/"

// titles is the fixed human-readable summary per code, and it is exhaustive over
// the document's enum rather than a lookup with a fallback. `src/problem.ts` (removed at cutover)
// falls back to `undefined` for an unknown code, which renders the key as absent
// from the JSON — so a code nobody had written a title for produced a document
// the contract does not describe, silently. Here the map is total by
// construction (`TestEveryProblemCodeHasATitle` fails the build if it is not),
// and `writeProblem` refuses rather than inventing a title if one is missing at
// run time.
//
// A title is a summary, not per-occurrence detail: `detail` is that.
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

// problemContentType is NOT application/json, and the document says so on every
// non-2xx response. A client that switches on the content type — which is the
// whole reason RFC 9457 exists — reads "application/json" as a service that
// ignored the convention, and this repository's rule is that no service invents
// its own error body.
const problemContentType = "application/problem+json"

// A problem to write. The status is an argument rather than something derived
// from the code, because the two halves a client switches on are the slug and
// the status: deriving one from the other would make `unauthorized` reachable at
// a status nobody documented.
type Problem struct {
	// The status this answers with. A plain `int`: the document declares
	// `Problem.status` as `type: integer` with no enum — the fleet convention
	// (`any contract lint` refuses numeric enums) — so there is no generated
	// type to reach for, and the wire shape is unchanged either way.
	Status int

	// The slug, which is also the last segment of `type`.
	Code api.ProblemCode

	// What happened, in terms the caller can act on. Never an internal reason:
	// a host, a port, a query, or a parser's opinion goes to the log instead.
	// Every call site is a fixed string for that reason — see the 401s and 503s
	// in `src/middleware/jwt.ts` (removed at cutover), which this envelope is written to serve.
	Detail string

	// Per-field failures, for a 422 and nothing else. Dropped from any other
	// status below, so a caller cannot widen core's rule by passing them.
	Errors []api.FieldError
}

// writeProblem renders a problem response: the envelope, the status, and an
// `X-Trace-Id` header that matches the `trace_id` in the body.
//
// `detail` is written by the caller and is the only place a human-readable
// reason is chosen, which is why every caller is a fixed string rather than an
// interpolated error.
func writeProblem(w http.ResponseWriter, r *http.Request, p Problem) {
	title, ok := titles[p.Code]
	if !ok {
		// An undeclared code is a defect in this repository. The caller still
		// gets a document the contract describes: `500` with core's
		// `internal`… which gateway does not produce. So this rewrites to the
		// code it *can* justify rather than emitting an invented title, and the
		// rewrite is what `TestEveryProblemCodeHasATitle` exists to make
		// unreachable. Panicking would be honest and would turn a defect into a
		// dropped connection, which is a worse answer than a wrong-but-valid
		// document.
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
		// The path, never the query: a caller who put a credential in one
		// should not find it echoed back in an error body.
		Instance: instanceOf(r),
		Code:     p.Code,
		TraceID:  traceID,
	}
	// Set last and only for a 422, so the key is absent rather than empty: a
	// client rendering `errors` must be able to tell "no fields failed" from
	// "this response is not about fields".
	if p.Status == 422 && len(p.Errors) > 0 {
		fields := p.Errors
		body.Errors = &fields
	}

	w.Header().Set("Content-Type", problemContentType)
	w.Header().Set("X-Trace-Id", traceID)
	writeProblemBody(w, r, body)
}

// instanceOf is the path a problem document names.
//
// ## THE PATH IS NORMALISED, AND THAT IS NOT TIDINESS
//
// The reference writes `new URL(c.req.url).pathname`, and a WHATWG URL parser
// resolves dot segments AND keeps the request line's own spelling of every other
// character: `/v1/../v1/me` is `/v1/me` there, `/v1/pantry/a%2Fb` is
// `/v1/pantry/a%2Fb` there and `/v1/pantry/a/b` here. Go's `net/url` resolves
// nothing and keeps two spellings, `Path` decoded and `EscapedPath` raw.
//
// It is `EscapedPath`, and the equivalence check is what said so — the reference's
// own answer for `/v1/pantry/caf%C3%A9%20au%20lait` is
// `/v1/pantry/caf%C3%A9%20au%20lait`, with the escapes intact.
//
// That is a divergence in what a *caller is told*, not only in what a service
// receives, and it is worth having the right answer for: a caller who sent
// `/v1/pantry/../secret` and is handed `instance: "/v1/pantry/../secret"` cannot
// correlate the refusal with their own request log, and two answers for one request
// is the thing `trace_id` exists to prevent.
//
// So the same `NormaliseRequestPath` the pass-through routes on is applied here.
// There is one normalisation function in this package on purpose: two would be two
// spellings of "what path is this", and a routing rule tightened in one of them
// would leave the other naming something else.
func instanceOf(r *http.Request) string {
	return NormaliseRequestPath(r.URL.EscapedPath())
}

// writeProblemBody renders the envelope in the document's own field order.
//
// ## THE ORDER IS THE DOCUMENT'S, AND `encoding/json` WOULD GET IT WRONG
//
// `openapi/v1.yaml`'s `Problem.required` is `[type, title, status, detail,
// instance, code, trace_id]` — in that order — and `src/problem.ts` (removed at cutover) writes its
// object literal in that order. `api.Problem` is a **generated** struct whose
// fields are in alphabetical order, so `json.Marshal` on it produced
// `{"code":…,"detail":…,"instance":…,"status":…,"title":…,"trace_id":…,"type":…}`.
//
// That is the same trap `/readyz` hit and for the same reason: `encoding/json`
// honors struct field order and the generator writes fields sorted. The
// equivalence check found it on the first run of a single 503 case — every problem
// document in the comparison differed on nothing else — and every client parses
// both spellings identically, which is exactly why it would have shipped.
//
// So the object is built here, by hand, in the document's order, with every value
// escaped by `json.Marshal` and only the braces, the commas and the keys written
// literally. `errors` goes last and only for a 422, which is where the document
// puts it too.
func writeProblemBody(w http.ResponseWriter, r *http.Request, body api.Problem) {
	// Encoded first, joined second. Building the members as complete
	// `"key":value` fragments and joining them is what keeps the separator in one
	// place: the first draft wrote each member with its own trailing comma and
	// produced `{"type":"…""title":…}`, which every test that decodes a problem
	// document noticed at once.
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

// jsonStringMember is one `"key":"value"` pair, both encoded.
//
// Encoded rather than interpolated, so a detail containing a quote is a detail with
// a quote in it rather than a malformed document.
func jsonStringMember(name, value string) string {
	encodedName, _ := json.Marshal(name)
	encodedValue, _ := json.Marshal(value)
	return string(encodedName) + ":" + string(encodedValue)
}

// encodeFieldErrors renders the `errors` array in the reference's order, which is
// `{ field, code }` per entry.
//
// NOT `json.Marshal`, and this is the same trap as the seven members above applied
// one level down: `api.FieldError` is a GENERATED struct, so its fields are
// alphabetical — `code` before `field` — and `internal/equivalence` compared bodies
// BYTE FOR BYTE. The proxy packet, which owns this function, had no 422 to compare
// and marshaled the array; the BFF packet, which did, hand-rendered it. Taking one
// side of the merge wholesale dropped the other's fix, and this is the commit that
// puts it back with a note on why it is not the obvious one line.
//
// `errors` is appended LAST, after `trace_id`, and that ordering is the
// reference's too.
func encodeFieldErrors(fields []api.FieldError) string {
	entries := make([]string, 0, len(fields))
	for _, field := range fields {
		entries = append(entries, "{"+jsonStringMember("field", field.Field)+","+jsonStringMember("code", field.Code)+"}")
	}
	return "[" + strings.Join(entries, ",") + "]"
}

// jsonNumberMember is one `"key":value` where the value is a JSON number and not a
// string.
//
// It exists because the obvious thing — routing `status` through `jsonStringMember`
// — writes `"status":"503"`, and the first run of the suite said so on every problem
// document this service produces. `status` is `type: integer` in
// `openapi/v1.yaml`, and a string would be a document the contract does not describe.
func jsonNumberMember(name string, value int) string {
	encodedName, _ := json.Marshal(name)
	return string(encodedName) + ":" + strconv.Itoa(value)
}

// writeJSON writes a body, and is where the JSON content type is decided once
// rather than per handler.
//
// The type is set ONLY when the caller has not already chosen one, and that
// conditional is not defensive tidiness — it is the whole difference between the
// two envelopes core's conventions talk about. `writeProblem` sets
// `application/problem+json` and then calls this; an unconditional `Set` here
// overwrote it with `application/json`, and every problem document in the
// service would have been served with the media type that says "this is not a
// problem document". `TestAProblemIsTheDocumentedEnvelope` is what found it, and
// it found it because that test asserts the content type rather than decoding
// the body and stopping there.
func writeJSON(w http.ResponseWriter, r *http.Request, status int, body any) {
	// `json.Marshal` and NOT `json.NewEncoder(w).Encode`, and the difference is a
	// byte on every response the service writes. `Encode` appends a newline
	// after the value — a convenience for writing a stream of values to a file —
	// and Hono's `c.json()` does not. So `Encode` produced
	// `{"status":"ok"}\n` where the reference produces `{"status":"ok"}`, and 63
	// of the 72 comparisons in `internal/equivalence` failed on that one byte
	// before anything else in this package was trusted. A trailing newline is
	// legal JSON and every client parses it identically, which is exactly why it
	// is the kind of difference that ships unnoticed and is worth the byte.
	//
	// `Marshal` first, `WriteHeader` second, is the other half: a marshaling
	// failure means the handler built a body the document does not allow, and
	// doing it in this order means nothing has been written yet. There is
	// therefore nothing half-sent for a client to parse.
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

// newTraceID is 32 hex characters, the shape core's conventions show.
//
// This is a correlation id for a single failed response, not a distributed
// trace: gateway has no tracing yet, and a request that never reached a handler
// still has to leave something a caller can quote in a bug report.
func newTraceID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand does not fail in any way this service can recover from,
		// and an id that is not unique costs support its search. Panic rather
		// than serve responses whose trace ids may collide.
		panic("httpapi: crypto/rand is unavailable: " + err.Error())
	}
	return hex.EncodeToString(b[:])
}
