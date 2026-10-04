package httpapi

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/cafaye/gateway/internal/api"
)

// core's error envelope, ported from `src/problem.ts`: RFC 9457 problem+json
// with cafaye's extensions (`core/docs/openapi-conventions.md`, "Error
// envelope"). No service invents its own error body, and this is the one every
// rejection in gateway goes through.
//
// Only the codes gateway can actually produce, and the list is the generated
// one rather than a hand-written copy: `openapi/v1.yaml`'s `Problem.code`
// enumerates them, so a code the document does not name cannot be written and a
// code the document adds is a missing row here that `TestEveryProblemCodeHasATitle`
// names. `src/problem.ts` carries the same list with the same note — the
// reserved list is longer, and the codes here are not a closed set for the
// platform, only for this repository.
//
// `invalid_json`, `account_locked` and `payload_too_large` are not on core's
// reserved list. They are the slugs identity already answers with
// (`identity/internal/httpapi/problem.go`), and one vocabulary across the
// platform beats a gateway-private synonym for the same failure. Recorded as a
// DECISION NEEDED in cafaye.yml, and carried over unchanged.

// problemTypeBase is where every problem's `type` lives. The document pins it:
// the type is a stable URI and the `code` is the slug under it, so a client can
// switch on one and print the other.
const problemTypeBase = "https://errors.cafaye.com/"

// titles is the fixed human-readable summary per code, and it is exhaustive over
// the document's enum rather than a lookup with a fallback. `src/problem.ts`
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
	// The status this answers with. `api.ProblemStatus` rather than `int`,
	// because it is the document's enum and this file cannot be handed a 418.
	Status api.ProblemStatus

	// The slug, which is also the last segment of `type`.
	Code api.ProblemCode

	// What happened, in terms the caller can act on. Never an internal reason:
	// a host, a port, a query, or a parser's opinion goes to the log instead.
	// Every call site is a fixed string for that reason — see the 401s and 503s
	// in `src/middleware/jwt.ts`, which this envelope is written to serve.
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
		Instance: r.URL.Path,
		Code:     p.Code,
		TraceID:  traceID,
	}
	// Set last and only for a 422, so the key is absent rather than empty: a
	// client rendering `errors` must be able to tell "no fields failed" from
	// "this response is not about fields".
	if p.Status == api.N422 && len(p.Errors) > 0 {
		fields := p.Errors
		body.Errors = &fields
	}

	w.Header().Set("Content-Type", problemContentType)
	w.Header().Set("X-Trace-Id", traceID)
	writeJSON(w, r, int(p.Status), body)
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
	if w.Header().Get("Content-Type") == "" {
		w.Header().Set("Content-Type", "application/json")
	}
	w.WriteHeader(status)
	// A marshalling failure here means the handler built a body the document
	// does not allow. The header is already written, so the only honest thing
	// left is to stop rather than emit a truncated body a client would parse.
	if err := json.NewEncoder(w).Encode(body); err != nil {
		panic(fmt.Sprintf("httpapi: %s %s: response did not encode: %v", r.Method, r.URL.Path, err))
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
