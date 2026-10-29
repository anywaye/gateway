package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/anywaye/gateway/internal/auth"
)

// GetCurrentPrincipal answers what gateway proved about the caller.
//
// It DECLINES with the reference's `404` when no verifier was configured, because
// `createApp` does not register this route at all in that case and the packet
// rules that the TypeScript answer is the correct one. A `401` would be the
// tempting answer and it is wrong twice over: nothing has been proven about the
// caller, so there is no credential to reject, and the reference does not answer
// `401` on a route it does not have.
//
// The `500` branch is the one a reader should look at twice. A nil principal on a
// request that REACHED this handler means the gate ran and let the request through
// without setting one — a wiring mistake — and there is no problem-document code
// for "this deployment is broken". core's `internal_error` is the code identity
// already answers with for the same thing (`identity/internal/httpapi`), so it is
// the one reused here rather than inventing a fourth.
func (s *server) GetCurrentPrincipal(w http.ResponseWriter, r *http.Request) {
	if s.verifier == nil {
		writeV0NotFound(w, r)
		return
	}

	principal := auth.PrincipalOf(r)
	if principal == nil {
		CaptureError(fmt.Errorf("principal: unexpected nil principal"), r)
		writeProblem(w, r, Problem{
			Status: http.StatusInternalServerError,
			Code:   "internal_error",
			Detail: "unexpected server error",
		})
		return
	}

	writePrincipal(w, r, principal)
}

func writePrincipal(w http.ResponseWriter, r *http.Request, principal *auth.Principal) {
	body, err := renderPrincipal(principal)
	if err != nil {
		CaptureError(fmt.Errorf("principal: render failed"), r)
		writeRawJSON(w, r, http.StatusInternalServerError, `{"error":"internal_error","message":"unexpected server error"}`)
		return
	}
	writeRawJSON(w, r, http.StatusOK, body)
}

func renderPrincipal(principal *auth.Principal) (string, error) {
	sub, err := json.Marshal(principal.Sub)
	if err != nil {
		return "", err
	}

	scopes := make([]json.RawMessage, 0, len(principal.Scope))
	for _, scope := range principal.Scope {
		encoded, err := json.Marshal(scope)
		if err != nil {
			return "", err
		}
		scopes = append(scopes, encoded)
	}
	scopeList, err := json.Marshal(scopes)
	if err != nil {
		return "", err
	}

	accountID := ""
	if principal.AccountID != nil {
		encoded, err := json.Marshal(*principal.AccountID)
		if err != nil {
			return "", err
		}
		accountID = ",\"accountId\":" + string(encoded)
	}

	claims, err := principal.Claims.MarshalJSON()
	if err != nil {
		return "", err
	}

	return "{\"sub\":" + string(sub) +
		",\"scope\":" + string(scopeList) +
		accountID +
		",\"claims\":" + string(claims) + "}", nil
}
