// `GET /v1/me` — the route that proves the auth chain is wired.
//
// # IT HAS NO BEHAVIOUR OF ITS OWN, AND THAT IS THE POINT
//
// No forwarding, no transformation, no decision. It exists so a deployment can be
// checked end to end without asking a service for anything: what it answers is
// exactly what gateway proved about the caller and nothing more.
//
// # WHY IT IS RENDERED BY HAND
//
// `api.Principal` is the generated type and this file deliberately does NOT hand
// it to `writeJSON`. Two reasons, and both were measured rather than argued:
//
//  1. **Key order.** `oapi-codegen` writes the struct's fields alphabetically
//     (`AccountID, Claims, Scope, Sub`), so `writeJSON` renders
//     `{"accountId":…,"claims":{…},"scope":[…],"sub":…}`. `src/middleware/jwt.ts`
//     builds the object literal as `{sub, scope, accountId, claims}`, and Hono's
//     `c.json()` preserves insertion order, so the reference renders
//     `{"sub":…,"scope":[…],"accountId":…,"claims":{…}}`. `internal/equivalence`
//     compares bodies byte for byte, so this one line of ordering is a difference
//     on every request. The substrate hit the same wall for `/readyz`'s `deps`
//     and solved it the same way — `orderedDeps` — and the reason is the same one:
//     the order a caller wrote is the order the response carries.
//
//  2. **Claim order.** `Claims` is `map[string]interface{}` in the generated type,
//     and `encoding/json` sorts a map's keys. The reference echoes the token's own
//     payload order. `auth.Claims` keeps that order (see `internal/auth/claims.go`)
//     and marshals itself, so this file writes the member it was given.
//
// The `sub, scope, accountId, claims` sequence below is therefore NOT
// alphabetical and MUST NOT be sorted. `TestThePrincipalBodyIsNotAlphabetical`
// fails if it ever becomes one, because that failure is invisible to every other
// test in this repository except the equivalence check — which is precisely why a
// local assertion is needed.
package httpapi

import (
	"encoding/json"
	"net/http"

	"github.com/cafaye/gateway/internal/api"
	"github.com/cafaye/gateway/internal/auth"
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
		// Unreachable while `Require` is mounted above this route on `/v1/*`, and
		// the check is here because "unreachable" is a claim about code in another
		// file and this file is what a caller reads when it is wrong. A `200` with
		// a null body would be the answer nobody wants to debug.
		writeProblem(w, r, Problem{
			Status: api.ProblemStatus(http.StatusInternalServerError),
			Code:   "internal_error",
			Detail: "unexpected server error",
		})
		return
	}

	writePrincipal(w, r, principal)
}

// writePrincipal renders the four members in the reference's order.
//
// Hand-built rather than marshalled from a struct, and `renderPrincipal` carries
// the reason. Every value that could carry a character a caller chose goes through
// `json.Marshal`: the `sub`, each scope, and the `account_id`. So this is not a
// place a caller can inject a byte into a body, and the file says so rather than
// leaving it as an assumption.
func writePrincipal(w http.ResponseWriter, r *http.Request, principal *auth.Principal) {
	body, err := renderPrincipal(principal)
	if err != nil {
		// Only reachable if a claim carried a value `encoding/json` refuses, which
		// cannot happen for a payload that parsed. A `500` with the v0 envelope is
		// the honest answer for a body that could not be built.
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

	// `accountId` is ABSENT, not null, when the claim is absent — `omitempty` on the
	// generated `*string` and `accountId: undefined` in the reference both drop the
	// key, and a client rendering `accountId` must be able to tell "no account claim"
	// from "the account is null".
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
