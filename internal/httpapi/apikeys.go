package httpapi

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/anywaye/gateway/internal/api"
	"github.com/anywaye/gateway/internal/auth"
)

// The three API-key management routes, on the API surface behind the auth gates.
//
// # WHY THE ACCOUNT IS NEVER A FIELD
//
// Every route here acts on the caller's OWN account, taken from the verified
// principal. `POST /v1/api-keys` in particular mints a credential, and a document
// that let a caller name the account it mints for would describe the cross-tenant
// bug as a feature. So the account is read off the principal the auth gate
// established and is not a field anywhere.
//
// # WHAT HAPPENS WHEN THERE IS NO AUTH SURFACE
//
// With neither a verifier nor a key store configured, no gate is mounted on
// `/v1/*` and an anonymous request reaches these handlers. That is the same
// "operation not here" shape as `/v1/me` with no verifier and the four `/auth/*`
// routes with no identity: the honest answer is the v0 `404`, because the route
// cannot establish the one thing it needs. The shipped binary always configures a
// verifier, so this is the bare-constructor shape and not a deployed one.

// requireApiKeyStore is the store these routes read, or the v0 `404` when there is
// none — the same "operation not here" shape as `/v1/me` with no verifier.
func (s *server) requireApiKeyStore(w http.ResponseWriter, r *http.Request) auth.ApiKeyStore {
	if s.apiKeys == nil || s.apiKeys.Store == nil {
		notBuilt(w, r)
		return nil
	}
	return s.apiKeys.Store
}

// authenticatedAccount is the account these routes act on, or false when the
// request cannot be served.
func (s *server) authenticatedAccount(w http.ResponseWriter, r *http.Request) (string, bool) {
	if s.verifier == nil && s.apiKeys == nil {
		notBuilt(w, r)
		return "", false
	}

	principal := auth.PrincipalOf(r)
	if principal == nil {
		// Unreachable while a gate is mounted above these routes on `/v1/*`, and
		// the check is here because "unreachable" is a claim about code in another
		// file. A `200` with a null body would be the answer nobody wants to debug.
		writeProblem(w, r, Problem{
			Status: http.StatusInternalServerError,
			Code:   "internal_error",
			Detail: "unexpected server error",
		})
		return "", false
	}

	if principal.AccountID != nil {
		return *principal.AccountID, true
	}
	// A key is the account, and a token with no `account_id` claim belongs to a user
	// with no workspace — the user *is* the account. The limiter makes the same
	// fallback (`accountIdOf`), so the bucket and the tenant boundary agree.
	return principal.Sub, true
}

// CreateAPIKey mints a key for the caller's own account.
func (s *server) CreateAPIKey(w http.ResponseWriter, r *http.Request) {
	store := s.requireApiKeyStore(w, r)
	if store == nil {
		return
	}
	account, ok := s.authenticatedAccount(w, r)
	if !ok {
		return
	}

	var body api.CreateAPIKeyRequest
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&body); err != nil {
		writeProblem(w, r, Problem{Status: 400, Code: api.ProblemCodeInvalidJSON, Detail: "the request body is not valid JSON"})
		return
	}

	// The one field, and it must name at least one scope. An empty list is a
	// credential with nothing it can do, which is not a machine credential — it is
	// a mistake, and the refusal is a `422` with the field named.
	if len(body.Scopes) == 0 {
		writeProblem(w, r, Problem{Status: 422, Code: api.ProblemCodeValidationFailed, Detail: "scopes must name at least one scope"})
		return
	}
	for _, scope := range body.Scopes {
		if strings.TrimSpace(scope) == "" || strings.ContainsAny(scope, " \t\n\r") {
			writeProblem(w, r, Problem{Status: 422, Code: api.ProblemCodeValidationFailed, Detail: "each scope must be a single non-empty token"})
			return
		}
	}

	record, key, err := store.Issue(account, body.Scopes)
	if err != nil {
		writeProblem(w, r, Problem{Status: 503, Code: api.ProblemCodeUnavailable, Detail: "the key could not be minted"})
		return
	}

	writeJSON(w, r, http.StatusCreated, apiKeyIssued{Key: key, Prefix: record.Prefix, ID: record.ID})
}

// ListAPIKeys lists the caller's own keys, live and revoked.
func (s *server) ListAPIKeys(w http.ResponseWriter, r *http.Request) {
	store := s.requireApiKeyStore(w, r)
	if store == nil {
		return
	}
	account, ok := s.authenticatedAccount(w, r)
	if !ok {
		return
	}

	records, err := store.List(account)
	if err != nil {
		writeProblem(w, r, Problem{Status: 503, Code: api.ProblemCodeUnavailable, Detail: "the keys could not be listed"})
		return
	}

	summaries := make([]apiKeySummary, 0, len(records))
	for _, record := range records {
		var revokedAt *time.Time
		if !record.RevokedAt.IsZero() {
			revokedAt = &record.RevokedAt
		}
		summaries = append(summaries, apiKeySummary{ID: record.ID, Prefix: record.Prefix, Scopes: record.Scopes, RevokedAt: revokedAt})
	}
	writeJSON(w, r, http.StatusOK, summaries)
}

// RevokeAPIKey revokes one of the caller's own keys.
//
// The `204` is unconditional and that is a decision, not an omission: a key that is
// not the caller's — including one nobody ever issued — is a `204` no-op, because
// cross-tenant is absence and a `403` would confirm that a guessed id once existed.
// The store's `Revoke` is where that is enforced.
func (s *server) RevokeAPIKey(w http.ResponseWriter, r *http.Request, id api.APIKeyID) {
	store := s.requireApiKeyStore(w, r)
	if store == nil {
		return
	}
	account, ok := s.authenticatedAccount(w, r)
	if !ok {
		return
	}

	store.Revoke(account, id)
	w.WriteHeader(http.StatusNoContent)
}

// apiKeyIssued is the mint notice. The plaintext `key` appears exactly once.
type apiKeyIssued struct {
	Key    string `json:"key"`
	Prefix string `json:"prefix"`
	ID     string `json:"id"`
}

// apiKeySummary is one key as the listing shows it — never the hash.
type apiKeySummary struct {
	ID        string     `json:"id"`
	Prefix    string     `json:"prefix"`
	Scopes    []string   `json:"scopes"`
	RevokedAt *time.Time `json:"revokedAt"`
}
