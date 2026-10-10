package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// The API key, the second credential. It authenticates on the API surface the
// way the bearer token does, and it is the one that can be revoked before it
// expires: a self-contained JWT cannot be withdrawn before its `exp`, and a
// long-lived key that is only as revocable as its own expiry is not a machine
// credential, it is a password with a longer memory.
//
// # WHAT CROSSES THE WIRE AND WHAT IS STORED
//
// The key is `caf_` followed by 43 base64url characters — 32 bytes from the
// platform CSPRNG. Only its SHA-256 is stored, so a leaked database yields
// digests and not credentials. Only its first twelve characters are ever
// displayed, and the plaintext is shown exactly once, at issue.
//
// # THE STORE IS A SEAM, AND THE v0 IMPLEMENTATION IS ONE PROCESS
//
// `ApiKeyStore` is the trait and `MemoryApiKeyStore` is the honest v0 shape:
// a key issued on one replica does not exist on the next, and every key is lost
// on restart. That is the same limitation the reference's own v0 store had, and
// closing it is `TODO(guard-07)`'s shared store — a packet, not an oversight.

// apiKeyScheme is the `Authorization` header's scheme for a key. Case-insensitive
// like the bearer scheme, per RFC 6750 §2.1's rule for credentials generally.
const apiKeyScheme = "apikey"

// apiKeyPrefix marks a key on the wire and is never stored separately: it is the
// first twelve characters of the key itself.
const apiKeyPrefix = "caf_"

// apiKeySecretBytes is the entropy behind one key. 32 bytes is 256 bits, which
// no dictionary and no brute force reaches, and it is the number the contract's
// own security scheme declares.
const apiKeySecretBytes = 32

// ApiKeyRecord is one stored key. `Hash` and `AccountID` never leave the store:
// the first is a credential digest and the second is the tenant boundary, and
// the listing is the one place every key an account holds appears at once.
type ApiKeyRecord struct {
	ID        string
	AccountID string
	Hash      string
	Prefix    string
	Scopes    []string
	RevokedAt time.Time
}

// ApiKeyStore is the persistence seam for keys. Every method that acts on a
// record takes the account, because an id a caller can hold is a handle and not
// a tenant: `Revoke` on another account's key is a no-op with no error and no
// return value, because a distinguishable failure is the same oracle one layer
// down.
type ApiKeyStore interface {
	// Issue mints a key for an account and returns the record and the plaintext.
	Issue(accountID string, scopes []string) (ApiKeyRecord, string, error)
	// ByHash looks a key up by the digest of its plaintext.
	ByHash(hash string) (ApiKeyRecord, bool)
	// List returns an account's keys, live and revoked.
	List(accountID string) ([]ApiKeyRecord, error)
	// Revoke removes one of the account's keys. Cross-tenant is a no-op.
	Revoke(accountID, id string)
}

// MemoryApiKeyStore is the v0 `ApiKeyStore`: correct, and one process.
type MemoryApiKeyStore struct {
	mu     sync.Mutex
	byID   map[string]ApiKeyRecord
	byHash map[string]ApiKeyRecord
}

// NewMemoryApiKeyStore is an empty in-memory store.
func NewMemoryApiKeyStore() *MemoryApiKeyStore {
	return &MemoryApiKeyStore{byID: map[string]ApiKeyRecord{}, byHash: map[string]ApiKeyRecord{}}
}

// Issue mints a key. The id is `key_` plus a uuid so it is not enumerable and
// does not collide with a claim name, and the scopes are copied so a caller
// cannot reach in after the fact and widen a key it holds.
func (s *MemoryApiKeyStore) Issue(accountID string, scopes []string) (ApiKeyRecord, string, error) {
	secret := make([]byte, apiKeySecretBytes)
	if _, err := rand.Read(secret); err != nil {
		return ApiKeyRecord{}, "", err
	}
	key := apiKeyPrefix + base64.RawURLEncoding.EncodeToString(secret)

	record := ApiKeyRecord{
		ID:        "key_" + uuid.NewString(),
		AccountID: accountID,
		Hash:      hashApiKey(key),
		Prefix:    key[:12],
		Scopes:    append([]string(nil), scopes...),
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.byID[record.ID] = record
	s.byHash[record.Hash] = record
	return record, key, nil
}

// ByHash looks a key up by its digest.
func (s *MemoryApiKeyStore) ByHash(hash string) (ApiKeyRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.byHash[hash]
	return record, ok
}

// List returns the account's keys, live ones first.
func (s *MemoryApiKeyStore) List(accountID string) ([]ApiKeyRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var out []ApiKeyRecord
	for _, record := range s.byID {
		if record.AccountID == accountID {
			out = append(out, record)
		}
	}
	return out, nil
}

// Revoke removes one of the account's keys. A key that is not the caller's —
// including one nobody ever issued — is a no-op: cross-tenant is absence, not a
// distinguishable status.
func (s *MemoryApiKeyStore) Revoke(accountID, id string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	record, ok := s.byID[id]
	if !ok || record.AccountID != accountID {
		return
	}
	record.RevokedAt = time.Now()
	s.byID[id] = record
	s.byHash[record.Hash] = record
}

// hashApiKey is the one digest a key's plaintext becomes, and the only form the
// store keeps. SHA-256, hex-encoded.
func hashApiKey(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

// apiKeyCredential reads the key out of an `Authorization` header, or "" when
// the header is not an API key. Case-insensitive scheme, like the bearer one.
func apiKeyCredential(authorization string) string {
	fields := strings.Fields(strings.TrimSpace(authorization))
	if len(fields) != 2 {
		return ""
	}
	if !strings.EqualFold(fields[0], apiKeyScheme) {
		return ""
	}
	return fields[1]
}

// ApiKeyGate authenticates `Authorization: ApiKey caf_…` on the API surface, and
// is mounted BEFORE the bearer gate: a caller presenting a key is judged on the
// key, the way the reference's `app.use("*", apiKeyGate)` precedes
// `app.use("/v1/*", requireJwt)`.
//
// A request with no API-key header passes straight through — the caller may be
// using a bearer token, or a cookie, or nothing, and each of those is a
// different gate's question. A request WITH one is judged on the key: an unknown
// key and a withdrawn key are one refusal, because telling them apart would
// confirm that a guessed key once existed.
//
// The principal a key sets is the account's: a key *is* the account, so `sub`
// is the account id and the scopes are the key's, in the same vocabulary as a
// token's `scope`. The key's id rides along for the limiter, which keys on it
// ahead of the address.
func ApiKeyGate(store ApiKeyStore, refuse Refuser) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// A principal already on the context means a gate in front of this one
			// authenticated the request — the outer credential gate when a route
			// table is configured. Re-authenticating would either refuse a key (its
			// header is not a bearer token) or pay for a second lookup of a key the
			// first already found.
			if PrincipalOf(r) != nil {
				next.ServeHTTP(w, r)
				return
			}

			key := apiKeyCredential(r.Header.Get("Authorization"))
			if key == "" {
				next.ServeHTTP(w, r)
				return
			}

			record, ok := store.ByHash(hashApiKey(key))
			if !ok || !record.RevokedAt.IsZero() {
				refuse(w, r, unauthorized("the API key is not valid"))
				return
			}

			accountID := record.AccountID
			principal := &Principal{
				Sub:       accountID,
				Scope:     append([]string(nil), record.Scopes...),
				AccountID: &accountID,
			}
			next.ServeHTTP(w, WithAPIKeyID(WithPrincipal(r, principal), record.ID))
		})
	}
}
