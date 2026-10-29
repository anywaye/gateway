package testkeys

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	KeyID = "test-key-1"

	Issuer = "https://identity.test"

	Audience = "gateway"

	Subject = "00000000-0000-4000-8000-000000000001"
)

// Clock is the fixed instant a verifier built by `Fixture.Verifier` reads.
//
// # WHY IT EXISTS, AND WHY IT IS NOT JUST `time.Now`
//
// The cache TTL and the `exp`/`nbf` checks are both clock-driven, and a test that
// wanted to cross a window boundary would otherwise have to sleep. A fixed clock
// makes both testable in microseconds.
//
// It is also what lets two independently-built implementations be compared: the Go
// gateway and the TypeScript reference each verify a token the runner minted, and
// both must reach the same answer about `exp`. With two wall clocks milliseconds
// apart, a token whose `exp` sits on the boundary would be expired on one side and
// valid on the other, and the comparison would fail on a difference neither side
// chose. So every claim a test mints is relative to THIS instant, and so is every
// verifier.
var Clock = time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)

const (
	Expired = -time.Hour
	Valid   = time.Hour
)

// Fixture is one key pair, the JWKS document it publishes, and a server that
// publishes it.
//
// The server is a parameter rather than a package-level singleton so two tests in
// one process do not share a document — a fixture whose state is global is a fixture
// whose tests cannot run in parallel, and `go test` runs a package's tests in
// parallel by default only when they say `t.Parallel()`. Each `NewFixture` gets its
// own listener and its own key.
type Fixture struct {
	Private *rsa.PrivateKey
	Public  *rsa.PublicKey

	Document []byte

	URL string

	DocumentURL string

	server *httptest.Server

	mu       sync.Mutex
	fetched  int
	failing  bool
	failWith int
}

// NewFixture generates a key pair and publishes it as a JWKS.
//
// A 2048-bit key, because that is the smallest size any current JWKS endpoint is
// likely to publish and a fixture smaller than that would let a verifier accept a
// key size no real issuer uses.
func NewFixture(t *testing.T) *Fixture {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating a 2048-bit test key: %v", err)
	}

	document, err := json.Marshal(map[string]any{
		"keys": []any{map[string]any{
			"kty": "RSA",
			"use": "sig",
			"alg": "RS256",
			"kid": KeyID,
			"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes()),
		}},
	})
	if err != nil {
		t.Fatalf("encoding the JWKS document: %v", err)
	}

	return &Fixture{Private: key, Public: &key.PublicKey, Document: document}
}

// Serve publishes the key set over HTTP on an ephemeral port, and stops the server
// when the test ends.
//
// `httptest.NewServer` rather than a bare `net.Listen` because the test needs a real
// HTTP client to fetch over: the verifier's whole claim is that it fetches a key set
// from a URL, and a `RoundTripper` stubbed to return `document` is not a fetch.
func (f *Fixture) Serve(t *testing.T) *Fixture {
	t.Helper()

	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.fetched++
		failing, status, document := f.failing, f.failWith, f.Document
		f.mu.Unlock()

		if failing {
			w.WriteHeader(status)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(document)
	}))
	t.Cleanup(f.server.Close)

	f.URL = f.server.URL + "/.well-known/jwks.json"
	f.DocumentURL = f.URL
	return f
}

// Fetches is how many times the key set has been asked for.
//
// The single-flight assertions read this and the alternative — a log line, or an
// inferred count from a failure — would make "exactly one fetch" a claim about a
// test rather than a measurement of one.
func (f *Fixture) Fetches() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.fetched
}

// FailWith makes the key-set endpoint answer a status instead of a document.
//
// Used for the identity-is-down case: `503` is the shape a real outage has, and
// `200` with a login page is the shape a misconfigured proxy has. Both are worth
// driving, and only one is a status code.
//
// `0` is NOT a status and is spelled as HEALING rather than as a magic value: a
// test that drives an outage and then recovers needs the recovery to be a fact
// rather than a number nobody can read.
func (f *Fixture) FailWith(status int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failing, f.failWith = status != 0, status
}

// Heal puts the key-set endpoint back to serving the document.
func (f *Fixture) Heal() { f.FailWith(0) }

// Claims is a token's payload, as a test writes it.
//
// A struct rather than a map so a field cannot be spelled wrong and silently become
// an extra claim: a fixture that sends `{"exp":…,"sub":…,"scope":…}` because a test
// wrote three map keys is a fixture whose claim set is invisible to a reader.
type Claims struct {
	Issuer   string
	Audience string
	Subject  string

	ExpiresIn time.Duration
	NotBefore time.Duration

	AccountID string

	Scope string

	KeyID string

	Algorithm string

	RawClaims map[string]any
}

// Publish adds a key to the document this fixture serves, under its own `kid`.
//
// It is the rotation a test drives: the set gateway holds does not carry the new
// key, and the only way it learns that identity now publishes it is the unknown-`kid`
// refresh. `Publish` is separate from `Serve` for exactly that reason — a fixture
// whose document could only be written once could not express a rotation at all.
func (f *Fixture) Publish(t *testing.T, kid string, key *rsa.PublicKey) {
	t.Helper()

	var document struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(f.Document, &document); err != nil {
		t.Fatalf("decoding the fixture's own document to add a key: %v", err)
	}

	document.Keys = append(document.Keys, map[string]any{
		"kty": "RSA",
		"use": "sig",
		"alg": "RS256",
		"kid": kid,
		"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
	})

	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatalf("re-encoding the JWKS document: %v", err)
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	f.Document = encoded
}

// NewKey generates a second key pair, for a rotation.
//
// Separate from `Publish` because publishing a key and SIGNING with it are two
// decisions a test makes at two different moments: the point of a rotation test is
// that a token signed by a key the cached set does not carry is admitted after one
// refresh, and minting it before publishing is what makes that observable.
func NewKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating a second 2048-bit test key: %v", err)
	}
	return key
}

// Mint signs a token and returns it in compact JWS form.
func (f *Fixture) Mint(t *testing.T, claims Claims) string {
	t.Helper()
	return MintWith(t, f.Private, claims)
}

// MintWith signs a token with a key that is not necessarily this fixture's.
//
// A package function rather than a method because the point of a rotation test is a
// token signed by a key the VERIFIER's set does not carry, and expressing that as a
// method on the fixture whose set it is not in would read as if it were.
func MintWith(t *testing.T, key *rsa.PrivateKey, claims Claims) string {
	t.Helper()

	header := map[string]any{"typ": "JWT", "alg": "RS256"}
	if claims.Algorithm != "" {
		header["alg"] = claims.Algorithm
	}
	header["kid"] = KeyID
	if claims.KeyID != "" {
		header["kid"] = claims.KeyID
	}

	payload := map[string]any{
		"iss": or(claims.Issuer, Issuer),
		"aud": or(claims.Audience, Audience),
		"sub": or(claims.Subject, Subject),
	}
	if claims.ExpiresIn != 0 {
		payload["exp"] = Clock.Add(claims.ExpiresIn).Unix()
	}
	if claims.NotBefore != 0 {
		payload["nbf"] = Clock.Add(claims.NotBefore).Unix()
	}
	if claims.AccountID != "" {
		payload["account_id"] = claims.AccountID
	}
	if claims.Scope != "" {
		payload["scope"] = claims.Scope
	}
	for name, value := range claims.RawClaims {
		payload[name] = value
	}

	encodedHeader, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("encoding the token header: %v", err)
	}
	encodedPayload, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("encoding the token payload: %v", err)
	}

	signingInput := base64.RawURLEncoding.EncodeToString(encodedHeader) +
		"." + base64.RawURLEncoding.EncodeToString(encodedPayload)

	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("signing the token: %v", err)
	}

	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

// Compact joins three segments a caller supplies verbatim, base64url-encoding each
// unless it starts with `!`.
//
// It exists so a test can produce a compact form jose would refuse BEFORE it looks
// at a key: two segments, four segments, a segment that is not base64, a signature
// that is not the right length. `Mint` cannot produce any of those, and a verifier
// whose header parsing is untested is a verifier whose `alg: none` path is untested.
func Compact(segments ...string) string {
	encoded := make([]string, 0, len(segments))
	for _, segment := range segments {
		if strings.HasPrefix(segment, "!") {
			encoded = append(encoded, strings.TrimPrefix(segment, "!"))
			continue
		}
		encoded = append(encoded, base64.RawURLEncoding.EncodeToString([]byte(segment)))
	}
	return strings.Join(encoded, ".")
}

// Segment encodes one JSON document the way a JWT encodes it, for a test building a
// compact form by hand.
func Segment(document string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(document))
}

func or(value, fallback string) string {
	if value != "" {
		return value
	}
	return fallback
}
