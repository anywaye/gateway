package httpapi

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/anywaye/gateway/internal/auth"
)


// AssertionHeader is the header the assertion crosses in.
//
// A header of its own rather than a second `Authorization`, and the reason is the
// same one `proxy.go` gives for dropping the caller's: the table entry's `Token`
// is already in `authorization`, it is a *different* credential, and asking one
// header to carry two answers to two questions is how a service ends up reading
// the wrong one. The name is namespaced because it is not a standard header and
// no proxy in the fleet should have an opinion about it.
const AssertionHeader = "x-anywaye-principal"

// DefaultAssertionIssuer is what gateway asserts when nothing is configured: an
// origin, like identity's.
const DefaultAssertionIssuer = "https://gateway.localhost"

const (
	DefaultAssertionTTL = 120 * time.Second
	MaxAssertionTTL     = 600 * time.Second
)

// ReservedClaims are the claims gateway owns, and which an entry naming one is
// refused for.
//
// These are the envelope: the audience that binds the assertion to an upstream,
// the lifetime that keeps it short-lived, and the issuer that says which gateway
// minted it. An operator who wrote one of these names into a route entry has not
// decided what they meant — the same reasoning `ValidateRouteTable` applies to an
// entry that is `public` *and* carries a `token`.
//
// `sub` is deliberately NOT here. It is the caller, it is verified, and half the
// upstreams in a gateway exist to answer questions about it.
var ReservedClaims = []string{"iss", "aud", "exp", "nbf", "iat", "jti"}

func isReservedClaim(name string) bool {
	for _, reserved := range ReservedClaims {
		if name == reserved {
			return true
		}
	}
	return false
}

// Principal is what a credential gate established about the caller.
//
// ## AN ALIAS, AND WHY IT USED TO BE A STRUCT
//
// This was a local `struct { Sub string; Claims map[string]any }`, written by the
// pass-through packet with a note that the packet porting token verification would
// own the question of what a principal carries. That packet has landed, so this is
// `auth.Principal` under the name the pass-through already uses — one principal,
// built once by the verifier, read by the assertion minter and rendered by
// `/v1/me`.
//
// Two types would have been two answers to "who is this caller", and the gap
// between them is exactly where a security property goes missing: the
// pass-through would assert about a principal the verifier never saw, or the
// verifier would prove a caller and the assertion would drop what it proved. An
// alias makes that unrepresentable rather than merely unlikely.
//
// ## WHY THE CLAIM SET IS STILL THE VERBATIM ONE
//
// `auth.Principal.Claims` is the payload **as the token carried it**, and that is
// the load-bearing part for the assertion: the minter copies claims out of it
// rather than out of a typed struct, so `scope` stays the space-separated string
// identity signed rather than becoming the array gateway parsed it into, and
// `github_id` — which is not a field gateway knows — crosses without gateway
// having to be taught its name. gateway is a signer here, not a translator:
// reshaping a claim would make the assertion a *different* claim from the one
// identity verified, which is a second thing to get right for no gain.
//
// It is read for claim *names*, and never indexed by a name gateway owns —
// `checkClaimName` refuses those in a route entry, and the envelope is written
// first so a claim could not overwrite it even if that check were removed. Hence
// `Lookup` rather than an index: `Claims` keeps the token's order, and an order-
// preserving type cannot be indexed without pretending it is a map.
//
// ## WHY IT GREW
//
// The scope list and the account id were "deliberately absent" here, on the
// grounds that nothing read them yet. `internal/ratelimit` reads the account —
// that is what it keys its buckets on — and `/v1/me` renders both. They are not a
// widening of the pass-through's idea of a principal; they are the verifier's idea
// of one, and having two of those was the defect.
type Principal = auth.Principal

// AssertionKey is a gateway signing key: the pair, and the id upstreams select it
// by.
type AssertionKey struct {
	KeyID string

	Private *rsa.PrivateKey

	Public *rsa.PublicKey
}

// AssertionOptions configures a minter. Everything here is validated at
// construction.
//
// The issuer and the lifetime are refusals at construction rather than at request
// time, for the reason the verifier's options give: a typo in an environment
// variable should be a startup failure and not a 503 on every request. The clock
// is injected rather than read so a test can assert expiry without sleeping — an
// expiry test that sleeps is an expiry test that is slow, and then skipped.
type AssertionOptions struct {
	Issuer string

	Key AssertionKey

	TTL time.Duration

	Now func() time.Time
}

// AssertionSubject is what one mint is about: the upstream it is for, and the
// claims it may carry.
type AssertionSubject struct {
	Audience string

	Claims []string
}

// AssertionMinter mints assertions, and knows nothing about routing or about HTTP.
//
// The facts it is given per call are the verified principal and what the route
// declared; what it does with them is the whole of its responsibility, which is
// why it can be tested without a gateway and why the gateway's only decision is
// *whether* to call it.
type AssertionMinter struct {
	issuer string
	ttl    time.Duration
	now    func() time.Time
	key    AssertionKey

	published     *JSONWebKey
	publishedOnce sync.Once
}

// NewAssertionMinter builds the minter, validating everything configuration can
// get wrong here.
func NewAssertionMinter(options AssertionOptions) (*AssertionMinter, error) {
	issuer := options.Issuer
	if issuer == "" {
		issuer = DefaultAssertionIssuer
	}

	origin, err := parseAssertionIssuer(issuer)
	if err != nil {
		return nil, err
	}

	ttl := options.TTL
	if ttl == 0 {
		ttl = DefaultAssertionTTL
	}
	if err := assertAssertionTTL(ttl); err != nil {
		return nil, err
	}

	if options.Key.Private == nil || options.Key.Public == nil {
		return nil, fmt.Errorf("%w: createAssertionMinter: an assertion signing key is required, and the one it was given has no RSA key pair. Unset the signing key and no assertion is minted on any route", ErrNotConfigured)
	}
	if !options.Key.Public.Equal(&options.Key.Private.PublicKey) {
		return nil, fmt.Errorf("%w: createAssertionMinter: the assertion signing key's public half is not the public half of its private key. Every assertion would verify against a key set this gateway publishes which does not contain the key that signed it", ErrNotConfigured)
	}

	now := options.Now
	if now == nil {
		now = time.Now
	}

	return &AssertionMinter{issuer: origin, ttl: ttl, now: now, key: options.Key}, nil
}

// Mint returns a compact JWS asserting `subject.Claims` for `subject.Audience`.
func (m *AssertionMinter) Mint(principal Principal, subject AssertionSubject) (string, error) {
	seconds := m.now().Unix()

	envelope := map[string]any{
		"iss": m.issuer,
		"aud": subject.Audience,
		"iat": seconds,
		"exp": seconds + int64(m.ttl/time.Second),
		"jti": newAssertionID(),
	}
	for name, value := range declaredClaims(principal, subject.Claims) {
		envelope[name] = value
	}

	payload, err := json.Marshal(envelope)
	if err != nil {
		return "", fmt.Errorf("gateway: the assertion claim set did not encode: %w", err)
	}

	key, err := m.PublicJWK()
	if err != nil {
		return "", err
	}

	return signCompactJWS(key, m.key.Private, payload)
}

func declaredClaims(principal Principal, names []string) map[string]any {
	out := make(map[string]any, len(names)+1)

	for _, name := range names {
		value, ok := principal.Claims.Lookup(name)
		if !ok {
			continue
		}
		out[name] = value
	}

	if principal.Sub != "" {
		if _, declared := out["sub"]; !declared {
			out["sub"] = principal.Sub
		}
	}

	return out
}

// PublicJWK is the public half, with the id in it.
//
// ## THE PUBLIC HALF IS TAKEN FROM THE PUBLIC KEY, AND THE STRUCT IS THE PROOF
//
// `src/routes/assertion.ts` (removed at cutover) measures this rather than assuming it: `exportJWK`
// given a Node **private** `KeyObject` returns `kty, n, e, d, p, q, dp, dq, qi` —
// the whole private key, RSA primes included. The first draft of that function
// exported the private key it had been handed, and nothing about the token set
// would have looked wrong, because the RFC 7638 thumbprint hashes only `e`,
// `kty` and `n`.
//
// So `AssertionKey` carries both halves rather than just the private one, and
// `TestThePublishedJWKCarriesOnlyThePublicHalf` asserts the published field names
// **exactly** rather than merely that it verifies. `JSONWebKey` has no field for a
// private exponent, so the tempting shortcut has nowhere to write.
func (m *AssertionMinter) PublicJWK() (JSONWebKey, error) {
	m.publishedOnce.Do(m.resolvePublished)

	if m.published == nil {
		return JSONWebKey{}, errors.New("gateway: the assertion's public key did not export")
	}
	return *m.published, nil
}

func (m *AssertionMinter) resolvePublished() {
	if m.key.Public == nil {
		return
	}

	published := JSONWebKey{
		Kty: "RSA",
		N:   base64.RawURLEncoding.EncodeToString(m.key.Public.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(exponentBytes(m.key.Public.E)),
		Alg: "RS256",
		Use: "sig",
	}

	if m.key.KeyID != "" {
		published.Kid = m.key.KeyID
	} else {
		published.Kid = thumbprint(published)
	}
	m.published = &published
}

// KeyID is the id the assertion's protected header names. Derived if not
// configured, so it is the published value rather than the raw option.
func (m *AssertionMinter) KeyID() string {
	key, err := m.PublicJWK()
	if err != nil {
		return m.key.KeyID
	}
	return key.Kid
}

// JSONWebKey is a public key in the shape an upstream's key set is written in.
//
// Six fields, and **no field for a private exponent**. That is the whole reason
// the type exists rather than a `map[string]any`: the mistake this file's comment
// above describes is one a map cannot refuse.
type JSONWebKey struct {
	Kty string `json:"kty"`
	N   string `json:"n"`
	E   string `json:"e"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
}

func thumbprint(key JSONWebKey) string {
	canonical := fmt.Sprintf(`{"e":%q,"kty":%q,"n":%q}`, key.E, key.Kty, key.N)
	sum := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func exponentBytes(exponent int) []byte {
	if exponent <= 0 {
		return []byte{0}
	}

	out := []byte{byte(exponent & 0xff)}
	for value := exponent >> 8; value > 0; value >>= 8 {
		out = append([]byte{byte(value & 0xff)}, out...)
	}
	for len(out) > 1 && out[0] == 0 {
		out = out[1:]
	}
	return out
}

func signCompactJWS(key JSONWebKey, private *rsa.PrivateKey, payload []byte) (string, error) {
	header, err := json.Marshal(struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}{Alg: "RS256", Kid: key.Kid})
	if err != nil {
		return "", fmt.Errorf("gateway: the assertion header did not encode: %w", err)
	}

	signingInput := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(signingInput))

	signature, err := rsa.SignPKCS1v15(rand.Reader, private, crypto.SHA256, digest[:])
	if err != nil {
		return "", fmt.Errorf("gateway: the assertion could not be signed: %w", err)
	}

	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

// ReadAssertionKey reads a PKCS#8 PEM into a signing key, or reports why not.
//
// ## WHY IT REFUSES A NON-RSA KEY RATHER THAN SIGNING WITH IT
//
// `{"alg":"RS256"}` over an EC key is a token no standard verifier will accept,
// so signing with one would produce a failure that surfaces at the upstream rather
// than here. The algorithm is a property of this process's key, not a hint — so an
// EC key is refused at startup with a message naming why.
func ReadAssertionKey(pemText, keyID string) (AssertionKey, error) {
	block, _ := pem.Decode([]byte(pemText))
	if block == nil {
		return AssertionKey{}, fmt.Errorf("%w: ReadAssertionKey: the assertion signing key is not a PEM block. It must be a PKCS#8 RSA private key, and this is text with no -----BEGIN anywhere in it", ErrNotConfigured)
	}

	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return AssertionKey{}, fmt.Errorf("%w: ReadAssertionKey: the assertion signing key is not a PKCS#8 key: %w", ErrNotConfigured, err)
	}

	private, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return AssertionKey{}, fmt.Errorf("%w: ReadAssertionKey: the assertion signing key must be RSA, got %T. The algorithm is a property of this process's key, not a hint a token carries — the same rule the verifier pins for the keys it checks — so an EC key is refused rather than signed with under an RS256 header", ErrNotConfigured, parsed)
	}

	return AssertionKey{KeyID: keyID, Private: private, Public: &private.PublicKey}, nil
}

func parseAssertionIssuer(value string) (string, error) {
	trimmed := trimSpace(value)
	if trimmed == "" {
		return "", fmt.Errorf("%w: createAssertionMinter: issuer must be a non-empty string", ErrNotConfigured)
	}

	parsed, err := parseAbsoluteURL(trimmed)
	if err != nil {
		return "", fmt.Errorf("%w: createAssertionMinter: issuer must be an absolute URL, got %q", ErrNotConfigured, value)
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return "", fmt.Errorf("%w: createAssertionMinter: issuer must be a base URL with no path, got %q. An upstream verifies it to learn which gateway minted the assertion, so it names the gateway rather than a route on it", ErrNotConfigured, value)
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("%w: createAssertionMinter: issuer must carry no query or fragment, got %q", ErrNotConfigured, value)
	}

	return originOf(parsed), nil
}

func assertAssertionTTL(ttl time.Duration) error {
	if ttl < time.Millisecond {
		return fmt.Errorf("%w: createAssertionMinter: ttl must be at least 1ms, got %s", ErrNotConfigured, ttl)
	}
	if ttl > MaxAssertionTTL {
		return fmt.Errorf("%w: createAssertionMinter: ttl must be at most %s, got %s. An assertion is minted for one hop and verified by the service on the other end of it; a window of minutes is the whole of what it is for, and a lifetime nobody may exceed cannot be configured into something that is no longer short-lived", ErrNotConfigured, MaxAssertionTTL, ttl)
	}
	return nil
}

func newAssertionID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("httpapi: crypto/rand is unavailable: " + err.Error())
	}

	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80

	hexed := strings.ToUpper(hex.EncodeToString(b[:]))
	return hexed[0:8] + "-" + hexed[8:12] + "-" + hexed[12:16] + "-" + hexed[16:20] + "-" + hexed[20:32]
}
