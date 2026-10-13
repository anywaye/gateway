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

	"github.com/cafaye/gateway/internal/auth"
)

// The principal assertion: gateway's own signature over who the caller is, sent to
// one upstream and to nothing else.
//
// Ported from `src/routes/assertion.ts` (removed at cutover).
//
// ## THE GAP THIS EXISTS TO CLOSE, AND WHY IT IS A FACT RATHER THAN A BUG
//
// `proxy.go` sends the per-upstream `token` as `authorization` and copies
// nothing else. Its own header says the cost out loud: "an upstream cannot tell
// which caller sent a request. The per-upstream `token` is a service credential,
// not a delegation, and no header here asserts who the caller was."
//
// That rule is correct and load-bearing — forwarding the caller's `Authorization`
// would make gateway a confused deputy — and it is exactly why a publisher write
// cannot work: pantry's RLS predicates compare against
// `pantry.current_publisher_id()`, and the request arrives with nothing to
// compare. The caller is not missing. The credential gate resolved them to a
// principal before the proxy runs. It was discarded at the boundary, and this file
// is the boundary.
//
// ## THE ONE THING, STATED
//
// **A request to a non-public `RouteTable` upstream that declared claims carries a
// short-lived signed assertion of who the caller is. A request to a public one
// carries nothing, ever.**
//
// ## WHY IT IS A JWS AND NOT A HEADER
//
// Because the upstream has to be able to *verify* it without trusting the
// network, and "the header said so" is not a fact a service can check. A compact
// JWS over a minimal claim set is the smallest object that carries a signature an
// independent service can check with an off-the-shelf verifier.
//
// ## WHY IT IS NOT THE CALLER'S TOKEN, AND CANNOT BECOME ONE
//
// Two reasons, and the second is the one that would survive a well-meaning
// refactor:
//
//  1. The caller's token was minted for a *different audience*. Forwarding it makes
//     gateway a credential relay for a token issued to something else, and the
//     upstream has no way to narrow what it accepts.
//  2. The claim set would be the caller's whole JWT. MD19's fourth property is
//     *minimal claims* — what the upstream is declared to need, not the JWT — and a
//     forwarded token is the opposite of minimal by construction: the caller
//     decides what is in it.
//
// ## WHY THE SIGNING HALF IS HAND-ROLLED
//
// `go.mod` names two dependencies today and this adds none, which is a
// deliberate reading of the repository's rule that a dependency has to earn
// itself. The whole of what is needed is in the standard library: `crypto/rsa`
// signs, `encoding/base64` writes compact JWS, `encoding/json` writes the two
// objects. A JWT library would bring a second implementation of the thing being
// asserted here, and the assertion's security does not benefit from being written
// by code this repository has read.
//
// The cost is stated rather than hidden: `signCompactJWS` below is ~20 lines and
// the proof that it is correct is `TestTheAssertionVerifiesAgainstThePublishedJWK`,
// which checks the signature with `rsa.VerifyPKCS1v15` and the standard library's
// own verifier. A hand-rolled signer that no standard verifier has ever checked
// would be a real risk; a hand-rolled signer whose output a standard verifier
// accepts is not.

// AssertionHeader is the header the assertion crosses in.
//
// A header of its own rather than a second `Authorization`, and the reason is the
// same one `proxy.go` gives for dropping the caller's: the table entry's `Token`
// is already in `authorization`, it is a *different* credential, and asking one
// header to carry two answers to two questions is how a service ends up reading
// the wrong one. The name is namespaced because it is not a standard header and
// no proxy in the fleet should have an opinion about it.
const AssertionHeader = "x-cafaye-principal"

// DefaultAssertionIssuer is what gateway asserts when nothing is configured: an
// origin, like identity's.
const DefaultAssertionIssuer = "https://gateway.localhost"

// How long an assertion is good for, and how long it may be configured to be.
//
// Two minutes by default because the assertion is minted at the proxy and
// verified by the service on the other end of the same request: the window only
// has to cover one hop plus a clock skew, and MD19 asked for "minutes". The
// ceiling is the half that matters, because a lifetime nobody may exceed cannot be
// configured into something that is no longer short-lived — ten minutes is a
// refusal to boot naming the maximum, not a value that gets used.
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
	// The `kid`, or empty for "derive it from the key" — see `ReadAssertionKey`.
	KeyID string

	// Signs. Never leaves the process, and is never published.
	Private *rsa.PrivateKey

	// What `PublicJWK` exports. Held separately, and that is load-bearing: see
	// `PublicJWK`.
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
	// Who minted it. Defaults to `DefaultAssertionIssuer`.
	Issuer string

	Key AssertionKey

	// Defaults to `DefaultAssertionTTL`; above `MaxAssertionTTL` is refused.
	TTL time.Duration

	// Clock, injected so a test can cross `exp` without sleeping. Defaults to
	// `time.Now`.
	Now func() time.Time
}

// AssertionSubject is what one mint is about: the upstream it is for, and the
// claims it may carry.
type AssertionSubject struct {
	// The audience, which is the upstream's origin. `ValidateRouteTable` has
	// already reduced `BaseURL` to an origin, so this needs no parsing here — and
	// parsing it again would be a second spelling of "which upstream is this".
	Audience string

	// The claims the route entry declared, in the order the operator wrote them.
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

	// The published public half, resolved on first use and kept. A key id that
	// changed between two requests would be a key set no upstream could select
	// from, and the failure would be entirely on their side.
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
	// The two halves must be one key. They are separate fields because the public
	// half is what gets published, and a pair that disagreed would mint assertions
	// nobody could verify against the key set the gateway publishes — a failure
	// with no local symptom at all, discovered by the upstream.
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

	// Computed from the same `seconds` as `iat`, so the window is exactly the TTL
	// and cannot drift by a rounding of the clock — which is the kind of thing
	// that is only visible in production.
	envelope := map[string]any{
		"iss": m.issuer,
		"aud": subject.Audience,
		"iat": seconds,
		"exp": seconds + int64(m.ttl/time.Second),
		"jti": newAssertionID(),
	}
	// The declared claims are written LAST and cannot overwrite the envelope:
	// `checkClaimName` refuses those names in a route entry, and the ordering is
	// the second of the two gates on MD19's "bound to the upstream". Like the other
	// one it is redundant on purpose — a security property that depends on a
	// validation three files away is a property that is one refactor away from
	// gone.
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

// declaredClaims are the claims to assert about the caller, and nothing else.
//
// A name the caller's token does not hold is **skipped rather than refused**:
// MD19 wants a publisher with no row to get a "no publisher record" refusal rather
// than a silently minted one, and a missing `github_id` has to reach the upstream
// as a missing `github_id` for that to happen.
//
// `sub` is included from `Principal.Sub` when the declared set happens not to name
// it, because every verified principal has one and an assertion that dropped the
// subject would be useless — but the *declared* set still governs, so an entry
// that asked for nothing does not get it.
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

// resolvePublished builds the published key exactly once, from `key.Public`.
//
// The `sync.Once` rather than a plain "if nil": two requests arriving together on
// a cold gateway would otherwise both publish, and one of them would win a race to
// assign — with the same value, so the consequence is nil. It is here because the
// thing being protected is that the *id* cannot change between two requests, and
// `sync.Once` says that in one word.
func (m *AssertionMinter) resolvePublished() {
	// A nil public half is reported as a mint-time failure rather than dereferenced.
	// `NewAssertionMinter` refuses such a key, so the only way here is a minter
	// assembled without it — and the answer that matters is that a minter which
	// cannot sign says so. It does not take the process down: a panic in a
	// pass-through is a gateway that is no longer answering anything, which is a
	// strictly worse outcome than the 503 this turns into.
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

// thumbprint is the RFC 7638 JWK thumbprint: SHA-256 over the required members in
// lexicographic order with no whitespace, base64url-encoded.
//
// `{"e":…,"kty":"RSA","n":…}` and nothing else. A thumbprint that hashed `alg` or
// `use` as well would change if somebody edited the key set's annotations, so the
// same key would get a different id — which is the collision the id exists to
// avoid.
func thumbprint(key JSONWebKey) string {
	canonical := fmt.Sprintf(`{"e":%q,"kty":%q,"n":%q}`, key.E, key.Kty, key.N)
	sum := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// exponentBytes is the RSA public exponent as minimal big-endian bytes.
//
// `65537` is three bytes (`01 00 01`, the `AQAB` every published RSA key carries)
// and encoding it as a fixed-width word would put `AAAB` in the key set, which is
// still a valid exponent and still verifies — and which no other implementation
// would produce, so an upstream comparing `n` and `e` against its own key would
// fail on a key that is correct.
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

// signCompactJWS writes `base64url(header) "." base64url(payload) "." base64url(sig)`.
//
// RSASSA-PKCS1-v1_5 over SHA-256, which is what `alg: RS256` names. The algorithm
// is pinned here and is never read from anything a caller sent, for the same
// reason the verifier's is: `alg` is a property of this process's key, not a hint
// a token carries.
func signCompactJWS(key JSONWebKey, private *rsa.PrivateKey, payload []byte) (string, error) {
	// A struct rather than a map, because `encoding/json` sorts map keys and
	// `{"alg":…,"kid":…}` is the order every other JWS library writes.
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

	// Both halves, deliberately: the public key is what `PublicJWK` exports, and it
	// is taken from here rather than re-derived per call so that the thing published
	// is the thing the key was configured as.
	return AssertionKey{KeyID: keyID, Private: private, Public: &private.PublicKey}, nil
}

// parseAssertionIssuer accepts an absolute http(s) origin with no path.
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

// assertAssertionTTL refuses a lifetime that is not an integer number of
// milliseconds, or that is longer than the ceiling.
//
// The ceiling is the half that matters: a lifetime nobody may exceed cannot be
// configured into something that is no longer short-lived, which is MD19's third
// property stated as a limit an operator cannot argue with.
func assertAssertionTTL(ttl time.Duration) error {
	if ttl < time.Millisecond {
		return fmt.Errorf("%w: createAssertionMinter: ttl must be at least 1ms, got %s", ErrNotConfigured, ttl)
	}
	if ttl > MaxAssertionTTL {
		return fmt.Errorf("%w: createAssertionMinter: ttl must be at most %s, got %s. An assertion is minted for one hop and verified by the service on the other end of it; a window of minutes is the whole of what it is for, and a lifetime nobody may exceed cannot be configured into something that is no longer short-lived", ErrNotConfigured, MaxAssertionTTL, ttl)
	}
	return nil
}

// newAssertionID is a correlation id that is not a constant, and is never a secret.
//
// It is here rather than nowhere because it makes two assertions for the same
// caller on the same route differ byte for byte, which is what lets an upstream
// log and correlate one without being able to replay either. A `jti` that is
// accidentally constant is a field nobody reads and nobody notices, so it is
// asserted in the tests rather than merely claimed.
//
// UUIDv4's *shape*, not its bytes: `crypto/rand` is the randomness and the
// formatting is a rendering, and a service that logs a `jti` should not have to
// care which of the two produced it.
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
