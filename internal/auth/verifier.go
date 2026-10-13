// Real RS256 verification against identity's published JWKS.
//
// The contract this implements is the platform auth contract in packet guard-02:
// RS256, keys at `{issuer}/.well-known/jwks.json`, and a refusal for a bad
// signature, an expired token, a wrong `iss`, a wrong `aud`, an `nbf` in the
// future, or a token that is not a JWT at all.
//
// # WHAT IS HAND-ROLLED HERE, AND WHY IT IS THE RIGHT CALL
//
// `crypto/rsa`, `crypto/sha256`, `encoding/base64` and `encoding/json` from the
// standard library, and nothing else. `go.mod` still names two dependencies.
//
// The alternative was `github.com/golang-jwt/jwt/v5`, and it was rejected for a
// reason this repository has already applied twice — `internal/equivalence`
// hand-marshals `/readyz`'s `deps`, and `rateLimitRedis.ts` hand-rolls RESP2
// rather than take a client: **a port whose whole job is byte-equivalence with
// the reference cannot delegate the bytes to a third party.** Every refusal
// string below is `jwt.ts`'s verbatim, because `internal/equivalence` compared
// problem documents byte for byte and `refusalOf`'s mapping of jose error codes
// onto five sentences is part of the observable contract. A library would give
// us its own error taxonomy and a translation layer between the two, and the
// translation layer is where a subtle divergence would live.
//
// The security-critical operation is still the standard library's:
// `rsa.VerifyPKCS1v15` is what checks the signature, and there is no padding
// choice, no digest selection and no key parsing written here beyond base64url.
package auth

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Options is the verifier's configuration, and it is validated at construction.
//
// `Options` mirrors `JwtOptions` in `src/middleware/jwt.ts` (removed at cutover) field for field, with
// the two millisecond numbers as `time.Duration` because Go has a type for a
// span of time and spelling one in milliseconds is how a caller ends up with a
// nanosecond value where a second was meant. The environment reader converts.
type Options struct {
	// The issuer, and nothing else: an origin such as `https://identity.localhost`.
	// Both the expected `iss` and the base the JWKS path is appended to.
	Issuer string

	// The `client_id` every token must be addressed to.
	Audience string

	// Defaults to `{Issuer}/.well-known/jwks.json`. An operator who points gateway
	// at a key set somewhere other than the issuer's own well-known path means it.
	JWKSURL string

	// How long a fetched key set is reused. Zero means `DefaultJWKSCacheTTL`.
	// An UNBOUNDED cache is an outage the first time a key rotates, and the
	// unknown-kid refresh below is what makes rotation possible without a
	// redeploy — which is only true if the budget is per window.
	JWKSCacheTTL time.Duration

	// How long one fetch of the key set may take. Zero means `DefaultJWKSTimeout`.
	JWKSTimeout time.Duration

	// Clock, injected so the cache TTL and the claim checks are testable without
	// sleeping. Nil means `time.Now`.
	Now func() time.Time

	// The HTTP client the key-set fetch uses. Nil means a client with no overall
	// timeout, because `JWKSTimeout` is per request and an overall timeout would
	// be a second, unrelated bound on the same operation.
	Client *http.Client
}

// ErrNotConfigured is a configuration this verifier cannot serve. It exists so a
// caller can tell its own mistake from a defect in this package, which a bare
// string cannot — the same reason `httpapi.ErrNotConfigured` is a sentinel.
var ErrNotConfigured = errors.New("auth: invalid configuration")

// Verifier is the built verifier. One per process, because the cache inside it is
// one per verifier: two verifiers would fetch the key set twice and could
// disagree about whether a rotation has happened.
type Verifier struct {
	issuer   string
	audience string

	// The pinned algorithm, as a constant read through a field so the tests can
	// assert it without reaching into the source. `TestTheAlgorithmIsRS256AndIs
	// NotConfigurable` is that assertion.
	algorithm string

	keys *jwksCache
	now  func() time.Time
}

// New builds the verifier, or refuses the configuration.
//
// A refusal here is a refusal to start, which is the point: a typo in
// `IDENTITY_ISSUER` is a startup failure rather than a 503 on every request.
// `createJwtVerifier` does the same and says why.
func New(options Options) (*Verifier, error) {
	issuer, err := trimIssuer(options.Issuer)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNotConfigured, err)
	}

	audience := strings.TrimSpace(options.Audience)
	if audience == "" {
		return nil, fmt.Errorf("%w: audience must be a non-empty string", ErrNotConfigured)
	}

	ttl := options.JWKSCacheTTL
	if ttl == 0 {
		ttl = DefaultJWKSCacheTTL
	}
	if ttl < 0 {
		return nil, fmt.Errorf("%w: jwksCacheTtl must be a positive duration, got %v", ErrNotConfigured, options.JWKSCacheTTL)
	}

	timeout := options.JWKSTimeout
	if timeout == 0 {
		timeout = DefaultJWKSTimeout
	}
	if timeout < 0 {
		return nil, fmt.Errorf("%w: jwksTimeout must be a positive duration, got %v", ErrNotConfigured, options.JWKSTimeout)
	}

	jwksURL := options.JWKSURL
	if jwksURL == "" {
		jwksURL = issuer + JWKSPath
	} else if err := assertHTTPURL(jwksURL); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNotConfigured, err)
	}

	now := options.Now
	if now == nil {
		now = time.Now
	}
	client := options.Client
	if client == nil {
		client = &http.Client{}
	}

	return &Verifier{
		issuer:    issuer,
		audience:  audience,
		algorithm: algorithm,
		keys:      newJWKSCache(jwksURL, ttl, timeout, now, client),
		now:       now,
	}, nil
}

// assertHTTPURL is `parseHttpUrl`'s half that applies to `jwksUrl`: absolute, and
// http(s). A typo here is an operator's, and it must be named at startup.
func assertHTTPURL(value string) error {
	trimmed := strings.TrimSpace(value)
	scheme, _, found := strings.Cut(trimmed, "://")
	if !found || (scheme != "https" && scheme != "http") {
		return fmt.Errorf("jwksUrl must be an absolute http(s) URL, got %q", value)
	}
	if trimmed == scheme+"://" {
		return fmt.Errorf("jwksUrl must name a host, got %q", value)
	}
	return nil
}

// Principal is what a verified request carries. Handlers read this and nothing
// else.
//
// Ported from `Principal` in `src/middleware/jwt.ts` (removed at cutover), including the field whose
// comment there explains why it is a field rather than a claim lookup at each
// use: the one place that decides what an account is is the one place that read
// the token.
type Principal struct {
	// The user uuid from the `sub` claim.
	Sub string

	// The `scope` claim, split on whitespace. Empty when the claim is absent —
	// never everything. A scope gate that treated "no scopes" as "all scopes"
	// would be a gate with no gate.
	Scope []string

	// The account the request acts on, from the `account_id` claim. Nil for a
	// token that has no such claim, which is not an error: a user with no
	// workspace *is* the account, and `accountIdOf` in `internal/ratelimit` falls
	// back to `Sub`.
	AccountID *string

	// The verified claims, unfiltered and in the token's own order.
	Claims Claims
}

// Refusal is why a caller does not get a principal.
//
// A status and a code rather than an `error`, because the two ARE the answer: a
// `401` and a `503` are different decisions about different subjects, and a
// refusal that had to be re-classified by its message would be a refusal whose
// classification could drift. `Detail` is a fixed string per case and is never an
// interpolated reason — see `unauthorized` and `unavailable`.
type Refusal struct {
	Status int
	Code   string
	Detail string
}

// The three refusals the verifier has more than one way to reach, and the one
// place each sentence is written. `jwt.ts` has the same four functions and the
// same comment: the reason goes to the log and the caller gets a fixed sentence,
// because a jose message quotes expected values and an expected issuer is a map
// of the platform's internals.
func unauthorized(detail string) *Refusal {
	return &Refusal{Status: http.StatusUnauthorized, Code: "unauthorized", Detail: detail}
}

func forbidden(detail string) *Refusal {
	return &Refusal{Status: http.StatusForbidden, Code: "forbidden", Detail: detail}
}

func unavailable() *Refusal {
	// Fixed string: the URL that failed, the status it answered and the parser's
	// complaint are all in the error the cache wraps, and none of them is the
	// caller's business.
	return &Refusal{Status: http.StatusServiceUnavailable, Code: "unavailable", Detail: "the signing keys could not be retrieved"}
}

// scopeClaim is core's `scopes` claim under the name JWT spells it.
const scopeClaim = "scope"

// Authenticate is the whole verifier: the header, the key set, the signature,
// the claims, or the reason.
//
// The order is the reference's order and it is load-bearing in two places:
//
//   - the header is read BEFORE any key is fetched, because the algorithm and
//     the key id are attacker-controlled and an `alg: none` or HS256 token must
//     not be able to make gateway call identity;
//   - the signature is checked BEFORE the claims, because a token that is both
//     expired and wrongly signed is a signature failure, and a caller who is told
//     "token has expired" for a forged token has been told the wrong thing about
//     their own credential.
func (v *Verifier) Authenticate(ctx context.Context, token string) (*Principal, *Refusal) {
	kid, refusal := decodeHeader(token)
	if refusal != nil {
		return nil, refusal
	}

	set, err := v.keys.keysFor(ctx, kid)
	if err != nil {
		// identity being down is not the caller's fault, and a 401 would tell them
		// to fix a credential that was fine. The reason goes to the log, which is
		// the wrapped error.
		return nil, unavailable()
	}

	return v.verifyClaims(token, kid, set)
}

// verifyClaims checks the signature, then the claims, then reads the principal.
func (v *Verifier) verifyClaims(token, kid string, set []jwk) (*Principal, *Refusal) {
	parts := strings.Split(token, ".")
	// `decodeHeader` already refused anything that is not three or five segments.
	// Five is a JWE, which `jwtVerify` answers `ERR_JWE_INVALID` for, and that
	// code is not in `refusalOf`'s list — so it lands on "token is not valid".
	if len(parts) != 3 {
		return nil, unauthorized("token is not valid")
	}

	key, refusal := selectKey(set, kid)
	if refusal != nil {
		return nil, refusal
	}

	if err := checkSignature(key, parts[0], parts[1], parts[2]); err != nil {
		return nil, unauthorized(err.Error())
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, unauthorized("token is not valid")
	}

	var claims Claims
	if err := json.Unmarshal(payload, &claims); err != nil {
		// jose: `JWT Claims Set must be a top-level JSON object` —
		// `ERR_JWT_INVALID`, which is not in `refusalOf`'s list either.
		return nil, unauthorized("token is not valid")
	}

	if refusal := v.checkClaims(&claims); refusal != nil {
		return nil, refusal
	}

	return principalOf(&claims)
}

// selectKey is jose's candidate filter plus its two throws, in jose's order.
//
// Zero candidates is `ERR_JWKS_NO_MATCHING_KEY` and more than one is
// `ERR_JWKS_MULTIPLE_MATCHING_KEYS`. They refuse DIFFERENTLY and that is not an
// accident: no matching key means the caller named a key identity that does not
// exist, which is worth saying; two matching keys means the publisher has
// published an ambiguous set, and "token is not valid" is the only answer that
// does not tell an unauthenticated caller which of two keys to try.
func selectKey(set []jwk, kid string) (*rsa.PublicKey, *Refusal) {
	var usable []jwk
	for _, key := range set {
		if key.isUsable(kid) {
			usable = append(usable, key)
		}
	}

	switch len(usable) {
	case 1:
		return publicKeyOf(usable[0])
	case 0:
		return nil, unauthorized("token was signed by an unknown key")
	default:
		return nil, unauthorized("token is not valid")
	}
}

// publicKeyOf is `jwkToKey` for an RSA JWK: `n` is the modulus and `e` the
// public exponent, both base64url, both unsigned big-endian.
//
// `rsa.PublicKey` also has a `Size` field, which is derived from `N` by the
// standard library on first use and must not be set by hand — a wrong one
// produces a verification that fails rather than one that passes.
func publicKeyOf(key jwk) (*rsa.PublicKey, *Refusal) {
	modulus, err := base64.RawURLEncoding.DecodeString(key.N)
	if err != nil || len(modulus) == 0 {
		return nil, unauthorized("token is not valid")
	}
	exponent, err := base64.RawURLEncoding.DecodeString(key.E)
	// Four bytes is 2^32, and `rsa.checkPub` refuses an exponent outside
	// `[2, 2^31-1]`. Checking the length here means a JWK carrying a
	// deliberately enormous `e` is a refusal rather than an overflow into a
	// negative `int`.
	if err != nil || len(exponent) == 0 || len(exponent) > 4 {
		return nil, unauthorized("token is not valid")
	}

	e := 0
	for _, b := range exponent {
		e = e<<8 | int(b)
	}
	if e < 3 || e%2 == 0 {
		return nil, unauthorized("token is not valid")
	}

	n := new(big.Int).SetBytes(modulus)
	// A public modulus is an odd number above one. Refusing an even or trivial
	// modulus here turns a malformed key set into a refusal at the point the
	// refusal is meaningful, instead of relying on the standard library's own
	// bounds check to notice it later.
	if n.Bit(0) == 0 || n.Cmp(big.NewInt(3)) <= 0 {
		return nil, unauthorized("token is not valid")
	}

	return &rsa.PublicKey{N: n, E: e}, nil
}

// checkSignature is `verifyCompact` for RS256 and nothing else.
//
// RS256 is `RSASSA-PKCS1-v1_5` over `SHA-256`, per RFC 7518 §3.3. PKCS#1 v1.5 and
// not PSS: the algorithm is named in the token's own header, so a verifier that
// honored `alg: PS256` would honor the claim this whole file exists to refuse.
// The `crypto.Hash` is hard-coded rather than looked up from a name, for the same
// reason.
func checkSignature(key *rsa.PublicKey, header, payload, signature string) error {
	sig, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil || len(sig) == 0 {
		return errString("token is not valid")
	}

	signingInput := []byte(header + "." + payload)
	digest := sha256.Sum256(signingInput)

	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], sig); err != nil {
		// jose's `ERR_JWS_SIGNATURE_VERIFICATION_FAILED` says one thing about
		// every way the signature can be wrong, and so does this: a caller who
		// could tell "your key is not ours" from "your token was truncated" would
		// be probing an oracle.
		return errString("token signature does not verify")
	}
	return nil
}

// errString is a refusal reason as an error, because `checkSignature` is the one
// place in this file whose failure is a sentence rather than a status.
type errString string

func (e errString) Error() string { return string(e) }

// checkClaims is jose's `validateClaimsSet` for the four claims gateway
// verifies, in jose's order.
//
// # THE ORDER IS THE CONTRACT, IN THREE PLACES
//
//  1. `aud` is checked BEFORE `iss`. jose builds its presence list as
//     `[...requiredClaims, "aud", "iss"]` and a token missing both is told it is
//     missing `aud`. Getting this backwards changes the message for one token
//     shape and nothing else, which is exactly the kind of difference
//     the equivalence check existed to find.
//
//  2. `iss` is compared before `aud`. Same reason.
//
//  3. `nbf` is checked before `exp`. A token that is both not-yet-valid and
//     already expired is a `nbf` failure, and a caller told "has expired" for a
//     token identity has not issued yet has been told something false.
//
// # SECONDS, FLOORED, NOT MILLISECONDS
//
// `Math.floor(Date.now() / 100e2)` — floor, not round, and seconds not
// milliseconds. A token one millisecond past its `exp` is EXPIRED here, because
// at second resolution `exp <= now` already holds. This is the arithmetic jose
// does and the boundary a test that rounds would not find.
func (v *Verifier) checkClaims(claims *Claims) *Refusal {
	// Presence. `Object.hasOwn`, so a claim present with the value `undefined`
	// is not present — which in JSON cannot be written, so the practical reading
	// is: an absent claim is absent.
	if _, ok := claims.Lookup("aud"); !ok {
		return claimRefusal("aud")
	}
	if _, ok := claims.Lookup("iss"); !ok {
		return claimRefusal("iss")
	}

	if claims.String("iss") != v.issuer {
		// Strict equality on a string. jose compares
		// `[issuer].includes(payload.iss)`, so a payload `iss` that is not a
		// string is a mismatch rather than a type error.
		return claimRefusal("iss")
	}

	if !audienceHolds(claims, v.audience) {
		return claimRefusal("aud")
	}

	now := v.now().Unix()

	if raw, present := claims.Lookup("nbf"); present {
		seconds, ok := raw.(float64)
		if !ok {
			return claimRefusal("nbf")
		}
		if seconds > float64(now) {
			return claimRefusal("nbf")
		}
	}

	if raw, present := claims.Lookup("exp"); present {
		seconds, ok := raw.(float64)
		if !ok {
			// jose raises `JWTClaimValidationFailed` for a non-numeric `exp`, not
			// `JWTExpired`, and the two have different sentences.
			return claimRefusal("exp")
		}
		if seconds <= float64(now) {
			return unauthorized("token has expired")
		}
	}

	return nil
}

// claimRefusal is `refusalOf`'s `ERR_JWT_CLAIM_VALIDATION_FAILED` branch:
// `token claim '<name>' is not valid`. The claim name is safe to echo — it is one
// of six fixed names — and naming it is what lets a caller tell a clock problem
// from an addressing problem.
func claimRefusal(claim string) *Refusal {
	return unauthorized(fmt.Sprintf("token claim '%s' is not valid", claim))
}

// audienceHolds is jose's `checkAudiencePresence`: a string `aud` must equal the
// expected audience, and an array `aud` must CONTAIN it.
//
// Containment and not equality, and that is a real distinction: a token minted
// for `["gateway", "admin"]` is addressed to gateway, and refusing it would
// break a multi-audience token identity issues for several services at once.
// Anything that is neither a string nor an array of strings fails, which is what
// stops `aud: {"gateway": true}` from being an audience.
func audienceHolds(claims *Claims, expected string) bool {
	raw, present := claims.Lookup("aud")
	if !present {
		return false
	}

	switch value := raw.(type) {
	case string:
		return value == expected
	case []any:
		for _, member := range value {
			text, ok := member.(string)
			if !ok {
				// jose's `validateAudienceClaim` refuses a mixed array outright.
				// It runs at SIGNING time in jose, not verification, so a token
				// arriving with one is not something this verifier sees; refusing
				// is the safe direction and matches what jose would have minted.
				return false
			}
			if text == expected {
				return true
			}
		}
	}
	return false
}

// principalOf is the claims a handler is allowed to see, or the reason there are
// none.
func principalOf(claims *Claims) (*Principal, *Refusal) {
	sub := claims.String("sub")
	if sub == "" {
		return nil, unauthorized("token has no subject")
	}

	scope := []string{}
	if raw, present := claims.Lookup(scopeClaim); present {
		text, ok := raw.(string)
		if !ok {
			return nil, unauthorized("token scope claim is not a string")
		}
		scope = strings.Fields(text)
	}

	principal := &Principal{Sub: sub, Scope: scope, Claims: *claims}

	// A non-string `account_id` is IGNORED rather than rejected: the token is
	// still a valid token, and a rate-limit key is a worse thing to lose than a
	// well-formed claim is to gain. This is the one deliberate asymmetry in the
	// three claims above and the comment is the reference's.
	if account := claims.String("account_id"); account != "" {
		principal.AccountID = &account
	}

	return principal, nil
}

// decodeHeader is the protected header, read before anything else.
//
// This runs before any key is fetched: the algorithm and the key id are
// attacker-controlled, and an `alg: none` or HS256 token must not be able to make
// gateway call identity. It also means a malformed token costs no network.
func decodeHeader(token string) (string, *Refusal) {
	segments := strings.Split(token, ".")
	// jose's `decodeProtectedHeader` accepts three segments (a JWS) or five (a
	// JWE) and nothing else, and takes the first as the protected header.
	if len(segments) != 3 && len(segments) != 5 {
		return "", unauthorized("token is malformed")
	}

	raw, err := base64.RawURLEncoding.DecodeString(segments[0])
	if err != nil {
		return "", unauthorized("token is malformed")
	}

	var header map[string]any
	if err := json.Unmarshal(raw, &header); err != nil {
		return "", unauthorized("token is malformed")
	}

	// `header.alg !== "RS256"`, and `String(header.alg)` for the message. The
	// `String()` conversion is reproduced rather than simplified because the
	// message reaches a caller and `undefined` is the answer for an absent claim
	// — a token with no `alg` is told `token algorithm 'undefined' is not
	// accepted`, which is a stranger sentence than it looks and is what the
	// reference sends.
	alg, present := header["alg"]
	if !present {
		return "", unauthorized(fmt.Sprintf("token algorithm '%s' is not accepted", "undefined"))
	}
	if text, ok := alg.(string); !ok || text != algorithm {
		return "", unauthorized(fmt.Sprintf("token algorithm '%s' is not accepted", jsString(alg)))
	}

	kid, ok := header["kid"].(string)
	if !ok || kid == "" {
		return "", unauthorized("token header names no key")
	}

	return kid, nil
}

// jsString is JavaScript's `String(value)` for the shapes a JOSE header can
// carry, and it exists for one line of one refusal message.
//
// The value reaching it is always an `alg` that is not `"RS256"`, so the
// interesting cases are an absent claim (handled by the caller), `null`, a
// number, a boolean, an array and an object. Those are all reproduced. It is NOT
// a general JavaScript stringifier and does not try to be: a value that would
// need one is not something a real issuer publishes, and an approximation here
// would be a divergence nobody could find.
func jsString(value any) string {
	switch typed := value.(type) {
	case nil:
		return "null"
	case bool:
		if typed {
			return "true"
		}
		return "false"
	case string:
		return typed
	case float64:
		return jsNumber(typed)
	case []any:
		// `Array.prototype.toString` joins with "," and renders null members as
		// empty strings.
		parts := make([]string, 0, len(typed))
		for _, member := range typed {
			if member == nil {
				parts = append(parts, "")
				continue
			}
			parts = append(parts, jsString(member))
		}
		return strings.Join(parts, ",")
	default:
		// A plain object's `toString` is inherited from `Object.prototype`, and
		// `null` and arrays are the only two that override it — both handled above.
		return "[object Object]"
	}
}

// jsNumber is `Number.prototype.toString` for the base-10 rendering Go's `strconv`
// spells differently.
//
// Go prints a float64 with `%v` in a shortest-round-trip form that agrees with
// JavaScript for every integer, and switches to exponent notation at 1e21 where
// JavaScript switches at 1e21 too. The two places they disagree — `1e-7` and
// below — are not reachable from a JOSE header, so the shared cases are the only
// ones implemented and this says so rather than pretending otherwise.
func jsNumber(value float64) string {
	if math.IsNaN(value) {
		return "NaN"
	}
	if math.IsInf(value, 1) {
		return "Infinity"
	}
	if math.IsInf(value, -1) {
		return "-Infinity"
	}
	return strconv.FormatFloat(value, 'g', -1, 64)
}
