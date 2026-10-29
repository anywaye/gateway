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
	Issuer string

	Audience string

	JWKSURL string

	JWKSCacheTTL time.Duration

	JWKSTimeout time.Duration

	Now func() time.Time

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
		return nil, fmt.Errorf("%w: %w", ErrNotConfigured, err)
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
		return nil, fmt.Errorf("%w: %w", ErrNotConfigured, err)
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
	Sub string

	Scope []string

	AccountID *string

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

func unauthorized(detail string) *Refusal {
	return &Refusal{Status: http.StatusUnauthorized, Code: "unauthorized", Detail: detail}
}

func forbidden(detail string) *Refusal {
	return &Refusal{Status: http.StatusForbidden, Code: "forbidden", Detail: detail}
}

func unavailable() *Refusal {
	return &Refusal{Status: http.StatusServiceUnavailable, Code: "unavailable", Detail: "the signing keys could not be retrieved"}
}

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
		return nil, unavailable()
	}

	return v.verifyClaims(token, kid, set)
}

func (v *Verifier) verifyClaims(token, kid string, set []jwk) (*Principal, *Refusal) {
	parts := strings.Split(token, ".")
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
		return nil, unauthorized("token is not valid")
	}

	if refusal := v.checkClaims(&claims); refusal != nil {
		return nil, refusal
	}

	return principalOf(&claims)
}

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

func publicKeyOf(key jwk) (*rsa.PublicKey, *Refusal) {
	modulus, err := base64.RawURLEncoding.DecodeString(key.N)
	if err != nil || len(modulus) == 0 {
		return nil, unauthorized("token is not valid")
	}
	exponent, err := base64.RawURLEncoding.DecodeString(key.E)
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
	if n.Bit(0) == 0 || n.Cmp(big.NewInt(3)) <= 0 {
		return nil, unauthorized("token is not valid")
	}

	return &rsa.PublicKey{N: n, E: e}, nil
}

func checkSignature(key *rsa.PublicKey, header, payload, signature string) error {
	sig, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil || len(sig) == 0 {
		return errString("token is not valid")
	}

	signingInput := []byte(header + "." + payload)
	digest := sha256.Sum256(signingInput)

	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], sig); err != nil {
		return errString("token signature does not verify")
	}
	return nil
}

type errString string

func (e errString) Error() string { return string(e) }

func (v *Verifier) checkClaims(claims *Claims) *Refusal {
	if _, ok := claims.Lookup("aud"); !ok {
		return claimRefusal("aud")
	}
	if _, ok := claims.Lookup("iss"); !ok {
		return claimRefusal("iss")
	}

	if claims.String("iss") != v.issuer {
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
			return claimRefusal("exp")
		}
		if seconds <= float64(now) {
			return unauthorized("token has expired")
		}
	}

	return nil
}

func claimRefusal(claim string) *Refusal {
	return unauthorized(fmt.Sprintf("token claim '%s' is not valid", claim))
}

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
				return false
			}
			if text == expected {
				return true
			}
		}
	}
	return false
}

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

	if account := claims.String("account_id"); account != "" {
		principal.AccountID = &account
	}

	return principal, nil
}

func decodeHeader(token string) (string, *Refusal) {
	segments := strings.Split(token, ".")
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
		return "[object Object]"
	}
}

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
