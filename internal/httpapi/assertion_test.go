package httpapi

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cafaye/gateway/internal/auth"
)

// The principal assertion, and MD19's four properties.
//
// 1. Never on a public route.
// 2. Not the caller's token, ever.
// 3. Bound to the upstream and short-lived.
// 4. Minimal claims.
//
// Each has a test below, and `test/proxyMutations.sh` makes each of them absent in
// turn to show the test goes red without it.

// fixedNow is the clock every assertion in this file reads, so `iat` and `exp` are
// values a test can state rather than a moment it has to catch.
var fixedNow = time.Unix(1_700_000_000, 0)

// testMinter is a minter with a fixed clock and a generated key.
func testMinter(t *testing.T) *AssertionMinter {
	t.Helper()

	minter, err := NewAssertionMinter(AssertionOptions{Key: testKey(t), Now: func() time.Time { return fixedNow }})
	if err != nil {
		t.Fatalf("NewAssertionMinter refused a generated key: %v", err)
	}
	return minter
}

// principal is a verified caller, with the claims identity actually signed.
func principal(claims map[string]any) Principal {
	return Principal{Sub: "user-1", Claims: auth.ClaimsFrom(claims)}
}

// decodedAssertion is a compact JWS taken apart.
type decodedAssertion struct {
	Header map[string]any
	Claims map[string]any
	Raw    string
}

// decode reads a compact JWS apart WITHOUT verifying it, so a test that wants to
// look at the claims does not have to trust them and a test that wants to know the
// signature verifies calls `verify` as well.
func decodeAssertion(t *testing.T, compact string) decodedAssertion {
	t.Helper()

	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		t.Fatalf("the assertion is not a compact JWS (%d parts): %q", len(parts), compact)
	}

	out := decodedAssertion{Raw: compact}
	for i, part := range parts[:2] {
		raw, err := base64.RawURLEncoding.DecodeString(part)
		if err != nil {
			t.Fatalf("part %d is not base64url: %v", i, err)
		}
		into := map[string]any{}
		if err := json.Unmarshal(raw, &into); err != nil {
			t.Fatalf("part %d is not a JSON object: %v (%s)", i, err, raw)
		}
		if i == 0 {
			out.Header = into
		} else {
			out.Claims = into
		}
	}

	return out
}

// verify checks the signature the way any independent service would: with the
// published key, `net/http`'s own standard library, and no cafaye-specific code.
func (d decodedAssertion) verify(t *testing.T, key *rsa.PublicKey) {
	t.Helper()

	parts := strings.Split(d.Raw, ".")
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("the signature is not base64url: %v", err)
	}

	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature); err != nil {
		t.Fatalf("the assertion does not verify against the key this gateway publishes: %v", err)
	}
}

// mintOne asks the pass-through for an assertion and returns what the upstream saw.
func mintOne(t *testing.T, minter *AssertionMinter, table RouteTable, principal Principal) *upstream {
	t.Helper()

	service := newUpstream(t, nil)
	// The origins are rewritten to the test upstream, because what is under test is
	// the `aud` claim and the claim set rather than reachability — and a table naming
	// `http://pantry:8080` would answer 503 for a service that is not there, which
	// is a different test wearing this one's name.
	pointed := make(RouteTable, len(table))
	for prefix, target := range table {
		target.BaseURL = service.Origin()
		pointed[prefix] = target
	}

	handler, err := New(Options{
		Routes:       pointed,
		Assert:       minter,
		Authenticate: func(*http.Request) (*Principal, error) { return &principal, nil },
	})
	if err != nil {
		t.Fatalf("New refused %+v: %v", pointed, err)
	}

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/v1/pantry/items", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("the gateway answered %d, want 200\n  %s", rec.Code, rec.Body.String())
	}

	return service
}

// --------------------------------------------------------------------------
// property 2: not the caller's token, ever
// --------------------------------------------------------------------------

// TestTheAssertionIsGatewaySignedAndNotTheCallersToken is MD19's second property.
//
// The assertion is gateway's OWN signature over a claim set, and it is carried in
// its own header beside a *different* credential — the per-upstream service token
// in `authorization`. Forwarding the caller's bearer token would make gateway a
// credential relay for a token minted for a different audience, and the upstream
// has no way to narrow what it accepts.
//
// Four things are asserted because any one of them could be true of a wrong
// implementation: the header is present and separate, it verifies under the key
// gateway publishes, `authorization` carries the service credential and not the
// caller's, and the payload is the claim set gateway signed rather than the
// caller's JWT.
func TestTheAssertionIsGatewaySignedAndNotTheCallersToken(t *testing.T) {
	silenceLog(t)
	minter := testMinter(t)
	service := newUpstream(t, nil)

	callerClaims := map[string]any{
		"sub":         "user-1",
		"scope":       "catalog:read catalog:write",
		"github_id":   "12345",
		"account_id":  "acct-1",
		"token_type":  "Bearer",
		"org_id":      "org-9",
		"permissions": []any{"everything", "including", "this"},
	}

	handler, err := New(Options{
		Routes: RouteTable{"/v1/pantry": {BaseURL: service.Origin(), Token: "svc-token", Principal: []string{"sub", "github_id"}}},
		Assert: minter,
		Authenticate: func(*http.Request) (*Principal, error) {
			return &Principal{Sub: "user-1", Claims: auth.ClaimsFrom(callerClaims)}, nil
		},
	})
	if err != nil {
		t.Fatalf("New refused: %v", err)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/v1/pantry/items", nil)
	req.Header.Set("Authorization", "Bearer the-callers-own-jwt")
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("the gateway answered %d, want 200", rec.Code)
	}

	seen := service.Last(t)

	// A third header, not a second value in the first: `authorization` already
	// carries a different credential, and asking one header to carry two answers to
	// two questions is how a service ends up reading the wrong one.
	if got := seen.Header.Get("Authorization"); got != "Bearer svc-token" {
		t.Errorf("the upstream saw Authorization %q, want the table's own service credential", got)
	}
	compact := seen.Header.Get(AssertionHeader)
	if compact == "" {
		t.Fatalf("the upstream saw no %s header", AssertionHeader)
	}
	if strings.Contains(compact, "the-callers-own-jwt") {
		t.Error("the assertion carries the caller's own token")
	}

	decoded := decodeAssertion(t, compact)
	decoded.verify(t, minter.key.Public)

	// It is a *different* signature from anything identity could have minted,
	// because it is signed with a key identity does not hold. Asserting that here
	// would need identity's private key, so what is asserted instead is the payload
	// is gateway's own claim set: five envelope fields and the declared claims.
	for _, name := range []string{"iss", "aud", "iat", "exp", "jti"} {
		if _, ok := decoded.Claims[name]; !ok {
			t.Errorf("the assertion has no %q; gateway signs its own envelope", name)
		}
	}
	if decoded.Claims["iss"] != DefaultAssertionIssuer {
		t.Errorf("iss is %v, want %s", decoded.Claims["iss"], DefaultAssertionIssuer)
	}
	if decoded.Header["alg"] != "RS256" {
		t.Errorf("alg is %v, want RS256 — the algorithm is a property of gateway's key, not a hint", decoded.Header["alg"])
	}
}

// TestTheAssertionVerifiesAgainstThePublishedJWK is what makes the hand-rolled
// signer honest.
//
// The signing half is `crypto/rsa` plus `encoding/base64` plus `encoding/json`
// rather than a dependency, and a hand-rolled signer that no standard verifier has
// ever checked would be a real risk. So the assertion is verified here against a
// key rebuilt **from the published JWK alone** — `n`, `e` and nothing else — with
// `rsa.VerifyPKCS1v15`. If the compact form, the header, or the encoding were
// wrong, this fails and no other test in the package would notice.
func TestTheAssertionVerifiesAgainstThePublishedJWK(t *testing.T) {
	minter := testMinter(t)

	published, err := minter.PublicJWK()
	if err != nil {
		t.Fatalf("PublicJWK refused: %v", err)
	}

	// A verifier that knows nothing about gateway: the two numbers and the rest.
	modulus, err := base64.RawURLEncoding.DecodeString(published.N)
	if err != nil {
		t.Fatalf("n is not base64url: %v", err)
	}
	exponentBytes, err := base64.RawURLEncoding.DecodeString(published.E)
	if err != nil {
		t.Fatalf("e is not base64url: %v", err)
	}

	rebuilt := &rsa.PublicKey{
		N: new(big.Int).SetBytes(modulus),
		E: int(new(big.Int).SetBytes(exponentBytes).Int64()),
	}
	if !rebuilt.Equal(minter.key.Public) {
		t.Fatal("the published key is not this gateway's key, so nothing signed here could ever be verified by anyone")
	}
	if exponent := base64.RawURLEncoding.EncodeToString(exponentBytes); exponent != "AQAB" {
		t.Errorf("the published exponent is %q, want AQAB — %d is three bytes of big-endian 65537 and a wider word would be a key no other implementation produces", exponent, rebuilt.E)
	}

	compact, err := minter.Mint(principal(map[string]any{"sub": "user-1"}), AssertionSubject{Audience: "http://pantry:8080", Claims: []string{"sub"}})
	if err != nil {
		t.Fatalf("Mint refused: %v", err)
	}
	decodeAssertion(t, compact).verify(t, rebuilt)
}

// --------------------------------------------------------------------------
// property 3: bound to the upstream, and short-lived
// --------------------------------------------------------------------------

// TestTheAssertionIsBoundToTheUpstreamAndShortLived is MD19's third property.
//
// `aud` is the upstream's **origin**, which `ValidateRouteTable` has already
// reduced it to, so a leaked assertion is worth nothing on any other upstream — and
// the check is one any JWT verifier that has never heard of cafaye can make, with
// no cafaye-specific claim to understand first.
//
// The lifetime is the second half and it is a *ceiling*, not a default: a lifetime
// nobody may exceed cannot be configured into something that is no longer
// short-lived.
func TestTheAssertionIsBoundToTheUpstreamAndShortLived(t *testing.T) {
	silenceLog(t)
	minter := testMinter(t)
	table := RouteTable{"/v1/pantry": {BaseURL: "http://pantry:8080", Principal: []string{"sub"}}}
	service := mintOne(t, minter, table, principal(map[string]any{"sub": "user-1"}))

	compact := service.Last(t).Header.Get(AssertionHeader)
	decoded := decodeAssertion(t, compact)

	if got := decoded.Claims["aud"]; got != service.Origin() {
		t.Errorf("aud is %v, want the upstream's origin %s — an assertion asserted for one route must not verify on another", got, service.Origin())
	}

	iat, exp := numberClaim(t, decoded.Claims, "iat"), numberClaim(t, decoded.Claims, "exp")
	if exp <= iat {
		t.Fatalf("exp (%d) is not after iat (%d); the window would be zero or negative", exp, iat)
	}
	window := time.Duration(exp-iat) * time.Second
	if window > MaxAssertionTTL {
		t.Errorf("the window is %s, above the %s ceiling MD19 asks for", window, MaxAssertionTTL)
	}
	if window != DefaultAssertionTTL {
		t.Errorf("the window is %s, want the %s default", window, DefaultAssertionTTL)
	}

	// `nbf` is deliberately absent, and its absence is asserted rather than left
	// alone: a not-before on a token minted microseconds ago buys a skew window
	// nobody configured and refuses nothing, so an upstream that enforces it rejects
	// a token it should have accepted.
	if _, present := decoded.Claims["nbf"]; present {
		t.Error("the assertion carries nbf; gateway signs it microseconds before it is used")
	}
}

// An assertion minted for one upstream does not verify for another. The refusal is
// the point, so it is checked by *minting twice* against two audiences and
// comparing the audiences rather than by asserting on one string.
func TestAnAssertionForOneUpstreamNamesTheOtherUpstreamsOrigin(t *testing.T) {
	minter := testMinter(t)

	first, err := minter.Mint(principal(map[string]any{"sub": "user-1"}), AssertionSubject{Audience: "http://pantry:8080", Claims: []string{"sub"}})
	if err != nil {
		t.Fatalf("Mint refused: %v", err)
	}
	second, err := minter.Mint(principal(map[string]any{"sub": "user-1"}), AssertionSubject{Audience: "http://other:9000", Claims: []string{"sub"}})
	if err != nil {
		t.Fatalf("Mint refused: %v", err)
	}

	if got := decodeAssertion(t, first).Claims["aud"]; got != "http://pantry:8080" {
		t.Errorf("the first assertion's aud is %v", got)
	}
	if got := decodeAssertion(t, second).Claims["aud"]; got != "http://other:9000" {
		t.Errorf("the second assertion's aud is %v; the audience is the route being called and nothing else", got)
	}
	if first == second {
		t.Error("two assertions for two upstreams are byte-identical, so a leaked one would verify on the other")
	}
}

// `jti` is what makes two assertions for the same caller on the same route differ,
// which is what lets an upstream log and correlate one without being able to
// replay either. A `jti` that is accidentally constant is a field nobody reads.
func TestTwoAssertionsForTheSameCallerDiffer(t *testing.T) {
	minter := testMinter(t)
	subject := AssertionSubject{Audience: "http://pantry:8080", Claims: []string{"sub"}}

	first, err := minter.Mint(principal(map[string]any{"sub": "user-1"}), subject)
	if err != nil {
		t.Fatalf("Mint refused: %v", err)
	}
	second, err := minter.Mint(principal(map[string]any{"sub": "user-1"}), subject)
	if err != nil {
		t.Fatalf("Mint refused: %v", err)
	}

	if first == second {
		t.Error("two assertions for the same caller and route are byte-identical")
	}
	if firstJTI, secondJTI := decodeAssertion(t, first).Claims["jti"], decodeAssertion(t, second).Claims["jti"]; firstJTI == secondJTI {
		t.Errorf("both assertions carry jti %v; a constant correlation id is a field nobody reads", firstJTI)
	}
}

// An assertion lifetime nobody may exceed is a refusal to boot, and so is a lifetime
// that is not a whole number of milliseconds. `30d` naming the maximum is the
// refusal worth having: a ceiling that could be configured past is not a ceiling.
func TestAnAssertionLifetimeNobodyMayExceedIsARefusalToBoot(t *testing.T) {
	key := testKey(t)

	cases := []struct {
		name string
		ttl  time.Duration
	}{
		{name: "a day", ttl: 24 * time.Hour},
		{name: "thirty days, which is the refusal that names the maximum", ttl: 30 * 24 * time.Hour},
		{name: "above the ceiling by a millisecond", ttl: MaxAssertionTTL + time.Millisecond},
		{name: "sub-millisecond", ttl: 500 * time.Microsecond},
		{name: "negative", ttl: -time.Second},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			minter, err := NewAssertionMinter(AssertionOptions{Key: key, TTL: tc.ttl})
			if err == nil {
				t.Fatalf("NewAssertionMinter accepted a %s lifetime and returned %+v; an assertion nobody may make long-lived is the property", tc.ttl, minter)
			}
			if !strings.Contains(err.Error(), "short-lived") && !strings.Contains(err.Error(), "at least 1ms") {
				t.Errorf("the refusal does not say why: %v", err)
			}
		})
	}

	// And the ceiling itself is accepted, so the check is not "refuse everything".
	if _, err := NewAssertionMinter(AssertionOptions{Key: key, TTL: MaxAssertionTTL}); err != nil {
		t.Errorf("NewAssertionMinter refused the ceiling itself: %v", err)
	}
}

// --------------------------------------------------------------------------
// property 4: minimal claims
// --------------------------------------------------------------------------

// TestTheAssertionCarriesOnlyTheDeclaredClaims is MD19's fourth property.
//
// An upstream that has not declared what it needs gets nothing at all; an upstream
// that declares three claims gets exactly those three, from the verified token and
// not from gateway's idea of the caller. Both halves are asserted as *sets*, so a
// claim the caller carried and nobody declared is a failure — that is the direction
// a refactor goes wrong in.
func TestTheAssertionCarriesOnlyTheDeclaredClaims(t *testing.T) {
	silenceLog(t)
	minter := testMinter(t)

	// The caller carries seven claims. The table names two.
	table := RouteTable{"/v1/pantry": {BaseURL: "http://pantry:8080", Principal: []string{"sub", "github_id"}}}
	service := mintOne(t, minter, table, principal(map[string]any{
		"sub":        "user-1",
		"github_id":  "12345",
		"scope":      "catalog:read catalog:write",
		"account_id": "acct-1",
		"org_id":     "org-9",
		"aud":        "gateway",
		"token_type": "Bearer",
	}))

	claims := decodeAssertion(t, service.Last(t).Header.Get(AssertionHeader)).Claims

	got := make([]string, 0, len(claims))
	for name := range claims {
		got = append(got, name)
	}
	want := []string{"aud", "exp", "github_id", "iat", "iss", "jti", "sub"}

	if !reflect.DeepEqual(sortedStrings(got), want) {
		t.Errorf("the assertion carries %v, want exactly %v. The five envelope fields are gateway's; the other two are what the table declared.", sortedStrings(got), want)
	}

	if got := claims["github_id"]; got != "12345" {
		t.Errorf("github_id is %v, want 12345", got)
	}
	// `scope` crosses as the STRING identity signed, never as the array gateway
	// parsed it into: reshaping a claim would make the assertion a *different*
	// claim from the one identity verified.
	if _, present := claims["scope"]; present {
		t.Error("scope crossed, and the table did not declare it")
	}
	// `aud` is gateway's, whatever the caller's token said. `checkClaimName` refuses
	// the name in a route entry and the envelope is written first; this is the
	// property that makes the second of those two gates observable.
	if claims["aud"] != service.Origin() {
		t.Errorf("aud is %v, want %s; the caller's token cannot choose the audience", claims["aud"], service.Origin())
	}
}

// A declared claim the caller's token does not carry is **omitted**, not invented
// and not refused — because MD19 wants a publisher with no row to get a "no
// publisher record" refusal at the upstream, and that needs a missing `github_id`
// to arrive as a missing `github_id`.
func TestADeclaredClaimTheTokenDoesNotCarryIsOmittedRatherThanInvented(t *testing.T) {
	silenceLog(t)
	minter := testMinter(t)

	table := RouteTable{"/v1/pantry": {BaseURL: "http://pantry:8080", Principal: []string{"sub", "github_id"}}}
	service := mintOne(t, minter, table, principal(map[string]any{"sub": "user-1"}))

	claims := decodeAssertion(t, service.Last(t).Header.Get(AssertionHeader)).Claims

	if _, present := claims["github_id"]; present {
		t.Errorf("github_id is %v in an assertion for a caller whose token carried none; a missing claim must arrive missing", claims["github_id"])
	}
	if claims["sub"] != "user-1" {
		t.Errorf("sub is %v; the declared claims that DID exist must still cross", claims["sub"])
	}
}

// `sub` is included from the principal when the declared set does not name it,
// because an assertion that dropped the subject would be useless — but the declared
// set still governs, so an entry that asked for nothing does not get it (and an
// entry that asked for nothing gets no assertion at all; see the next test).
func TestTheSubjectCrossesWhenTheDeclaredSetDoesNotNameIt(t *testing.T) {
	minter := testMinter(t)

	compact, err := minter.Mint(principal(map[string]any{"sub": "user-1", "github_id": "1"}),
		AssertionSubject{Audience: "http://pantry:8080", Claims: []string{"github_id"}})
	if err != nil {
		t.Fatalf("Mint refused: %v", err)
	}

	claims := decodeAssertion(t, compact).Claims
	if claims["sub"] != "user-1" {
		t.Errorf("sub is %v, want user-1 — every verified principal has one and an assertion that dropped it would be useless", claims["sub"])
	}
	if claims["github_id"] != "1" {
		t.Errorf("github_id is %v, want 1", claims["github_id"])
	}
}

// The four conditions, each of which can independently mean "no assertion". Three of
// them are conveniences and the second is the security rule; the table names each
// one so a reader can see which is which.
func TestNoAssertionIsMintedWithoutAMinterOrWithoutADeclaration(t *testing.T) {
	silenceLog(t)
	minter := testMinter(t)

	cases := []struct {
		name    string
		table   RouteTable
		minter  *AssertionMinter
		gated   bool
		absent  string
		present bool
	}{
		{
			name:    "no minter configured, which is every deployment without a signing key",
			table:   RouteTable{"/v1/pantry": {BaseURL: "up", Principal: []string{"sub"}}},
			minter:  nil,
			gated:   true,
			absent:  "no signing key means the headers a gateway without one already sent",
			present: false,
		},
		{
			name:    "the entry declared no claims, so the upstream never agreed to hold one",
			table:   RouteTable{"/v1/pantry": {BaseURL: "up", Principal: nil}},
			minter:  minter,
			gated:   true,
			absent:  "no wildcard: an upstream that declared nothing gets no assertion",
			present: false,
		},
		{
			name:    "no verified principal, so there is nothing to assert and nothing to assert about",
			table:   RouteTable{"/v1/pantry": {BaseURL: "up", Principal: []string{"sub"}}},
			minter:  minter,
			gated:   false,
			absent:  "a gateway with routes and no verifier has no principal to sign",
			present: false,
		},
		{
			name:    "the entry declared claims and a caller was verified",
			table:   RouteTable{"/v1/pantry": {BaseURL: "up", Principal: []string{"sub"}}},
			minter:  minter,
			gated:   true,
			absent:  "this is the case an assertion is for",
			present: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			service := newUpstream(t, nil)
			authenticate := Authenticate(nil)
			if tc.gated {
				authenticate = func(*http.Request) (*Principal, error) {
					return &Principal{Sub: "user-1", Claims: auth.ClaimsFrom(map[string]any{"sub": "user-1"})}, nil
				}
			}

			table := RouteTable{}
			for prefix, target := range tc.table {
				table[prefix] = RouteTarget{BaseURL: service.Origin(), Principal: target.Principal}
			}

			handler, err := New(Options{Routes: table, Assert: tc.minter, Authenticate: authenticate})
			if err != nil {
				t.Fatalf("New refused: %v", err)
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/v1/pantry/items", nil))

			got := service.Last(t).Header.Get(AssertionHeader)
			if tc.present && got == "" {
				t.Errorf("no assertion was minted (%s)", tc.absent)
			}
			if !tc.present && got != "" {
				t.Errorf("an assertion was minted for a route that must not carry one (%s): %s", tc.absent, got)
			}
		})
	}
}

// --------------------------------------------------------------------------
// property 1: never on a public route
// --------------------------------------------------------------------------

// TestAPublicEntryIsRefusedAnAssertionEvenByATableThatBootWouldHaveRefused is
// MD19's first property, and it is the only one of the four that is a security rule
// rather than a convenience.
//
// `ValidateRouteTable` already refuses `public` together with `principal`, so
// condition 2 in `assertionFor` is unreachable through `New` — and a line that is
// unreachable is a line nothing tests. So this builds the proxy **directly**, with a
// table the validator would refuse, and asks it what it does with the header. This
// is the only way that line is not a green by omission, and it is the same reason
// `src/routes/assertion.test.ts` (removed at cutover) exists.
func TestAPublicEntryIsRefusedAnAssertionEvenByATableThatBootWouldHaveRefused(t *testing.T) {
	silenceLog(t)
	minter := testMinter(t)
	service := newUpstream(t, nil)

	// The table `New` would refuse. Reached through `newRouteProxy` so that the
	// send-site gate has something to refuse.
	hostile := RouteTable{"/v1/catalog": {
		BaseURL:   service.Origin(),
		Public:    true,
		Principal: []string{"sub"},
	}}

	handler := newRouteProxy(proxyOptions{Routes: hostile, Assertion: minter}).handle(
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			t.Fatal("the pass-through called the next handler; an unclaimed path must fall through to the 404")
		}),
	)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, withPrincipal(httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/v1/catalog/items", nil),
		Principal{Sub: "user-1", Claims: auth.ClaimsFrom(map[string]any{"sub": "user-1"})}))

	if got := service.Last(t).Header.Get(AssertionHeader); got != "" {
		t.Errorf("an assertion was minted for a public route: %s. A public route has no verified caller, so that is a signed statement about a request nobody was required to make.", got)
	}

	// And the boot-time half of the same rule, so neither gate is standing alone.
	if _, err := New(Options{Routes: hostile}); err == nil {
		t.Error("New accepted a table that is public AND declares claims")
	}
}

// --------------------------------------------------------------------------
// the published key
// --------------------------------------------------------------------------

// TestThePublishedJWKCarriesOnlyThePublicHalf is the mistake `assertion.ts`
// documents having made, held as a test.
//
// `exportJWK` given a Node **private** `KeyObject` returns `kty, n, e, d, p, q, dp,
// dq, qi` — the whole private key, RSA primes included — and the first draft of that
// function exported the private key it had been handed. Nothing about the token set
// would have looked wrong, because the RFC 7638 thumbprint hashes only `e`, `kty`
// and `n`.
//
// In Go the mistake is available as a struct with a private-exponent field, and the
// defense is that `JSONWebKey` **has no such field** — so this asserts the exact
// field set rather than merely that the key verifies.
func TestThePublishedJWKCarriesOnlyThePublicHalf(t *testing.T) {
	minter := testMinter(t)

	published, err := minter.PublicJWK()
	if err != nil {
		t.Fatalf("PublicJWK refused: %v", err)
	}

	encoded, err := json.Marshal(published)
	if err != nil {
		t.Fatalf("the published key did not encode: %v", err)
	}
	var fields map[string]any
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatalf("the published key is not a JSON object: %v", err)
	}

	want := map[string]bool{"kty": true, "n": true, "e": true, "kid": true, "alg": true, "use": true}
	for name := range fields {
		if !want[name] {
			t.Errorf("the published key carries %q, which no RFC 7517 public key needs. The private halves are `d`, `p`, `q`, `dp`, `dq`, `qi` and every one of them is a signing key handed to every upstream.", name)
		}
		delete(want, name)
	}
	for name := range want {
		t.Errorf("the published key has no %q; a key set without it says less and an upstream cannot select the key", name)
	}

	if fields["kty"] != "RSA" || fields["alg"] != "RS256" || fields["use"] != "sig" {
		t.Errorf("the published key is %v; `alg` and `use` are what stop an upstream accepting this key for anything but a signature", fields)
	}
}

// The `kid` is the RFC 7638 thumbprint unless an operator named one, because an
// invented `kid` that two deployments both call `gateway-1` is a key set in which
// an upstream silently verifies against the wrong deployment's key — and a thumbprint
// cannot collide across keys.
func TestTheKeyIdIsTheThumbprintUnlessAnOperatorNamedOne(t *testing.T) {
	key := testKey(t)

	derived, err := NewAssertionMinter(AssertionOptions{Key: key})
	if err != nil {
		t.Fatalf("NewAssertionMinter refused: %v", err)
	}
	published, err := derived.PublicJWK()
	if err != nil {
		t.Fatalf("PublicJWK refused: %v", err)
	}
	if published.Kid == "" {
		t.Error("no kid was derived from the key")
	}
	if want := thumbprint(published); published.Kid != want {
		t.Errorf("the derived kid is %q, want the RFC 7638 thumbprint %q", published.Kid, want)
	}
	// The thumbprint hashes only `e`, `kty` and `n` — so `alg` and `use` cannot be in
	// it, or editing a key set's annotations would change a key's identity.
	if strings.Contains(published.Kid, published.Alg) {
		t.Errorf("the kid %q contains the alg, so the thumbprint is hashing more than RFC 7638 names", published.Kid)
	}

	withID, err := NewAssertionMinter(AssertionOptions{Key: AssertionKey{KeyID: "gateway-2026-q3", Private: key.Private, Public: key.Public}})
	if err != nil {
		t.Fatalf("NewAssertionMinter refused an explicit kid: %v", err)
	}
	publishedWithID, err := withID.PublicJWK()
	if err != nil {
		t.Fatalf("PublicJWK refused: %v", err)
	}
	if publishedWithID.Kid != "gateway-2026-q3" {
		t.Errorf("an operator-named kid became %q; the trade is documented — a hand-published id is one gateway cannot check", publishedWithID.Kid)
	}
	if withID.KeyID() != "gateway-2026-q3" {
		t.Errorf("KeyID() is %q, want gateway-2026-q3 — the protected header must name the key the set publishes", withID.KeyID())
	}
}

// A minter whose two halves disagree refuses to exist, because every assertion
// would verify against a key set this gateway publishes which does not contain the
// key that signed it — a failure with no local symptom at all.
func TestAMinterWhoseTwoHalvesDisagreeIsARefusalToBoot(t *testing.T) {
	first, second := testKey(t), testKey(t)

	_, err := NewAssertionMinter(AssertionOptions{Key: AssertionKey{Private: first.Private, Public: second.Public}})
	if err == nil {
		t.Error("NewAssertionMinter accepted a key pair whose halves are different keys")
	}
	if _, err := NewAssertionMinter(AssertionOptions{}); err == nil {
		t.Error("NewAssertionMinter accepted a configuration with no key")
	}
}

// --------------------------------------------------------------------------
// reading a key
// --------------------------------------------------------------------------

// A key is read from a file path, not from an environment value, because a private
// key in an environment variable turns up in `docker inspect`, in
// `/proc/<pid>/environ` and in any crash dump. Every way a PEM can be wrong is a
// startup refusal — there is no third case where it is discovered on the first
// proxied request.
func TestAMalformedAssertionKeyIsARefusalToBoot(t *testing.T) {
	valid := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: mustMarshalPKCS8(t, testKey(t))})

	cases := []struct{ name, document string }{
		{name: "not a PEM block at all", document: "this is not a key"},
		{name: "a PEM block that is not a key", document: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("nonsense")}))},
		{name: "an EC key, which cannot sign an RS256 header", document: mustECKeyPEM(t)},
		{name: "empty", document: ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			key, err := ReadAssertionKey(tc.document, "")
			if err == nil {
				t.Fatalf("ReadAssertionKey accepted %s and returned %+v", tc.name, key)
			}
			if !strings.Contains(err.Error(), "ErrNotConfigured") && !strings.Contains(err.Error(), "httpapi: invalid configuration") {
				t.Errorf("the refusal is not ErrNotConfigured, so a caller cannot tell its own mistake from a defect: %v", err)
			}
		})
	}

	// And the one that works, which is what makes the refusals a check rather than a
	// blanket: the generated PEM is read back, the halves agree, and it verifies.
	round, err := ReadAssertionKey(string(valid), "")
	if err != nil {
		t.Fatalf("ReadAssertionKey refused a PEM this test generated with the same toolchain: %v", err)
	}
	if round.KeyID != "" {
		t.Errorf("KeyID is %q, want empty so the thumbprint is derived", round.KeyID)
	}
	if round.Public == nil || round.Private == nil {
		t.Fatal("the key round-tripped with a half missing")
	}
}

func mustMarshalPKCS8(t *testing.T, key AssertionKey) []byte {
	t.Helper()

	der, err := x509.MarshalPKCS8PrivateKey(key.Private)
	if err != nil {
		t.Fatalf("cannot marshal the test key: %v", err)
	}
	return der
}

func mustECKeyPEM(t *testing.T) string {
	t.Helper()

	// A syntactically valid PKCS#8 block holding an EC key. Hand-built rather than
	// generated so the test does not depend on `crypto/ec` being worth importing for
	// one string: the marshaled form below is the smallest ASN.1 sequence the
	// standard library's parser will accept as a key, and any key that is not RSA is
	// refused by the type assertion in `ReadAssertionKey` either way.
	der := []byte{
		0x30, 0x0a, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2a, 0x86, 0x48,
		0xce, 0x3d, 0x02, 0x01, 0x04, 0x22, 0x04, 0x20,
	}
	// 32 bytes of key material after the OID, which is the shape the parser wants.
	der = append(der, make([]byte, 32)...)

	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

// The issuer is an origin, and every way it can be wrong is a startup refusal.
func TestAMalformedAssertionIssuerIsARefusalToBoot(t *testing.T) {
	key := testKey(t)

	for _, issuer := range []string{"not a url", "ftp://gateway", "https://gateway.example/v1/thing", "https://gateway.example?x=1"} {
		if _, err := NewAssertionMinter(AssertionOptions{Key: key, Issuer: issuer}); err == nil {
			t.Errorf("NewAssertionMinter accepted the issuer %q; an upstream verifies it to learn which gateway minted the assertion", issuer)
		}
	}

	for _, issuer := range []string{"", DefaultAssertionIssuer, "http://gateway.localhost", "https://gateway.localhost:8443"} {
		if _, err := NewAssertionMinter(AssertionOptions{Key: key, Issuer: issuer}); err != nil {
			t.Errorf("NewAssertionMinter refused the issuer %q: %v", issuer, err)
		}
	}
}

// numberClaim reads a numeric claim out of a decoded payload.
//
// JSON numbers decode as `float64`, and `int64(v.(float64))` is the only way back.
// A missing or non-numeric claim is a failure rather than a zero, because `iat: 0`
// would make the window look enormous and pass a check it should fail.
func numberClaim(t *testing.T, claims map[string]any, name string) int64 {
	t.Helper()

	raw, present := claims[name]
	if !present {
		t.Fatalf("the assertion has no %q claim", name)
	}
	number, ok := raw.(float64)
	if !ok {
		t.Fatalf("the %q claim is %T, want a number", name, raw)
	}
	return int64(number)
}

// sortedStrings is `sort.Strings` without the import, for the one call site that
// compares two claim sets and does not care about the order otherwise.
func sortedStrings(in []string) []string {
	out := append([]string{}, in...)
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}
