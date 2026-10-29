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

	"github.com/anywaye/gateway/internal/auth"
)


var fixedNow = time.Unix(1_700_000_000, 0)

func testMinter(t *testing.T) *AssertionMinter {
	t.Helper()

	minter, err := NewAssertionMinter(AssertionOptions{Key: testKey(t), Now: func() time.Time { return fixedNow }})
	if err != nil {
		t.Fatalf("NewAssertionMinter refused a generated key: %v", err)
	}
	return minter
}

func principal(claims map[string]any) Principal {
	return Principal{Sub: "user-1", Claims: auth.ClaimsFrom(claims)}
}

type decodedAssertion struct {
	Header map[string]any
	Claims map[string]any
	Raw    string
}

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

func mintOne(t *testing.T, minter *AssertionMinter, table RouteTable, principal Principal) *upstream {
	t.Helper()

	service := newUpstream(t, nil)
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

func TestTheAssertionVerifiesAgainstThePublishedJWK(t *testing.T) {
	minter := testMinter(t)

	published, err := minter.PublicJWK()
	if err != nil {
		t.Fatalf("PublicJWK refused: %v", err)
	}

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

	if _, present := decoded.Claims["nbf"]; present {
		t.Error("the assertion carries nbf; gateway signs it microseconds before it is used")
	}
}

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

	if _, err := NewAssertionMinter(AssertionOptions{Key: key, TTL: MaxAssertionTTL}); err != nil {
		t.Errorf("NewAssertionMinter refused the ceiling itself: %v", err)
	}
}


func TestTheAssertionCarriesOnlyTheDeclaredClaims(t *testing.T) {
	silenceLog(t)
	minter := testMinter(t)

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
	if _, present := claims["scope"]; present {
		t.Error("scope crossed, and the table did not declare it")
	}
	if claims["aud"] != service.Origin() {
		t.Errorf("aud is %v, want %s; the caller's token cannot choose the audience", claims["aud"], service.Origin())
	}
}

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


func TestAPublicEntryIsRefusedAnAssertionEvenByATableThatBootWouldHaveRefused(t *testing.T) {
	silenceLog(t)
	minter := testMinter(t)
	service := newUpstream(t, nil)

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

	if _, err := New(Options{Routes: hostile}); err == nil {
		t.Error("New accepted a table that is public AND declares claims")
	}
}


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

	der := []byte{
		0x30, 0x0a, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2a, 0x86, 0x48,
		0xce, 0x3d, 0x02, 0x01, 0x04, 0x22, 0x04, 0x20,
	}
	der = append(der, make([]byte, 32)...)

	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

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

func sortedStrings(in []string) []string {
	out := append([]string{}, in...)
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}
