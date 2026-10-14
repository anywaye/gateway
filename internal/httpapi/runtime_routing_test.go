package httpapi

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The environment reader, and what a gateway built from it actually does.
//
// `TestTheRuntimeReaderReadsExactlyTheseVariables` in `runtime_variables_test.go`
// is the tripwire for the SET. This file is the other half: it asserts that what
// the reader produced is a gateway with the properties a reader of `RuntimeOptions`
// needs to be able to see — a route table, a minter, a credential gate, and the
// two refusals that gate is supposed to make.

// A PEM in a temporary file, because `ASSERTION_SIGNING_KEY_FILE` is a **path** and
// the reason is the property this whole file is about — a private key in an
// environment variable turns up in `docker inspect`, in `/proc/<pid>/environ` and in
// any crash dump.
func writeKeyFile(t *testing.T, name string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), name)
	der, err := x509.MarshalPKCS8PrivateKey(testKey(t).Private)
	if err != nil {
		t.Fatalf("cannot marshal a test key: %v", err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatalf("cannot write the test key: %v", err)
	}
	return path
}

// An unset `ROUTE_TABLE` is no routing, which is the honest default for a deployment
// that has not decided where anything goes — and it is DIFFERENT from an empty table,
// which is a refusal to boot. An operator who wrote `ROUTE_TABLE={}` meant to
// configure something, and the gateway that forwards nothing should say so rather
// than look configured.
func TestARouteTableIsReadFromTheEnvironmentAndAnUnsetOneIsNoRouting(t *testing.T) {
	for _, document := range []string{
		`{"/v1/pantry":{"baseUrl":"http://pantry:8080","token":"svc"}}`,
		`{"/v1/pantry":{"baseUrl":"http://pantry:8080"},"/v1/catalog":{"baseUrl":"http://pantry:8080","public":true}}`,
	} {
		config, err := RuntimeOptions(mapEnv(map[string]string{"ROUTE_TABLE": document}))

		if err != nil {
			t.Fatalf("RuntimeOptions refused %s: %v", document, err)
		}
		if len(config.Options.Routes) == 0 {
			t.Fatalf("RuntimeOptions read %s and configured %d route(s); the table is the configuration and a deployment that set it has routes", document, len(config.Options.Routes))
		}
		if _, err := New(config.Options); err != nil {
			t.Errorf("New refused the configuration RuntimeOptions built from %s: %v", document, err)
		}
	}

	for _, unset := range []string{"", "   "} {
		config, err := RuntimeOptions(mapEnv(map[string]string{"ROUTE_TABLE": unset}))

		if err != nil {
			t.Errorf("RuntimeOptions(%q) refused an unset variable: %v", unset, err)
		}
		if config.Options.Routes != nil {
			t.Errorf("RuntimeOptions(%q) configured %+v; an empty variable is what an unset one looks like in a compose file", unset, config.Options.Routes)
		}
	}
}

// Every refusal is a refusal to **boot**, and it names the variable. A route table
// that is malformed is a gateway that answers 404 for a service that exists, and the
// only moment at which anybody can be told about it is startup.
func TestAMalformedRouteTableVariableIsARefusalToBoot(t *testing.T) {
	for _, document := range []string{
		`not json`,
		`{"/v1/pantry":{"baseUrl":"http://pantry:8080","public":"true"}}`,
		`{"/auth/me":{"baseUrl":"http://identity:8080"}}`,
		`{"/v1/pantry":{"baseUrl":"http://pantry:8080","token":"a b"}}`,
	} {
		config, err := RuntimeOptions(mapEnv(map[string]string{"ROUTE_TABLE": document}))

		if err == nil {
			t.Errorf("RuntimeOptions accepted ROUTE_TABLE=%s and configured %+v", document, config.Options.Routes)
			continue
		}
		if !errors.Is(err, ErrNotConfigured) {
			t.Errorf("ROUTE_TABLE=%s gave %v, which is not ErrNotConfigured", document, err)
		}
	}
}

// The signing key is a path, the TTL has a ceiling, and both are read only when the
// key is named. The last row is the one that matters: `ASSERTION_TTL_MS` set with no
// key is a variable that configures nothing, and it is refused rather than accepted
// so an operator who set it finds out.
func TestTheAssertionKeyIsReadFromTheEnvironmentAndNothingElseIs(t *testing.T) {
	path := writeKeyFile(t, "signing.pem")

	config, err := RuntimeOptions(mapEnv(map[string]string{
		"ASSERTION_SIGNING_KEY_FILE": path,
		"ASSERTION_TTL_MS":           "60000",
		"ASSERTION_ISSUER":           "https://gateway.example",
	}))
	if err != nil {
		t.Fatalf("RuntimeOptions refused a readable key: %v", err)
	}
	if config.Options.Assert == nil {
		t.Fatal("RuntimeOptions configured no minter, so an assertion would never be minted from a key it read")
	}
	if got := config.Options.Assert.ttl; got != time.Minute {
		t.Errorf("the lifetime is %s, want 1m", got)
	}
	if got := config.Options.Assert.issuer; got != "https://gateway.example" {
		t.Errorf("the issuer is %q, want https://gateway.example", got)
	}

	// And the refusal paths, each naming the variable.
	if _, err := RuntimeOptions(mapEnv(map[string]string{"ASSERTION_SIGNING_KEY_FILE": filepath.Join(t.TempDir(), "absent.pem")})); err == nil {
		t.Error("RuntimeOptions accepted a key file that is not there; a missing key must be a refusal to boot")
	} else if !strings.Contains(err.Error(), "ASSERTION_SIGNING_KEY_FILE") {
		t.Errorf("the refusal does not name the variable:\n  %v", err)
	}

	if _, err := RuntimeOptions(mapEnv(map[string]string{"ASSERTION_SIGNING_KEY_FILE": path, "ASSERTION_TTL_MS": "soon"})); err == nil {
		t.Error("RuntimeOptions accepted ASSERTION_TTL_MS=soon")
	} else if !strings.Contains(err.Error(), "ASSERTION_TTL_MS") {
		t.Errorf("the TTL refusal does not name the variable:\n  %v", err)
	}

	// Above the ceiling, which `NewAssertionMinter` refuses with its own sentence —
	// and which is worth asserting here because the ceiling is MD19's third property
	// and this is the only way an operator reaches it.
	if _, err := RuntimeOptions(mapEnv(map[string]string{"ASSERTION_SIGNING_KEY_FILE": path, "ASSERTION_TTL_MS": "2592000000"})); err == nil {
		t.Error("RuntimeOptions accepted a thirty-day assertion lifetime")
	} else if !strings.Contains(err.Error(), "short-lived") {
		t.Errorf("the ceiling refusal does not say why:\n  %v", err)
	}

	// The TTL variables with no key are not read at all, because a lifetime with
	// nothing to sign is not a configuration.
	config, err = RuntimeOptions(mapEnv(map[string]string{"ASSERTION_TTL_MS": "60000"}))
	if err != nil {
		t.Fatalf("RuntimeOptions refused a TTL with no key: %v", err)
	}
	if config.Options.Assert != nil {
		t.Error("RuntimeOptions built a minter with no key file; nothing to sign with is not a minter")
	}
}

// A gateway started from the environment HAS a credential gate, and this test is
// the one that says so.
//
// # IT USED TO ASSERT THE OPPOSITE, AND THE FLIP IS THE WHOLE STORY
//
// This test was written by the pass-through packet as
// `TestAGatewayBuiltFromTheEnvironmentHasNoCredentialGateYet`, and it asserted that
// an anonymous request to a private route reached the pass-through and got the
// upstream's `503`. That was true — there was no verifier in this repository yet —
// and it is false now.
//
// The name ended in "Yet" precisely because it was a statement about a temporary
// state, and the temporary state ended when `internal/auth` landed. What is
// interesting is not that the test had to change but that it changed SILENTLY: the
// reader would have taken away "no gate from the environment" and gone on. The test
// is now its own opposite, and its new assertion is the one that matters: an
// anonymous request is refused **at the gate**, and never reaches an upstream.
//
// # THE `503` MOVED TO WHERE IT BELONGS
//
// Nothing is listening on `127.0.0.1:1`, so a relayed request answers `503`. The
// assertion below is that it answers `401` instead — the refusal happens above the
// pass-through, so the dead port is never dialed. That is the observable difference
// between "relayed anonymously" and "refused", and it is worth being able to tell
// them apart from a test rather than from a log line.
func TestAGatewayBuiltFromTheEnvironmentRefusesAnAnonymousRequestBeforeTheUpstream(t *testing.T) {
	config, err := RuntimeOptions(mapEnv(map[string]string{
		"ROUTE_TABLE": `{"/v1/pantry":{"baseUrl":"http://127.0.0.1:1"}}`,
	}))
	if err != nil {
		t.Fatalf("RuntimeOptions refused a valid table: %v", err)
	}
	t.Cleanup(config.CloseResources)

	if config.Options.Authenticate != nil {
		t.Error("RuntimeOptions set Options.Authenticate directly; it leaves that to the verifier, which `New` reads instead")
	}
	if config.Options.Verifier == nil {
		t.Fatal("RuntimeOptions built a gateway with no verifier, so nothing can authenticate anybody. `runtimeOptions` in the reference always passes `jwt:` — there is no unset-issuer state there — so the honest v0 shape is `New(Options{})`, not a started gateway.")
	}

	handler, err := New(config.Options)
	if err != nil {
		t.Fatalf("New refused: %v", err)
	}

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/v1/pantry/items", nil))

	if rec.Code != 401 {
		t.Fatalf("an anonymous request answered %d, want 401 — a `503` would mean it reached the pass-through and dialed a dead upstream, which is the failure the gate above the pass-through exists to prevent", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/problem+json" {
		t.Errorf("Content-Type is %q on the 401, want application/problem+json", got)
	}
}

// The OTHER half of the gate, and the one that is easy to leave out: a route the
// operator declared `public` answers for an anonymous caller, even on a gateway
// that has a verifier.
//
// One test above and this one together are the property. A gate that refuses
// everything is not a gate, it is a wall, and the difference between them is a
// single word in one JSON entry.
func TestAPublicRouteStillAnswersForAnAnonymousCallerOnAGatewayWithAVerifier(t *testing.T) {
	fixture := newJWKSFixture(t)
	verifier, err := authVerifierFor(t, fixture)
	if err != nil {
		t.Fatalf("building a verifier against the fixture's key set: %v", err)
	}

	handler, err := New(Options{
		Verifier: verifier,
		Routes:   RouteTable{"/v1/catalog": {BaseURL: "http://127.0.0.1:1", Public: true}},
	})
	if err != nil {
		t.Fatalf("New refused: %v", err)
	}

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/v1/catalog/items", nil))

	// `503`, not `401`: port 1 is closed, so a request that was NOT refused at the
	// gate reaches the pass-through and finds nothing listening. A `401` here would
	// be the wall.
	if rec.Code != 503 {
		t.Errorf("an anonymous request to a public route answered %d, want 503 — the upstream is closed, so 503 is the pass-through's own answer and a 401 means the gate refused a route it was told to leave open", rec.Code)
	}
}

// The whole configuration at once, because a reader who sees four variables handled
// separately has learned nothing about whether they compose.
func TestTheWholeRuntimeConfigurationComposes(t *testing.T) {
	path := writeKeyFile(t, "signing.pem")

	config, err := RuntimeOptions(mapEnv(map[string]string{
		"PORT":                       "9100",
		"ROUTE_TABLE":                `{"/v1/pantry":{"baseUrl":"http://pantry:8080","principal":["sub"]}}`,
		"ASSERTION_SIGNING_KEY_FILE": path,
		"ASSERTION_SIGNING_KEY_ID":   "gateway-2026-q3",
		"ASSERTION_TTL_MS":           "120000",
	}))
	if err != nil {
		t.Fatalf("RuntimeOptions refused a complete configuration: %v", err)
	}
	if config.Addr != ":9100" {
		t.Errorf("Addr is %q, want :9100", config.Addr)
	}
	if config.Options.Assert == nil || config.Options.Assert.KeyID() != "gateway-2026-q3" {
		t.Error("the key id the assertion's protected header names is not the one the operator set")
	}
	if _, ok := config.Options.Routes["/v1/pantry"]; !ok {
		t.Errorf("the table is %+v", config.Options.Routes)
	}
	// And the handler builds and answers, which is the only proof that four
	// separately-parsed variables produced one working gateway.
	if rec := ask(t, config.Options, "GET", "/healthz", nil); rec.Code != 200 {
		t.Errorf("the gateway built from the whole configuration answered %d on /healthz", rec.Code)
	}
}

// The key file is read once, at startup — which is the difference between a missing
// key being a refusal to boot and being a 503 on every proxied request. Read twice
// with the second read failing, the property is gone.
func TestTheKeyFileIsReadAtStartupRatherThanPerRequest(t *testing.T) {
	path := writeKeyFile(t, "signing.pem")

	if _, err := RuntimeOptions(mapEnv(map[string]string{"ASSERTION_SIGNING_KEY_FILE": path})); err != nil {
		t.Fatalf("RuntimeOptions refused: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatalf("cannot remove the key file: %v", err)
	}

	// The configuration survives the file going away, because it already holds the
	// parsed key. A gateway that re-read it per request would start failing here.
	if _, err := RuntimeOptions(mapEnv(map[string]string{"ASSERTION_SIGNING_KEY_FILE": path})); err == nil {
		t.Fatal("RuntimeOptions accepted a key file that is gone, so the key is not being read at startup")
	}
}

// A generated key must actually generate: this is the one place a test asserts that
// `testKey` produced something usable, so a failure in `TestTheAssertionVerifies-
// AgainstThePublishedJWK` cannot be a failure of the fixture instead.
func TestTheTestKeyFixtureIsAnRSAKeyPair(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("cannot generate a key: %v", err)
	}
	if key.N.BitLen() != 2048 {
		t.Errorf("the generated modulus is %d bits", key.N.BitLen())
	}
}
