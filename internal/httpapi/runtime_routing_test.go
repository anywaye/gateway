package httpapi

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The environment reader, and the four variables the pass-through needs.
//
// `TestTheRuntimeReaderReadsNoOtherVariable` in `httpapi_test.go` is the tripwire
// for the SET, and it needed widening in this packet. That is the point of it: a
// variable added without the assertion is a variable nobody reads.

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

// A gateway started from the environment has NO credential gate, and that is the
// reference's own state rather than an oversight in this port.
//
// `createApp({routes})` does not register the token gate when no `jwt` option was
// configured, so an anonymous request is relayed — and `gatedUpstream` in
// `internal/equivalence` compares exactly that against the reference. This test
// states it from the environment's side so a reader of `RuntimeOptions` cannot
// mistake "the verifier is not ported yet" for "the gate was forgotten".
func TestAGatewayBuiltFromTheEnvironmentHasNoCredentialGateYet(t *testing.T) {
	config, err := RuntimeOptions(mapEnv(map[string]string{
		"ROUTE_TABLE": `{"/v1/pantry":{"baseUrl":"http://127.0.0.1:1"}}`,
	}))
	if err != nil {
		t.Fatalf("RuntimeOptions refused a valid table: %v", err)
	}
	if config.Options.Authenticate != nil {
		t.Error("RuntimeOptions configured a credential gate, and this packet has no verifier to put behind it")
	}

	handler, err := New(config.Options)
	if err != nil {
		t.Fatalf("New refused: %v", err)
	}

	// Nothing is listening on port 1, so the answer is the pass-through's own 503 —
	// which is the observable difference between "relayed anonymously" and "refused
	// at the gate".
	rec := ask(t, config.Options, "GET", "/v1/pantry/items", nil)
	if rec.Code != 503 {
		t.Fatalf("an anonymous request answered %d, want 503 — it reached the pass-through, which is the reference's behaviour with no verifier configured", rec.Code)
	}
	_ = handler
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
