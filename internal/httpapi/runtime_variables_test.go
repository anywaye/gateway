package httpapi

import (
	"net/http"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/anywaye/gateway/internal/ratelimit"
	"github.com/anywaye/gateway/internal/testkeys"
)

var runtimeVariables = []string{
	"PORT",

	"ASSERTION_ISSUER",
	"ASSERTION_SIGNING_KEY_FILE",
	"ASSERTION_SIGNING_KEY_ID",
	"ASSERTION_TTL_MS",
	"ROUTE_TABLE",

	"VHOST_TABLE",

	"IDENTITY_URL",

	"GATEWAY_CLIENT_ID",
	"IDENTITY_ISSUER",
	"IDENTITY_JWKS_TTL_MS",
	"IDENTITY_JWKS_URL",
	"RATE_LIMIT_REQUESTS",
	"RATE_LIMIT_WINDOW_MS",
	"REDIS_URL",
	"TRUSTED_PROXIES",
}

func TestTheRuntimeReaderReadsExactlyTheseVariables(t *testing.T) {
	reads := regexp.MustCompile(`env(?:\(|,\s*)"([A-Z0-9_]+)"`)

	found := map[string]bool{}
	for _, match := range reads.FindAllStringSubmatch(read(t, "runtime.go"), -1) {
		found[match[1]] = true
	}

	want := map[string]bool{}
	for _, name := range runtimeVariables {
		want[name] = true
	}

	var missing, extra []string
	for _, name := range runtimeVariables {
		if !found[name] {
			missing = append(missing, name)
		}
	}
	for name := range found {
		if !want[name] {
			extra = append(extra, name)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)

	if len(missing) > 0 {
		t.Errorf("RuntimeOptions is supposed to read %v and does not read %v. A variable on this list that the reader stopped reading is configuration an operator can set that changes nothing.", runtimeVariables, missing)
	}
	if len(extra) > 0 {
		t.Errorf("RuntimeOptions reads %v, which is not on the list. Either the variable belongs to a subsystem this packet does not port — ROUTE_TABLE and the four ASSERTION_* are the four — or it is a new one and it needs a sentence in runtime.go saying what it configures and what answers when it is set.", extra)
	}
}

func TestTheProbeOrderIsIdentityThenRedis(t *testing.T) {
	config, err := RuntimeOptions(mapEnv(map[string]string{
		"PORT":      "9001",
		"REDIS_URL": "redis://127.0.0.1:6379",
	}))
	if err != nil {
		t.Fatalf("RuntimeOptions refused a valid environment: %v", err)
	}
	t.Cleanup(config.CloseResources)

	var names []string
	for _, probe := range config.Options.Probes {
		names = append(names, probe.Name)
	}

	want := []string{"identity", "redis"}
	if len(names) != len(want) {
		t.Fatalf("RuntimeOptions registered %v; with a REDIS_URL the two documented dependencies are %v. A probe that is not there is a dependency nobody can watch, and a probe that is there without a dependency behind it is a deployment reporting itself broken.", names, want)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Errorf("probe %d is %q, want %q. /readyz renders `deps` in registration order, so this is the order a reader sees — and these two names sort the other way, which is why the assertion can see a reordering at all.", i, names[i], want[i])
		}
	}
}

func TestAProxiedGatewayVerifiesARealToken(t *testing.T) {
	fixture := newJWKSFixture(t)

	verifier, err := authVerifierFor(t, fixture)
	if err != nil {
		t.Fatalf("building a verifier against the fixture's key set: %v", err)
	}

	rec := askWithVerifier(t, Options{Verifier: verifier}, http.MethodGet, "/v1/me",
		map[string]string{"Authorization": bearer(tokenValid(t, fixture))})

	if rec.Code != http.StatusOK {
		t.Fatalf("a valid RS256 token was answered %d, want 200. body: %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type is %q on a 200, want application/json", got)
	}

	if !strings.Contains(rec.Body.String(), `"sub":"`+testkeys.Subject+`"`) {
		t.Errorf("the 200 does not carry the verified subject %q. body: %s", testkeys.Subject, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"iss":"`+testkeys.Issuer+`"`) {
		t.Errorf("the 200 does not echo the verified claims, so it is not proving the payload was parsed. body: %s", rec.Body.String())
	}
	for _, name := range ratelimit.RateLimitHeaders {
		if rec.Header().Get(name) == "" && name != "Retry-After" {
			t.Errorf("%s is absent from an authenticated 200. The contract declares the whole family on this operation and a client reading one of them from a header nobody sends is throttled by nothing.", name)
		}
	}
}
