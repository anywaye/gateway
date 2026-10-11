// The environment reader's own tripwires.
//
// `gateway-go-substrate-01` left two of them here and this packet updates both,
// which is the mechanism working: the reader was one variable long, this packet
// ports the subsystems that own eight more, and each assertion moved in the commit
// that gave it a reason to move. Neither was deleted — a tripwire that is deleted
// rather than re-pointed is a tripwire that will not fire for the packet after this
// one.
//
// The three here are:
//
//   - the reader's variable list, held to the fourteen the ported subsystems own,
//   - the probe list, held to identity-then-redis in THAT order,
//   - and the fact that a gateway built from `RuntimeOptions` with a live issuer
//     really does verify a token, which is what makes the list above a list of
//     things that work rather than a list of things that are read.
package httpapi

import (
	"net/http"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/cafaye/gateway/internal/ratelimit"
	"github.com/cafaye/gateway/internal/testkeys"
)

// runtimeVariables is every variable `RuntimeOptions` reads, and the assertion is
// that the reader reads EXACTLY these.
//
// Named as a list rather than derived, and the difference is deliberate and worth
// stating because the worker contract asks for derived scope: a check that derives
// its scope from the code under test reads whatever the code happens to read and
// reports green forever. A check that holds a written list says "the reader grew,
// someone said so". The failure message names which direction the list moved, so a
// new variable reads as a question rather than as an assertion failure with no
// explanation.
var runtimeVariables = []string{
	// The listening address.
	"PORT",

	// The pass-through: where things go, and what gateway signs about the caller.
	//
	// These five were on the list the pass-through packet wrote and were MISSING
	// here when this packet's list was written — which is the exact failure the
	// assertion exists to catch, caught in the one direction that hurts: two
	// packets, each with a correct exhaustive list, each of which was a superset of
	// the other. Neither list was wrong and the union was what the reader reads.
	"ASSERTION_ISSUER",
	"ASSERTION_SIGNING_KEY_FILE",
	"ASSERTION_SIGNING_KEY_ID",
	"ASSERTION_TTL_MS",
	"ROUTE_TABLE",

	// The hostname split: which name is which backend. Read by `vhostsFromEnv`
	// and nothing else, additive to the path table — an unset split is a gateway
	// whose routing is the path table alone.
	"VHOST_TABLE",

	// The browser surface. The FIFTEENTH, and the only one that is read together
	// with another: a session store has to be shared to be worth having, so
	// `IDENTITY_URL` with no `REDIS_URL` configures no browser surface at all.
	// `browserSurfaceFromEnv` carries why, and `runtime.go`'s header says what
	// answers when it is set.
	"IDENTITY_URL",

	// The verifier and the limiter.
	"GATEWAY_CLIENT_ID",
	"IDENTITY_ISSUER",
	"IDENTITY_JWKS_TTL_MS",
	"IDENTITY_JWKS_URL",
	"RATE_LIMIT_REQUESTS",
	"RATE_LIMIT_WINDOW_MS",
	"REDIS_URL",
	"TRUSTED_PROXIES",
}

// TestTheRuntimeReaderReadsExactlyTheseVariables is the reader's tripwire, and it is
// a REWRITE of `TestTheRuntimeReaderReadsNoOtherVariable` rather than a deletion.
//
// The old one asserted "one variable, and it is PORT", which was true and is now
// false. Asserting the new list keeps the property the old test existed for: a
// variable an operator sets that changes nothing is worse than one they cannot set,
// because `IDENTITY_ISSUER` in a compose file looks configured and configures a
// `404`. A test that only counted would let `ROUTE_TABLE` in silently, which is
// exactly the mistake it was written to catch.
func TestTheRuntimeReaderReadsExactlyTheseVariables(t *testing.T) {
	// BOTH CALL SHAPES, and the second one is not optional.
	//
	// `env("NAME")` is a direct read — `PORT`, `IDENTITY_ISSUER`. `env, "NAME"` is a
	// read handed to one of the two parsing helpers, which take the reader as their
	// first argument so a caller cannot bypass it. Five of the nine variables are
	// read the second way, and a pattern that only matched the first would report
	// five of them missing on every run — which is a check that looks broken rather
	// than a check that is looking at too little, so it would be deleted rather than
	// repaired.
	//
	// What this does NOT match is `os.Getenv`, and that is the other half's job:
	// `TestExactlyOneFileInThisPackageTouchesTheProcessEnvironment` holds that
	// `env.go` is the only file in this package that may read one at all.
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

// TestTheProbeOrderIsIdentityThenRedis is the ordering assertion, and it exists
// because a sorted fixture tests nothing.
//
// `Options.Probes` is a slice rather than a map because `/readyz` renders `deps`
// in registration order: `encoding/json` sorts a map's keys and `Object.entries`
// does not, so a map answers `{"redis":"…","identity":"…"}` where the reference
// answers `{"identity":"…","redis":"…"}` and `internal/equivalence` failed on bytes
// neither side chose.
//
// And `redis` sorts BEFORE `identity`, so the two names here are deliberately the
// wrong way round alphabetically — which is the same trap the substrate packet fell
// into with its three degraded-scenario names (`aperture, identity, redis` was
// alphabetical, so a planted mutation rendering through `json.Marshal` passed). A
// fixture whose names are already sorted renders identically whichever way the code
// renders them, and the property is untested.
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

// TestAProxiedGatewayVerifiesARealToken is the "the list above is a list of things
// that work" assertion.
//
// The other two tests in this file are about the reader's SHAPE: which variables it
// reads, which probes it registers. Both would be satisfied by a reader that read
// nine variables and threw them away. This one drives a signed RS256 token through
// the whole handler — bearer gate, JWKS fetch over HTTP, signature, claims — and
// asserts a `200` carrying the principal.
//
// The key set is served by an `httptest.Server` rather than handed in, because the
// JWKS fetch is one of the things that has to work and a fetch that is stubbed out
// is not a fetch. The clock is injected so the token's `exp` is not a race against
// the wall clock.
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

	// The subject is named by the fixture rather than read out of the token, because
	// a test that read the subject back out of the body it is asserting on would pass
	// on an empty body.
	if !strings.Contains(rec.Body.String(), `"sub":"`+testkeys.Subject+`"`) {
		t.Errorf("the 200 does not carry the verified subject %q. body: %s", testkeys.Subject, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"iss":"`+testkeys.Issuer+`"`) {
		t.Errorf("the 200 does not echo the verified claims, so it is not proving the payload was parsed. body: %s", rec.Body.String())
	}
	// The header family's presence, not its values: the values depend on the clock
	// and are compared against the reference by `internal/equivalence`, which is
	// where a number belongs.
	for _, name := range ratelimit.RateLimitHeaders {
		if rec.Header().Get(name) == "" && name != "Retry-After" {
			t.Errorf("%s is absent from an authenticated 200. The contract declares the whole family on this operation and a client reading one of them from a header nobody sends is throttled by nothing.", name)
		}
	}
}
