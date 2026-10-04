package httpapi

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

// Config is everything `cmd/gateway` needs to serve, as read from the
// environment: the handler's own configuration, and the address to reach it on.
//
// The two are one value because there is exactly one reader, and splitting them
// would mean either two readers or a second argument the caller has to thread.
// They are separate fields because they are separate facts: `Options` is what
// the gateway serves, `Addr` is how the process is reached, and a test holds
// that they do not get mixed.
type Config struct {
	// What to build the handler from.
	Options Options

	// `host:port`, already validated. An empty port would be an unspecified one,
	// which `cmd/gateway` refuses rather than passing on — see `portFromEnv`.
	Addr string
}

// RuntimeOptions builds the configuration from the environment, and with
// `env.go` it is the only function in this module that reads one.
//
// The property is `guard/AGENTS.md`'s and the reason it is worth a function of
// its own rather than three lines in `cmd/gateway`: *"Configuration arrives as
// an argument, never as a module-level global read from the environment, so a
// test can build two differently-configured apps in one process."* Two
// differently-configured apps in one process is exactly what `internal/
// equivalence` does — the TypeScript reference and the Go gateway, side by side,
// with different probe sets — so the property is load-bearing here rather than
// decorative.
//
// # WHAT THIS READS IN THIS PACKET: FIVE VARIABLES, and four of them are the pass-through.
//
// `PORT`, `ROUTE_TABLE`, `ASSERTION_SIGNING_KEY_FILE`, `ASSERTION_TTL_MS` and
// `ASSERTION_ISSUER` — the last three read only when the first of them is set.
// Everything else `src/index.ts` reads belongs to a subsystem this packet does not
// port: `IDENTITY_*` and the JWKS cache to the verifier, `RATE_LIMIT_*` and
// `TRUSTED_PROXIES` to the limiter, `REDIS_*` to the counter store. Reading them
// now would be configuration for endpoints that do not exist, and a variable an
// operator sets that changes nothing is worse than one they cannot set:
// `IDENTITY_ISSUER` in a compose file would look configured and configure a 404.
//
// So the reader is five variables long and says what comes next, rather than being
// a table of placeholders. `TestTheRuntimeReaderReadsNoOtherVariable` holds that: it
// reads this file's own source and fails if a variable outside this set appears in
// it, so the next packet that adds one adds the assertion with it.
//
// # WHY ROUTING IS WIRED HERE RATHER THAN LEFT UNREACHABLE
//
// The first version of this packet left `RuntimeOptions` reading `PORT` alone, which
// meant `cmd/gateway` served a gateway with **no route table**: the pass-through was
// there, tested and mutation-proved, and no deployment could reach it. The honest
// shape of "not yet wired" is a gateway that says so; the dishonest shape is one
// that accepts a `ROUTE_TABLE` nobody has told it about.
//
// # EMPTY IS UNSET
//
// An empty or whitespace-only variable counts as unset, because that is what an
// unset variable looks like in a compose file. `PORT=` must not be "listen on port
// zero", which is a different thing and a strange one, and `ROUTE_TABLE=` must not be
// "a table with nothing in it" — that is a refusal to boot with a reason, and an
// operator who wrote it meant to configure something.
func RuntimeOptions(env Env) (Config, error) {
	port, err := portFromEnv(env)
	if err != nil {
		return Config{}, err
	}

	routes, err := routesFromEnv(env)
	if err != nil {
		return Config{}, err
	}

	assertion, err := assertionFromEnv(env)
	if err != nil {
		return Config{}, err
	}

	// No probes are registered here. In the reference, `runtimeOptions` registers
	// `identity` unconditionally and `redis` when `REDIS_URL` is set — because
	// both subsystems exist there. Neither does here, so a gateway started by
	// `cmd/gateway` answers `{"deps":{}}`, which is the document's own words for
	// "an app built with no probes at all". The first packet that ports the
	// verifier registers `identity` in this function and nowhere else.
	//
	// And no `Authenticate` is set: the verifier does not exist in this packet, so
	// a gateway started from the environment has NO credential gate and relays an
	// anonymous request to a private route — which is exactly what `createApp({routes})`
	// does in the reference, and exactly what `gatedUpstream` compares. The packet
	// that ports RS256 sets it here and nowhere else.
	return Config{
		Options: Options{Routes: routes, Assert: assertion},
		Addr:    ":" + strconv.Itoa(port),
	}, nil
}

// defaultPort is what an unset `PORT` means, and it is `src/index.ts`'s number.
const defaultPort = "8080"

// portFromEnv reads `PORT`, or reports the default.
//
// A non-numeric or out-of-range port is a refusal to boot rather than a silent
// fallback to 8080: a gateway that listened somewhere other than where its
// operator asked is a gateway that is up and unreachable, and the symptom of that
// is a health check failing against nothing. `strings.TrimSpace` is not used here
// — see `env.go`'s `trimSpace` for why, and for the empty-is-unset rule this
// shares with the reference.
func portFromEnv(env Env) (int, error) {
	raw := trimSpace(env("PORT"))
	if raw == "" {
		return mustAtoi(defaultPort), nil
	}

	port := 0
	for _, r := range raw {
		if r < '0' || r > '9' {
			return 0, badPort(raw)
		}
		port = port*10 + int(r-'0')
		if port > 65535 {
			return 0, badPort(raw)
		}
	}

	// `0` parses, so it needs its own refusal rather than being caught by the
	// range check above. There is no sense in which it is a listening port.
	if port == 0 {
		return 0, fmt.Errorf("%w: PORT must be a whole number between 1 and 65535, got %q — 0 is not a port a process listens on", ErrNotConfigured, raw)
	}

	return port, nil
}

// badPort is one error for every way a port is unreadable, so the two call sites
// above say the same thing and there is one sentence to change.
func badPort(raw string) error {
	return fmt.Errorf("%w: PORT must be a whole number between 1 and 65535, got %q", ErrNotConfigured, raw)
}

// mustAtoi is for the one literal this file parses. A constant that does not
// parse is a defect in this file rather than a deployment problem, so it panics
// where it is written instead of returning a wrong port.
func mustAtoi(digits string) int {
	value := 0
	for _, r := range digits {
		value = value*10 + int(r-'0')
	}
	return value
}

// routesFromEnv is the route table, or nothing.
//
// One variable holding one JSON object, because the table is the configuration and
// a per-service variable per service would be N variables whose names encode a
// routing decision (`PANTRY_PREFIX`) that the table states instead:
//
//	ROUTE_TABLE={"/v1/pantry":{"baseUrl":"http://pantry:8080","token":"…"}}
//
// and the one entry that answers to nobody:
//
//	ROUTE_TABLE={"/v1/catalog":{"baseUrl":"http://pantry:8080","public":true}}
//
// `public` is per entry, default `false`, and means the prefix is mounted with no
// caller credential required. `principal` is a list of the claim names this upstream
// is declared to need, and it is the only thing that makes gateway sign an assertion
// about the caller for this route. Absent means no assertion; an entry that is
// `public` and declares it refuses to boot, because a public route has no verified
// caller to assert one about.
//
// Unset or empty means no routing at all, which is the honest default for a
// deployment that has not decided where anything goes. A value that is not JSON, or
// JSON of the wrong shape, or JSON that `ValidateRouteTable` refuses is a refusal to
// boot — the same rule as every other variable here, and for the same reason: a
// typo'd route table is a gateway that answers 404 for a service that exists.
//
// Nothing is wrapped. `ParseRouteTable` already names `ROUTE_TABLE` in every message
// it writes, because it has one caller and that caller is a gateway variable — so
// prefixing here would print the name twice and teach a reader to skim.
func routesFromEnv(env Env) (RouteTable, error) {
	raw := trimSpace(env("ROUTE_TABLE"))
	if raw == "" {
		return nil, nil
	}

	return ParseRouteTable(raw)
}

// assertionFromEnv is the principal assertion's signing key, or nothing at all.
//
// Four variables, and only the first is required — because only the first is needed:
//
//   - ASSERTION_SIGNING_KEY_FILE  path to a PKCS#8 PEM. Unset or empty means no
//     assertion is minted on any route, which is the default and the reason this
//     feature cannot change a deployment that has not asked for it.
//   - ASSERTION_SIGNING_KEY_ID    the `kid` upstreams select the key by. Defaults to
//     the RFC 7638 thumbprint of the public key, which cannot collide between two
//     deployments the way an invented `gateway-1` can.
//   - ASSERTION_ISSUER            who minted it. Defaults to
//     `https://gateway.localhost`, matching `DEFAULT_IDENTITY_ISSUER`'s shape.
//   - ASSERTION_TTL_MS            how long it is good for. Defaults to 120_000 and is
//     **refused above `MaxAssertionTTL`** — see `assertion.go` for why a lifetime
//     nobody may exceed is the property and not the default.
//
// A path rather than the PEM itself, because a private key in an environment value
// turns up in `docker inspect`, in `/proc/<pid>/environ` and in any crash dump, and
// this repository already refuses a base URL carrying a password for the same reason.
//
// A file which is not there is a **startup** failure naming the variable — the rule
// every other field here follows — and so is a file that exists and is not a key.
// There is no third case: a key discovered to be wrong on the first proxied request
// would be the one configuration mistake here that reads as a 503 on every request.
func assertionFromEnv(env Env) (*AssertionMinter, error) {
	path := trimSpace(env("ASSERTION_SIGNING_KEY_FILE"))
	if path == "" {
		return nil, nil
	}

	document, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w: gateway: ASSERTION_SIGNING_KEY_FILE names %q, and that file could not be read. It is a path to a PKCS#8 PEM private key, and gateway reads it once at startup so a missing key is a refusal to boot rather than a 503 on every proxied request. Unset the variable to mint no principal assertions at all", ErrNotConfigured, path)
	}

	key, err := ReadAssertionKey(string(document), trimSpace(env("ASSERTION_SIGNING_KEY_ID")))
	if err != nil {
		return nil, fmt.Errorf("%w: gateway: ASSERTION_SIGNING_KEY_FILE names %q and gateway could not use it: %v", ErrNotConfigured, path, err)
	}

	ttl, err := assertionTTLFromEnv(env)
	if err != nil {
		return nil, err
	}

	return NewAssertionMinter(AssertionOptions{
		Key:    key,
		Issuer: trimSpace(env("ASSERTION_ISSUER")),
		TTL:    ttl,
	})
}

// assertionTTLFromEnv is `ASSERTION_TTL_MS` as a duration, or the default.
//
// It exists so a variable that is not a whole number of milliseconds is refused with
// a message naming **the variable**, rather than arriving as "ttl must be at least
// 1ms" from a function the operator has never heard of and cannot search for. The
// ceiling itself is `NewAssertionMinter`'s, because a lifetime nobody may exceed is
// a property of the minter and not of the environment reader.
func assertionTTLFromEnv(env Env) (time.Duration, error) {
	raw := trimSpace(env("ASSERTION_TTL_MS"))
	if raw == "" {
		return 0, nil
	}

	milliseconds, err := strconv.Atoi(raw)
	if err != nil || milliseconds < 1 {
		return 0, fmt.Errorf("%w: gateway: ASSERTION_TTL_MS must be a whole number of milliseconds of at least 1, got %q", ErrNotConfigured, raw)
	}

	return time.Duration(milliseconds) * time.Millisecond, nil
}
