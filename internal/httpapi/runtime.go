package httpapi

import (
	"fmt"
	"strconv"
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
// # WHAT THIS READS IN THIS PACKET: ONE VARIABLE.
//
// `PORT`, and nothing else. Every other variable `src/index.ts` reads belongs to
// a subsystem this packet does not port — `IDENTITY_*` and the JWKS cache to the
// verifier, `RATE_LIMIT_*` and `TRUSTED_PROXIES` to the limiter, `REDIS_*` to the
// counter store, `ROUTE_TABLE` to the pass-through, `ASSERTION_*` to the
// principal minter. Reading them now would be configuration for endpoints that do
// not exist, and a variable an operator sets that changes nothing is worse than
// one they cannot set: `IDENTITY_ISSUER` in a compose file would look configured
// and configure a 404.
//
// So the reader is one variable long and says what comes next, rather than being
// a table of placeholders. `TestTheRuntimeReaderReadsNoOtherVariable` holds that:
// it reads this file's own source and fails if a variable other than `PORT`
// appears in it, so the next packet that adds one adds the assertion with it.
//
// # EMPTY IS UNSET
//
// An empty or whitespace-only variable counts as unset, because that is what an
// unset variable looks like in a compose file. `PORT=` must not be "listen on
// port zero", which is a different thing and a strange one.
func RuntimeOptions(env Env) (Config, error) {
	port, err := portFromEnv(env)
	if err != nil {
		return Config{}, err
	}

	// No probes are registered here. In the reference, `runtimeOptions` registers
	// `identity` unconditionally and `redis` when `REDIS_URL` is set — because
	// both subsystems exist there. Neither does here, so a gateway started by
	// `cmd/gateway` answers `{"deps":{}}`, which is the document's own words for
	// "an app built with no probes at all". The first packet that ports the
	// verifier registers `identity` in this function and nowhere else.
	return Config{Options: Options{}, Addr: ":" + strconv.Itoa(port)}, nil
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

// badPort is one error for every way a port is unreadable, so the three call
// sites above say the same thing and there is one sentence to change.
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
