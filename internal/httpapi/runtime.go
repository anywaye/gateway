package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/cafaye/gateway/internal/auth"
	"github.com/cafaye/gateway/internal/ratelimit"
	"github.com/cafaye/gateway/internal/sessionredis"
)

// Config is everything `cmd/gateway` needs to serve, as read from the
// environment: the handler's own configuration, the address to reach it on, and
// the closer the counter store owns.
//
// # WHY THE CLOSER IS HERE
//
// The JWKS cache holds no socket of its own — `net/http` pools them and the process
// exiting is what discards them. The Redis connection DOES hold one, and
// `cmd/gateway` must close it on the way out rather than leaking it into a test
// binary or a graceful restart. So `Config` carries a `Close`, the closers are
// registered in the one function that knows a subsystem exists, and `Close` is
// nil-safe so a caller holding a `Config` by value never has to ask whether the
// field is set.
type Config struct {
	// What to build the handler from.
	Options Options

	// `host:port`, already validated. An empty port would be an unspecified one,
	// which `portFromEnv` refuses rather than passing on.
	Addr string

	// Close releases whatever the configured subsystems hold. Nil means nothing
	// needs closing, which is the v0 shape.
	Close func()
}

// RuntimeOptions builds the configuration from the environment, and with `env.go`
// it is the only function in this module that reads one.
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
// # WHAT THIS READS, AND NOT ONE MORE
//
//	PORT                    the listening address
//	ROUTE_TABLE             the pass-through's table, as one JSON object
//	ASSERTION_SIGNING_KEY_FILE   the principal minter's key, a path not a PEM
//	ASSERTION_SIGNING_KEY_ID     the `kid` upstreams select it by
//	ASSERTION_ISSUER             who minted the assertion
//	ASSERTION_TTL_MS             how long the assertion is good for
//	IDENTITY_ISSUER          the expected `iss`, and the base the JWKS path hangs off
//	GATEWAY_CLIENT_ID        the `aud` every token must be addressed to
//	IDENTITY_JWKS_URL        an explicit key set, when identity publishes it elsewhere
//	IDENTITY_JWKS_TTL_MS     how long a fetched key set is reused
//	RATE_LIMIT_REQUESTS      quota per window
//	RATE_LIMIT_WINDOW_MS     the window's length
//	TRUSTED_PROXIES          how much of `X-Forwarded-For` may be believed
//	REDIS_URL                where buckets are counted, when there is more than one replica
//	IDENTITY_URL             identity's base URL for the `/auth` calls — the browser
//	                         surface, and only WITH `REDIS_URL`: see
//	                         `browserSurfaceFromEnv` for why neither alone serves it
//
// The count is the assertion `TestTheRuntimeReaderReadsExactlyTheseVariables`
// holds, and it is the assertion that makes this function safe to extend: a
// variable an operator sets that changes nothing is worse than one they cannot
// set — `IDENTITY_ISSUER` in a compose file would look configured and configure a
// 404. The next packet that adds a subsystem adds its variables here AND to that
// test, or the test fails and the packet explains which one.
//
// There is no `REDIS_PREFIX`: `NewRedisStore` takes a sub-namespace and the
// reference's `runtimeOptions` never passes one, so reading one would be a
// variable that configures a thing the reference cannot configure, which is the
// exact failure this reader exists to prevent. The argument is still there for two
// gateways sharing one Redis, and it is reached by a caller that builds the store
// directly.
//
// # EMPTY IS UNSET
//
// An empty or whitespace-only variable counts as unset, because that is what an
// unset variable looks like in a compose file. `PORT=` must not be "listen on port
// zero", which is a different thing and a strange one; `ROUTE_TABLE=` must not be
// "a table with nothing in it" — that is a refusal to boot with a reason, and an
// operator who wrote it meant to configure something; and `IDENTITY_ISSUER=` must
// not be a malformed issuer rather than an absent one.
//
// # THE VERIFIER IS BUILT UNCONDITIONALLY, LIKE THE REFERENCE'S
//
// `runtimeOptions` in `src/index.ts` (removed at cutover) always passes `jwt:` — there is no "unset
// issuer" state there, because the default is a real issuer. So the Go reader does
// the same: a gateway started by `cmd/gateway` always verifies tokens, always
// fetches a key set, and always rate-limits. The shape with none of that is
// `New(Options{})`, which is what `internal/equivalence`'s `bare` scenario builds
// and which is the honest v0 gateway.
//
// # `ROUTE_TABLE` IS THE ONE THING NOT EVERY CONFIGURATION GETS
//
// A table is a routing decision, and the deployments that have not made one are
// the reason `ROUTE_TABLE` is optional. Everything else above has a default worth
// having. A gateway with no table answers 404 for everything, which is exactly
// what `src/index.ts` (removed at cutover) does when it is handed no `routes`, and it is not a
// degraded mode: it is a gateway whose operator has not told it where anything
// goes yet.
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

	// THE JWKS URL IS RESOLVED HERE, ONCE, and handed to both the verifier and the
	// readiness probe. That is the whole reason this function is a function: the
	// probe has to ask the same URL the verifier fetches, and resolving it twice
	// would be two places where an operator's `IDENTITY_JWKS_URL` could be applied
	// to one and not the other — a `/readyz` reporting `identity: ok` for a key set
	// no request will ever use.
	issuer := orDefault(env("IDENTITY_ISSUER"), auth.DefaultIdentityIssuer)
	jwksURL := orDefault(env("IDENTITY_JWKS_URL"), issuer+auth.JWKSPath)

	ttl, err := durationFromEnv(env, "IDENTITY_JWKS_TTL_MS", 0)
	if err != nil {
		return Config{}, err
	}

	verifier, err := auth.New(auth.Options{
		Issuer:       issuer,
		Audience:     orDefault(env("GATEWAY_CLIENT_ID"), defaultClientID),
		JWKSURL:      jwksURL,
		JWKSCacheTTL: ttl,
	})
	if err != nil {
		return Config{}, err
	}

	store, redis, closer, err := counterStore(env)
	if err != nil {
		return Config{}, err
	}

	bff, err := browserSurfaceFromEnv(env, redis)
	if err != nil {
		// The closer is registered after this on purpose. `counterStore` opened a
		// lazy client that holds a socket, and returning without closing it here
		// would leak a connection on the refusal path — which is the path where
		// `REDIS_URL` parsed fine and something else did not, so it is reached with
		// a Redis already dialled rather than not.
		if closer != nil {
			closer()
		}
		return Config{}, err
	}

	limit, err := intFromEnv(env, "RATE_LIMIT_REQUESTS", ratelimit.DefaultLimit, 1)
	if err != nil {
		return Config{}, err
	}
	window, err := durationFromEnv(env, "RATE_LIMIT_WINDOW_MS", ratelimit.DefaultWindow)
	if err != nil {
		return Config{}, err
	}
	proxies, err := intFromEnv(env, "TRUSTED_PROXIES", 0, 0)
	if err != nil {
		return Config{}, err
	}

	// THE PER-ROUTE TABLE, and this is the line that was missing.
	//
	// `Options.Policy` and `Options.Resolve` both existed and nothing set them, so
	// the limiter fell back to `DefaultPolicy` for every path: `/auth/login` was
	// served at 600/min rather than the 10/min it is supposed to be, and the audit
	// found the gap silent. The seam is here; these two lines are what make the
	// table reachable from the shipped binary.
	//
	// Validated at construction rather than per request, so a bad number is a
	// refusal to boot and not a surprise on the first request of the week —
	// `NewLimiter` refuses for the same reason.
	table, err := ratelimit.ValidateLimitTable(ratelimit.DefaultLimitTable())
	if err != nil {
		return Config{}, err
	}
	policy, resolve, err := ratelimit.PolicyResolver(table)
	if err != nil {
		return Config{}, err
	}

	limiter, err := ratelimit.NewLimiter(ratelimit.Options{
		Limit:          limit,
		Window:         window,
		Store:          store,
		TrustedProxies: proxies,
		Policy:         policy,
		Resolve:        resolve,
		Exempt:         isProbePath,
	}, RateLimitRefuser)
	if err != nil {
		return Config{}, err
	}

	return Config{
		Options: Options{
			// THE ORDER IS THE ANSWER. `/readyz` renders `deps` in registration order
			// because `Options.Probes` is a slice, and the order an operator reads is
			// identity then redis. A map would sort them — and `redis` sorts BEFORE
			// `identity` — so `internal/equivalence` would fail on bytes neither side
			// chose. The substrate's `probeTimeout` made the same point about a sorted
			// fixture rendering identically either way.
			Probes:   probeList(jwksURL, redis),
			Verifier: verifier,
			Limiter:  limiter,
			Routes:   routes,
			Assert:   assertion,

			// THE BROWSER SURFACE, AND IT IS NOT A POINTER TO NOTHING.
			//
			// `browserSurfaceFromEnv` returns nil when either half of the browser
			// surface is unconfigured, and `Options.BFF`'s comment says what nil
			// means: the four routes decline with the reference's `404`. Passing a
			// non-nil empty `BffOptions` instead would be the v0 gateway wearing a
			// browser surface it cannot serve, and `NewBff` refuses it — so the two
			// spellings would not both work and the difference would be invisible
			// until a deployment set one of the two variables.
			BFF: bff,
		},
		Addr:  ":" + strconv.Itoa(port),
		Close: closer,
	}, nil
}

// CloseResources is idempotent and safe on a zero `Config`, which is why it is a
// method and not a bare field read at the call site.
func (c Config) CloseResources() {
	if c.Close != nil {
		c.Close()
	}
}

// defaultPort is what an unset `PORT` means, and it is `src/index.ts` (removed at cutover)'s number.
const defaultPort = "8080"

// DefaultPort is `defaultPort`, exported for one caller: `cmd/gateway`'s
// `-healthcheck`, which has to know where to aim its probe.
//
// It is exported rather than written a second time in `cmd/gateway` because two
// copies of a port number is the shape this repository's pin checks exist for — and
// the failure here is not a failing test but a container healthcheck aimed at a
// port nothing is listening on, reporting a healthy service as dead.
//
// A `var` and not a `const` so the test can aim the probe at a port it controls.
// The unset-PORT case asserts the probe reaches the DEFAULT port, and the only way
// to assert that positively is to decide what the default is for the length of the
// test — a const makes the case assert "nothing is listening on 8080", which is an
// environmental assumption any development tool holding that port violates.
// Production code never writes it; the test restores it.
var DefaultPort = defaultPort

// defaultClientID is the audience gateway accepts when nothing says otherwise:
// gateway itself. `DEFAULT_CLIENT_ID` in `src/index.ts` (removed at cutover).
const defaultClientID = "gateway"

// portFromEnv reads `PORT`, or reports the default.
//
// A non-numeric or out-of-range port is a refusal to boot rather than a silent
// fallback to 8080: a gateway that listened somewhere other than where its operator
// asked is a gateway that is up and unreachable, and the symptom of that is a health
// check failing against nothing.
//
// `strings.TrimSpace` is not used here — see `env.go`'s `trimSpace` for why, and for
// the empty-is-unset rule this shares with the reference.
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

	// `0` parses, so it needs its own refusal rather than being caught by the range
	// check above. There is no sense in which it is a listening port.
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

// mustAtoi is for the one literal this module parses. A constant that does not parse
// is a defect in this file rather than a deployment problem, so it panics where it is
// written instead of returning a wrong port.
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
//
// The four are read here rather than by the verifier's packet because the minter is
// the pass-through's, not the verifier's: it answers a question about the CALLER
// that a route declares it needs, and a gateway that verified tokens but minted no
// assertions would forward the identity claims in the token itself — handing an
// upstream a token it is meant never to see.
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

// probeList is the registered probes, in the order `/readyz` renders them.
//
// `redis` is a `Commands` and nil means "no Redis was configured", so the decision
// and the probe come from the same fact — a probe list that claimed a Redis no store
// is using would report `redis: unavailable` for a limiter that is counting in
// memory, which is a readiness endpoint lying about a healthy deployment.
// `redis` is the concrete `*LazyRedis` so a NIL is a nil POINTER rather than a nil
// interface holding nothing — which is checked here rather than anywhere else,
// because `if redis != nil` on an interface value is true for a typed nil, and a
// probe that calls `Ping` on that would panic on the first `/readyz`.
func probeList(jwksURL string, redis *ratelimit.LazyRedis) []NamedProbe {
	probes := []NamedProbe{{Name: "identity", Probe: keySetProbe(jwksURL)}}
	if redis != nil {
		probes = append(probes, NamedProbe{Name: "redis", Probe: redisProbe(redis)})
	}
	return probes
}

// counterStore is where buckets are counted, or the in-memory one.
//
// A `REDIS_URL` is the operator saying there is more than one replica, and the
// counter has to be shared or the limit is multiplied by the replica count. Without
// one the in-memory store is the honest answer for a single instance, and it says so
// in its own source and in the README.
//
// It returns the store, the transport for the readiness probe, and the closer. Three
// values rather than one object because `Store` deliberately has no `Close` and no
// `Ping` on its interface: closing and pinging are transport concerns, and
// `Commands` is where the socket is. Nothing else in the repository constructs a
// Redis store, so there is exactly one caller and exactly one closer.
// The return type is the CONCRETE `*ratelimit.LazyRedis` rather than the
// `ratelimit.Commands` interface, and that is a change with a caller rather than a
// preference. `Commands` is the limiter's two methods — `Eval` and `Ping` — and the
// session store needs a third, `Do`, which is on `Connection` and not on the
// interface. Returning the concrete client is what lets `browserSurfaceFromEnv`
// hand the SAME socket to both, instead of the interface widening for everyone and
// every fake in the limiter's tests growing a method they have no use for.
func counterStore(env Env) (ratelimit.Store, *ratelimit.LazyRedis, func(), error) {
	url := trimSpace(env("REDIS_URL"))
	if url == "" {
		store, err := ratelimit.NewMemoryStore(0)
		return store, nil, nil, err
	}

	redis, err := ratelimit.NewLazyRedis(ratelimit.RedisConnectionOptions{URL: url})
	if err != nil {
		return nil, nil, nil, err
	}

	// The empty prefix, deliberately: `runtimeOptions` in the reference passes
	// `prefix: redis.prefix` where `redis.prefix` is a compile-time constant, so the
	// runtime configuration carries no prefix at all.
	store, err := ratelimit.NewRedisStore(redis, "")
	if err != nil {
		// The lazy connection opened nothing, so there is nothing to close on this
		// path — and saying so is why the closer is registered AFTER the store builds
		// rather than before.
		return nil, nil, nil, err
	}
	return store, redis, func() { _ = redis.Close() }, nil
}

// browserSurfaceFromEnv is `Options.BFF`, or the `404` four routes declining.
//
// # BOTH VARIABLES, OR NEITHER
//
// `IDENTITY_URL` is "there is an identity to ask". `REDIS_URL` is "there is more
// than one replica, and the things that must survive a restart or a peer live in a
// shared store". A browser session is BOTH of those — a per-process map signs a
// browser out on the next restart and on whichever replica it did not sign in to —
// so this is the one place the two variables are read together, and the rule is
// that neither alone builds a browser surface:
//
//   - `IDENTITY_URL` and no `REDIS_URL`: no browser surface. Not a degraded one.
//     A per-process store is the shape this packet exists to stop, and refusing to
//     offer it is the refusal `NewBff` already makes on a nil store.
//   - `REDIS_URL` and no `IDENTITY_URL`: no browser surface either, and the four
//     routes decline with the reference's `404`. A limiter that counts buckets in
//     Redis is a perfectly configured gateway that serves no browser traffic, which
//     is `createApp({})` with a shared counter and not a fault.
//
// # THE STORE IS BUILT ON THE LIMITER'S CLIENT, NOT A SECOND ONE
//
// `redis` is the `*ratelimit.LazyRedis` that `counterStore` already built, and it
// hands the SAME connection to `sessionredis`. So one deployment has one socket to
// Redis rather than two, one command-in-flight lock rather than two, and one
// implementation of RESP2 rather than two implementations that will disagree. It
// is why `counterStore` returns the concrete `*LazyRedis` rather than the
// `ratelimit.Commands` interface it used to: the interface is the limiter's two
// methods and has no `Do`, so a session store held as an interface value would
// have had to type-assert its way to the third.
//
// And the store's connection is LAZY, so building it does not dial: a gateway
// configured with a `REDIS_URL` that is down still starts, and answers `/readyz`
// with `redis` named as unavailable — which is the contract the limiter already
// has, and the reason a session store being unavailable is a `503` on one route
// rather than a gateway that will not boot.
//
// # AN `IDENTITY_URL` THAT DOES NOT PARSE IS A REFUSAL TO BOOT
//
// Handed to `NewBff` unchanged, which validates it, rather than validated here and
// handed on. One validator for one variable: a second copy of the http(s)-and-no-
// path rule in this file is a second sentence to keep in step with the first.
func browserSurfaceFromEnv(env Env, redis *ratelimit.LazyRedis) (*BffOptions, error) {
	identityURL := trimSpace(env("IDENTITY_URL"))
	if identityURL == "" || redis == nil {
		return nil, nil
	}

	store, err := sessionredis.NewLazy(redis, time.Now)
	if err != nil {
		return nil, err
	}

	return &BffOptions{IdentityURL: identityURL, Sessions: store}, nil
}

// keySetProbe asks identity whether it can be reached at all.
//
// It is the readiness endpoint's whole claim about identity. A `HEAD` would be
// cheaper and would prove less: an endpoint that answers `200` to a `HEAD` with a
// login page is the exact failure `isKeySet` in `internal/auth` exists to catch, and
// a readiness probe that cannot see it reports `identity: ok` for an identity every
// request will get a `503` from.
//
// # IT DOES NOT SHARE THE VERIFIER'S CACHE
//
// A probe that read the cache would report what gateway last saw rather than what
// identity is publishing now, and the difference between those two is a rotated key
// — which is the one thing a readiness endpoint should notice. It costs one request
// per `/readyz` call and that is the price of the probe meaning something.
//
// # THE CLIENT IS BUILT ONCE PER PROBE, NOT PER CALL
//
// `probeTimeout` is the inner bound and `runProbe`'s deadline is the outer one, so
// this function's two bounds are the reason a hung identity cannot hang `/readyz`
// twice over. A client per call would be a client per readiness check, which is a
// connection pool gateway did not ask for.
func keySetProbe(url string) Probe {
	client := &http.Client{Timeout: probeTimeout}

	return func(ctx context.Context) error {
		// The inner bound, because a client with no timeout at all is a probe that can
		// hang on a socket even after the outer select has given up — and the goroutine
		// `runProbe` leaked is the cost that is already being paid.
		ctx, cancel := context.WithTimeout(ctx, probeTimeout)
		defer cancel()

		request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return fmt.Errorf("identity: the JWKS URL is not requestable: %w", err)
		}

		response, err := client.Do(request)
		if err != nil {
			// The host, the port and the reason go to the log and nowhere else:
			// `runProbe` turns any error into `unavailable` and no part of this message
			// reaches a response body.
			return fmt.Errorf("identity: the JWKS did not answer: %w", err)
		}
		defer response.Body.Close()

		if response.StatusCode < 200 || response.StatusCode > 299 {
			return fmt.Errorf("identity: the JWKS answered %d", response.StatusCode)
		}
		return nil
	}
}

// redisProbe is `PING`, and it is the whole Redis readiness check.
//
// `PING` rather than a script evaluation because the probe's question is "is there a
// Redis there", and the limiter's own failure mode is fail-OPEN: a Redis that is
// answering is the condition under which the limit is actually being applied, and
// the operator who needs to know that is the one watching `/readyz`.
func redisProbe(commands ratelimit.Commands) Probe {
	return func(ctx context.Context) error {
		answered, err := commands.Ping(ctx)
		if err != nil {
			return fmt.Errorf("redis: PING did not answer: %w", err)
		}
		if !answered {
			return fmt.Errorf("redis: PING answered something that is not PONG")
		}
		return nil
	}
}

// isProbePath is the limiter's exemption, and it is `ProbePaths` rather than a second
// list — a second list is a list that goes stale, and `ProbePaths` is already held to
// `openapi/v1.yaml` by `TestTheTwoProbeOperationsAreTheOnesWithNo429`.
func isProbePath(path string) bool {
	_, exempt := ProbePaths[path]
	return exempt
}

// orDefault is `env.X?.trim() || DEFAULT`, and the `||` is why it is here rather than
// `trimSpace(x)` followed by a zero check: an empty string and a whitespace-only one
// are the same answer in the reference and they are the same answer here.
func orDefault(value, fallback string) string {
	if trimmed := trimSpace(value); trimmed != "" {
		return trimmed
	}
	return fallback
}

// intFromEnv reads a whole number with a floor, and refuses anything else.
//
// `RATE_LIMIT_REQUESTS=0` has to be a refusal to boot rather than a surprise on the
// first request of the week, and `TRUSTED_PROXIES=-1` has to be a refusal to boot
// rather than a silent "treat it as zero": a negative count read as zero means keying
// on the socket peer, which is safe, and an operator who typed `-1` did not mean that.
func intFromEnv(env Env, name string, fallback, floor int) (int, error) {
	raw := trimSpace(env(name))
	if raw == "" {
		return fallback, nil
	}

	// Bounded by a `1e9` ceiling rather than an overflow check: a gateway refusing to
	// boot on a number nobody could rate-limit with is a better answer than one that
	// wraps into a small positive number.
	value := 0
	for _, r := range raw {
		if r < '0' || r > '9' {
			return 0, badNumber(name, raw, floor)
		}
		value = value*10 + int(r-'0')
		if value > 1_000_000_000 {
			return 0, badNumber(name, raw, floor)
		}
	}
	if value < floor {
		return 0, badNumber(name, raw, floor)
	}
	return value, nil
}

// durationFromEnv reads a count of MILLISECONDS into a `time.Duration`, or the
// fallback.
//
// Milliseconds because that is the unit `IDENTITY_JWKS_TTL_MS` and
// `RATE_LIMIT_WINDOW_MS` use, and because a Go duration written into an environment
// variable is a number with an implied unit nobody can read out of a compose file.
//
// The fallback is a `time.Duration` and not a millisecond count, which is the one
// asymmetry with the reference's `wholeNumber(env.X, DEFAULT.windowMs, …)`: the Go
// default is written where it is declared as a duration, so a reader comparing the two
// files sees the same number in two different types rather than two different numbers
// in one type. That is the trade, and it is a trade — the alternative is a fallback
// written in milliseconds in a file where every other duration is written as one.
func durationFromEnv(env Env, name string, fallback time.Duration) (time.Duration, error) {
	milliseconds, err := intFromEnv(env, name, -1, 0)
	if err != nil {
		return 0, err
	}
	if milliseconds < 0 {
		return fallback, nil
	}
	return time.Duration(milliseconds) * time.Millisecond, nil
}

// badNumber is one error for every unreadable number, so the four call sites above say
// the same thing and there is one sentence to change. It names the variable and
// nothing the operator did not type: no suggestion, no range, no example.
func badNumber(name, raw string, floor int) error {
	if floor == 0 {
		return fmt.Errorf("%w: %s must be a whole number >= 0, got %q", ErrNotConfigured, name, raw)
	}
	return fmt.Errorf("%w: %s must be a whole number >= %d, got %q", ErrNotConfigured, name, floor, raw)
}
