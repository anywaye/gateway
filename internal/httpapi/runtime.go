package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/anywaye/gateway/internal/auth"
	"github.com/anywaye/gateway/internal/ratelimit"
	"github.com/anywaye/gateway/internal/sessionredis"
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
	Options Options

	Addr string

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
//	VHOST_TABLE             the hostname split, as one JSON object
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
//	IDENTITY_URL             identity's base URL: for the `/auth` calls — the browser
//	                         surface, and only WITH `REDIS_URL`: see
//	                         `browserSurfaceFromEnv` for why neither alone serves it —
//	                         and, WITH or without it, for the public-fallback
//	                         pass-through, which forwards identity's public
//	                         operations with the path intact (see `identitypublic.go`)
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

	vhosts, err := vhostsFromEnv(env)
	if err != nil {
		return Config{}, err
	}

	assertion, err := assertionFromEnv(env)
	if err != nil {
		return Config{}, err
	}

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
			Probes:   probeList(jwksURL, redis),
			Verifier: verifier,
			Limiter:  limiter,
			Routes:   routes,
			VHosts:   vhosts,
			Assert:   assertion,

			IdentityBaseURL: trimSpace(env("IDENTITY_URL")),

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

const defaultClientID = "gateway"

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

	if port == 0 {
		return 0, fmt.Errorf("%w: PORT must be a whole number between 1 and 65535, got %q — 0 is not a port a process listens on", ErrNotConfigured, raw)
	}

	return port, nil
}

func badPort(raw string) error {
	return fmt.Errorf("%w: PORT must be a whole number between 1 and 65535, got %q", ErrNotConfigured, raw)
}

func mustAtoi(digits string) int {
	value := 0
	for _, r := range digits {
		value = value*10 + int(r-'0')
	}
	return value
}

func routesFromEnv(env Env) (RouteTable, error) {
	raw := trimSpace(env("ROUTE_TABLE"))
	if raw == "" {
		return nil, nil
	}

	return ParseRouteTable(raw)
}

func vhostsFromEnv(env Env) (VHostTable, error) {
	raw := trimSpace(env("VHOST_TABLE"))
	if raw == "" {
		return nil, nil
	}

	return ParseVHostTable(raw)
}

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
		return nil, fmt.Errorf("%w: gateway: ASSERTION_SIGNING_KEY_FILE names %q and gateway could not use it: %w", ErrNotConfigured, path, err)
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

func probeList(jwksURL string, redis *ratelimit.LazyRedis) []NamedProbe {
	probes := []NamedProbe{{Name: "identity", Probe: keySetProbe(jwksURL)}}
	if redis != nil {
		probes = append(probes, NamedProbe{Name: "redis", Probe: redisProbe(redis)})
	}
	return probes
}

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

	store, err := ratelimit.NewRedisStore(redis, "")
	if err != nil {
		return nil, nil, nil, err
	}
	return store, redis, func() { _ = redis.Close() }, nil
}

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

func keySetProbe(url string) Probe {
	client := &http.Client{Timeout: probeTimeout}

	return func(ctx context.Context) error {
		ctx, cancel := context.WithTimeout(ctx, probeTimeout)
		defer cancel()

		request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return fmt.Errorf("identity: the JWKS URL is not requestable: %w", err)
		}

		response, err := client.Do(request)
		if err != nil {
			return fmt.Errorf("identity: the JWKS did not answer: %w", err)
		}
		defer func() { _ = response.Body.Close() }()

		if response.StatusCode < 200 || response.StatusCode > 299 {
			return fmt.Errorf("identity: the JWKS answered %d", response.StatusCode)
		}
		return nil
	}
}

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

func isProbePath(path string) bool {
	_, exempt := ProbePaths[path]
	return exempt
}

func orDefault(value, fallback string) string {
	if trimmed := trimSpace(value); trimmed != "" {
		return trimmed
	}
	return fallback
}

func intFromEnv(env Env, name string, fallback, floor int) (int, error) {
	raw := trimSpace(env(name))
	if raw == "" {
		return fallback, nil
	}

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

func badNumber(name, raw string, floor int) error {
	if floor == 0 {
		return fmt.Errorf("%w: %s must be a whole number >= 0, got %q", ErrNotConfigured, name, raw)
	}
	return fmt.Errorf("%w: %s must be a whole number >= %d, got %q", ErrNotConfigured, name, floor, raw)
}
