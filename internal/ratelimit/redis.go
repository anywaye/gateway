package ratelimit

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Commands is the whole Redis surface this repository needs: one script and one
// ping.
//
// Deliberately not a general client. Every method added here is a method the RESP
// transport below has to grow and the fake in the tests has to implement.
type Commands interface {
	Eval(script string, keys []string, args []string) (Value, error)

	Ping(ctx context.Context) (bool, error)
}

// GCRALua is GCRA, as one atomic step.
//
// The same algorithm as `count()` in `store.go`, held to it by `parity_test.go`.
// `KEYS[1]` is the whole client namespace — `bucket:account:…` — so two policies
// never share a bucket by accident, and the script stays a single-key operation,
// which is what lets Redis run it on the shard that holds it.
//
// The four returned values are all integers: `allowed`, `resetAt`, `retryAt`,
// `remaining` — epoch MILLISECONDS or a count, so no conversion happens in the
// client.
//
// # THE TWO THINGS A TRANSCRIPTION CANNOT FIND
//
// `math.ceil((next - now) / interval)` is the FIRST, and it is why this script is
// run against a server rather than trusted. Redis converts a Lua number to an
// integer reply by TRUNCATING toward zero, so a script that computed `limit - 1.5`
// would hand the client `598` where the in-memory store computes `599`.
//
// The SECOND is `return {0, tat, next - window, 0}` on the refusal branch: it
// returns the OLD `tat` as `resetAt`, not `next`. Getting that wrong makes a
// throttled client's `RateLimit-Reset` count down from the wrong instant.
const GCRALua = `
local tat = tonumber(redis.call('GET', KEYS[1]) or '0')
local limit = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local now = tonumber(ARGV[3])
local interval = window / limit
local next = math.max(now, tat) + interval
local delay = next - now
if delay > window then return {0, tat, next - window, 0} end
redis.call('SET', KEYS[1], next, 'PX', window)
local used = math.ceil((next - now) / interval)
return {1, next, next - interval - window, math.max(0, limit - used)}
`

const namespace = "gateway:rl"

// RedisStore counts buckets in Redis.
//
// One `EVAL` per request and nothing else: the round trip is the latency a gateway
// pays on every single call, and splitting it into a read and a write doubles that
// and breaks atomicity at the same time.
type RedisStore struct {
	commands Commands
	prefix   string
}

var _ Store = (*RedisStore)(nil)

// NewRedisStore builds the Redis-backed store.
//
// An empty `prefix` is `gateway:rl`; anything else is `gateway:rl:<prefix>`.
// `AssertBucket` is the same charset the reference's `parsePrefix` enforces, and it
// is enforced at construction because a prefix is gateway's configuration and a
// configuration mistake should be a refusal to build.
func NewRedisStore(commands Commands, prefix string) (*RedisStore, error) {
	if commands == nil {
		return nil, fmt.Errorf("%w: a Redis store needs Commands", ErrNotConfigured)
	}

	if prefix == "" {
		return &RedisStore{commands: commands, prefix: namespace}, nil
	}

	if _, err := AssertBucket(prefix); err != nil {
		return nil, fmt.Errorf("%w: redisRateLimitStore: prefix must match [A-Za-z0-9_.:-]{1,%d}", ErrNotConfigured, maxKeyLength)
	}
	return &RedisStore{commands: commands, prefix: namespace + ":" + prefix}, nil
}

// KeyFor is the Redis key a bucket lives in. v0 introspection, off the interface.
func (s *RedisStore) KeyFor(bucket string) string {
	return s.prefix + ":" + bucket
}

// Hit counts one request against one bucket.
func (s *RedisStore) Hit(key string, request Request) (Verdict, error) {
	bucket, err := AssertBucket(key)
	if err != nil {
		return Verdict{}, err
	}

	reply, err := s.commands.Eval(GCRALua,
		[]string{s.KeyFor(bucket)},
		[]string{
			strconv.Itoa(request.Limit),
			strconv.FormatInt(request.Window.Milliseconds(), 10),
			strconv.FormatInt(request.Now.UnixMilli(), 10),
		})
	if err != nil {
		return Verdict{}, err
	}

	return verdictOf(reply)
}

func verdictOf(reply Value) (Verdict, error) {
	items, ok := reply.([]Value)
	if !ok || len(items) != 4 {
		return Verdict{}, fmt.Errorf("ratelimit: the rate-limit script answered %s", render(reply))
	}

	numbers := make([]float64, 4)
	for i, item := range items {
		value, err := numberOf(item)
		if err != nil {
			return Verdict{}, fmt.Errorf("ratelimit: the rate-limit script answered a non-number in %s", render(reply))
		}
		numbers[i] = value
	}

	return Verdict{
		Allowed:   numbers[0] == 1,
		ResetAt:   time.UnixMilli(int64(numbers[1])),
		RetryAt:   time.UnixMilli(int64(numbers[2])),
		Remaining: numbers[3],
	}, nil
}

func numberOf(value Value) (float64, error) {
	switch typed := value.(type) {
	case int:
		return float64(typed), nil
	case float64:
		return typed, nil
	case string:
		return strconv.ParseFloat(typed, 64)
	default:
		return 0, fmt.Errorf("ratelimit: %T is not a number", value)
	}
}

func render(value Value) string {
	switch typed := value.(type) {
	case nil:
		return "null"
	case string:
		return strconv.Quote(typed)
	case int:
		return strconv.Itoa(typed)
	case float64:
		return number(typed)
	case []Value:
		parts := make([]string, 0, len(typed))
		for _, item := range typed {
			parts = append(parts, render(item))
		}
		return "[" + strings.Join(parts, ",") + "]"
	default:
		return fmt.Sprintf("%v", typed)
	}
}

// RedisConnectionOptions is how to reach a Redis.
type RedisConnectionOptions struct {
	URL string

	Timeout time.Duration
}

// DefaultRedisTimeout is the reference's `DEFAULT_TIMEOUT_MS`.
const DefaultRedisTimeout = 2 * time.Second

// Connection is an open RESP connection with the two commands this store needs.
type Connection struct {
	Commands

	mu       sync.Mutex
	socket   net.Conn
	buffered []byte
	timeout  time.Duration
	broken   error
	closed   bool
}

// Connect opens a RESP connection to Redis.
//
// Deliberately the smallest thing that works: `EVAL` and `PING`, one command in
// flight at a time, a deadline on every operation. A general-purpose Redis client
// would be a dependency this repository does not have, and the reason is in
// README.md — this is a few dozen lines of RESP2, and the client half of it is
// covered by the pure `EncodeCommand`/`ParseReply` tests.
func Connect(options RedisConnectionOptions) (*Connection, error) {
	target, err := parseRedisURL(options.URL)
	if err != nil {
		return nil, err
	}

	timeout := options.Timeout
	if timeout == 0 {
		timeout = DefaultRedisTimeout
	}
	if timeout < time.Millisecond {
		return nil, fmt.Errorf("%w: connectRedis: timeoutMs must be an integer >= 1, got %v", ErrNotConfigured, timeout)
	}

	dialer := &net.Dialer{Timeout: timeout}
	var socket net.Conn
	if target.tls {
		tlsDialer := &tls.Dialer{NetDialer: dialer, Config: &tls.Config{}}
		socket, err = tlsDialer.DialContext(context.Background(), "tcp", net.JoinHostPort(target.hostname, target.port))
	} else {
		socket, err = dialer.Dial("tcp", net.JoinHostPort(target.hostname, target.port))
	}
	if err != nil {
		return nil, fmt.Errorf("ratelimit: connectRedis: %s did not answer: %w", redactRedisURL(options.URL), err)
	}

	connection := &Connection{socket: socket, timeout: timeout}

	if target.needsAuth() {
		if err := connection.authenticate(target, options.URL); err != nil {
			_ = socket.Close()
			return nil, err
		}
	}

	return connection, nil
}

func (c *Connection) authenticate(target redisTarget, rawURL string) error {
	command := []string{"AUTH", target.password}
	if target.username != "" {
		command = []string{"AUTH", target.username, target.password}
	}

	reply, err := c.Do(context.Background(), command...)
	if err != nil {
		return fmt.Errorf("ratelimit: connectRedis: %s refused the Redis password: authentication failed: %w", redactRedisURL(rawURL), err)
	}
	if text, ok := reply.(string); !ok || !strings.EqualFold(text, "OK") {
		return fmt.Errorf("ratelimit: connectRedis: %s refused the Redis password: authentication failed: the server answered %s", redactRedisURL(rawURL), render(reply))
	}
	return nil
}

// Ping is `PING`, for the readiness probe.
//
// A probe built on this is what makes Redis a registered dependency rather than a
// guess: `internal/httpapi` registers it under the name `redis`, and `/readyz`
// reports it. That is the whole visible consequence of a Redis being down, and it
// is deliberately the only one — see `Limiter.Wrap`'s `failedOpen`.
func (c *Connection) Ping(ctx context.Context) (bool, error) {
	reply, err := c.Do(ctx, "PING")
	if err != nil {
		return false, err
	}
	text, ok := reply.(string)
	return ok && strings.EqualFold(text, "PONG"), nil
}

// Eval is `EVAL script numkeys key… arg…`.
func (c *Connection) Eval(script string, keys []string, args []string) (Value, error) {
	command := make([]string, 0, 3+len(keys)+len(args))
	command = append(command, "EVAL", script, strconv.Itoa(len(keys)))
	command = append(command, keys...)
	command = append(command, args...)
	return c.Do(context.Background(), command...)
}

// Do writes one command and reads one reply, bounded in time.
//
// One command in flight at a time, held under the connection's mutex. That is a
// real restriction and it is stated rather than hidden: a pipelining client would
// need a queue of pending callers keyed by arrival order, and the limiter makes one
// call per request with no throughput argument for the extra state. The cost is
// that two goroutines sharing a connection serialize, which at the edge is one
// request per replica per round trip either way.
func (c *Connection) Do(ctx context.Context, args ...string) (Value, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil, errors.New("ratelimit: the redis connection is closed")
	}
	if c.broken != nil {
		return nil, c.broken
	}

	encoded, err := EncodeCommand(args...)
	if err != nil {
		return nil, err
	}

	deadline := time.Now().Add(c.timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	if err := c.socket.SetDeadline(deadline); err != nil {
		return c.fail(fmt.Errorf("ratelimit: could not set a redis deadline: %w", err))
	}

	if _, err := c.socket.Write(encoded); err != nil {
		return c.fail(fmt.Errorf("ratelimit: EVAL did not write: %w", err))
	}

	value, err := c.readReply()
	if err != nil {
		var reply *ReplyError
		if errors.As(err, &reply) {
			return nil, reply
		}
		return c.fail(err)
	}

	return value, nil
}

func (c *Connection) readReply() (Value, error) {
	for {
		if len(c.buffered) > 0 {
			value, read, err := ParseReply(c.buffered, 0)
			switch err {
			case nil:
				c.buffered = c.buffered[read:]
				return value, nil

			default:
				var reply *ReplyError
				if errors.As(err, &reply) {
					c.buffered = c.buffered[reply.Read:]
					return nil, reply
				}
			}
		}

		chunk := make([]byte, readChunkBytes)
		n, err := c.socket.Read(chunk)
		if n > 0 {
			c.buffered = append(c.buffered, chunk[:n]...)
		}
		if err != nil {
			return nil, fmt.Errorf("ratelimit: redis sent nothing: %w", err)
		}
	}
}

const readChunkBytes = 8192

func (c *Connection) fail(err error) (Value, error) {
	c.broken = err
	return nil, err
}

// Close closes the socket.
func (c *Connection) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil
	}
	c.closed = true
	return c.socket.Close()
}

// LazyRedis is a connection that opens on first use.
//
// # TWO THINGS FOLLOW, AND BOTH ARE DELIBERATE
//
//   - A malformed URL is still a startup error. The URL is parsed eagerly, because
//     `REDIS_URL=redis//redis` should not wait for the first request to discover it.
//   - A Redis that is DOWN is not a startup error. The store fails open until the
//     socket answers and `/readyz` reports `redis: unavailable` meanwhile. A gateway
//     that refuses to boot because its counter store is down has turned someone
//     else's outage into its own.
//
// A failed attempt is NOT cached, so the next request retries: an outage that ends
// is an outage a long-lived process recovers from rather than one it remembers
// forever. That is the difference from `LazyRedis` in the reference that is worth
// naming — the reference also does not cache the failure, for the same reason, and
// both say so in the same words.
type LazyRedis struct {
	options RedisConnectionOptions

	mu   sync.Mutex
	open *Connection
}

// NewLazyRedis parses the URL eagerly and opens nothing.
//
// The eager parse is the point, and a caller that skipped it would get a Redis
// down reported as a configuration error for the length of the first request.
func NewLazyRedis(options RedisConnectionOptions) (*LazyRedis, error) {
	if _, err := parseRedisURL(options.URL); err != nil {
		return nil, err
	}
	return &LazyRedis{options: options}, nil
}

// Connect returns the open connection, opening one if needed.
//
// # THE LOCK IS HELD ACROSS THE DIAL, AND THAT IS THE SINGLE-FLIGHT
//
// A burst of requests arriving while Redis is coming up must not open a socket
// each, and the mechanism is the same one `internal/auth` uses for the JWKS fetch:
// hold the lock across the work, so the second arrival waits and then finds the
// connection already there. The cost is that every verification of this connection
// waits for one dial, bounded by `Timeout` — which is the same trade, in the same
// direction, for the same reason: a bounded wait is better than a thundering herd
// against a dependency.
//
// A failed dial is NOT remembered, which is the line above: an outage that ends is
// an outage a long-lived process recovers from rather than one it remembers
// forever.
func (l *LazyRedis) Connect() (*Connection, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.open != nil {
		return l.open, nil
	}

	opened, err := Connect(l.options)
	if err != nil {
		return nil, err
	}
	l.open = opened
	return opened, nil
}

// Eval is `EVAL` through the connection, opening one if needed.
func (l *LazyRedis) Eval(script string, keys []string, args []string) (Value, error) {
	connection, err := l.Connect()
	if err != nil {
		return nil, err
	}
	return connection.Eval(script, keys, args)
}

// Ping is `PING` through the connection, opening one if needed.
func (l *LazyRedis) Ping(ctx context.Context) (bool, error) {
	connection, err := l.Connect()
	if err != nil {
		return false, err
	}
	return connection.Ping(ctx)
}

// Close closes the open connection. A failure to open is not a failure to close.
func (l *LazyRedis) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.open == nil {
		return nil
	}
	err := l.open.Close()
	l.open = nil
	return err
}

type redisTarget struct {
	hostname string
	port     string
	tls      bool

	username string
	password string
}

func (t redisTarget) needsAuth() bool { return t.username != "" || t.password != "" }

func parseRedisURL(value string) (redisTarget, error) {
	trimmed := strings.TrimSpace(value)

	parsed, err := url.Parse(trimmed)
	if err != nil {
		return redisTarget{}, fmt.Errorf("%w: connectRedis: url must be a redis:// URL, got %q", ErrNotConfigured, redactRedisURL(value))
	}

	if parsed.Scheme != "redis" && parsed.Scheme != "rediss" {
		return redisTarget{}, fmt.Errorf("%w: connectRedis: url must be redis:// or rediss://, got %q", ErrNotConfigured, redactRedisURL(value))
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return redisTarget{}, fmt.Errorf("%w: connectRedis: url must have no path, got %q", ErrNotConfigured, redactRedisURL(value))
	}
	if parsed.Hostname() == "" {
		return redisTarget{}, fmt.Errorf("%w: connectRedis: url must name a host, got %q", ErrNotConfigured, redactRedisURL(value))
	}

	port := parsed.Port()
	if port == "" {
		port = "6379"
	}
	number, err := strconv.Atoi(port)
	if err != nil || number < 1 || number > 65535 {
		return redisTarget{}, fmt.Errorf("%w: connectRedis: port must be a whole number between 1 and 65535, got %q", ErrNotConfigured, port)
	}

	target := redisTarget{hostname: parsed.Hostname(), port: port, tls: parsed.Scheme == "rediss"}
	if parsed.User != nil {
		target.username = parsed.User.Username()
		target.password, _ = parsed.User.Password()
	}
	return target, nil
}

func redactRedisURL(value string) string {
	if at := strings.LastIndex(value, "@"); at >= 0 {
		if scheme := strings.Index(value, "://"); scheme >= 0 && scheme+3 < at {
			return value[:scheme+3] + "…" + value[at:]
		}
	}
	return value
}

var _ Commands = (*Connection)(nil)
var _ Commands = (*LazyRedis)(nil)
