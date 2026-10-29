package ratelimit

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

type authFake struct {
	listener net.Listener
	mu       sync.Mutex
	commands [][]string
	expect   []string
	authed   bool
}

func newAuthFake(t *testing.T, expect []string) *authFake {
	t.Helper()

	listener, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("could not open a port for the scripted Redis: %v", err)
	}
	fake := &authFake{listener: listener, expect: expect}
	go fake.serve()
	t.Cleanup(func() { _ = listener.Close() })
	return fake
}

func (f *authFake) addr() string { return f.listener.Addr().String() }

func (f *authFake) serve() {
	connection, err := f.listener.Accept()
	if err != nil {
		return
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(10 * time.Second))

	var buffered []byte
	chunk := make([]byte, 4096)
	for {
		value, read, err := parseCommand(buffered)
		if err != nil {
			n, readErr := connection.Read(chunk)
			if n > 0 {
				buffered = append(buffered, chunk[:n]...)
			}
			if readErr != nil {
				return
			}
			continue
		}
		buffered = buffered[read:]

		command, ok := value.([]string)
		if !ok {
			_, _ = connection.Write([]byte("-ERR the scripted Redis only speaks arrays of bulk strings\r\n"))
			continue
		}
		f.mu.Lock()
		f.commands = append(f.commands, command)
		f.mu.Unlock()

		_, _ = connection.Write([]byte(f.answer(command)))
	}
}

func parseCommand(buffered []byte) (any, int, error) {
	value, read, err := ParseReply(buffered, 0)
	if err != nil {
		return nil, 0, err
	}
	items, ok := value.([]Value)
	if !ok {
		return nil, 0, errors.New("not a command")
	}
	command := make([]string, 0, len(items))
	for _, item := range items {
		text, ok := item.(string)
		if !ok {
			return nil, 0, errors.New("not a command")
		}
		command = append(command, text)
	}
	return command, read, nil
}

func (f *authFake) answer(command []string) string {
	if len(command) == 0 {
		return "-ERR empty command\r\n"
	}
	switch strings.ToUpper(command[0]) {
	case "AUTH":
		if f.expect != nil && equalStrings(command[1:], f.expect) {
			f.authed = true
			return "+OK\r\n"
		}
		return "-WRONGPASS invalid username-password pair or user is disabled.\r\n"
	case "PING":
		if f.expect != nil && !f.authed {
			return "-NOAUTH Authentication required.\r\n"
		}
		return "+PONG\r\n"
	default:
		if f.expect != nil && !f.authed {
			return "-NOAUTH Authentication required.\r\n"
		}
		return "+OK\r\n"
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func (f *authFake) transcript() [][]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([][]string(nil), f.commands...)
}

func TestConnectSendsAuthPasswordBeforeAnythingElse(t *testing.T) {
	fake := newAuthFake(t, []string{"s3cret"})

	connection, err := Connect(RedisConnectionOptions{URL: "redis://:s3cret@" + fake.addr()})
	if err != nil {
		t.Fatalf("Connect with a password URL: %v", err)
	}
	defer connection.Close()

	if answered, err := connection.Ping(context.Background()); err != nil || !answered {
		t.Fatalf("PING after AUTH answered (%v, %v), want (true, nil). Without the AUTH write the server answers NOAUTH here, which is the live-box failure.", answered, err)
	}

	transcript := fake.transcript()
	if len(transcript) == 0 {
		t.Fatal("the dial wrote nothing. A check that passes without anything on the wire is not checking the dial.")
	}
	if !equalStrings(transcript[0], []string{"AUTH", "s3cret"}) {
		t.Errorf("the first command was %q, want [AUTH s3cret]. AUTH is the first write after the dial, before any PING or EVAL.", transcript[0])
	}
}

func TestConnectSendsAuthUserAndPassword(t *testing.T) {
	fake := newAuthFake(t, []string{"app", "s3cret"})

	connection, err := Connect(RedisConnectionOptions{URL: "redis://app:s3cret@" + fake.addr()})
	if err != nil {
		t.Fatalf("Connect with a userinfo URL: %v", err)
	}
	defer connection.Close()

	transcript := fake.transcript()
	if len(transcript) == 0 {
		t.Fatal("the dial wrote nothing.")
	}
	if !equalStrings(transcript[0], []string{"AUTH", "app", "s3cret"}) {
		t.Errorf("the first command was %q, want [AUTH app s3cret].", transcript[0])
	}
}

func TestConnectSendsNoAuthWhenTheURLCarriesNone(t *testing.T) {
	fake := newAuthFake(t, nil)

	connection, err := Connect(RedisConnectionOptions{URL: "redis://" + fake.addr()})
	if err != nil {
		t.Fatalf("Connect with no userinfo: %v", err)
	}
	defer connection.Close()

	if answered, err := connection.Ping(context.Background()); err != nil || !answered {
		t.Fatalf("PING answered (%v, %v), want (true, nil)", answered, err)
	}
	for _, command := range fake.transcript() {
		if len(command) > 0 && strings.EqualFold(command[0], "AUTH") {
			t.Errorf("a URL with no userinfo sent %q. An unauthenticated Redis stays supported, and a gratuitous AUTH against one that requires none is a failure the operator did not cause.", command)
		}
	}
}

func TestConnectRefusedPasswordNamesAuthenticationAndHidesTheSecret(t *testing.T) {
	fake := newAuthFake(t, []string{"the-right-password"})

	_, err := Connect(RedisConnectionOptions{URL: "redis://:wrong-secret-xyz@" + fake.addr()})
	if err == nil {
		t.Fatal("Connect with the wrong password succeeded. A NOAUTH-class refusal at connect time is the operator's password being wrong, and swallowing it moves the failure to the first PING.")
	}
	message := strings.ToLower(err.Error())
	if !strings.Contains(message, "auth") {
		t.Errorf("the refusal %q never says authentication. The message must name the failure as an authentication problem rather than surfacing on the first PING.", err.Error())
	}
	if strings.Contains(err.Error(), "wrong-secret-xyz") {
		t.Errorf("the refusal %q contains the secret. A URL with a password in it must not reach an error string, a log line or a metrics label.", err.Error())
	}
}

func TestParseRedisURLReadsTheUserinfo(t *testing.T) {
	cases := []struct {
		name     string
		url      string
		username string
		password string
		tls      bool
	}{
		{"kit's spelling, empty user", "redis://:s3cret@redis.data.svc.cluster.local:6379", "", "s3cret", false},
		{"named user", "redis://app:s3cret@redis.data.svc.cluster.local:6379", "app", "s3cret", false},
		{"no userinfo", "redis://redis.data.svc.cluster.local:6379", "", "", false},
		{"tls with a password", "rediss://:s3cret@redis.data.svc.cluster.local:6379", "", "s3cret", true},
		{"percent-encoded password", "redis://:p%40ss@redis.data.svc.cluster.local:6379", "", "p@ss", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			target, err := parseRedisURL(tc.url)
			if err != nil {
				t.Fatalf("parseRedisURL(%q): %v", tc.url, err)
			}
			if target.username != tc.username || target.password != tc.password {
				t.Errorf("parseRedisURL(%q) read user %q password %q, want %q %q", tc.url, target.username, target.password, tc.username, tc.password)
			}
			if target.tls != tc.tls {
				t.Errorf("parseRedisURL(%q) tls %v, want %v", tc.url, target.tls, tc.tls)
			}
		})
	}
}

func TestParseRedisURLStillRefusesAPath(t *testing.T) {
	for _, url := range []string{
		"redis://redis.data.svc.cluster.local:6379/1",
		"redis://:s3cret@redis.data.svc.cluster.local:6379/1",
	} {
		if _, err := parseRedisURL(url); err == nil {
			t.Errorf("parseRedisURL(%q) accepted a database path. The path is refused rather than ignored, and auth must not weaken that.", url)
		}
	}
}

func TestRedactRedisURLHidesThePassword(t *testing.T) {
	redacted := redactRedisURL("redis://:s3cret@redis.data.svc.cluster.local:6379")
	if strings.Contains(redacted, "s3cret") {
		t.Errorf("redactRedisURL left the secret in %q", redacted)
	}
	if !strings.Contains(redacted, "redis.data.svc.cluster.local") {
		t.Errorf("redactRedisURL ate the host: %q", redacted)
	}
	if got := redactRedisURL("redis://redis.data.svc.cluster.local:6379"); got != "redis://redis.data.svc.cluster.local:6379" {
		t.Errorf("redactRedisURL rewrote a URL with no credentials: %q", got)
	}

	if _, err := parseRedisURL("redis://:s3cret@redis.data.svc.cluster.local:notaport"); err == nil {
		t.Fatal("parseRedisURL accepted a non-numeric port")
	} else if strings.Contains(err.Error(), "s3cret") {
		t.Errorf("a parse refusal carried the secret: %q", err.Error())
	}
}
