package ratelimit

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/anywaye/gateway/internal/auth"
)

func request(peer string, forwarded string, headers map[string]string) *http.Request {
	req := httptest.NewRequestWithContext(context.Background(), "GET", "http://gateway.test/v1/me", nil)
	if peer != "" {
		req.RemoteAddr = peer
	}
	if forwarded != "" {
		req.Header.Set("X-Forwarded-For", forwarded)
	}
	for name, value := range headers {
		req.Header.Set(name, value)
	}
	return req
}

func TestTheBucketOrderIsAccountThenAPIKeyThenAddress(t *testing.T) {
	for _, tc := range []struct {
		name   string
		source KeySource
		want   string
	}{
		{
			name: "an account beats an api key",
			source: KeySource{
				AccountID: "acct-1",
				APIKeyID:  "key-1",
				Address:   "203.0.113.4",
			},
			want: "account:acct-1",
		},
		{
			name:   "an account beats an address",
			source: KeySource{AccountID: "acct-1", Address: "203.0.113.4"},
			want:   "account:acct-1",
		},
		{
			name:   "an api key beats an address",
			source: KeySource{APIKeyID: "key-1", Address: "203.0.113.4"},
			want:   "apikey:key-1",
		},
		{
			name:   "an address is the last resort",
			source: KeySource{Address: "203.0.113.4"},
			want:   "ip:203.0.113.4",
		},
		{
			name:   "nothing at all is a named unknown",
			source: KeySource{},
			want:   "ip:unknown",
		},
		{
			name:   "an empty account id is not an account",
			source: KeySource{AccountID: "", APIKeyID: "key-1"},
			want:   "apikey:key-1",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := Key(tc.source); got != tc.want {
				t.Errorf("Key(%+v) is %q, want %q", tc.source, got, tc.want)
			}
		})
	}

	t.Run("and the prefixes cannot collide across tiers", func(t *testing.T) {
		account := CounterKey(DefaultPolicy, Key(KeySource{AccountID: "203.0.113.4"}))
		address := CounterKey(DefaultPolicy, Key(KeySource{Address: "203.0.113.4"}))
		if account == address {
			t.Errorf("an account id of %q and an address of %q landed on the same bucket %q. The prefixes are load-bearing: they are the counter key.", "203.0.113.4", "203.0.113.4", account)
		}
	})
}

func TestTheAccountIsTheClaimThenTheClaimFieldThenTheSubject(t *testing.T) {
	t.Run("the account_id claim", func(t *testing.T) {
		principal := &auth.Principal{Sub: "sub-1"}
		if got := AccountIDOf(principal); got != "sub-1" {
			t.Errorf("with no account anywhere the bucket is %q, want the subject sub-1 — a user with no workspace IS the account, and refusing to fall back means a perfectly valid token gets no limiter at all", got)
		}
	})

	t.Run("a non-string account_id is ignored rather than fatal", func(t *testing.T) {
		principal := &auth.Principal{Sub: "sub-1", Claims: claimSet(t, `{"account_id":42}`)}
		if got := AccountIDOf(principal); got != "sub-1" {
			t.Errorf("a numeric account_id gave the bucket %q, want the subject sub-1", got)
		}
	})

	t.Run("a nil principal is no bucket", func(t *testing.T) {
		if got := AccountIDOf(nil); got != "" {
			t.Errorf("AccountIDOf(nil) is %q, want the empty string — and the empty string is what routes an anonymous request to the address tier", got)
		}
	})
}

func TestTrustedProxiesDefaultsToTheSocketPeerAndTheDefaultIsNotAProxyCount(t *testing.T) {
	t.Run("at zero the header is not read at all", func(t *testing.T) {
		for _, forwarded := range []string{
			"203.0.113.9",
			"203.0.113.9, 198.51.100.7",
			"10.0.0.1, 10.0.0.2, 10.0.0.3",
		} {
			got := ClientIP(request("198.51.100.7:41234", forwarded, nil), 0)
			if got != "198.51.100.7" {
				t.Errorf("with X-Forwarded-For: %q and zero trusted proxies the bucket address is %q, want the socket peer 198.51.100.7", forwarded, got)
			}
		}
	})

	t.Run("and the default really is zero, in the reader that reads it", func(t *testing.T) {
		limiter, err := NewLimiter(Options{Store: newTestStore(t)}, refuseInTest)
		if err != nil {
			t.Fatalf("NewLimiter refused a configuration with no TrustedProxies: %v", err)
		}
		if limiter.trustedProxies != 0 {
			t.Errorf("NewLimiter's default TrustedProxies is %d, want 0 — a gateway directly exposed to the internet believes no forwarding chain", limiter.trustedProxies)
		}
	})

	t.Run("when it is set, the nth hop from the RIGHT is believed", func(t *testing.T) {
		for _, tc := range []struct {
			proxies   int
			forwarded string
			want      string
		}{
			{proxies: 1, forwarded: "203.0.113.9, 198.51.100.7", want: "198.51.100.7"},
			{proxies: 2, forwarded: "203.0.113.9, 198.51.100.7, 192.0.2.5", want: "198.51.100.7"},
			{proxies: 3, forwarded: "203.0.113.9, 198.51.100.7, 192.0.2.5, 192.0.2.6", want: "198.51.100.7"},
			{proxies: 1, forwarded: "203.0.113.9", want: "203.0.113.9"},
		} {
			got := ClientIP(request("192.0.2.99:5000", tc.forwarded, nil), tc.proxies)
			if got != tc.want {
				t.Errorf("%d trusted proxies and X-Forwarded-For: %q gave %q, want %q", tc.proxies, tc.forwarded, got, tc.want)
			}
		}
	})

	t.Run("a chain shorter than the trusted run falls back to the peer", func(t *testing.T) {
		got := ClientIP(request("198.51.100.7:41234", "203.0.113.9", nil), 3)
		if got != "198.51.100.7" {
			t.Errorf("three trusted proxies and a one-entry chain gave %q, want the socket peer 198.51.100.7", got)
		}
	})

	t.Run("a hole in the chain is not a bucket", func(t *testing.T) {
		if got := ClientIP(request("198.51.100.7:41234", "203.0.113.9, , 192.0.2.5", nil), 2); got != "198.51.100.7" {
			t.Errorf("a chain with a hole at hop 2 and two trusted proxies gave %q, want the socket peer — hop 2 from the right is the hole, and a hole is not an address", got)
		}
		if got := ClientIP(request("198.51.100.7:41234", "203.0.113.9, , 192.0.2.5", nil), 3); got != "203.0.113.9" {
			t.Errorf("a chain with a hole at hop 2 and three trusted proxies gave %q, want 203.0.113.9 — positions are preserved, so hop 3 from the right is the first entry and not the hole", got)
		}
	})
}

func TestAnEntryIsParsedAsAnAddressAndNotMatchedForSafeCharacters(t *testing.T) {
	t.Run("rejected: inside the old character class, not addresses", func(t *testing.T) {
		for _, entry := range []string{
			"deadbeef",
			"cafe",
			"...",
			"999.1.1.1",
			"0.0.0.0.0",
			"203.0.113.999",
			"gateway.internal",
			"[not-an-address]",
			"203.0.113.4 extra",
		} {
			got := ClientIP(request(entry+":1234", "", nil), 0)
			if got != unknown {
				t.Errorf("the socket peer %q was accepted as address %q. Every character of it is inside the old [0-9a-f:.%%]+ class and none of it is a host, so each was a bucket identity of its own — and a caller who can put an entry in the trusted position mints a fresh allowance per request by varying a string that was never an address.", entry, got)
			}
		}
	})

	t.Run("accepted: with and without a port, bracketed and bare", func(t *testing.T) {
		for _, tc := range []struct{ entry, want string }{
			{entry: "203.0.113.4:443", want: "203.0.113.4"},
			{entry: "203.0.113.4", want: "203.0.113.4"},
			{entry: "[::1]:443", want: "::1"},
			{entry: "[2001:db8::1]", want: "2001:db8::1"},
			{entry: "2001:db8::1", want: "2001:db8::1"},
			{entry: "fe80::1%eth0", want: "fe80::1%eth0"},
			{entry: "FE80::1%ETH0", want: "fe80::1%eth0"},
		} {
			if got := ClientIP(request(tc.entry, "", nil), 0); got != tc.want {
				t.Errorf("the socket peer %q was read as %q, want %q", tc.entry, got, tc.want)
			}
		}
	})

	t.Run("the placeholder is refused even though it would not parse", func(t *testing.T) {
		if got := addressOf("unknown"); got != "" {
			t.Errorf("addressOf(\"unknown\") is %q, want the empty string", got)
		}
		if got := ClientIP(request("unknown:1234", "", nil), 0); got != unknown {
			t.Errorf("a peer address of the literal string \"unknown\" produced %q", got)
		}
	})
}

func TestNoHeaderValueBecomesABucket(t *testing.T) {
	principal := &auth.Principal{
		Sub:       "sub-1",
		AccountID: strptr("acct-from-the-token"),
		Claims:    claimSet(t, `{"account_id":"acct-from-the-token"}`),
	}
	req := request("198.51.100.7:41234", "203.0.113.9", map[string]string{
		"X-Account-Id":    "acct-the-caller-chose",
		"X-Forwarded-For": "203.0.113.9",
		"Authorization":   "Bearer forged",
	})

	source := KeySourceOf(withPrincipal(req, principal), 0)
	if source.AccountID != "acct-from-the-token" {
		t.Errorf("the bucket's account is %q, want acct-from-the-token — it must come from the VERIFIED principal and from nothing a caller wrote", source.AccountID)
	}
	if got := Key(source); got != "account:acct-from-the-token" {
		t.Errorf("the bucket is %q, want account:acct-from-the-token", got)
	}
	if strings.Contains(Key(source), "acct-the-caller-chose") {
		t.Errorf("the bucket %q carries a header the caller chose", Key(source))
	}
}
