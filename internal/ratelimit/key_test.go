// Which bucket a request belongs to, and how much of `X-Forwarded-For` is believed.
//
// Two properties, and the packet's is explicit that the ORDER is the policy:
//
//  5. account > api key > address — a request with a principal is limited per
//     principal, not per address;
//  6. `TRUSTED_PROXIES` at its default of 0 keys on the socket peer, and the old
//     behavior of keying on the first hop was worse because the caller chose it.
//
// The second is the one where being wrong is quiet. Behind one NAT every caller
// shares a bucket — a known, documented limitation — and the change that would
// "fix" it by believing the header is the change that lets a caller mint a fresh
// allowance per request. So there is a test for the DEFAULT and a test that the
// non-default is honored when it is set, and neither of them is the same test.
package ratelimit

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cafaye/gateway/internal/auth"
)

// request is a request with a socket peer and any headers a test wants.
func request(peer string, forwarded string, headers map[string]string) *http.Request {
	req := httptest.NewRequest("GET", "http://gateway.test/v1/me", nil)
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

// -----------------------------------------------------------------------------
// PROPERTY 5 — the bucket order is the policy.
//
// The mutation that breaks this: swapping the first two branches. A caller with
// BOTH an account and an API key would then be limited per key rather than per
// account, and every key in an account would get its own allowance — which is the
// opposite of what the order is for.
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
			// A NAMED unknown rather than a blank. A blank key is a key every
			// unresolved caller shares, which is correct — and it is also a key that
			// reads like a bug in a log line six months from now.
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
		// The prefixes are the counter key, so an account id that happens to look
		// like an address must not share a bucket with it. One hash, two callers,
		// one allowance — which is the failure the prefixes exist to prevent.
		account := CounterKey(DefaultPolicy, Key(KeySource{AccountID: "203.0.113.4"}))
		address := CounterKey(DefaultPolicy, Key(KeySource{Address: "203.0.113.4"}))
		if account == address {
			t.Errorf("an account id of %q and an address of %q landed on the same bucket %q. The prefixes are load-bearing: they are the counter key.", "203.0.113.4", "203.0.113.4", account)
		}
	})
}

// -----------------------------------------------------------------------------
// PROPERTY 5, the other half: the principal a handler sees IS the bucket.
//
// The mutation that breaks this: `AccountIDOf` reading `claims["account_id"]` but
// not falling back to `sub`. Then a user with no workspace — who IS their own
// account — gets no limiter at all on the account tier, and every such caller
// shares the anonymous address bucket instead. That is the one outcome the reference
// calls worse than sharing.
func TestTheAccountIsTheClaimThenTheClaimFieldThenTheSubject(t *testing.T) {
	t.Run("the account_id claim", func(t *testing.T) {
		principal := &auth.Principal{Sub: "sub-1"}
		if got := AccountIDOf(principal); got != "sub-1" {
			t.Errorf("with no account anywhere the bucket is %q, want the subject sub-1 — a user with no workspace IS the account, and refusing to fall back means a perfectly valid token gets no limiter at all", got)
		}
	})

	t.Run("a non-string account_id is ignored rather than fatal", func(t *testing.T) {
		// The one deliberate asymmetry in `principalOf`: a `scope` claim that is
		// present and is not a string is REJECTED, and an `account_id` that is
		// present and is not a string is IGNORED. A rate-limit key is a worse thing
		// to lose than a well-formed claim is to gain.
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

// -----------------------------------------------------------------------------
// PROPERTY 6 — `TRUSTED_PROXIES` defaults to 0 and the default keys on the peer.
//
// The mutation that breaks this: defaulting it to 1, or reading the FIRST
// `X-Forwarded-For` hop instead of the nth from the right. Both were the old
// behavior and both are worse, because the caller chose them.
func TestTrustedProxiesDefaultsToTheSocketPeerAndTheDefaultIsNotAProxyCount(t *testing.T) {
	t.Run("at zero the header is not read at all", func(t *testing.T) {
		// The header names an address a caller chose. A gateway directly exposed to
		// the internet has no forwarding chain to believe, and believing one anyway is
		// how a caller walks around the limiter by sending a new address per request.
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
		// The runtime reader's default is asserted here as well as in
		// `internal/httpapi`, because this is where the property lives: a
		// `TrustedProxies: 1` default added to either file would be invisible to the
		// other package's test.
		limiter, err := NewLimiter(Options{Store: newTestStore(t)}, refuseInTest)
		if err != nil {
			t.Fatalf("NewLimiter refused a configuration with no TrustedProxies: %v", err)
		}
		if limiter.trustedProxies != 0 {
			t.Errorf("NewLimiter's default TrustedProxies is %d, want 0 — a gateway directly exposed to the internet believes no forwarding chain", limiter.trustedProxies)
		}
	})

	t.Run("when it is set, the nth hop from the RIGHT is believed", func(t *testing.T) {
		// `TRUSTED_PROXIES=2` means two proxies appended to the header, and the
		// address is the second entry from the end — the last one that arrived from
		// something the operator vouches for. Everything to the LEFT of the trusted
		// run is whatever the caller felt like sending.
		for _, tc := range []struct {
			proxies   int
			forwarded string
			want      string
		}{
			{proxies: 1, forwarded: "203.0.113.9, 198.51.100.7", want: "198.51.100.7"},
			{proxies: 2, forwarded: "203.0.113.9, 198.51.100.7, 192.0.2.5", want: "198.51.100.7"},
			{proxies: 3, forwarded: "203.0.113.9, 198.51.100.7, 192.0.2.5, 192.0.2.6", want: "198.51.100.7"},
			// The first entry is the caller's claim and it is NEVER the answer while
			// the count is above zero. This is the old behavior the README says was
			// worse, and it is the one this table exists to keep out.
			{proxies: 1, forwarded: "203.0.113.9", want: "203.0.113.9"},
		} {
			got := ClientIP(request("192.0.2.99:5000", tc.forwarded, nil), tc.proxies)
			if got != tc.want {
				t.Errorf("%d trusted proxies and X-Forwarded-For: %q gave %q, want %q", tc.proxies, tc.forwarded, got, tc.want)
			}
		}
	})

	t.Run("a chain shorter than the trusted run falls back to the peer", func(t *testing.T) {
		// There is no entry the operator vouched for, so the only address left is the
		// one the kernel gave us, and a bucket that is too broad is the direction to
		// be wrong in.
		got := ClientIP(request("198.51.100.7:41234", "203.0.113.9", nil), 3)
		if got != "198.51.100.7" {
			t.Errorf("three trusted proxies and a one-entry chain gave %q, want the socket peer 198.51.100.7", got)
		}
	})

	t.Run("a hole in the chain is not a bucket", func(t *testing.T) {
		// Positions are preserved, blanks included: entry n is hop n, and a proxy that
		// appended nothing leaves a hole rather than shortening the chain. So the
		// trusted entry — two hops from the right of a three-entry chain — IS the
		// hole, and a hole is "no address at this hop" and falls back to the peer.
		//
		// Which is the right answer for a DIFFERENT reason than "the hole is skipped":
		// the fallback is the socket peer, and the reference's `addressOf(claimed) ??
		// peerAddress(c)` is the same fallback for the same reason — a bucket that is
		// too broad is the direction to be wrong in. The property here is that the
		// hole does not become a bucket of its own and does not SHIFT the chain, so
		// one more trusted proxy reads the entry to its LEFT rather than to its right.
		if got := ClientIP(request("198.51.100.7:41234", "203.0.113.9, , 192.0.2.5", nil), 2); got != "198.51.100.7" {
			t.Errorf("a chain with a hole at hop 2 and two trusted proxies gave %q, want the socket peer — hop 2 from the right is the hole, and a hole is not an address", got)
		}
		// One more proxy and the trusted entry moves LEFT, past the hole. If blanks
		// were collapsed rather than preserved, this would read the hole again.
		if got := ClientIP(request("198.51.100.7:41234", "203.0.113.9, , 192.0.2.5", nil), 3); got != "203.0.113.9" {
			t.Errorf("a chain with a hole at hop 2 and three trusted proxies gave %q, want 203.0.113.9 — positions are preserved, so hop 3 from the right is the first entry and not the hole", got)
		}
	})
}

// -----------------------------------------------------------------------------
// Addresses are PARSED, not pattern-matched.
//
// The charset question is real — a bucket name ends up in a Redis key, and a header
// the caller chose must not put a newline or a brace in one — but `[0-9a-f:.%]+`
// answers "is every character safe" and not "is this an address". `deadbeef`,
// `cafe`, `...` and `999.1.1.1` are all inside that character class and none of them
// is a host.
//
// The mutation that breaks this: the character-class filter the reference replaced.
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
			// A bare IPv6 literal has colons and no port. Peeling a trailing `:digits`
			// off it would leave `2001:db8:` which is not an address — and then the
			// entry would be refused, which is why the port rule counts colons.
			{entry: "2001:db8::1", want: "2001:db8::1"},
			// The `%zone` suffix is part of an IPv6 literal and is the reason the old
			// character class had to allow `%` at all.
			{entry: "fe80::1%eth0", want: "fe80::1%eth0"},
			// Uppercase is normalised, because the header is case-insensitive in
			// practice and `FE80::1` and `fe80::1` are the same host.
			{entry: "FE80::1%ETH0", want: "fe80::1%eth0"},
		} {
			if got := ClientIP(request(tc.entry, "", nil), 0); got != tc.want {
				t.Errorf("the socket peer %q was read as %q, want %q", tc.entry, got, tc.want)
			}
		}
	})

	t.Run("the placeholder is refused even though it would not parse", func(t *testing.T) {
		// `unknown` is refused explicitly so it cannot be confused with the
		// placeholder that means the same thing. It does not parse as an address
		// either, so the refusal is belt and braces — and that is the point: a
		// placeholder that parses is a placeholder that can become a bucket.
		if got := addressOf("unknown"); got != "" {
			t.Errorf("addressOf(\"unknown\") is %q, want the empty string", got)
		}
		if got := ClientIP(request("unknown:1234", "", nil), 0); got != unknown {
			t.Errorf("a peer address of the literal string \"unknown\" produced %q", got)
		}
	})
}

// -----------------------------------------------------------------------------
// Nothing that is a HEADER becomes a bucket.
//
// The mutation that breaks this: reading `X-Account-Id`, which is chosen by the
// caller. A limiter keyed on it is not a limiter: it is a way for every caller to
// mint a fresh allowance per request, which is a self-DoS with extra steps.
func TestNoHeaderValueBecomesABucket(t *testing.T) {
	// The principal's ACCOUNT field, which is the thing `AccountIDOf` reads first —
	// and which is populated from the `account_id` claim at verification.
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
