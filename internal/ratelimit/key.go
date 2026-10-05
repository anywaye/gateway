// Which bucket a request belongs to.
//
// This is the file the whole limiter rests on, because a rate limiter is only as
// good as the identity of the thing it is counting. The key is derived in one
// order and one order only:
//
//  1. the account id from the *verified* principal  ->  `account:<id>`
//  2. the id of an API key the store authenticated   ->  `apikey:<id>`
//  3. the client address, when the deployment says it can be trusted
//     ->  `ip:<address>`
//  4. nothing at all                                    ->  `ip:unknown`
//
// What is never a key:
//
//   - a header value. `X-Account-Id` is chosen by the caller, and a limiter keyed
//     on it is not a limiter: it is a way for every caller to mint a fresh
//     allowance per request, which is a self-DoS with extra steps.
//   - an unverified token. Nothing reaches this package before the JWT verifier or
//     the API-key gate has run, so the principal is a fact and not a claim.
//
// The prefixes are load-bearing in a second way: they are the counter key, so an
// account id that collides with an address can never share a bucket with it.
package ratelimit

import (
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/cafaye/gateway/internal/auth"
)

// KeySource is what is known about the caller by the time the limiter reads the
// request.
type KeySource struct {
	// The account id from the verified principal, or "" when there is none.
	AccountID string

	// The id of the API key that authenticated, or "".
	APIKeyID string

	// The client address, or "" when it could not be established.
	Address string
}

// unknown stands in for an address gateway could not establish. A NAMED unknown
// rather than a blank: a blank key is a key every unresolved caller shares, which
// is correct — and it is also a key that reads like a bug in a log line six months
// from now.
const unknown = "unknown"

// Key is the bucket name. Two callers share a bucket exactly when this is equal.
//
// `rateLimitKey` in `src/middleware/limitKey.ts` (removed at cutover), branch for branch.
func Key(source KeySource) string {
	if source.AccountID != "" {
		return "account:" + source.AccountID
	}
	if source.APIKeyID != "" {
		return "apikey:" + source.APIKeyID
	}
	if source.Address != "" {
		return "ip:" + source.Address
	}
	return "ip:" + unknown
}

// KeySourceOf reads the credential out of a request. `trustedProxies` is how much
// of `X-Forwarded-For` may be believed; see `ClientIP`.
func KeySourceOf(r *http.Request, trustedProxies int) KeySource {
	return KeySource{
		AccountID: AccountIDOf(auth.PrincipalOf(r)),
		APIKeyID:  auth.APIKeyIDOf(r),
		Address:   ClientIP(r, trustedProxies),
	}
}

// AccountIDOf is the account a verified principal belongs to, or "".
//
// `account_id` is the claim identity issues for the account a request acts on,
// which is not always the subject: a user acting inside a workspace has a `sub` of
// their own and an `account_id` of the workspace. When identity issues no
// `account_id`, the subject stands in — the user *is* the account, and refusing to
// fall back would mean a token that is perfectly valid gets no limiter at all,
// which is the one outcome worse than sharing a bucket.
//
// THREE SOURCES, IN THIS ORDER, and the middle one is the subtle one. The
// reference reads `principal.accountId` (a field, set once at verification) and
// falls back to `principal.claims.account_id` — the same claim, reached a second
// way. Both are reproduced here because `Claims.String` is a nil-safe accessor
// rather than a map index, so the fallback costs one call and cannot panic on a
// payload that is not an object.
func AccountIDOf(principal *auth.Principal) string {
	if principal == nil {
		return ""
	}
	if principal.AccountID != nil && *principal.AccountID != "" {
		return *principal.AccountID
	}
	if claim := principal.Claims.String("account_id"); claim != "" {
		return claim
	}
	return principal.Sub
}

// ClientIP is the client address, and how much of `X-Forwarded-For` is believed.
//
// `X-Forwarded-For` is a list the *caller* can write, and the caller can write as
// much of it as they like. So the number that matters is how many proxies the
// operator says stand in front of gateway, and the entry is read from the RIGHT of
// the chain: everything to the left of the trusted run is whatever the caller felt
// like sending. `TRUSTED_PROXIES=2` means two proxies appended to the header, and
// the address is the second entry from the end — the last one that arrived from
// something the operator vouches for.
//
// # THE DEFAULT IS ZERO AND IT STAYS ZERO
//
// With `trustedProxies` at zero the header is not read at all and the answer is the
// socket peer. That is the honest default: a gateway directly exposed to the
// internet has no forwarding chain to believe, and believing one anyway is how a
// caller walks around the limiter by sending a new address per request.
//
// The cost is real and documented rather than quietly fixed: behind one NAT every
// caller shares a bucket. The alternative — the old behaviour, keying on the FIRST
// `X-Forwarded-For` hop — was worse, because the caller chose it. Both are honest;
// neither is a substitute for a proxy that overwrites the header.
//
// A chain shorter than the trusted run falls back to the peer for the same reason:
// there is no entry the operator vouched for, so the only address left is the one
// the kernel gave us, and a bucket that is too broad is the direction to be wrong
// in.
func ClientIP(r *http.Request, trustedProxies int) string {
	if trustedProxies < 0 {
		// Validated at construction in `NewLimiter`; refused here so a direct
		// caller cannot get the silent "treat it as zero" answer that a negative
		// index into a chain would otherwise produce.
		return unknown
	}
	if trustedProxies == 0 {
		return peerAddress(r)
	}

	chain := forwardedChain(r)
	// Index `trustedProxies` from the right is index `length - trustedProxies`
	// from the left, and a negative index means the chain is shorter than the run.
	at := len(chain) - trustedProxies
	if at < 0 {
		return peerAddress(r)
	}

	if address := addressOf(chain[at]); address != "" {
		return address
	}
	return peerAddress(r)
}

// forwardedChain is `X-Forwarded-For`, split.
//
// Positions are preserved, blanks included: entry *n* is hop *n*, and a proxy that
// appended nothing leaves a hole rather than shortening the chain. A hole is read
// as "no address at this hop" and never becomes a bucket of its own.
//
// `strings.Split` on the raw value and `TrimSpace` per entry, which is what the
// reference does, and the difference from a `Fields`-based parse is the blanks: a
// chain `["", "203.0.113.4"]` has two hops and the first is a hole. `Fields`
// would call it one hop and resolve a different entry.
func forwardedChain(r *http.Request) []string {
	header := r.Header.Get("X-Forwarded-For")
	if header == "" {
		return nil
	}
	parts := strings.Split(header, ",")
	for i, part := range parts {
		parts[i] = strings.TrimSpace(part)
	}
	return parts
}

// peerAddress is the socket peer.
//
// `http.Request.RemoteAddr` is the same fact `c.env.requestIP()` returns in Bun,
// and it is `host:port`, so it goes through `addressOf` and the port is stripped
// by the same code that strips one out of a forwarded chain.
func peerAddress(r *http.Request) string {
	if address := addressOf(r.RemoteAddr); address != "" {
		return address
	}
	return unknown
}

// addressOf is an address, or "".
//
// Entries are PARSED, not pattern-matched for characters that are safe to write
// somewhere. Both were tried and only one of them is a defence, and the reference's
// comment on `addressOf` says why at more length than is repeated here:
//
//   - The charset question is real: a bucket name ends up in a Redis key, and a
//     header the caller chose must not be able to put a newline, a space or a
//     brace in one.
//   - But `[0-9a-f:.%]+` answers "is every character safe" and not "is this an
//     address", and the second is the question. `deadbeef`, `cafe`, `...` and
//     `999.1.1.1` are all inside that character class and none of them is a host,
//     so each became a bucket identity of its own and a caller who could put an
//     entry in the trusted position minted a fresh allowance per request.
//
// `net.ParseIP` is the parse — IPv4 or IPv6, nothing else — and it is a pure
// function in the standard library rather than a dependency.
//
// # IT DOES NOT SETTLE THE `%zone` SUFFIX, AND THIS PARAGRAPH USED TO SAY IT DID
//
// `ParseIP` answers nil for `fe80::1%eth0`, because a zone is an interface index
// rather than a property of the address bytes. The `%` is still in the old charset
// for a reason — a zone IS part of an IPv6 literal as written — so the suffix has
// to be dealt with, and it is dealt with three lines below rather than here. The
// fix and the reference's own behaviour are both written out there; this paragraph
// is only here so the summary above the function does not claim a property the
// function does not have.
//
// `unknown` is refused explicitly so it cannot be confused with the placeholder
// that means the same thing, even though it would not parse either.
func addressOf(entry string) string {
	if entry == "" {
		return ""
	}

	bare := stripPort(strings.ToLower(strings.TrimSpace(entry)))
	if bare == "" || bare == unknown {
		return ""
	}

	// THE ZONE IS STRIPPED FOR THE PARSE AND KEPT IN THE ANSWER, and that is not
	// tidiness — it is a measured divergence from the reference.
	//
	// `src/middleware/limitKey.ts` (removed at cutover) parses with Node's `net.isIP`, which accepts
	// `fe80::1%eth0` and returns 6 for it (measured: `node -e` over the same
	// literals). `net.ParseIP` — Go's equivalent — returns nil for it, because a zone
	// is a scope identifier the parser is not given an interface table for. So a
	// port that called `net.ParseIP` directly refused every link-local IPv6 address
	// carrying a zone, fell through to `addressOf`'s empty answer, and put EVERY such
	// caller in the shared `ip:unknown` bucket.
	//
	// The zone stays in the bucket name because the reference's does: two callers on
	// different interfaces are different addresses, and the reference keeps them apart.
	// Stripping it here would be a second divergence, in the opposite direction, and
	// the one the zone's own purpose argues against.
	host, _, _ := strings.Cut(bare, "%")
	if net.ParseIP(host) == nil {
		return ""
	}
	return bare
}

// stripPort reduces `[::1]:443` and `203.0.113.4:443` to the address.
//
// A bare IPv6 literal has colons and no port, so a single trailing `:digits` is
// the only port that can be peeled off — `strings.LastIndex` plus a colon count is
// the reference's rule and it is reproduced rather than reimplemented, because
// `net.SplitHostPort` ERRORS on a bare IPv6 literal rather than returning it and
// `addressOf` needs the difference.
func stripPort(value string) string {
	if strings.HasPrefix(value, "[") {
		if end := strings.IndexByte(value, ']'); end >= 0 {
			inner := value[1:end]
			rest := value[end+1:]
			if rest == "" || (strings.HasPrefix(rest, ":") && isDigits(rest[1:])) {
				return inner
			}
			// Not `[host]` and not `[host]:port`. The reference's regex requires
			// one of the two, so a malformed bracket falls through to the
			// unbracketed rule below and is then refused as not an address.
			return value
		}
		return value
	}

	last := strings.LastIndexByte(value, ':')
	if last < 0 || strings.Count(value, ":") != 1 {
		return value
	}
	if !isDigits(value[last+1:]) {
		return value
	}
	return value[:last]
}

func isDigits(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// BucketCharset is what a bucket name and a sub-namespace must match, and it is
// `BUCKET` in `rateLimitRedis.ts`: `[A-Za-z0-9_.:-]{1,128}`.
//
// Constrained because these strings end up in a Redis key. `internal/ratelimit`
// hashes the identity before the store ever sees it (`CounterKey` in
// `limiter.go`), so in practice the store's own check is a second line of defence
// rather than the only one — and it is kept, because a store is a public type and
// the next caller will not have read the middleware.
const maxKeyLength = 128

// AssertBucket is the store-side charset check, and it is a refusal to build
// rather than a sanitised string.
func AssertBucket(value string) (string, error) {
	if value == "" || len(value) > maxKeyLength {
		return "", fmt.Errorf("%w: bucket must match [A-Za-z0-9_.:-]{1,%d}, got %q", ErrNotConfigured, maxKeyLength, value)
	}
	for _, r := range value {
		switch {
		case r >= 'A' && r <= 'Z':
		case r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9':
		case r == '_' || r == '.' || r == ':' || r == '-':
		default:
			return "", fmt.Errorf("%w: bucket must match [A-Za-z0-9_.:-]{1,%d}, got %q", ErrNotConfigured, maxKeyLength, value)
		}
	}
	return value, nil
}
