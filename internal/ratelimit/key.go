package ratelimit

import (
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/anywaye/gateway/internal/auth"
)

// KeySource is what is known about the caller by the time the limiter reads the
// request.
type KeySource struct {
	AccountID string

	APIKeyID string

	Address string
}

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
// caller shares a bucket. The alternative — the old behavior, keying on the FIRST
// `X-Forwarded-For` hop — was worse, because the caller chose it. Both are honest;
// neither is a substitute for a proxy that overwrites the header.
//
// A chain shorter than the trusted run falls back to the peer for the same reason:
// there is no entry the operator vouched for, so the only address left is the one
// the kernel gave us, and a bucket that is too broad is the direction to be wrong
// in.
func ClientIP(r *http.Request, trustedProxies int) string {
	if trustedProxies < 0 {
		return unknown
	}
	if trustedProxies == 0 {
		return peerAddress(r)
	}

	chain := forwardedChain(r)
	at := len(chain) - trustedProxies
	if at < 0 {
		return peerAddress(r)
	}

	if address := addressOf(chain[at]); address != "" {
		return address
	}
	return peerAddress(r)
}

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

func peerAddress(r *http.Request) string {
	if address := addressOf(r.RemoteAddr); address != "" {
		return address
	}
	return unknown
}

func addressOf(entry string) string {
	if entry == "" {
		return ""
	}

	bare := stripPort(strings.ToLower(strings.TrimSpace(entry)))
	if bare == "" || bare == unknown {
		return ""
	}

	host, _, _ := strings.Cut(bare, "%")
	if net.ParseIP(host) == nil {
		return ""
	}
	return bare
}

func stripPort(value string) string {
	if strings.HasPrefix(value, "[") {
		if end := strings.IndexByte(value, ']'); end >= 0 {
			inner := value[1:end]
			rest := value[end+1:]
			if rest == "" || (strings.HasPrefix(rest, ":") && isDigits(rest[1:])) {
				return inner
			}
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

const maxKeyLength = 128

// AssertBucket is the store-side charset check, and it is a refusal to build
// rather than a sanitized string.
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
