// The cached key set: its TTL, its refresh, and the budget that keeps a burst of
// forged `kid`s from turning into a burst of fetches.
//
// Ported from the closure inside `createJwtVerifier` in `src/middleware/jwt.ts`
// — the variables named `cache`, `window` and `refreshSpentIn`, and the two
// decisions the comment there records as having been got wrong at least once.
// Both are preserved, and the reasons are the same reasons.
package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// errKeySetUnavailable is what `fetchKeys` failure becomes, and it is a sentinel
// rather than a formatted error for the same reason `ErrNotConfigured` is one in
// `internal/httpapi`: a caller has to be able to tell "identity is unreachable"
// from "this key set is not a key set", because only the first is a `503` and
// both are otherwise a `503` reached for different reasons.
var errKeySetUnavailable = errors.New("auth: the signing keys could not be retrieved")

// The default cache window and fetch deadline, and they are `jwt.ts`'s numbers.
const (
	DefaultJWKSCacheTTL = 5 * time.Minute
	DefaultJWKSTimeout  = 5 * time.Second
)

// A cached key set and when it arrived.
type keySet struct {
	keys      []jwk
	fetchedAt time.Time
}

// jwksCache is the cache, the window counter and the refresh budget.
//
// # WHY THE LOCK IS HELD ACROSS THE FETCH
//
// This is the one place the port is structurally different from the TypeScript,
// and the difference is a consequence of the language rather than a choice: Go
// runs requests on goroutines and TypeScript runs them on one loop, so
// "claimed before the await" needs a mutex here rather than a statement
// ordering.
//
// The mutex is held for the whole of `keysFor`, including the network call. That
// is deliberate and it is what makes the refresh single-flight: twenty-five
// requests naming a `kid` the cached set does not publish arrive, the first
// takes the lock and spends the window's budget, and the other twenty-four block
// until it is done and then find the budget already spent. Exactly one fetch.
// The reference reaches the same place by claiming `refreshSpentIn` before its
// `await` — a statement that cannot be interleaved — and the comment there
// records exactly what that costs when it is claimed after instead.
//
// The cost is stated rather than hidden: a fetch that hangs holds every other
// verification for `jwksTimeout` (5s by default). That is bounded, it is
// shorter than an orchestrator's readiness probe timeout, and the alternative —
// letting goroutines race to the same URL — is the thundering herd this whole
// mechanism exists to prevent.
type jwksCache struct {
	url     string
	ttl     time.Duration
	timeout time.Duration
	now     func() time.Time
	client  *http.Client

	// Serialises every read of the fields below AND every fetch. See above.
	mu sync.Mutex

	// `nil` until the first successful fetch. A FAILED fetch must leave the last
	// good set in place rather than replacing it with an outage, so this is only
	// ever assigned on success.
	cached *keySet

	// Which cache window the forced refresh has already been spent in, and
	// `refreshSpentIn`'s window number. `noWindow` means "never spent".
	window         int
	refreshSpentIn int
}

// noWindow is the sentinel for "this window's refresh budget is unspent". `0` is
// not usable because the first window is itself numbered `0`.
const noWindow = -1

func newJWKSCache(url string, ttl, timeout time.Duration, now func() time.Time, client *http.Client) *jwksCache {
	return &jwksCache{
		url:            url,
		ttl:            ttl,
		timeout:        timeout,
		now:            now,
		client:         client,
		window:         0,
		refreshSpentIn: noWindow,
	}
}

// isFresh is the TTL test, and it is only ever asked with the lock held.
func (c *jwksCache) isFresh() bool {
	return c.cached != nil && c.now().Sub(c.cached.fetchedAt) < c.ttl
}

// load fetches and caches. `opening` marks a fetch that starts a window — a
// TTL-driven one — and only that kind refills the forced-refresh budget.
//
// Stored only on success. The comment in `jwt.ts` is the reason and it is worth
// keeping whole: replacing the last good set with an outage turns a transient
// identity blip into a total authentication outage for the length of the TTL.
func (c *jwksCache) load(ctx context.Context, opening bool) ([]jwk, error) {
	fetched, err := c.fetch(ctx)
	if err != nil {
		return nil, err
	}

	c.cached = &keySet{keys: fetched, fetchedAt: c.now()}
	if opening {
		c.window++
		c.refreshSpentIn = noWindow
	}
	return fetched, nil
}

// keysFor is the cache read, the TTL refresh, and the one-budget unknown-kid
// refresh. The whole of it under the lock; see the type comment.
//
// The two paths are the same as the reference's, decision for decision:
//
//   - a stale or absent cache opens a new window and is refilled,
//   - a `kid` the set does not publish spends this window's refresh budget once
//     and only once, and the twenty-four requests that follow it are refused off
//     the CACHED set without a network call at all,
//   - a refresh that FAILS still consumes the budget, because an unreachable
//     identity is otherwise an unlimited fetch allowance for anyone naming a
//     `kid`.
func (c *jwksCache) keysFor(ctx context.Context, kid string) ([]jwk, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	var set []jwk
	var fetched bool

	if c.isFresh() {
		set = c.cached.keys
	} else {
		loaded, err := c.load(ctx, true)
		if err != nil {
			return nil, err
		}
		set = loaded
		fetched = true
	}

	if !publishes(set, kid) {
		// `!fetched` is the reference's `!fetched`: a set this request has just
		// read is not re-read. A TTL-driven fetch already saw the whole key set
		// as it is now, so spending the budget on a second fetch of the same
		// thing would buy nothing.
		if !fetched && c.refreshSpentIn != c.window {
			// CLAIMED BEFORE THE FETCH, and that is the whole fix. `jwt.ts`
			// records what the alternative cost: twenty-five requests naming a key
			// identity does not publish bought twenty-five fetches aimed at
			// identity, from anonymous pre-auth traffic.
			c.refreshSpentIn = c.window

			refreshed, err := c.load(ctx, false)
			if err != nil {
				return nil, err
			}
			set = refreshed
		}
	}

	return set, nil
}

// fetch one key set over HTTP.
//
// Three refusals, all of them fatal, and the last two are the ones that matter:
// an endpoint that answers `200` with a login page, and a JSON document that is
// not a key set. `isKeySet` in `jwt.ts` says why — "the shape is checked before
// anything is imported" — and importing a login page as a key set produces an
// error message about a key that says nothing about the login page.
func (c *jwksCache) fetch(ctx context.Context) ([]jwk, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %s is not a requestable URL: %v", errKeySetUnavailable, c.url, err)
	}

	response, err := c.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("%w: %s did not answer: %v", errKeySetUnavailable, c.url, err)
	}
	defer response.Body.Close()

	if response.StatusCode < 200 || response.StatusCode > 299 {
		return nil, fmt.Errorf("%w: %s answered %d", errKeySetUnavailable, c.url, response.StatusCode)
	}

	// Bounded, because this reads a document from a service this repository does
	// not control into a process that is on every request's path. `jwt.ts` gets
	// this for free from `fetch` and a JSON parse; Go does not, so the limit is
	// stated here. 1 MiB is far above any key set a JWKS endpoint has ever
	// published and far below anything that would matter to a memory budget.
	body, err := io.ReadAll(io.LimitReader(response.Body, maxJWKSBytes))
	if err != nil {
		return nil, fmt.Errorf("%w: %s: reading the body failed: %v", errKeySetUnavailable, c.url, err)
	}

	var document struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(body, &document); err != nil {
		return nil, fmt.Errorf("%w: %s is not JSON: %v", errKeySetUnavailable, c.url, err)
	}
	if len(document.Keys) == 0 {
		return nil, fmt.Errorf("%w: %s is not a key set — no keys, which is what a login page or an empty array looks like", errKeySetUnavailable, c.url)
	}

	keys := make([]jwk, 0, len(document.Keys))
	for _, raw := range document.Keys {
		key, err := parseJWK(raw)
		if err != nil || key == nil {
			// One unparseable member does not fail the key set. jose keeps
			// unusable members in the snapshot and filters them per verification,
			// and a JWKS that carries a key for another algorithm alongside the
			// RSA ones is normal rather than broken. What MUST fail the set is
			// zero usable keys, which is the check below.
			continue
		}
		keys = append(keys, *key)
	}

	if len(keys) == 0 {
		return nil, fmt.Errorf("%w: %s published %d key(s) and none of them is a key this verifier can use", errKeySetUnavailable, c.url, len(document.Keys))
	}

	return keys, nil
}

// maxJWKSBytes bounds one fetch. See `fetch`.
const maxJWKSBytes = 1 << 20

// publishes whether the set carries a key with this id. `keys.some(key => key.kid
// === kid)` in `jwt.ts`, verbatim.
func publishes(keys []jwk, kid string) bool {
	for _, key := range keys {
		if key.Kid == kid {
			return true
		}
	}
	return false
}

// jwk is the subset of a JWK member this verifier uses.
//
// Field names are the JOSE spellings, not Go's, because the JSON tags are the
// wire format and renaming `key_ops` to `KeyOps` with a hand-written tag would
// make the one place a typo hides a place nobody reads.
type jwk struct {
	Kty    string   `json:"kty"`
	Kid    string   `json:"kid"`
	Use    string   `json:"use"`
	Alg    string   `json:"alg"`
	KeyOps []string `json:"key_ops"`
	Ext    *bool    `json:"ext"`
	N      string   `json:"n"`
	E      string   `json:"e"`
}

// parseJWK reads one member. A member that is not a JSON object at all is an
// error; a member that IS an object is returned even when this verifier cannot
// use it, because usability is `isUsable`'s question and conflating the two is
// how a JWKS carrying an EC key would come to look like an empty one.
func parseJWK(raw json.RawMessage) (*jwk, error) {
	var key jwk
	if err := json.Unmarshal(raw, &key); err != nil {
		return nil, err
	}
	return &key, nil
}

// isUsable is jose's `isUsableJWK` for RS256, condition for condition.
//
// It is not "does the kid match". jose filters on eight separate conditions and
// then THROWS when the filter leaves zero or more than one, and each condition
// exists for a reason that survives the port:
//
//   - `ext` absent or boolean. `ext: false` means "do not use this key", which
//     is how a key is withdrawn without removing it.
//   - `key_ops` absent, or an array of unique strings that INCLUDES `verify`.
//     A key published for signing only must not verify.
//   - `kty` is `RSA`. The key type is a property of the key set, not a hint.
//   - `kid` matches, which is the rotation axis.
//   - `alg` absent, or `RS256`. A key that names its own algorithm must agree
//     with the one pinned here — `alg` confusion is the attack this whole
//     verifier is shaped around.
//   - `use` absent, or `sig`.
//   - `crv` absent, which for RSA it always is.
func (key jwk) isUsable(kid string) bool {
	if key.Ext != nil {
		return false
	}
	if key.KeyOps != nil && !key.verifiable() {
		return false
	}
	if key.Kty != "RSA" {
		return false
	}
	if key.Kid != kid {
		return false
	}
	if key.Alg != "" && key.Alg != algorithm {
		return false
	}
	if key.Use != "" && key.Use != "sig" {
		return false
	}
	return true
}

// verifiable reports whether a `key_ops` array permits verifying.
//
// A repeat in the array refuses the whole key, which is jose's condition
// (`keyOps.every((op, i) => keyOps.indexOf(op) === i)`) and it is worth a line
// because it looks like pedantry: a duplicated operation in a security field is
// a document that was assembled rather than authored, and the assembler is
// whoever published it.
func (key jwk) verifiable() bool {
	seen := make(map[string]bool, len(key.KeyOps))
	for _, operation := range key.KeyOps {
		if seen[operation] {
			return false
		}
		seen[operation] = true
	}
	return seen["verify"]
}

// algorithm is RS256 and nothing else.
//
// The algorithm is a property of the key set identity publishes, not a hint the
// token carries, so it is pinned here and checked BEFORE anything is fetched. The
// reference says the same thing in `jwt.ts` and it is worth repeating the
// failure this prevents: accepting the token's own claim of which algorithm it
// used is `alg` confusion, and the classic form of it is accepting an HS256
// token signed with the RSA PUBLIC key, which every party can see.
//
// core's conventions also allow ES256. Widening this is a one-line change and
// doing it without identity publishing ES256 keys would only widen the attack
// surface — see the DECISION NEEDED in cafaye.yml and the README's "Not built
// yet".
const algorithm = "RS256"

// JWKSPath is where identity publishes its keys. Fixed, and appended to the
// issuer, which is why an issuer carrying a path is a configuration error.
const JWKSPath = "/.well-known/jwks.json"

// DefaultIdentityIssuer is what gateway falls back to when nothing is configured.
const DefaultIdentityIssuer = "https://identity.localhost"

// trimIssuer mirrors `parseIssuer`: an origin, a trailing slash dropped, and no
// path. Both halves are refused at construction so a typo in an environment
// variable is a startup failure rather than a 503 on every request.
func trimIssuer(value string) (string, error) {
	scheme, rest, found := strings.Cut(strings.TrimSpace(value), "://")
	if !found || (scheme != "https" && scheme != "http") {
		return "", fmt.Errorf("auth: issuer must be an absolute http(s) URL, got %q", value)
	}

	host := rest
	path := ""
	if slash := strings.IndexByte(rest, '/'); slash >= 0 {
		host, path = rest[:slash], rest[slash:]
	}
	if host == "" {
		return "", fmt.Errorf("auth: issuer must name a host, got %q", value)
	}

	if path != "" && path != "/" {
		return "", fmt.Errorf("auth: issuer must be a base URL with no path, got %q — the JWKS path is appended to it", value)
	}

	return scheme + "://" + host, nil
}
