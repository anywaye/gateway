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

var errKeySetUnavailable = errors.New("auth: the signing keys could not be retrieved")

const (
	DefaultJWKSCacheTTL = 5 * time.Minute
	DefaultJWKSTimeout  = 5 * time.Second
)

type keySet struct {
	keys      []jwk
	fetchedAt time.Time
}

type jwksCache struct {
	url     string
	ttl     time.Duration
	timeout time.Duration
	now     func() time.Time
	client  *http.Client

	mu sync.Mutex

	cached *keySet

	window         int
	refreshSpentIn int
}

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

func (c *jwksCache) isFresh() bool {
	return c.cached != nil && c.now().Sub(c.cached.fetchedAt) < c.ttl
}

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
		if !fetched && c.refreshSpentIn != c.window {
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

func (c *jwksCache) fetch(ctx context.Context) ([]jwk, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %s is not a requestable URL: %w", errKeySetUnavailable, c.url, err)
	}

	response, err := c.client.Do(request)
	if err != nil {
		CaptureError(fmt.Errorf("gateway: JWKS fetch failed: %s: %w", c.url, err), nil)
		return nil, fmt.Errorf("%w: %s did not answer: %w", errKeySetUnavailable, c.url, err)
	}
	defer func() { _ = response.Body.Close() }()

	if response.StatusCode < 200 || response.StatusCode > 299 {
		CaptureError(fmt.Errorf("gateway: JWKS fetch returned %d from %s", response.StatusCode, c.url), nil)
		return nil, fmt.Errorf("%w: %s answered %d", errKeySetUnavailable, c.url, response.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(response.Body, maxJWKSBytes))
	if err != nil {
		return nil, fmt.Errorf("%w: %s: reading the body failed: %w", errKeySetUnavailable, c.url, err)
	}

	var document struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(body, &document); err != nil {
		return nil, fmt.Errorf("%w: %s is not JSON: %w", errKeySetUnavailable, c.url, err)
	}
	if len(document.Keys) == 0 {
		return nil, fmt.Errorf("%w: %s is not a key set — no keys, which is what a login page or an empty array looks like", errKeySetUnavailable, c.url)
	}

	keys := make([]jwk, 0, len(document.Keys))
	for _, raw := range document.Keys {
		key, err := parseJWK(raw)
		if err != nil || key == nil {
			continue
		}
		keys = append(keys, *key)
	}

	if len(keys) == 0 {
		return nil, fmt.Errorf("%w: %s published %d key(s) and none of them is a key this verifier can use", errKeySetUnavailable, c.url, len(document.Keys))
	}

	return keys, nil
}

const maxJWKSBytes = 1 << 20

func publishes(keys []jwk, kid string) bool {
	for _, key := range keys {
		if key.Kid == kid {
			return true
		}
	}
	return false
}

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

func parseJWK(raw json.RawMessage) (*jwk, error) {
	var key jwk
	if err := json.Unmarshal(raw, &key); err != nil {
		return nil, err
	}
	return &key, nil
}

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

const algorithm = "RS256"

// JWKSPath is where identity publishes its keys. Fixed, and appended to the
// issuer, which is why an issuer carrying a path is a configuration error.
const JWKSPath = "/.well-known/jwks.json"

// DefaultIdentityIssuer is what gateway falls back to when nothing is configured.
const DefaultIdentityIssuer = "https://identity.localhost"

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
