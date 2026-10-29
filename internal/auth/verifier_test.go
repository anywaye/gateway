package auth

import (
	"context"
	"errors"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/anywaye/gateway/internal/testkeys"
)

type fixture struct {
	keys *testkeys.Fixture
	now  time.Time
	mu   sync.Mutex
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	return &fixture{keys: testkeys.NewFixture(t).Serve(t), now: testkeys.Clock}
}

func (f *fixture) failWith(status int) { f.keys.FailWith(status) }

func (f *fixture) fetches() int { return f.keys.Fetches() }

func (f *fixture) verifier(t *testing.T) *Verifier {
	t.Helper()

	v, err := New(Options{
		Issuer:       testkeys.Issuer,
		Audience:     testkeys.Audience,
		JWKSURL:      f.keys.URL,
		JWKSCacheTTL: 5 * time.Minute,
		Now:          func() time.Time { return f.clock() },
	})
	if err != nil {
		t.Fatalf("New refused a valid configuration: %v", err)
	}
	return v
}

func (f *fixture) clock() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now
}

func (f *fixture) advance(by time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.now = f.now.Add(by)
}

func TestTheKeySetCacheHasABoundedTTLAndRefreshesOnAnUnknownKid(t *testing.T) {
	t.Run("a fresh set is not refetched, and a stale one is", func(t *testing.T) {
		f := newFixture(t)
		f.now = testkeys.Clock
		v := f.verifier(t)

		for i := 0; i < 3; i++ {
			if _, refusal := v.Authenticate(context.Background(), f.keys.Mint(t, testkeys.Claims{ExpiresIn: testkeys.Valid})); refusal != nil {
				t.Fatalf("request %d was refused: %+v", i, refusal)
			}
		}
		if got := f.fetches(); got != 1 {
			t.Fatalf("three verifications inside the TTL caused %d fetch(es), want 1", got)
		}

		f.advance(5*time.Minute + time.Millisecond)
		if _, refusal := v.Authenticate(context.Background(), f.keys.Mint(t, testkeys.Claims{ExpiresIn: testkeys.Valid})); refusal != nil {
			t.Fatalf("a verification after the TTL was refused: %+v", refusal)
		}
		if got := f.fetches(); got != 2 {
			t.Fatalf("a verification past the TTL caused %d fetch(es) in total, want 2 — an unbounded cache is an outage the first time a key rotates", got)
		}
	})

	t.Run("a rotated key is picked up without a redeploy, for one fetch", func(t *testing.T) {
		f := newFixture(t)
		f.now = testkeys.Clock
		v := f.verifier(t)

		if _, refusal := v.Authenticate(context.Background(), f.keys.Mint(t, testkeys.Claims{ExpiresIn: testkeys.Valid})); refusal != nil {
			t.Fatalf("the warming verification was refused: %+v", refusal)
		}
		if got := f.fetches(); got != 1 {
			t.Fatalf("the warming verification caused %d fetch(es), want 1", got)
		}

		rotated := testkeys.NewKey(t)
		const rotatedKID = "test-key-2"
		f.keys.Publish(t, rotatedKID, &rotated.PublicKey)

		rotatedToken := testkeys.MintWith(t, rotated, testkeys.Claims{ExpiresIn: testkeys.Valid, KeyID: rotatedKID})
		principal, refusal := v.Authenticate(context.Background(), rotatedToken)
		if refusal != nil {
			t.Fatalf("a token signed by the newly published key was refused: %+v. The unknown-kid refresh is what makes rotation possible without a redeploy, and this is that property.", refusal)
		}
		if principal.Sub != testkeys.Subject {
			t.Errorf("the principal's sub is %q, want %q", principal.Sub, testkeys.Subject)
		}
		if got := f.fetches(); got != 2 {
			t.Errorf("the rotation caused %d fetch(es), want 1 more than the warm-up. The refresh budget is per WINDOW, so the rotation costs one fetch and every request after it costs none.", got-1)
		}

		if _, refusal := v.Authenticate(context.Background(), rotatedToken); refusal != nil {
			t.Fatalf("the second request naming the rotated key was refused: %+v", refusal)
		}
		if got := f.fetches(); got != 2 {
			t.Errorf("the request after the rotation caused %d more fetch(es), want 0 — a cache that refetches every request is not a cache", got-2)
		}
	})

	t.Run("a kid nobody publishes is refused after the refresh finds nothing", func(t *testing.T) {
		f := newFixture(t)
		f.now = testkeys.Clock
		v := f.verifier(t)

		forged := f.keys.Mint(t, testkeys.Claims{ExpiresIn: testkeys.Valid, KeyID: "nobody-publishes-this"})

		_, refusal := v.Authenticate(context.Background(), forged)
		if refusal == nil {
			t.Fatal("a token signed by a key nobody publishes was ACCEPTED")
		}
		if refusal.Status != http.StatusUnauthorized {
			t.Errorf("the refusal is %d, want 401", refusal.Status)
		}
		if refusal.Detail != "token was signed by an unknown key" {
			t.Errorf("the detail is %q, want %q", refusal.Detail, "token was signed by an unknown key")
		}
	})
}

func TestKeyRefreshIsSingleFlight(t *testing.T) {
	t.Run("twenty-five requests naming an unknown kid cause one fetch", func(t *testing.T) {
		f := newFixture(t)
		f.now = testkeys.Clock
		v := f.verifier(t)

		if _, refusal := v.Authenticate(context.Background(), f.keys.Mint(t, testkeys.Claims{ExpiresIn: testkeys.Valid})); refusal != nil {
			t.Fatalf("the warming verification was refused: %+v", refusal)
		}

		forged := f.keys.Mint(t, testkeys.Claims{ExpiresIn: testkeys.Valid, KeyID: "a-key-identity-does-not-publish"})
		before := f.fetches()
		if before != 1 {
			t.Fatalf("the warm-up caused %d fetch(es), want 1", before)
		}

		const burst = 25
		var wg sync.WaitGroup
		wg.Add(burst)
		start := make(chan struct{})
		refusals := make([]*Refusal, burst)

		for i := range burst {
			go func() {
				defer wg.Done()
				<-start
				_, refusals[i] = v.Authenticate(context.Background(), forged)
			}()
		}
		close(start)
		wg.Wait()

		if got := f.fetches(); got != before+1 {
			t.Errorf("%d concurrent requests naming an unpublished key caused %d fetch(es), want 1. Anonymous pre-auth traffic does not publish, so this is a fetch amplifier aimed at identity and it costs identity nothing to answer.", burst, got-before)
		}
		for i, refusal := range refusals {
			if refusal == nil {
				t.Fatalf("request %d with a forged kid was ACCEPTED", i)
			}
			if refusal.Detail != "token was signed by an unknown key" {
				t.Errorf("request %d was refused with %q, want %q", i, refusal.Detail, "token was signed by an unknown key")
			}
		}
	})

	t.Run("a failed refresh still spends the budget", func(t *testing.T) {
		f := newFixture(t)
		f.now = testkeys.Clock
		v := f.verifier(t)

		if _, refusal := v.Authenticate(context.Background(), f.keys.Mint(t, testkeys.Claims{ExpiresIn: testkeys.Valid})); refusal != nil {
			t.Fatalf("the warming verification was refused: %+v", refusal)
		}
		before := f.fetches()
		f.failWith(http.StatusInternalServerError)

		forged := f.keys.Mint(t, testkeys.Claims{ExpiresIn: testkeys.Valid, KeyID: "unpublished"})

		for i := 0; i < 5; i++ {
			_, refusal := v.Authenticate(context.Background(), forged)
			if refusal == nil {
				t.Fatalf("request %d against a failing key set was ACCEPTED", i)
			}
			if i == 0 && refusal.Status != http.StatusServiceUnavailable {
				t.Errorf("request 0 against a failing key set was answered %+v, want a 503", refusal)
			}
			if i > 0 && refusal.Detail != "token was signed by an unknown key" {
				t.Errorf("request %d was answered %q. Once the budget is spent the answer comes off the cached set, so this is the reference's behavior — see the comment above — and the port is holding to it.", i, refusal.Detail)
			}
		}
		if got := f.fetches(); got != before+1 {
			t.Errorf("five requests against a failing key set caused %d fetch(es), want 1 — a failed refresh that is not charged for is an open-endless fetch allowance during an outage", got-before)
		}
	})
}

func TestTheSingleFlightIsTheLockAndNotTheStatementOrder(t *testing.T) {
	source := read(t, "jwks.go")

	from := strings.Index(source, "func (c *jwksCache) keysFor(")
	if from < 0 {
		t.Fatal("jwks.go no longer has a keysFor method. The refresh budget lives in it — see this test's comment — so its absence means the four properties above are about code that has moved.")
	}
	to := strings.Index(source[from+1:], "\nfunc ")
	if to < 0 {
		to = len(source) - from
	}
	body := source[from : from+to]

	lockAt := strings.Index(body, "c.mu.Lock()")
	if lockAt < 0 {
		t.Fatal("keysFor no longer takes c.mu. The refresh budget is enforced by the lock rather than by statement order — see this test's comment — so an unlocked cache is the herd back.")
	}
	if !strings.Contains(body[lockAt:], "defer c.mu.Unlock()") {
		t.Errorf("keysFor takes c.mu and does not defer its release. A lock released on one path and not another is the wedge this repository has already been bitten by once, in the Redis reader.")
	}
	for _, call := range []string{"c.isFresh()", "c.load(ctx, true)", "c.load(ctx, false)", "c.refreshSpentIn = c.window"} {
		at := strings.Index(body, call)
		switch {
		case at < 0:
			t.Errorf("keysFor no longer calls %s. The cache is smaller than this packet expects; if that is deliberate then the four properties above need re-reading, because each of them is a statement about what this function does.", call)
		case at < lockAt:
			t.Errorf("%s is called before keysFor takes c.mu. Every goroutine naming a `kid` reaches that line, so work outside the lock is work all of them do — and a fetch outside the lock is one fetch per request, which is the amplifier `src/middleware/jwt.ts` (removed at cutover) documents in detail.", call)
		}
	}
}

func TestOnlyRS256IsAccepted(t *testing.T) {
	f := newFixture(t)
	f.now = testkeys.Clock
	v := f.verifier(t)

	before := f.fetches()

	for _, alg := range []string{"none", "HS256", "ES256", "PS256", "rs256"} {
		t.Run(alg, func(t *testing.T) {
			token := f.keys.Mint(t, testkeys.Claims{ExpiresIn: testkeys.Valid, Algorithm: alg})

			_, refusal := v.Authenticate(context.Background(), token)
			if refusal == nil {
				t.Fatalf("a token declaring alg=%q was ACCEPTED", alg)
			}
			if refusal.Status != http.StatusUnauthorized {
				t.Errorf("alg=%q was refused with status %d, want 401", alg, refusal.Status)
			}
			if !strings.Contains(refusal.Detail, "is not accepted") {
				t.Errorf("alg=%q was refused with %q, want a sentence saying the algorithm is not accepted", alg, refusal.Detail)
			}
		})
	}

	if got := f.fetches(); got != before {
		t.Errorf("five tokens with a rejected algorithm caused %d fetch(es), want 0 — the header is read before anything is fetched precisely so a forged algorithm cannot make gateway call identity", got-before)
	}
}

func TestExpiryAndNotBeforeAreVerifiedAndNoLifetimeCeilingExists(t *testing.T) {
	f := newFixture(t)
	f.now = testkeys.Clock
	v := f.verifier(t)

	t.Run("an expired token", func(t *testing.T) {
		_, refusal := v.Authenticate(context.Background(), f.keys.Mint(t, testkeys.Claims{ExpiresIn: testkeys.Expired}))
		if refusal == nil || refusal.Detail != "token has expired" {
			t.Fatalf("an expired token was answered %+v, want 401 token has expired", refusal)
		}
	})

	t.Run("an expired token one millisecond past its exp", func(t *testing.T) {
		expiresAt := testkeys.Clock.Add(time.Second)
		token := f.keys.Mint(t, testkeys.Claims{RawClaims: map[string]any{"exp": expiresAt.Unix()}})

		f.mu.Lock()
		f.now = expiresAt.Add(time.Millisecond)
		f.mu.Unlock()

		_, refusal := v.Authenticate(context.Background(), token)
		if refusal == nil || refusal.Detail != "token has expired" {
			t.Fatalf("a token 1ms past its exp was answered %+v, want 401 token has expired — the comparison is in whole seconds, floored", refusal)
		}

		f.mu.Lock()
		f.now = expiresAt.Add(-time.Millisecond)
		f.mu.Unlock()
		if _, refusal := v.Authenticate(context.Background(), token); refusal != nil {
			t.Fatalf("a token 1ms before its exp was refused: %+v", refusal)
		}
	})

	t.Run("an nbf in the future", func(t *testing.T) {
		_, refusal := v.Authenticate(context.Background(), f.keys.Mint(t, testkeys.Claims{
			ExpiresIn: testkeys.Valid,
			NotBefore: time.Hour,
		}))
		if refusal == nil || refusal.Detail != "token claim 'nbf' is not valid" {
			t.Fatalf("a token not valid for another hour was answered %+v, want 401 naming nbf", refusal)
		}
	})

	t.Run("nbf is checked BEFORE exp", func(t *testing.T) {
		_, refusal := v.Authenticate(context.Background(), f.keys.Mint(t, testkeys.Claims{
			ExpiresIn: testkeys.Expired,
			NotBefore: time.Hour,
		}))
		if refusal == nil || refusal.Detail != "token claim 'nbf' is not valid" {
			t.Fatalf("a token both expired and not-yet-valid was answered %+v, want the nbf refusal", refusal)
		}
	})

	t.Run("no ceiling: a token good for a year verifies", func(t *testing.T) {
		principal, refusal := v.Authenticate(context.Background(), f.keys.Mint(t, testkeys.Claims{
			ExpiresIn: 365 * 24 * time.Hour,
		}))
		if refusal != nil {
			t.Fatalf("a token with a one-year lifetime was refused: %+v. There is no lifetime ceiling: gateway verifies `exp` and `nbf` and enforces no maximum, and a ceiling added here would be someone's decision made by accident.", refusal)
		}
		if principal == nil {
			t.Fatal("a token with a one-year lifetime produced no principal and no refusal")
		}
	})

	t.Run("no ceiling is a property of the code, not of a case", func(t *testing.T) {
		source := read(t, "verifier.go")
		for _, forbidden := range []string{"MaxTokenAge", "maxTokenAge", "maxLifetime", "MaxLifetime", "tokenLifetime"} {
			if strings.Contains(source, forbidden) {
				t.Errorf("internal/auth/verifier.go mentions %q. There is no lifetime ceiling at this edge — the README calls it a later decision — so the name appearing here is either the decision being made silently or a variable left over from one.", forbidden)
			}
		}
	})
}

func TestAnUnreachableIdentityIsA503AndNeverA401(t *testing.T) {
	t.Run("a fresh cache does not notice an outage, and that is correct", func(t *testing.T) {
		f := newFixture(t)
		v := f.verifier(t)

		if _, refusal := v.Authenticate(context.Background(), f.keys.Mint(t, testkeys.Claims{ExpiresIn: testkeys.Valid})); refusal != nil {
			t.Fatalf("the warming verification was refused: %+v", refusal)
		}
		f.failWith(http.StatusInternalServerError)

		for i := 0; i < 5; i++ {
			if _, refusal := v.Authenticate(context.Background(), f.keys.Mint(t, testchars())); refusal != nil {
				t.Fatalf("request %d was refused while the cache was fresh and the token verifiable: %+v", i, refusal)
			}
		}
	})

	t.Run("once a fetch is attempted, an outage is a 503", func(t *testing.T) {
		f := newFixture(t)
		f.now = testkeys.Clock
		v := f.verifier(t)

		if _, refusal := v.Authenticate(context.Background(), f.keys.Mint(t, testkeys.Claims{ExpiresIn: testkeys.Valid})); refusal != nil {
			t.Fatalf("the warming verification was refused: %+v", refusal)
		}

		for _, status := range []int{http.StatusInternalServerError, http.StatusServiceUnavailable, http.StatusNotFound, http.StatusUnauthorized} {
			t.Run(http.StatusText(status), func(t *testing.T) {
				f.failWith(status)
				f.advance(5*time.Minute + time.Millisecond)

				_, refusal := v.Authenticate(context.Background(), f.keys.Mint(t, testkeys.Claims{ExpiresIn: testkeys.Valid}))
				if refusal == nil {
					t.Fatalf("a key set answering %d was answered with a principal once the cache expired", status)
				}
				if refusal.Status != http.StatusServiceUnavailable {
					t.Errorf("a key set answering %d was answered %d, want 503", status, refusal.Status)
				}
				if refusal.Detail != "the signing keys could not be retrieved" {
					t.Errorf("the detail is %q, want the fixed sentence — a jose-shaped message here would quote identity's URL and status to whoever presented the token", refusal.Detail)
				}
				if strings.Contains(refusal.Detail, testkeys.Issuer) || strings.Contains(refusal.Detail, "http") {
					t.Errorf("the 503's detail names an internal fact: %q", refusal.Detail)
				}

				f.advance(-5*time.Minute - time.Millisecond)
				f.keys.Heal()
				if _, refusal := v.Authenticate(context.Background(), f.keys.Mint(t, testchars())); refusal != nil {
					t.Errorf("a token that verified before the outage was refused after it: %+v. The cached set must survive a failed fetch — replacing it with the outage turns a transient identity blip into a total authentication outage.", refusal)
				}
				f.advance(5*time.Minute + time.Millisecond)
			})
		}
	})
}

func testchars() testkeys.Claims { return testkeys.Claims{ExpiresIn: testkeys.Valid} }

func TestABrokenConfigurationIsARefusalToBoot(t *testing.T) {
	for _, issuer := range []string{
		"",
		"   ",
		"identity.localhost",
		"https://",
		"https://identity.localhost/api",
		"ftp://identity.localhost",
		"https://identity.localhost/ with a trailing slash is fine but this is not",
	} {
		t.Run(issuer, func(t *testing.T) {
			_, err := New(Options{Issuer: issuer, Audience: testkeys.Audience})
			if err == nil {
				t.Fatalf("issuer %q was accepted", issuer)
			}
			if !errors.Is(err, ErrNotConfigured) {
				t.Errorf("issuer %q gave %v, which is not ErrNotConfigured — a caller cannot tell its own mistake from a defect in this package", issuer, err)
			}
		})
	}

	v, err := New(Options{Issuer: "https://identity.localhost/", Audience: testkeys.Audience})
	if err != nil {
		t.Fatalf("a trailing slash on the issuer was refused: %v", err)
	}
	if v.keys.url != "https://identity.localhost"+JWKSPath {
		t.Errorf("the JWKS URL is %q, want the issuer's origin plus %q", v.keys.url, JWKSPath)
	}
}

func read(t *testing.T, name string) string {
	t.Helper()

	raw, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("cannot read %s: %v", name, err)
	}
	return string(raw)
}
