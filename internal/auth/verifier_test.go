// The verifier's five properties, one test each, plus the coverage check on the
// list.
//
// The properties are the packet's, not the file's:
//
//  1. the cache has a BOUNDED TTL and refreshes on an unknown `kid`,
//  2. key refresh is SINGLE-FLIGHT,
//  3. only RS256,
//  4. `exp` and `nbf` are verified and there is NO lifetime ceiling,
//  5. identity being unreachable is a `503` and never a `401`.
//
// Each names the mutation that would break it in a comment, because a test that
// does not say what it is holding in place is a test whose deletion nobody notices.
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

	"github.com/cafaye/gateway/internal/testkeys"
)

// A fixture: a served key set, a verifier pointed at it, and a clock a test moves.
type fixture struct {
	keys *testkeys.Fixture
	now  time.Time
	mu   sync.Mutex
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	return &fixture{keys: testkeys.NewFixture(t).Serve(t), now: testkeys.Clock}
}

// failWith makes the key-set endpoint answer a status.
func (f *fixture) failWith(status int) { f.keys.FailWith(status) }

// fetches is how many times the key set has been fetched.
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

// -----------------------------------------------------------------------------
// PROPERTY 1 — a bounded TTL, and a refresh on an unknown `kid`.
//
// The mutation that breaks this: `isFresh` returning `true` unconditionally, or
// `refreshSpentIn` never being compared. Both are one operator each and both are
// silent: the first makes a rotated key unusable until a deploy, the second makes
// every unknown `kid` a fetch.
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

		// One millisecond PAST the TTL, not "well past". A TTL test that jumps a
		// minute proves the window exists; one that jumps a millisecond proves it is
		// the window this configuration named.
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

		// Warm the cache, so the refresh below is on the UNKNOWN-KID path and not on
		// the TTL path. Without this the two properties are indistinguishable and a
		// mutation to either one passes.
		if _, refusal := v.Authenticate(context.Background(), f.keys.Mint(t, testkeys.Claims{ExpiresIn: testkeys.Valid})); refusal != nil {
			t.Fatalf("the warming verification was refused: %+v", refusal)
		}
		if got := f.fetches(); got != 1 {
			t.Fatalf("the warming verification caused %d fetch(es), want 1", got)
		}

		// Identity rotates: a second key appears in the published set under a new
		// `kid`, and gateway's cached set does not carry it.
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

		// And the refreshed set is CACHED: the next request naming the rotated key
		// costs nothing, which is the difference between a refresh and a per-request
		// fetch wearing a refresh's name.
		if _, refusal := v.Authenticate(context.Background(), rotatedToken); refusal != nil {
			t.Fatalf("the second request naming the rotated key was refused: %+v", refusal)
		}
		if got := f.fetches(); got != 2 {
			t.Errorf("the request after the rotation caused %d more fetch(es), want 0 — a cache that refetches every request is not a cache", got-2)
		}
	})

	t.Run("a kid nobody publishes is refused after the refresh finds nothing", func(t *testing.T) {
		// The other half of the rotation case, and the one that is easy to leave
		// untested: the refresh happening and NOT helping has to be a `401` naming
		// the key, not a `503` and not a `200`.
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

// -----------------------------------------------------------------------------
// PROPERTY 2 — single-flight.
//
// The mutation that breaks this: claiming the refresh budget AFTER the fetch
// instead of before, which is precisely the mistake `src/middleware/jwt.ts` (removed at cutover)
// documents — twenty-five requests, twenty-five fetches, aimed at identity, from
// anonymous pre-auth traffic nobody can rate-limit.
//
// The test is the twenty-five. Fewer would not exercise the property: a mutex makes
// ONE fetch out of any number, and a race-detector run with two goroutines can pass
// by scheduling them serially.
func TestKeyRefreshIsSingleFlight(t *testing.T) {
	t.Run("twenty-five requests naming an unknown kid cause one fetch", func(t *testing.T) {
		f := newFixture(t)
		f.now = testkeys.Clock
		v := f.verifier(t)

		// THE WARM-UP IS LOAD-BEARING and it was the first version of this test that
		// got it wrong. A COLD cache makes the first request take the TTL path — one
		// fetch, `fetched: true`, no budget spent — and only the SECOND request reaches
		// the unknown-kid path, so the burst measures 2 fetches and looks like a
		// failure of single-flight when it is a failure of the fixture. Warm, and the
		// only fetch available is the budgeted one.
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
		// Spent means SPENT. Otherwise an unreachable identity is an unlimited fetch
		// allowance for anyone naming a `kid`, which is the amplifier with an outage
		// on top — and an outage is exactly when it would be used.
		f := newFixture(t)
		f.now = testkeys.Clock
		v := f.verifier(t)

		if _, refusal := v.Authenticate(context.Background(), f.keys.Mint(t, testkeys.Claims{ExpiresIn: testkeys.Valid})); refusal != nil {
			t.Fatalf("the warming verification was refused: %+v", refusal)
		}
		before := f.fetches()
		f.failWith(http.StatusInternalServerError)

		forged := f.keys.Mint(t, testkeys.Claims{ExpiresIn: testkeys.Valid, KeyID: "unpublished"})

		// The FIRST request spends the budget and reports the outage. The other four
		// find the budget spent, answer off the CACHED set, and are told the key is
		// unknown — which is false while identity is down, and is `jwt.ts`'s
		// behaviour exactly:
		//
		//     if (!fetched && refreshSpentIn !== window) { … await load(false) … }
		//     if (!publishes(set, header.kid)) return unauthorized("…unknown key");
		//
		// Reported in REPORT-gateway-go-auth-01.md rather than changed, because the
		// packet rules that the TypeScript answer is the correct one and because it is
		// not a security hole: only a token naming a kid the CACHED set does not carry
		// reaches it, and such a token cannot verify while identity is down either
		// way. What it costs is diagnostic: one caller in a window is told identity
		// is unreachable and the rest are told a falsehood.
		for i := 0; i < 5; i++ {
			_, refusal := v.Authenticate(context.Background(), forged)
			if refusal == nil {
				t.Fatalf("request %d against a failing key set was ACCEPTED", i)
			}
			if i == 0 && refusal.Status != http.StatusServiceUnavailable {
				t.Errorf("request 0 against a failing key set was answered %+v, want a 503", refusal)
			}
			if i > 0 && refusal.Detail != "token was signed by an unknown key" {
				t.Errorf("request %d was answered %q. Once the budget is spent the answer comes off the cached set, so this is the reference's behaviour — see the comment above — and the port is holding to it.", i, refusal.Detail)
			}
		}
		if got := f.fetches(); got != before+1 {
			t.Errorf("five requests against a failing key set caused %d fetch(es), want 1 — a failed refresh that is not charged for is an open-endless fetch allowance during an outage", got-before)
		}
	})
}

// TestTheSingleFlightIsTheLockAndNotTheStatementOrder is the answer to a question
// this packet's own mutation run asked.
//
// # WHAT WAS MEASURED
//
// `src/middleware/jwt.ts` (removed at cutover) claims the refresh budget BEFORE its `await` and its
// comment says claiming it after bought twenty-five fetches for twenty-five
// requests. Planting exactly that mutation HERE — moving the assignment below the
// fetch — changes nothing and the suite stays green:
//
//	mutation: refreshSpentIn assigned after load(false) instead of before
//	result:   PASSED. 0 differences. The property was untested.
//
// # WHY, AND IT IS NOT A DEFECT
//
// In TypeScript the ordering IS the mechanism: one event loop, and a statement
// between an `await` and the next caller can be walked straight through by the
// arrival order of a real edge. In Go the mutex is the mechanism — `keysFor` holds
// `c.mu` across the whole of the fetch, so the twenty-four other goroutines are
// blocked in `Lock()` and never reach the assignment at all. The property holds for
// a stronger reason, and reordering the two statements cannot weaken it.
//
// # SO WHY THE TEST
//
// Because a reader who tries that mutation, sees green, and concludes the ordering
// does not matter is right about THIS language and wrong about the property, and
// the next person to arrive with the reference's bug to fix will make the change and
// ship it. This asserts the mechanism instead: the lock is taken before the fresh
// check and released after the last write, so the ordering that matters is the lock's
// and it is in the source rather than in a comment nobody reads.
func TestTheSingleFlightIsTheLockAndNotTheStatementOrder(t *testing.T) {
	source := read(t, "jwks.go")

	// The WINDOW is `keysFor`'s whole body, from its own `func` line to the next one.
	//
	// The first draft of this took the window to be `source[Lock:Unlock]` — and both
	// anchors sit on consecutive lines, because `Lock()` is nine characters shorter
	// than `Unlock()`, so that slice was nineteen bytes long and reported two false
	// failures on correct code. A window that is measured wrong is worse than no
	// window: it looks like a finding.
	from := strings.Index(source, "func (c *jwksCache) keysFor(")
	if from < 0 {
		t.Fatal("jwks.go no longer has a keysFor method. The refresh budget lives in it — see this test's comment — so its absence means the four properties above are about code that has moved.")
	}
	to := strings.Index(source[from+1:], "\nfunc ")
	if to < 0 {
		to = len(source) - from
	}
	body := source[from : from+to]

	// The release is a DEFER, so the window is the `Lock` line to the end of the
	// function and the `defer` has to be the statement right after the `Lock` — that
	// is what makes the release happen at function exit rather than at that line.
	lockAt := strings.Index(body, "c.mu.Lock()")
	if lockAt < 0 {
		t.Fatal("keysFor no longer takes c.mu. The refresh budget is enforced by the lock rather than by statement order — see this test's comment — so an unlocked cache is the herd back.")
	}
	if !strings.Contains(body[lockAt:], "defer c.mu.Unlock()") {
		t.Errorf("keysFor takes c.mu and does not defer its release. A lock released on one path and not another is the wedge this repository has already been bitten by once, in the Redis reader.")
	}
	// Every read and every fetch is AFTER the `Lock`. `load` IS the fetch, so a
	// `load` call above it is a fetch every goroutine naming a `kid` reaches.
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

// -----------------------------------------------------------------------------
// PROPERTY 3 — only RS256.
//
// The mutation that breaks this: reading the algorithm off the token and believing
// it. `alg: none` and `HS256` are the two shapes that matter, and both are
// answered HERE — before any key is fetched — so a test that only checked the
// rejection would not prove the ordering.
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

	// THE ORDERING, and it is the property rather than the rejection. An
	// `alg: none` token costs no network call, so a caller cannot use one to make
	// gateway fetch a key set on demand.
	if got := f.fetches(); got != before {
		t.Errorf("five tokens with a rejected algorithm caused %d fetch(es), want 0 — the header is read before anything is fetched precisely so a forged algorithm cannot make gateway call identity", got-before)
	}
}

// -----------------------------------------------------------------------------
// PROPERTY 4 — `exp` and `nbf` verified, and NO ceiling.
//
// Two halves, and the second is the half that is easy to get wrong by adding.
//
// The mutation that breaks the first half: dropping the `exp` comparison, or
// comparing milliseconds against seconds (jose floors to whole seconds, so a token
// one millisecond past its `exp` IS expired). The mutation that breaks the second:
// adding a `maxTokenAge`. There is no test that catches an ADDED ceiling except one
// that presents a long-lived token and says it is fine — which is the last case here.
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
		// SECONDS, FLOORED. The token says `exp = T`; the verifier's clock reads
		// `T` in seconds plus a fraction, and `exp <= now` already holds. A verifier
		// comparing in milliseconds would find `exp` still in the future here and
		// admit a token identity has revoked by implication.
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
		// Both claims wrong at once. jose checks `nbf` first, so the message is the
		// `nbf` one — and a caller told "has expired" for a token identity has not
		// issued yet has been told something false.
		_, refusal := v.Authenticate(context.Background(), f.keys.Mint(t, testkeys.Claims{
			ExpiresIn: testkeys.Expired,
			NotBefore: time.Hour,
		}))
		if refusal == nil || refusal.Detail != "token claim 'nbf' is not valid" {
			t.Fatalf("a token both expired and not-yet-valid was answered %+v, want the nbf refusal", refusal)
		}
	})

	t.Run("no ceiling: a token good for a year verifies", func(t *testing.T) {
		// core's conventions cap an ACCESS token at fifteen minutes, and whether the
		// edge enforces that or trusts identity to mint short-lived ones is a DECISION
		// NOBODY HAS MADE. It is the README's "Not built yet", and this case is what
		// stops somebody making it by accident while fixing something else.
		//
		// A year, not a day: fifteen minutes is the number in the conventions, so a
		// test with a sixteen-minute token would pass under a ceiling of fifteen
		// minutes and under a ceiling of a month.
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
		// A test presenting a long token proves today's behaviour. This proves there
		// is nothing in the source that could refuse one — which is the property, and
		// it catches a `maxTokenAge` added with its own test.
		source := read(t, "verifier.go")
		for _, forbidden := range []string{"MaxTokenAge", "maxTokenAge", "maxLifetime", "MaxLifetime", "tokenLifetime"} {
			if strings.Contains(source, forbidden) {
				t.Errorf("internal/auth/verifier.go mentions %q. There is no lifetime ceiling at this edge — the README calls it a later decision — so the name appearing here is either the decision being made silently or a variable left over from one.", forbidden)
			}
		}
	})
}

// -----------------------------------------------------------------------------
// PROPERTY 5 — identity being unreachable is a 503, never a 401.
//
// The mutation that breaks this: folding the fetch failure into the unknown-key
// branch. It is the most consequential single line in the file, because a 401 sends
// a caller to rotate a credential that was fine.
func TestAnUnreachableIdentityIsA503AndNeverA401(t *testing.T) {
	t.Run("a fresh cache does not notice an outage, and that is correct", func(t *testing.T) {
		f := newFixture(t)
		v := f.verifier(t)

		if _, refusal := v.Authenticate(context.Background(), f.keys.Mint(t, testkeys.Claims{ExpiresIn: testkeys.Valid})); refusal != nil {
			t.Fatalf("the warming verification was refused: %+v", refusal)
		}
		f.failWith(http.StatusInternalServerError)

		// Five requests, all with a key the CACHED set carries, all answered `200`.
		// This is the property, not a setup step: going to identity to confirm a
		// token the gateway can already answer for would make every request depend on
		// identity's availability for no gain, and it is what the cache is for.
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

		// Warm, so the failure below is the CACHED path and not the first fetch — and
		// then CROSS THE TTL, because a fresh cache never fetches and an outage is
		// therefore invisible to verification until the key set expires.
		//
		// That is the reference's behaviour and it is correct: a gateway holding a fresh
		// key set is holding the answer, and going to identity to confirm would make
		// every request depend on identity's availability for no gain. It is also the
		// reason the TTL is bounded rather than "refresh on every request" — the outage
		// is noticed within one TTL and no sooner.
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

				// The cache must still hold the last good set, so the outage does not
				// become an authentication outage for the length of the TTL.
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

// testchars is the ordinary valid token, as one call. Three call sites want it and
// spelling the claims out three times is three chances to spell one differently.
func testchars() testkeys.Claims { return testkeys.Claims{ExpiresIn: testkeys.Valid} }

// A broken CONFIGURATION is the other direction, and it is the whole asymmetry: the
// same verifier that answers 503 when identity is unreachable refuses to BUILD when
// the operator typed something that does not mean what they meant.
//
// The mutation that breaks this: defaulting a malformed issuer to the default
// issuer. Then `IDENTITY_ISSUER=htp:/identity` is a gateway that verifies against
// the wrong origin and answers 401 for every real token.
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

	// And the one that must be ACCEPTED, because the trailing slash is what an
	// operator types out of habit and keeping it would join into
	// `https://identity.localhost//.well-known/…`.
	v, err := New(Options{Issuer: "https://identity.localhost/", Audience: testkeys.Audience})
	if err != nil {
		t.Fatalf("a trailing slash on the issuer was refused: %v", err)
	}
	if v.keys.url != "https://identity.localhost"+JWKSPath {
		t.Errorf("the JWKS URL is %q, want the issuer's origin plus %q", v.keys.url, JWKSPath)
	}
}

// read reads a file in this package's own directory, so a test can assert on what
// the source SAYS as well as on what it does.
//
// It is here rather than in a shared helper because there is one caller and one file,
// and a helper with one caller is a name for three lines.
func read(t *testing.T, name string) string {
	t.Helper()

	raw, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("cannot read %s: %v", name, err)
	}
	return string(raw)
}
