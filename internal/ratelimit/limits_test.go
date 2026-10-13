// The limit table, and the rule that decides which entry a path draws on.
//
// `src/middleware/limits.test.ts` (removed at cutover) is the specification for what follows, and its
// cases are ported one for one rather than paraphrased: a per-entry table whose
// tests do not name every entry is a table that can lose one silently, which is
// the whole failure this port exists to close. The Go tree drew every request on
// the default allowance and nothing said so.
//
// # WHAT THESE TESTS ARE FOR, AND THE MUTATION EACH ONE KILLS
//
//   - a per-entry assertion, because "some limit was applied" passes with the
//     table absent, which is the failure the audit found and called silent;
//   - the segment boundary, because getting it wrong in the PERMISSIVE direction
//     is the same class of bug as the missing table;
//   - validation, because a limit of `0` is a startup failure, not a surprise on
//     the first request of the week.
package ratelimit

import (
	"strings"
	"testing"
	"time"
)

// -----------------------------------------------------------------------------
// The shipped table.

func TestTheShippedTableIsWholeAndStrict(t *testing.T) {
	table := DefaultLimitTable()
	entries := append([]Limit{table.Default}, routeLimits(table)...)

	for _, entry := range entries {
		if entry.Limit < 1 {
			t.Errorf("a shipped allowance has limit %d, which is not >= 1", entry.Limit)
		}
		if entry.Window < time.Millisecond {
			t.Errorf("policy %q has window %v, which is under a millisecond", entry.Policy, entry.Window)
		}
		// The shipped names are stricter than the structured-field key they have to
		// be: no `_`, no `.`, no `*`. A shipped name that needed one of those would
		// be a wire-visible decision, and it should not happen by accident.
		if strings.ContainsAny(entry.Policy, "_.*") {
			t.Errorf("policy %q is outside the plain lowercase-hyphen shape the shipped names use", entry.Policy)
		}
		if policy := strings.ToLower(entry.Policy); policy != entry.Policy || policy == "" {
			t.Errorf("policy %q is not a lowercase name", entry.Policy)
		}
	}
}

func TestEveryShippedPrefixIsAPathAndNotAPattern(t *testing.T) {
	for prefix := range DefaultLimitTable().Routes {
		if !strings.HasPrefix(prefix, "/") {
			t.Errorf("prefix %q is not an absolute path", prefix)
		}
		if strings.ContainsAny(prefix, "*?") {
			t.Errorf("prefix %q is a pattern, not a path", prefix)
		}
	}
}

// The shipped table is the contract the README's endpoint table prints, so the
// NAMES and the NUMBERS are both asserted here rather than only through
// `ResolveLimit`. A policy name is half the counter key: renaming one silently
// gives every caller a fresh allowance on every deployment, which is a much nicer
// way to lose a rate limit than to widen it.
func TestTheShippedTableIsTheOneTheReferenceShips(t *testing.T) {
	for _, tc := range []struct {
		prefix string
		policy string
		limit  int
		window time.Duration
	}{
		{"/auth/", "gateway-auth", 60, minute},
		{"/auth/login", "gateway-auth-login", 10, minute},
		{"/auth/register", "gateway-auth-register", 5, minute},
		{"/auth/logout", "gateway-auth-logout", 30, minute},
		{"/v1/", "gateway-api", 600, minute},
		{"/v1/api-keys", "gateway-api-keys", 60, minute},
	} {
		t.Run(tc.prefix, func(t *testing.T) {
			entry, ok := DefaultLimitTable().Routes[tc.prefix]
			if !ok {
				t.Fatalf("the shipped table has no entry for %q", tc.prefix)
			}
			if entry.Policy != tc.policy {
				t.Errorf("policy for %q is %q, want %q", tc.prefix, entry.Policy, tc.policy)
			}
			if entry.Limit != tc.limit {
				t.Errorf("limit for %q is %d, want %d", tc.prefix, entry.Limit, tc.limit)
			}
			if entry.Window != tc.window {
				t.Errorf("window for %q is %v, want %v", tc.prefix, entry.Window, tc.window)
			}
		})
	}

	if got := DefaultLimitTable().Default; got.Limit != 600 || got.Window != minute || got.Policy != "gateway-api" {
		t.Errorf("the default row is %+v, want 600/min under gateway-api", got)
	}
}

func TestNoTwoShippedPrefixesAreTheSameString(t *testing.T) {
	// Not a compile error in Go: `Routes` is a map, so two literals spelling the
	// same key are one entry and the second is gone. That is why it is asserted.
	routes := DefaultLimitTable().Routes
	if len(routes) != 6 {
		t.Errorf("the shipped table has %d route entries, want 6", len(routes))
	}
}

// The default row is the limiter's own fallback, and one number in one place is
// the point: a `DefaultLimitTable` that restated 600 while `NewLimiter` defaulted
// to something else would answer the same path two different ways depending on
// which entry matched it.
func TestTheDefaultRowIsTheLimitersOwnDefault(t *testing.T) {
	entry := DefaultLimitTable().Default

	if entry.Limit != DefaultLimit {
		t.Errorf("the table's default limit is %d, DefaultLimit is %d", entry.Limit, DefaultLimit)
	}
	if entry.Window != DefaultWindow {
		t.Errorf("the table's default window is %v, DefaultWindow is %v", entry.Window, DefaultWindow)
	}
	if entry.Policy != DefaultPolicy {
		t.Errorf("the table's default policy is %q, DefaultPolicy is %q", entry.Policy, DefaultPolicy)
	}
}

// Two calls, two tables. An exported package-level map would be mutable by every
// package in the program, and a caller that inserted a route into the shipped table
// would change the allowance of the next gateway built in the same process.
func TestTheShippedTableIsNotSharedBetweenCallers(t *testing.T) {
	first := DefaultLimitTable()
	first.Routes["/v1/injected"] = Limit{Limit: 1, Window: minute, Policy: "injected"}

	if _, ok := DefaultLimitTable().Routes["/v1/injected"]; ok {
		t.Error("a route inserted into one caller's table appeared in another's")
	}
}

// -----------------------------------------------------------------------------
// ResolveLimit — one assertion per shipped entry.

func TestLoginIsTheStrictestThingGatewayServes(t *testing.T) {
	limit := ResolveLimit(DefaultLimitTable(), "/auth/login")

	if limit.Policy != "gateway-auth-login" {
		t.Errorf("policy is %q, want gateway-auth-login", limit.Policy)
	}
	if limit.Limit != 10 {
		t.Errorf("limit is %d, want 10", limit.Limit)
	}
	if limit.Window != 60_000*time.Millisecond {
		t.Errorf("window is %v, want 60s", limit.Window)
	}
}

func TestRegisterIsStrictInItsOwnRightNotTheLoginBudget(t *testing.T) {
	limit := ResolveLimit(DefaultLimitTable(), "/auth/register")

	if limit.Policy != "gateway-auth-register" {
		t.Errorf("policy is %q, want gateway-auth-register", limit.Policy)
	}
	if limit.Limit != 5 {
		t.Errorf("limit is %d, want 5", limit.Limit)
	}
}

func TestBruteForcingALoginDoesNotSpendTheRegistrationAllowance(t *testing.T) {
	// Same prefix family, different policy — so a separate bucket. A shared one
	// would let a caller who has exhausted registration also lock out every
	// legitimate sign-up from that address, which is the whole reason these are two
	// entries and not two numbers under `gateway-auth`.
	table := DefaultLimitTable()

	if ResolveLimit(table, "/auth/login").Policy == ResolveLimit(table, "/auth/register").Policy {
		t.Error("login and register share a policy, so exhausting one spends the other")
	}
}

func TestLogoutHasItsOwnBucket(t *testing.T) {
	if got := ResolveLimit(DefaultLimitTable(), "/auth/logout").Policy; got != "gateway-auth-logout" {
		t.Errorf("policy is %q, want gateway-auth-logout", got)
	}
}

func TestAnyOtherAuthRouteFallsBackToTheAuthAdjacentDefault(t *testing.T) {
	if got := ResolveLimit(DefaultLimitTable(), "/auth/me").Policy; got != "gateway-auth" {
		t.Errorf("policy is %q, want gateway-auth", got)
	}
}

func TestV1UsesTheGeneralAPIAllowance(t *testing.T) {
	limit := ResolveLimit(DefaultLimitTable(), "/v1/me")

	if limit.Policy != "gateway-api" {
		t.Errorf("policy is %q, want gateway-api", limit.Policy)
	}
	if limit.Limit != 600 {
		t.Errorf("limit is %d, want 600", limit.Limit)
	}
	if limit.Window != 60*time.Second {
		t.Errorf("window is %v, want 60s", limit.Window)
	}
}

func TestV1APIKeysIsItsOwnTighterSurface(t *testing.T) {
	limit := ResolveLimit(DefaultLimitTable(), "/v1/api-keys")

	if limit.Policy != "gateway-api-keys" {
		t.Errorf("policy is %q, want gateway-api-keys", limit.Policy)
	}
	if limit.Limit != 60 {
		t.Errorf("limit is %d, want 60", limit.Limit)
	}
}

func TestAnythingUnrecognisedFallsBackToTheDefault(t *testing.T) {
	table := DefaultLimitTable()

	for _, path := range []string{"/", "/v2/anything", "/healthz", "/auth"} {
		if got := ResolveLimit(table, path); got != table.Default {
			t.Errorf("%q resolved to %+v, want the default %+v", path, got, table.Default)
		}
	}
}

// -----------------------------------------------------------------------------
// ResolveLimit — the segment boundary.
//
// THE DIRECTION OF THE ERROR IS THE POINT. A prefix that matches too eagerly gives
// `/v1alpha` the `/v1` allowance, so a new top-level route inherits a budget by
// sharing a name with an old one — which is exactly how a table that looks right
// keeps being right until a route lands that it is not.
func TestAPrefixMustEndAtAPathSegmentBoundary(t *testing.T) {
	table := DefaultLimitTable()

	// `/auth/loginfoo` shares a NAME with `/auth/logout` and is not under it. It
	// lands on `/auth/` — the auth-adjacent entry — and not on the 30/min logout
	// budget and not on the default.
	limit := ResolveLimit(table, "/auth/loginfoo")
	if limit.Policy != "gateway-auth" {
		t.Errorf("/auth/loginfoo resolved to %q, want gateway-auth", limit.Policy)
	}

	if got := ResolveLimit(table, "/v1alpha/thing"); got.Policy != DefaultPolicy {
		t.Errorf("/v1alpha/thing resolved to %q, want the default", got.Policy)
	}
	if got := ResolveLimit(table, "/v1/apikeys"); got.Policy != DefaultPolicy {
		t.Errorf("/v1/apikeys resolved to %q, want the default", got.Policy)
	}
}

// A SUBDIAGONAL PATH IS STILL UNDER ITS PREFIX, and this is the reference's
// behavior rather than a reading of it.
//
// The packet for this port asked for a test that `/auth/login/extra` does NOT
// match the `/auth/login` entry. It does match, and porting that is correct: the
// reference's `claims` accepts `path === prefix || path.startsWith(prefix + "/")`,
// and its own table test asserts the same shape (`/v1/deep/thing` resolves to
// `deep`, not to `api`). Inverting it here would make the Go gateway draw a
// different allowance from the service it is meant to replace, on exactly the
// surface this packet exists to tighten — and a subpath under `/auth/login` is
// login work whatever it is named.
func TestASubpathUnderAPrefixDrawsThatPrefix(t *testing.T) {
	table := DefaultLimitTable()

	limit := ResolveLimit(table, "/auth/login/extra")
	if limit.Policy != "gateway-auth-login" {
		t.Errorf("/auth/login/extra resolved to %q, want gateway-auth-login", limit.Policy)
	}
	if limit.Limit != 10 {
		t.Errorf("/auth/login/extra drew a limit of %d, want 10", limit.Limit)
	}
}

// -----------------------------------------------------------------------------
// ResolveLimit — the matching rule, on a table chosen to make the rule visible.

func testTable() LimitTable {
	return LimitTable{
		Default: Limit{Limit: 100, Window: time.Second, Policy: "default"},
		Routes: map[string]Limit{
			"/":         {Limit: 1, Window: time.Second, Policy: "root"},
			"/v1/":      {Limit: 2, Window: time.Second, Policy: "api"},
			"/v1/deep/": {Limit: 3, Window: time.Second, Policy: "deep"},
		},
	}
}

func TestTheLongestMatchingPrefixWins(t *testing.T) {
	table := testTable()

	for _, tc := range []struct{ path, want string }{
		{"/v1/deep/thing", "deep"},
		{"/v1/thing", "api"},
		{"/other", "default"},
	} {
		if got := ResolveLimit(table, tc.path).Policy; got != tc.want {
			t.Errorf("%q resolved to %q, want %q", tc.path, got, tc.want)
		}
	}
}

// A Go map iterates in no order at all, so the reference's "the choice does not
// depend on the order the entries were written in" is structural here rather than
// testable. What is NOT structural is that the LONGER prefix wins, which is the
// property the order-independence was protecting — so `/v1/deep/` is asserted to
// beat `/v1/` above, and this case pins the tie: two prefixes of equal length
// cannot both claim a path, and one of them is chosen.
func TestTwoPrefixesOfEqualLengthCannotBothClaimAPath(t *testing.T) {
	table := LimitTable{
		Default: Limit{Limit: 100, Window: time.Second, Policy: "default"},
		Routes: map[string]Limit{
			"/v1/aaa": {Limit: 1, Window: time.Second, Policy: "left"},
			"/v1/bbb": {Limit: 2, Window: time.Second, Policy: "right"},
		},
	}

	for i := 0; i < 32; i++ {
		got := ResolveLimit(table, "/v1/aaa/x").Policy
		if got != "left" && got != "right" {
			t.Fatalf("/v1/aaa/x resolved to %q, want one of the two entries", got)
		}
		if got := ResolveLimit(table, "/v1/aaa").Policy; got != "left" {
			t.Fatalf("/v1/aaa resolved to %q, want the entry whose prefix equals it", got)
		}
	}
}

func TestDefaultIsTheFallbackAndRootDoesNotTakeThatJobAway(t *testing.T) {
	// A `/` entry in `routes` is an ordinary prefix: it claims the root path and
	// nothing else. Making it a catch-all would leave `Default` unreachable, and an
	// operator who lowered `Default` to stop something would find it doing nothing
	// at all.
	table := testTable()

	if got := ResolveLimit(table, "/").Policy; got != "root" {
		t.Errorf("/ resolved to %q, want root", got)
	}
	if got := ResolveLimit(table, "/anything/at/all").Policy; got != "default" {
		t.Errorf("/anything/at/all resolved to %q, want default", got)
	}
}

func TestAQueryStringDoesNotChangeWhichEntryApplies(t *testing.T) {
	table := testTable()

	for _, path := range []string{"/v1/thing?limit=1000", "/v1/thing#fragment", "/v1/thing?a=b#c"} {
		if got := ResolveLimit(table, path).Policy; got != "api" {
			t.Errorf("%q resolved to %q, want api", path, got)
		}
	}
}

func TestAnEmptyTableIsTheDefaultAndDoesNotFail(t *testing.T) {
	table := LimitTable{Default: Limit{Limit: 1, Window: time.Millisecond, Policy: "only"}}

	if got := ResolveLimit(table, "/anything"); got.Policy != "only" {
		t.Errorf("resolved to %q, want only", got.Policy)
	}
	// A nil map is the empty table. Reading it is fine; only writing to it is not,
	// which is why `ValidateLimitTable` always hands back a non-nil map.
	if _, ok := table.Routes["/anything"]; ok {
		t.Error("a nil map returned an entry")
	}
}

// -----------------------------------------------------------------------------
// Validation.
//
// `limitTable()` throws a `RangeError` in the reference. Go returns an error, and
// the tests assert the error is wrapped in `ErrNotConfigured` — the sentinel a
// caller uses to tell its own operator's mistake from a defect in this package.

func TestValidationAcceptsTheShippedTable(t *testing.T) {
	checked, err := ValidateLimitTable(DefaultLimitTable())
	if err != nil {
		t.Fatalf("the shipped table was refused: %v", err)
	}
	if len(checked.Routes) != len(DefaultLimitTable().Routes) {
		t.Errorf("validation returned %d entries, want %d", len(checked.Routes), len(DefaultLimitTable().Routes))
	}
	if got := ResolveLimit(checked, "/auth/login"); got.Policy != "gateway-auth-login" || got.Limit != 10 {
		t.Errorf("the validated table resolves /auth/login to %+v", got)
	}
}

func TestValidationRefusesABadNumberOrName(t *testing.T) {
	for _, tc := range []struct {
		name  string
		table LimitTable
		want  string
	}{
		{
			name:  "a zero limit on the default row",
			table: LimitTable{Default: Limit{Limit: 0, Window: time.Second, Policy: "default"}},
			want:  "default.limit",
		},
		{
			name:  "a negative limit",
			table: LimitTable{Default: Limit{Limit: -1, Window: time.Second, Policy: "default"}},
			want:  "default.limit",
		},
		{
			name:  "a zero window",
			table: LimitTable{Default: Limit{Limit: 1, Window: 0, Policy: "default"}},
			want:  "default.windowMs",
		},
		{
			name:  "a window under a millisecond",
			table: LimitTable{Default: Limit{Limit: 1, Window: time.Microsecond, Policy: "default"}},
			want:  "default.windowMs",
		},
		{
			name:  "an empty policy name",
			table: LimitTable{Default: Limit{Limit: 1, Window: time.Second, Policy: ""}},
			want:  "default.policy",
		},
		{
			name:  "a policy name with a space, which is the one that would inject a header field",
			table: LimitTable{Default: Limit{Limit: 1, Window: time.Second, Policy: `gw"api;q=1`}},
			want:  "default.policy",
		},
		{
			name: "a bad entry on a route, not just the default",
			table: LimitTable{
				Default: Limit{Limit: 1, Window: time.Second, Policy: "default"},
				Routes:  map[string]Limit{"/v1/": {Limit: 0, Window: time.Second, Policy: "api"}},
			},
			want: "/v1/.limit",
		},
		{
			name: "a policy name too long to serialize",
			table: LimitTable{
				Default: Limit{Limit: 1, Window: time.Second, Policy: "default"},
				Routes:  map[string]Limit{"/v1/": {Limit: 1, Window: time.Second, Policy: strings.Repeat("a", 65)}},
			},
			want: "/v1/.policy",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ValidateLimitTable(tc.table)
			if err == nil {
				t.Fatalf("the table was accepted, and it should not have been")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("the message does not name %q: %v", tc.want, err)
			}
			if !strings.Contains(err.Error(), ErrNotConfigured.Error()) {
				t.Errorf("the error is not wrapped in ErrNotConfigured: %v", err)
			}
		})
	}
}

func TestValidationRefusesAPrefixThatIsAPattern(t *testing.T) {
	for _, prefix := range []string{"auth/login", "/auth/*", "/auth/log?", ""} {
		table := LimitTable{
			Default: Limit{Limit: 1, Window: time.Second, Policy: "default"},
			Routes:  map[string]Limit{prefix: {Limit: 1, Window: time.Second, Policy: "p"}},
		}

		_, err := ValidateLimitTable(table)
		if err == nil {
			t.Errorf("prefix %q was accepted, and a pattern is a second matching language", prefix)
			continue
		}
		if !strings.Contains(err.Error(), "limitTable: route prefixes") {
			t.Errorf("prefix %q: the message does not say what is wrong: %v", prefix, err)
		}
	}
}

// A table an operator is allowed to build: a prefix outside `/v1` is refused by
// `internal/httpapi`'s route table because a pass-through could never reach it.
// Here it is FINE, because `/auth/` is the entry doing the most work on the most
// attacked surface. The two `checkPrefix` functions are deliberately not one
// function, and this is the case that would break if they were merged the other
// way round.
func TestValidationAcceptsAPrefixOutsideTheV1Surface(t *testing.T) {
	table := LimitTable{
		Default: Limit{Limit: 1, Window: time.Second, Policy: "default"},
		Routes:  map[string]Limit{"/auth/": {Limit: 60, Window: time.Minute, Policy: "gateway-auth"}},
	}

	if _, err := ValidateLimitTable(table); err != nil {
		t.Errorf("/auth/ was refused by the limit table's prefix rule: %v", err)
	}
}

// The validated table is a COPY. Validating in place would hand back the map the
// caller passed in, so a later insert would skip the check above — the same
// half-validated table the validator exists to prevent.
func TestValidationReturnsACopyRatherThanTheCallersMap(t *testing.T) {
	original := LimitTable{
		Default: Limit{Limit: 1, Window: time.Second, Policy: "default"},
		Routes:  map[string]Limit{"/v1/": {Limit: 600, Window: time.Minute, Policy: "gateway-api"}},
	}
	checked, err := ValidateLimitTable(original)
	if err != nil {
		t.Fatalf("validation failed: %v", err)
	}

	checked.Routes["/v1/injected"] = Limit{Limit: 1, Window: time.Millisecond, Policy: "injected"}
	if _, ok := original.Routes["/v1/injected"]; ok {
		t.Error("an insert into the returned table reached the caller's map")
	}

	// And the empty table still returns a writable map, so a caller adding its own
	// entries does not have to check for nil first.
	empty, err := ValidateLimitTable(LimitTable{Default: Limit{Limit: 1, Window: time.Second, Policy: "only"}})
	if err != nil {
		t.Fatalf("validating an empty table failed: %v", err)
	}
	if empty.Routes == nil {
		t.Error("an empty table validated to a nil map; writing to it would panic")
	}
}

// -----------------------------------------------------------------------------
// PolicyResolver — the table as the two hooks the limiter wants.
//
// The limiter reads a NAME and then the NUMBERS behind it, in two steps, so a table
// keyed by PREFIX has to be indexed by name. That index is `PolicyResolver`, and it
// is what `internal/httpapi/runtime.go` hands to `Options.Policy` and
// `Options.Resolve`.

func TestTheResolverGivesTheLimiterANameAndTheNumbersBehindIt(t *testing.T) {
	policy, resolve, err := PolicyResolver(DefaultLimitTable())
	if err != nil {
		t.Fatalf("the shipped table was refused: %v", err)
	}

	for _, tc := range []struct {
		path   string
		policy string
		limit  int
		window time.Duration
	}{
		{"/auth/login", "gateway-auth-login", 10, minute},
		{"/auth/register", "gateway-auth-register", 5, minute},
		{"/auth/logout", "gateway-auth-logout", 30, minute},
		{"/auth/me", "gateway-auth", 60, minute},
		{"/v1/me", "gateway-api", 600, minute},
		{"/v1/api-keys", "gateway-api-keys", 60, minute},
		{"/nowhere", "gateway-api", 600, minute},
	} {
		t.Run(tc.path, func(t *testing.T) {
			name := policy(tc.path)
			if name != tc.policy {
				t.Fatalf("%q drew policy %q, want %q", tc.path, name, tc.policy)
			}

			limit, window, ok := resolve(name)
			if !ok {
				t.Fatalf("the resolver does not carry %q, so the limiter would fall back to its constructor allowance", name)
			}
			if limit != tc.limit {
				t.Errorf("%q resolved to limit %d, want %d", name, limit, tc.limit)
			}
			if window != tc.window {
				t.Errorf("%q resolved to window %v, want %v", name, window, tc.window)
			}
		})
	}
}

// The fallback is FALLIBLE, and that is the point.
//
// A name the index does not carry answers `false`, and `Limiter.allow` then uses its
// constructor allowance. This is the reference's documented behavior rather than a
// convenience: a typo in a table costs the default allowance and nothing else, which
// is a failure a gateway mid-cutover can absorb.
func TestANameTheTableDoesNotCarryIsNotResolved(t *testing.T) {
	_, resolve, err := PolicyResolver(DefaultLimitTable())
	if err != nil {
		t.Fatalf("the shipped table was refused: %v", err)
	}

	for _, name := range []string{"", "gateway-auth-lgoin", "Gateway-Api", "gateway-api-keys "} {
		if limit, window, ok := resolve(name); ok {
			t.Errorf("%q resolved to %d/%v, want not resolved so the limiter falls back", name, limit, window)
		}
	}
}

// A NAME CLAIMED TWICE WITH DIFFERENT NUMBERS IS REFUSED.
//
// The reference's `byPolicy` is a `Map` written default-first and then routes in
// insertion order, so the last write wins — silently, and in a language where that
// order exists. A Go map has no insertion order, so the same loop would pick per
// iteration and a request could draw `q=5` on one call and `q=60` on the next.
//
// The port refuses rather than arbitrates, because the reference's own model says
// sharing a name means sharing an allowance: `limits.ts` says it twice, and it is
// why `/auth/login` and `/auth/register` are separate policies. Two entries sharing a
// name while disagreeing about the numbers are a table that contradicts itself, and
// a startup failure is the only answer that does not depend on iteration order.
func TestTwoEntriesSharingANameMustAgreeOnTheirNumbers(t *testing.T) {
	table := LimitTable{
		Default: Limit{Limit: 100, Window: time.Second, Policy: "shared"},
		Routes: map[string]Limit{
			"/v1/":     {Limit: 5, Window: time.Second, Policy: "shared"},
			"/v1/lens": {Limit: 60, Window: time.Second, Policy: "shared"},
		},
	}

	_, _, err := PolicyResolver(table)
	if err == nil {
		t.Fatal("a table with one name carrying two sets of numbers was accepted; which one a request draws would be a map's iteration order")
	}
	if !strings.Contains(err.Error(), "shared") {
		t.Errorf("the message does not name the policy: %v", err)
	}
	if !strings.Contains(err.Error(), ErrNotConfigured.Error()) {
		t.Errorf("the error is not wrapped in ErrNotConfigured: %v", err)
	}
}

// The shipped `/v1/` row REUSES the default's policy name with the default's
// numbers, and that has to keep working: it is the case where sharing a name is the
// model working rather than a contradiction.
func TestARouteReusingTheDefaultsNameWithTheSameNumbersIsAccepted(t *testing.T) {
	table := DefaultLimitTable()
	fallback := table.Default

	entry, ok := table.Routes["/v1/"]
	if !ok {
		t.Fatal("the shipped table has no /v1/ row")
	}
	if entry.Policy != fallback.Policy || entry.Limit != fallback.Limit || entry.Window != fallback.Window {
		t.Fatalf("/v1/ is %+v and the default row is %+v; this test is asserting the shipped table reuses the name with the same numbers", entry, fallback)
	}

	if _, _, err := PolicyResolver(table); err != nil {
		t.Errorf("the shipped table was refused: %v", err)
	}
}

// routeEntries is the shipped table's entries as a slice, so a table-wide property
// can be asserted over the default row and the routes together.
func routeLimits(table LimitTable) []Limit {
	entries := make([]Limit, 0, len(table.Routes))
	for _, entry := range table.Routes {
		entries = append(entries, entry)
	}
	return entries
}
