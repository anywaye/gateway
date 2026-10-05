// Which allowance a route draws on, in configuration rather than in code.
//
// The port of `src/middleware/limits.ts`, which is the specification: the table
// contents, the policy names, the longest-prefix-on-a-segment-boundary resolution
// and the validation are reproduced rather than redesigned, because the policy
// name is announced in `RateLimit-Policy` and is half the counter key. A limit
// that changes here is a wire-visible change and a change of which bucket a caller
// spends, not a refactor.
//
// A gateway that gives one number to every route cannot be strict where strictness
// is what stops an attack and generous where generosity is what a client needs.
// Without this table the Go gateway drew every request on `DefaultLimit` — 600/min
// on `/auth/login`, which is supposed to be the scarcest thing the edge serves.
//
// # WHY THE TABLE IS NOT IN internal/httpapi
//
// The route table is there, and this is not, and the difference is the direction
// of the dependency. `internal/httpapi` imports `internal/ratelimit`, never the
// reverse, so the table that decides a limiter's numbers belongs beside the limiter
// that spends them. `internal/httpapi/table.go` holds a *different* table — which
// upstream a path is forwarded to — and the two agree on the matching rule by
// being the same rule, deliberately not the same code. See `claims`.
package ratelimit

import (
	"fmt"
	"strings"
	"time"
)

// Limit is one allowance: how many requests, over how long, under what name.
type Limit struct {
	// Requests per window. An integer >= 1.
	Limit int

	// Window length. One millisecond at minimum, which is `NewLimiter`'s floor and
	// the reference's `assertPositiveInteger` on `windowMs`: an interval that
	// truncates to zero is a division by zero on every request.
	Window time.Duration

	// The name in `RateLimit-Policy` and `RateLimit`, and half the counter key.
	// Constrained to a structured-field key (RFC 9651 §3.1.1.3) because it is
	// written into a response header verbatim. `assertStructuredKey` is the check,
	// and it is shared with the limiter's own rather than reimplemented.
	Policy string
}

// LimitTable is a table of allowances: what a path no entry claims gets, and what
// the entries claim.
//
// `Routes` is a map and not a slice because the reference's `routes` is a keyed
// object and the resolution rule is defined over the KEYS — two entries sharing a
// prefix is a table that silently lost one, so `ValidateLimitTable` cannot
// express the duplicate as a compile error the way a slice literal could. The
// shipped table is checked for that case in `limits_test.go` instead, against the
// actual table, which is where the property is worth anything.
type LimitTable struct {
	// What a path no entry claims gets. Always consulted, never optional — an
	// empty zero `Limit` here is refused by `ValidateLimitTable` rather than
	// answering every request with an allowance of zero.
	Default Limit

	// Path prefix -> allowance. Longest matching prefix wins. A nil map is a valid
	// value: a gateway with one allowance everywhere has an empty table, so that a
	// table that has been half-read is a validation error instead of a silent
	// "everything falls back to the default".
	Routes map[string]Limit
}

// minute is the unit every shipped entry is expressed in.
const minute = 60 * time.Second

// DefaultLimitTable is what gateway ships with.
//
// # THE NUMBERS ARE A STARTING POINT, NOT A MEASUREMENT
//
// Nothing in this repository has watched a real caller. They are chosen so the
// ordering is defensible on its face — a password attempt is the scarcest thing a
// public edge serves, an authenticated API call is not.
//
// Every shipped window is `minute`, and that is what the reference ships, checked
// per entry rather than assumed. The field is still PER ENTRY rather than one
// global window, because a table whose window lived elsewhere could not express an
// entry with a different one, and a table that cannot express one quietly gives it
// the default anyway.
//
// A FUNCTION rather than a package-level `var`, and Go makes this sharper than
// TypeScript did. `export const DEFAULT_LIMIT_TABLE` in the reference is frozen by
// the type system; the Go spelling of that is an exported map, and an exported map
// is mutable by every package in the program. A caller that inserted a route into
// the shipped table would change the allowance of the next gateway built in the
// same process — so each call returns its own map and the table is a value.
//
// `DefaultLimit`, `DefaultWindow` and `DefaultPolicy` from `limiter.go` are the
// default ROW rather than constants restated here, so the number the limiter falls
// back to and the number the table falls back to cannot drift apart.
func DefaultLimitTable() LimitTable {
	return LimitTable{
		Default: Limit{Limit: DefaultLimit, Window: DefaultWindow, Policy: DefaultPolicy},
		Routes: map[string]Limit{
			// Auth-adjacent, and stricter than the API default: a login is guessable
			// work, and the per-minute allowance is what makes guessing slow.
			"/auth/":         {Limit: 60, Window: minute, Policy: "gateway-auth"},
			"/auth/login":    {Limit: 10, Window: minute, Policy: "gateway-auth-login"},
			"/auth/register": {Limit: 5, Window: minute, Policy: "gateway-auth-register"},
			"/auth/logout":   {Limit: 30, Window: minute, Policy: "gateway-auth-logout"},
			"/v1/":           {Limit: 600, Window: minute, Policy: "gateway-api"},
			// Minting and revoking credentials is a write on the security surface, so
			// it gets its own budget rather than the general API's.
			//
			// # 60, NOT 600. THAT NUMBER WAS CHECKED, AND IT STAYS.
			//
			// A port that copies a table is how a wrong number survives a rewrite
			// twice, so here is the record of the one that looks wrong.
			// `REPORT-gateway-api-keys-01.md` §1 has the long form; the short form is
			// the shape of the table.
			//
			// **Every entry in this table that names a NEW bucket is strictly cheaper
			// than the bucket it inherits.** `/auth/register` 5, `/auth/login` 10 and
			// `/auth/logout` 30 each sit under `/auth/`'s 60, which itself sits under
			// the default's 600. The one entry that is not cheaper than what it
			// inherits is `/v1/` — and it is not cheaper because it is not a new
			// bucket: it reuses the default's own `gateway-api` name at the default's
			// own 600. It is the same row written twice.
			//
			// So a nested entry has exactly one way to add itself here, and this is
			// the only entry on the `/v1` side that uses it. A digit dropped off a
			// `600` would not land on a number that is BOTH tighter than its parent
			// AND equal to the one number the table already spends on "a named
			// security surface". That is the outcome of a decision, and the direction
			// is the half the decision is about.
			//
			// What the endpoint does agrees. `/auth/login` is 10 because a password is
			// guessable work; a machine credential is 32 CSPRNG bytes, so there is
			// nothing to guess. It is not cheap to leak either — it works until
			// somebody revokes it, and a holder may never look — so it belongs between
			// guessable work and ordinary API traffic, which is where 60 already is.
			//
			// **THE NAME IS THE LOAD-BEARING HALF, NOT THE NUMBER.** The name is half
			// the counter key, so this row is what stops a caller spending its
			// credential-minting allowance on ordinary API traffic. The number bounds
			// how fast one compromised session fans out into standing credentials,
			// and the header on `DefaultLimitTable` already calls these a starting
			// point rather than a measurement.
			//
			// Worth knowing before editing the 60: the reference's own suite pins only
			// the POLICY NAME for this row — `limits.test.ts` asserts
			// `gateway-api-keys` and no number, while it does pin 10, 5 and 600 for
			// its neighbours. The three Go assertions over this number
			// (`limits_test.go` twice, `internal/httpapi/runtime_limits_test.go` once,
			// the last of them through the whole HTTP stack) are therefore the only
			// thing in either tree holding it, and this comment is why they say 60.
			"/v1/api-keys": {Limit: 60, Window: minute, Policy: "gateway-api-keys"},
		},
	}
}

// ValidateLimitTable is a table, checked.
//
// Every number and every policy name is checked here, at construction, because a
// limit of `0` or a policy name that cannot be serialised into a header is a
// startup failure and not a surprise on the first request of the week. Nothing is
// validated on the request path: `ResolveLimit` is called on every request and
// must stay a map scan.
//
// This is the reference's `limitTable()`, which throws a `RangeError`. The Go
// convention is a returned error, and it is wrapped in `ErrNotConfigured` for the
// reason `NewLimiter` wraps its refusals in the same sentinel: a caller can tell
// its own operator's mistake from a defect in this package. The reference's
// `RangeError` has no Go equivalent that carries the same job — a panic would be
// the literal translation, and a panic on configuration is worse than an error
// because it takes the process down instead of the boot.
//
// The returned table is a COPY. Validating a map in place and returning it would
// hand the caller back the map it passed in, so a later insert would skip the
// check above — the same half-validated table this function exists to prevent.
func ValidateLimitTable(table LimitTable) (LimitTable, error) {
	checked := LimitTable{}

	fallback, err := checkLimit(table.Default, "default")
	if err != nil {
		return LimitTable{}, err
	}
	checked.Default = fallback

	checked.Routes = make(map[string]Limit, len(table.Routes))
	for prefix, entry := range table.Routes {
		if err := checkPrefix(prefix); err != nil {
			return LimitTable{}, err
		}
		allow, err := checkLimit(entry, prefix)
		if err != nil {
			return LimitTable{}, err
		}
		checked.Routes[prefix] = allow
	}

	return checked, nil
}

// checkLimit is the reference's `checkLimit`: limit and window are integers >=
// 1, and the policy name is a structured-field key.
//
// The reference's `Number.isInteger` has no counterpart here and does not need
// one: `int` cannot hold `1.5`, so the whole-number half of that assertion is
// the type. What is left is the range, and a `0` is a programming error rather
// than "unlimited" — `NewLimiter` says the same about `RATE_LIMIT_REQUESTS=0`.
func checkLimit(limit Limit, field string) (Limit, error) {
	if limit.Limit < 1 {
		return Limit{}, fmt.Errorf("%w: %s.limit must be an integer >= 1, got %d", ErrNotConfigured, field, limit.Limit)
	}
	if limit.Window < time.Millisecond {
		return Limit{}, fmt.Errorf("%w: %s.windowMs must be an integer >= 1, got %v", ErrNotConfigured, field, limit.Window)
	}
	if err := assertStructuredKey(limit.Policy); err != nil {
		return Limit{}, fmt.Errorf("%w: %s.policy must be a structured-field key, got %q", ErrNotConfigured, field, limit.Policy)
	}

	return Limit{Limit: limit.Limit, Window: limit.Window, Policy: limit.Policy}, nil
}

// checkPrefix refuses a prefix that is a pattern.
//
// No `*` and no `?`: a glob is a second matching language to get wrong, and the
// only thing a route needs is "everything under here". The trailing slash is left
// alone because it is meaningful to the matcher.
//
// This is NOT `internal/httpapi`'s `checkPrefix` and the two are deliberately not
// one function: that one additionally confines prefixes to the `/v1` surface,
// because a prefix outside it names a route the pass-through could never reach.
// This table's prefixes are read from the same configuration but answer a different
// question, and borrowing the surface rule would refuse `/auth/` — the entry doing
// the most work on the most attacked surface.
func checkPrefix(prefix string) error {
	if !strings.HasPrefix(prefix, "/") {
		return fmt.Errorf("%w: limitTable: route prefixes must be absolute paths without globs, got %q", ErrNotConfigured, prefix)
	}
	if strings.ContainsAny(prefix, "*?") {
		return fmt.Errorf("%w: limitTable: route prefixes must be absolute paths without globs, got %q", ErrNotConfigured, prefix)
	}
	return nil
}

// ResolveLimit is the allowance for one request path.
//
// Longest matching prefix wins, so `/v1/api-keys` beats `/v1/` and the order the
// entries were written in does not matter — a table that resolved in insertion
// order would quietly change meaning the first time someone moved a line. A Go map
// has no insertion order at all, so that half of the property is structural here
// and `limits_test.go` asserts the other half — that `/v1/api-keys` beats `/v1/` —
// rather than asserting an order Go cannot express.
//
// A prefix matches on a path-segment boundary. `/v1/` claims `/v1/me` and not
// `/v1alpha/`, so a new top-level route cannot inherit an allowance by sharing a
// name with an old one. Getting that wrong in the PERMISSIVE direction is the same
// class of bug as the table being absent, so it is a test of its own.
//
// Anything unclaimed gets `Default`, which is why `Default` is a required field
// and not a convenience.
//
// NOT VALIDATED HERE, deliberately. This runs on every request and the reference
// says the same: a limit of `0` in the table is a startup failure, caught once by
// `ValidateLimitTable`, not a per-request check. Calling the validator from here
// would turn a configuration mistake into a cost on the hot path.
func ResolveLimit(table LimitTable, path string) Limit {
	target := pathname(path)

	var best Limit
	bestLength := -1

	for prefix, limit := range table.Routes {
		if len(prefix) <= bestLength || !claims(prefix, target) {
			continue
		}

		best = limit
		bestLength = len(prefix)
	}

	if bestLength < 0 {
		return table.Default
	}
	return best
}

// PolicyResolver is the table expressed as the two hooks `Options.Policy` and
// `Options.Resolve` want, and it is the whole of `buildLimiter`'s table handling
// in `src/index.ts`.
//
// This is the seam the port needed. Both hooks already existed and nothing set
// them, so the Go gateway drew every request on one default allowance — 600/min on
// `/auth/login`, which is the scarcest thing the edge is supposed to serve. The
// limiter reads a NAME and then the NUMBERS behind it, in two steps, so a table
// keyed by PREFIX has to be indexed by name to reach it.
//
// # `resolve` IS FALLIBLE, AND THAT IS THE POINT
//
// A name the index does not carry answers `false`, and the limiter then falls back
// to its constructor allowance. That is the reference's documented behaviour rather
// than a convenience: a typo in a table costs the default allowance and nothing
// else, which is the failure a gateway serving a cutover can absorb. It is also
// the reason the index is built here and the fallback lives in `allow()`.
//
// # A NAME CARRYING TWO SETS OF NUMBERS IS REFUSED, NOT ARBITRATED
//
// The reference's `byPolicy` is a `Map` written default-first and then routes in
// insertion order, so two entries sharing a name with different numbers means the
// last one written wins — silently, and in a language where that order exists.
// A Go map has no insertion order, so the same loop would pick per iteration and a
// request could draw `q=5` on one call and `q=60` on the next.
//
// Rather than pick one, this refuses the table at construction. The reference's own
// model says sharing a name means sharing an allowance — `limits.ts` states it
// twice, and it is why `/auth/login` and `/auth/register` are separate policies —
// so two entries sharing a name while disagreeing about the numbers are a table
// that contradicts itself, and a startup failure is the only answer that does not
// depend on iteration order. Identical numbers under one name are accepted: that is
// the model working, not a contradiction, and the shipped `/v1/` row relies on it
// (it reuses `gateway-api` under the same 600/min the default row carries).
func PolicyResolver(table LimitTable) (func(string) string, func(string) (int, time.Duration, bool), error) {
	index := make(map[string]Limit, len(table.Routes)+1)

	// The default row goes in FIRST and a route row overwrites it, which is the
	// reference's order: a route entry that reuses the default policy name brings
	// its own numbers with it. Since `DefaultLimitTable` gives both the same
	// numbers this is a no-op for the shipped table, and it is written the
	// reference's way rather than the obvious one so a deployment that diverges
	// them gets the reference's behaviour.
	for _, entry := range append([]Limit{table.Default}, routeEntries(table)...) {
		if known, ok := index[entry.Policy]; ok && known != entry {
			return nil, nil, fmt.Errorf("%w: policy %q is claimed by more than one entry with different numbers (%d/%v and %d/%v). Two entries sharing a name share an allowance, so they must agree; otherwise which one a request draws is a map's iteration order", ErrNotConfigured, entry.Policy, known.Limit, known.Window, entry.Limit, entry.Window)
		}
		index[entry.Policy] = entry
	}

	policy := func(path string) string { return ResolveLimit(table, path).Policy }
	resolve := func(name string) (int, time.Duration, bool) {
		entry, ok := index[name]
		return entry.Limit, entry.Window, ok
	}

	return policy, resolve, nil
}

// routeEntries is a table's route rows in no particular order.
//
// There is no order to have: `Routes` is a map. `PolicyResolver` above is written so
// that no result depends on this order, which is the property that makes the absence
// of one safe.
func routeEntries(table LimitTable) []Limit {
	entries := make([]Limit, 0, len(table.Routes))
	for _, entry := range table.Routes {
		entries = append(entries, entry)
	}
	return entries
}

// pathname is the path, without the query or the fragment.
//
// A local copy of the same three lines in `internal/httpapi/table.go`, and the
// duplication is the convention rather than an oversight: that file's own comment
// says the route table and the limit table agree "on a path-segment boundary — the
// same rule the rate-limit table applies, and deliberately the same *rule* rather
// than the same *code*". One exported helper serving both would couple the routing
// table to this package and vice versa, for four lines. The rule is held in place
// by both tables' tests rather than by a shared function.
func pathname(path string) string {
	if cut := strings.IndexAny(path, "?#"); cut >= 0 {
		return path[:cut]
	}
	return path
}

// claims reports whether a prefix owns a path, on a segment boundary.
//
// `"/"` claims the root path and nothing else, and that is the reference's rule
// rather than a Go reading of it: a `/` entry in `routes` is an ordinary prefix, so
// making it a catch-all would leave `Default` unreachable and an operator who
// lowered `Default` to stop something would find it doing nothing at all.
func claims(prefix, path string) bool {
	if prefix == "/" {
		return path == "/"
	}
	if strings.HasSuffix(prefix, "/") {
		return strings.HasPrefix(path, prefix)
	}
	return path == prefix || strings.HasPrefix(path, prefix+"/")
}
