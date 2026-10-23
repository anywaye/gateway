// The rate-limit headers this comparison checks BY VALUE rather than by presence.
//
// A separate file for one variable, and the reason is that it is the one thing in
// this package that is not derived from the two sides: `diff` compares the
// presence of every name in `comparedHeaders`, which is right for most headers and
// wrong for these, because a client reads a stale `RateLimit-Reset` as a promise
// the gateway is not keeping.
//
// # WHY THE SET IS READ FROM `ratelimit` RATHER THAN TYPED
//
// A list typed here is a second inventory of the header family, and the next field
// added to `announce` would then be compared for presence and not for value without
// anything going red — which is the exact half-comparison this variable exists to
// stop. `ratelimit.RateLimitHeaders` is the service's own list and it is exported
// for this reason: `limiter.go`'s comment says "`internal/equivalence` compares this
// list against the headers the reference actually sends", and this is that.
//
// # AND WHY `Retry-After` IS NAMED HERE RATHER THAN ADDED THERE
//
// It is not part of the allowance — it is an instruction, set only on a refusal,
// and RFC 9110 defines it rather than the draft the other eight come from. That is
// why `ratelimit.RateLimitHeaders` leaves it out deliberately, and it is the one
// header on the 429 whose absence changes what a client does next.
package equivalence

import "github.com/anywaye/gateway/internal/ratelimit"

// headerValuesComparedByValue is the rate-limit family compared as VALUES rather
// than as presence, plus `Retry-After`.
var headerValuesComparedByValue = append([]string{"Retry-After"}, ratelimit.RateLimitHeaders...)
