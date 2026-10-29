package equivalence

import "github.com/anywaye/gateway/internal/ratelimit"

var headerValuesComparedByValue = append([]string{"Retry-After"}, ratelimit.RateLimitHeaders...)
