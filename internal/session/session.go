// Package session is the contract a browser session store implements, and the
// record one holds.
//
// It is its own leaf package rather than part of `internal/httpapi` because
// `internal/sessiontest` implements it and must not import the package it stands
// in for: a test in `httpapi` that reached for the double would otherwise close
// an import cycle, and the workaround for that is either a second copy of the
// fixture or a duplicated mini-interface. A leaf is the third option, and it is
// the shape Go's own libraries use for exactly this — a contract with no
// behavior in it, implemented by packages that depend on it and not on each
// other.
//
// # WHERE A BROWSER SESSION LIVES
//
// The browser holds a session id and nothing else; the identity token that id
// stands for stays in gateway's process. That is the whole BFF claim, and this
// file is the only place the claim is stated — the alternative is a comment on one
// handler, which is a comment the next handler does not read.
//
// # THERE IS NO IN-MEMORY IMPLEMENTATION HERE, AND THAT IS STILL THE ANSWER
//
// `src/bff/session.ts` (removed at cutover) ships `memorySessionStore()`: a `Map` in one process,
// marked `TODO(guard-06)`/`TODO(guard-07)` for Redis. Porting it into Go would
// have been copying the worse of two designs into the language that makes the
// better one easier to write, so this package declares the seam and stops.
//
// **The seam is no longer empty.** `internal/sessionredis` is the implementation
// the service ships — Redis, over `internal/ratelimit`'s transport — and
// `RuntimeOptions` builds it when `IDENTITY_URL` and `REDIS_URL` are both set.
// What has not changed is the refusal below: the reason was never "a Map is hard
// to write in Go", it was "a Map is the wrong shape for a service whose claim is
// that it holds a credential", and that reason still rules out the map.
//
// The better design is `identity/internal/sessions/store.go`, and it has three
// properties the map store does not:
//
//  1. `NewSession` takes a `TokenDigest`, not a token. The store is handed the
//     hash and has no code path that can produce the raw credential, so the token
//     cannot be written into a row by accident from there.
//  2. `ErrNotFound` is ONE error for "no such token, a revoked token, an expired
//     token, and a token belonging to a deleted user" — one error, one status
//     code, one response time. Four distinguishable answers is four ways to
//     enumerate users.
//  3. Expiry is a `WHERE expires_at > $1` clause rather than a comparison the
//     caller is trusted to remember, so an expired session is never returned even
//     to be discarded by whoever asked.
//
// # WHY THE GO GATEWAY STILL CANNOT USE IT, MEASURED RATHER THAN ASSUMED
//
// Because the two stores are not the same thing pointing different ways, and
// that is the finding which made "just use identity's" false:
//
//   - `identity/internal/sessions` is keyed by `token_digest`. `ByToken` takes a
//     *token* and hashes it. Nothing in that package takes a hash and returns a
//     token, and nothing can: the digest is one-way by construction, which is
//     property 1 above and the reason it is there.
//   - What the gateway needs is the OPPOSITE DIRECTION. `Store.Get` is handed the
//     opaque id the browser holds and must return the identity token to put in a
//     `Bearer` header for `/v1/me`. There is no function anywhere in identity
//     that performs that direction, and adding one would give identity a
//     token-minting endpoint aimed at somebody else's cookie.
//   - Go's `internal/` rule forbids the import outright:
//     `github.com/anywaye/identity/internal/sessions` is importable only from
//     `github.com/anywaye/identity/...`. `gateway` is a different module, so even
//     with the direction right the compiler would refuse it. Reaching it would
//     mean identity publishing that package outside `internal/`, which is a change
//     to identity's public surface and not this repository's to make.
//   - So the only remaining route is an HTTP call, and identity exposes no
//     endpoint that does the inverse lookup either.
//
// Therefore: **gateway owns its sessions**, in Redis, over the transport it
// already speaks. The alternative this package rejected is shipping a `sync.Map`
// in the binary and calling it a port — a per-process store that signs a browser
// out on the next restart, in a service whose entire claim is that it holds a
// credential so the page does not have to.
//
// # THE REASON ABOVE WAS CHECKED, NOT INHERITED
//
// It arrived as a claim in a document, and it is a claim about another
// repository's schema. `REPORT-gateway-session-store-01` verifies it: identity's
// `sessions` table has no column for the presented value, `ByToken` is its only
// read and takes a token, and `/v1/session` carries `post` and `delete` with no
// inverse lookup. Go's `internal/` rule was answered by the compiler rather than by
// reading — `use of internal package … not allowed`. Both hold, so this section
// stands as written and only the conclusion moved.
//
// A reader who takes this paragraph as "therefore nothing could be built" is reading
// a stronger claim than the evidence supports, and that misreading is what left the
// Go service unable to serve `/auth/*` for several packets. The evidence supports
// "therefore not identity's", and gateway owns its own.
//
// The refusal is at CONSTRUCTION rather than at request time:
// `httpapi.NewBff` refuses a `Store` that is nil, so a deployment cannot
// accidentally serve the four `/auth` routes on nothing. With no
// `Options.BFF` at all those routes decline with the v0 `404`, which is exactly
// what the reference does when `createApp({})` gets no `bff` option.
//
// # WHAT THE TESTS STAND IN WITH
//
// `internal/sessiontest` holds the map-backed double, and
// `TestNoProductionFileImportsTheSessionDouble` reads every non-test source file
// under `cmd/` and `internal/` to prove nothing outside a test can reach it. The
// store the suite runs the browser surface against is therefore visibly a fixture
// rather than a deployment choice — and the REAL one is proved separately, because
// `internal/httpapi`'s runtime tests sign in against a real `redis-server` with a
// real session store and are the only thing in the tree that can say the shipped
// store works.
//
// The two guards are a pair and neither substitutes for the other:
// `sessiontest`'s says the FIXTURE is not linked, `sessionredis`'s says the REAL
// one is. A guard that only ever says "no" cannot notice that the "yes" stopped
// happening, which is the shape of the gap this packet closed.
package session

import (
	"context"
	"time"
)

// Session is one live browser session.
//
// `ExpiresAt` is the token's own expiry, taken from what identity said rather
// than from a TTL this package invented: identity decides how long a session is
// good for, and a second clock here would be a second answer to that question.
type Session struct {
	// The identity token, held here and nowhere else. It never reaches a
	// response body — `TestTheBrowserNeverReceivesTheIdentityToken` is what holds
	// that, and it is the property the BFF exists for.
	Token string

	// When the session stops being one, in UTC.
	ExpiresAt time.Time
}

// SessionStore is the contract every session backend implements.
//
// THREE METHODS AND NOTHING ELSE, deliberately, ported from
// `src/bff/session.ts` (removed at cutover) and not one more. A `Size`, a `List` and a `Count` are
// all things a caller could want and none of them anything the BFF needs, and
// every one of them added here is a method the Redis implementation has to grow.
//
// Absent and expired are the SAME answer, and that is not a simplification: a
// backend that returned an expired record would be handing out a session it
// knows is dead, and a backend that distinguished them would be telling a caller
// which of the two happened.
type SessionStore interface {
	// Get is the live session for an id, or nil. Nil means absent OR expired,
	// and no caller may tell the difference.
	Get(ctx context.Context, sessionID string) (*Session, error)

	// Put stores a session under an id the gateway minted. It is never handed a
	// caller-chosen id — see `login`, where the id is a fresh random UUID
	// precisely so fixation needs an id the attacker knew first.
	Put(ctx context.Context, sessionID string, session Session) error

	// Delete drops one. Deleting an id that is not there succeeds: a client
	// retrying a sign-out should not get an error for having retried it.
	Delete(ctx context.Context, sessionID string) error
}
