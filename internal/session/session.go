// Package session is the contract a browser session store implements, and the
// record one holds.
//
// It is its own leaf package rather than part of `internal/httpapi` because
// `internal/sessiontest` implements it and must not import the package it stands
// in for: a test in `httpapi` that reached for the double would otherwise close
// an import cycle, and the workaround for that is either a second copy of the
// fixture or a duplicated mini-interface. A leaf is the third option, and it is
// the shape Go's own libraries use for exactly this — a contract with no
// behaviour in it, implemented by packages that depend on it and not on each
// other.
//
// # WHERE A BROWSER SESSION LIVES
//
// The browser holds a session id and nothing else; the identity token that id
// stands for stays in gateway's process. That is the whole BFF claim, and this
// file is the only place the claim is stated — the alternative is a comment on one
// handler, which is a comment the next handler does not read.
//
// # THERE IS NO IMPLEMENTATION IN THIS MODULE, AND THAT IS THE DELIBERATE ANSWER
//
// `src/bff/session.ts` ships `memorySessionStore()`: a `Map` in one process,
// marked `TODO(guard-06)`/`TODO(guard-07)` for Redis. Porting it into Go would
// have been copying the worse of two designs into the language that makes the
// better one easier to write, so this package declares the seam and stops.
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
//     `github.com/cafaye/identity/internal/sessions` is importable only from
//     `github.com/cafaye/identity/...`. `gateway` is a different module, so even
//     with the direction right the compiler would refuse it. Reaching it would
//     mean identity publishing that package outside `internal/`, which is a change
//     to identity's public surface and not this repository's to make.
//   - So the only remaining route is an HTTP call, and identity exposes no
//     endpoint that does the inverse lookup either.
//
// Therefore: **deferred, with the reason recorded here rather than in a ticket.**
// The alternative this packet rejected is shipping a `sync.Map` in the binary and
// calling it a port — a per-process store that signs a browser out on the next
// restart, in a service whose entire claim is that it holds a credential so the
// page does not have to.
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
// under `cmd/` and `internal/` to prove nothing outside a test can reach it. So
// the Go service ships no session store at all, and the store the suite runs
// against is visibly a fixture rather than a deployment choice.
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
// `src/bff/session.ts` and not one more. A `Size`, a `List` and a `Count` are
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
