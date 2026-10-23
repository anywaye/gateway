package httpapi

import (
	"context"
	"errors"
	"time"

	"github.com/anywaye/gateway/internal/api"
)

// What a readiness probe reports for one dependency. It is the generated type,
// not a hand-written alias, so `/readyz` cannot answer a status the document's
// enum does not name — `openapi/v1.yaml`'s `Readiness.deps` is `enum: [ok,
// unavailable]` and this file is the only thing that decides which of those two
// a dependency gets.
type ProbeStatus = api.ReadinessDeps

// The two statuses. `ok` is "this dependency answered"; `unavailable` is every
// other outcome, including a probe that returns an error, one that panics, and
// one that never returns.
const (
	probeOK          = api.ReadinessDepsOk
	probeUnavailable = api.ReadinessDepsUnavailable
)

// One dependency's health.
//
// A nil error is `"ok"` and a non-nil one is `"unavailable"`, with nothing else
// expressible. That is the same contract `src/probe.ts` (removed at cutover) states — "a probe that
// throws, rejects, hangs or answers with anything but `"ok"` is `unavailable`" —
// reached by a different spelling: TypeScript can only return `"ok"`, return
// something else, or throw, and all three collapse to one value here. The Go
// signature cannot express the third case at all, which is the point of taking
// it.
//
// It is an `error` and not a status for the reason the TypeScript type unions
// the status with a thrown error: a probe that *decides* it is degraded and a
// probe that could not find out are different facts that must not be spelled the
// same way by accident. Returning an error for the second is enough; `runProbe`
// turns it into the one status a caller sees.
//
// The `context.Context` is the request's, so a probe that has to call a
// dependency inherits the client's deadline rather than inventing one — and
// `runProbe` bounds it regardless, because a context a probe may ignore is not a
// bound on one.
type Probe func(ctx context.Context) error

// One named probe.
//
// A NAME AND A FUNCTION, rather than a map, and the ordering is the reason.
// `GET /readyz` renders `deps` as a JSON object, and Go's `encoding/json` sorts
// map keys — so a map would answer `{"redis":"unavailable","identity":"ok"}`
// where the TypeScript implementation answers `{"identity":"ok","redis":
// "unavailable"}`, because `Object.entries` preserves insertion order. Both are
// the same object, and `internal/equivalence` compared the bytes, so the order a
// caller wrote is the order the response carries.
//
// The slice is also what makes "one entry per registered dependency" checkable:
// two probes with one name is a refusal to boot rather than a map that silently
// keeps the second, which is what the same mistake does in JavaScript.
type NamedProbe struct {
	// The name in `/readyz`'s `deps`, which is gateway's configuration rather
	// than a client's: `identity` in every deployment gateway has an identity
	// for, `redis` when a shared counter store is configured.
	Name string

	// The probe itself. Nil is refused by `New` — a registered dependency that
	// cannot be asked about would answer `unavailable` forever, which is a
	// readiness endpoint reporting a configuration mistake as an outage.
	Probe Probe
}

// probeTimeout bounds one dependency's probe.
//
// A variable, and the only reason is that one test proves the bound in
// milliseconds rather than four seconds. It is unexported, nothing outside this
// package reads it, and `TestTheTimeoutIsOnlyEverLoweredInATest` reads this
// package's sources to hold even that.
//
// Four seconds is long for a health check and short enough that an
// orchestrator's own probe timeout fires first, which is the ordering that keeps
// a slow dependency from looking like a dead process: gateway answers `503`
// while it is still being asked anything.
var probeTimeout = 4 * time.Second

// runProbe turns one probe's outcome into the one status `/readyz` publishes.
//
// Everything that is not a `nil` return is `unavailable`: an error from the
// probe, a panic inside it, and a probe that neither honors its context nor
// returns at all. None of those may take the process down, and reporting `503` is
// the entire contract of `/readyz`.
//
// # WHY THE PROBE RUNS SOMEWHERE ELSE
//
// A deadline on a `context.Context` does not interrupt a function that ignores
// it. `probe(bounded)` where `bounded` has already expired still blocks for as
// long as `probe` blocks, so a probe that hangs would hang `/readyz` with it —
// and `/readyz` hanging is the one failure an orchestrator cannot distinguish
// from a dead process, which is the failure this endpoint exists to prevent. So
// the call runs on its own goroutine and the answer is selected against the
// deadline, and the deadline is what actually bounds it.
//
// # WHAT THAT COSTS, STATED RATHER THAN HIDDEN
//
// A goroutine whose probe never returns is still running after `/readyz` has
// answered, and nothing in Go can stop it: there is no cancellation a function
// that ignores its context will observe. So the cost is one goroutine and
// whatever the probe holds — a socket, a lock — per hung probe, per request,
// until the process exits.
//
// That is accepted rather than solved, and the reason is that the alternative is
// worse in both directions. Not bounding the probe hands `/readyz` a hang. Killing
// the goroutine is not an option either: `runtime.Goexit` unwinds the probe's own
// deferred cleanup, and a probe holding a pooled connection would return it
// half-closed. A probe that honors its context has none of this cost, which is
// why the context is the FIRST argument and `TestAProbeThatIgnoresItsContextIs
// StillBounded` documents the other kind.
func runProbe(ctx context.Context, probe Probe) (status ProbeStatus) {
	if probe == nil {
		return probeUnavailable
	}

	if ctx == nil {
		ctx = context.Background()
	}
	bounded, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()

	// Buffered, so the goroutine below can always finish and be collected even
	// after the deadline has fired. An unbuffered channel would block a returning
	// probe forever, which is the leak this function is trying to bound.
	answered := make(chan error, 1)
	go func() {
		// Deferred, so a panic is turned into an outcome rather than taking the
		// process down: `src/probe.ts` (removed at cutover) put "throws" in the same
		// list as "hangs", and a panic is Go's spelling of a throw.
		defer func() {
			if r := recover(); r != nil {
				answered <- errors.New("probe panicked")
			}
		}()
		answered <- probe(bounded)
	}()

	select {
	case err := <-answered:
		if err != nil {
			return probeUnavailable
		}
		return probeOK
	case <-bounded.Done():
		return probeUnavailable
	}
}
