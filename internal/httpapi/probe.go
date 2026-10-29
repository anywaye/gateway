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
	Name string

	Probe Probe
}

var probeTimeout = 4 * time.Second

func runProbe(ctx context.Context, probe Probe) (status ProbeStatus) {
	if probe == nil {
		return probeUnavailable
	}

	if ctx == nil {
		ctx = context.Background()
	}
	bounded, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()

	answered := make(chan error, 1)
	go func() {
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
