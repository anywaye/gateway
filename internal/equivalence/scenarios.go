// The Go scenarios, and the one place the equivalence check is told what the Go
// gateway is configured with for each of them.
//
// This file is the counterpart to `test/equivalence/reference.ts`, and the two
// are read by the same runner: a scenario name in `TestTheGoSideHasAnAnswerFor
// EveryScenarioTheReferenceHas` must exist on both sides, or the runner refuses
// to start rather than comparing a scenario against nothing.
//
// The names are declared here as data rather than in the scenarios themselves
// because the test needs to enumerate them, and a `switch` inside a builder is
// not something a caller can read the keys of. `optionsFor` is the only function
// that knows what any scenario IS; the table above it is the inventory.
//
// # WHAT A SCENARIO CAN AND CANNOT DO
//
// `Probes`, and nothing else. The Go substrate has one configurable field, so a
// scenario is a probe set — which is enough to exercise the one part of the
// surface that varies (`/readyz`'s body and status) plus the refusals, and is not
// enough to exercise anything Wave 3 owns. That limit is the honest shape of this
// packet's equivalence and it is stated in the report rather than discovered by a
// reader who assumed more.
package equivalence

import (
	"context"
	"errors"
	"fmt"

	"github.com/cafaye/gateway/internal/httpapi"
)

// Scenario names. Both sides' lists are the same three, and
// `TestTheGoSideHasAnAnswerForEveryScenarioTheReferenceHas` holds them equal by
// reading the reference's.
const (
	// ScenarioBare is nothing configured: the two probes and nothing else.
	ScenarioBare = "bare"

	// ScenarioOneProbeOk is one dependency answering.
	ScenarioOneProbeOk = "oneProbeOk"

	// ScenarioProbesDegraded is three dependencies: one healthy, one refusing,
	// and one throwing. The refusal and the throw are the two shapes a healthy
	// scenario cannot reach, and the throw carries a host, a port and a
	// credential so the comparison can prove none of them reach a response body.
	ScenarioProbesDegraded = "probesDegraded"
)

// scenarios is the inventory, in the order the runner drives them.
var scenarios = []string{ScenarioBare, ScenarioOneProbeOk, ScenarioProbesDegraded}

// The dependency names the degraded scenario registers, in the order both sides
// declare them.
//
// NOT ALPHABETICAL, and that is the whole point of the list. `/readyz` renders
// `deps` in registration order because `Options.Probes` is a slice rather than a
// map — and a `map[string]ProbeStatus` would render in the order
// `encoding/json` sorts keys. So the two orders are only distinguishable if the
// names are declared in an order that is not already sorted, and the first draft
// of this file used `aperture, identity, redis`, which IS sorted: a planted
// mutation swapping the hand-written ordering for `json.Marshal(api.Readiness)`
// then passed, and the property was untested. Found by planting the mutation and
// finding it did not fail, which is the only way to find this one.
const (
	degradedHealthy  = "redis"
	degradedRefusing = "identity"
	degradedThrowing = "aperture"
)

// optionsFor builds the gateway configuration for one scenario, or an error
// naming the scenario it does not know.
//
// The error rather than a zero `Options`: a typo in a scenario name would
// otherwise compare an unconfigured gateway against a configured reference and
// report every difference, which is noise that hides the real ones. The runner
// checks the names against the inventory before calling this, and this checks
// again — two checks on one thing is cheap, and the second is the one that fails
// when the runner's list and this list are edited in different commits.
func optionsFor(scenario string) (httpapi.Options, error) {
	switch scenario {
	case ScenarioBare:
		// The zero value is the configuration, not a stand-in for one: with
		// nothing to probe there are no probes, and `/readyz` answers `{}` which
		// is what the document says that means.
		return httpapi.Options{}, nil

	case ScenarioOneProbeOk:
		return httpapi.Options{Probes: []httpapi.NamedProbe{
			{Name: "identity", Probe: alwaysOK},
		}}, nil

	case ScenarioProbesDegraded:
		return httpapi.Options{Probes: []httpapi.NamedProbe{
			{Name: degradedHealthy, Probe: alwaysOK},
			{Name: degradedRefusing, Probe: alwaysUnavailable},
			{Name: degradedThrowing, Probe: func(context.Context) error {
				// The shape of a dependency that is up and broken, which is the
				// case `AGENTS.md` calls out: a driver that answers 5xx reached
				// the readiness endpoint with no log line, so the message here
				// stands in for the detail that must never reach a caller.
				return errors.New("dial tcp://identity.internal:8080: connect: connection refused (password=hunter2)")
			}},
		}}, nil

	default:
		return httpapi.Options{}, fmt.Errorf("equivalence: no Go scenario named %q; known: %v", scenario, scenarios)
	}
}

func alwaysOK(context.Context) error          { return nil }
func alwaysUnavailable(context.Context) error { return errors.New("unavailable") }
