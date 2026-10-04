// The TypeScript reference, stood up on a port so the Go gateway can be compared
// with it.
//
// ## WHAT THIS FILE IS FOR
//
// `internal/equivalence` starts this process, drives the same requests against it
// and against the Go gateway, and fails where the two answers differ. The
// TypeScript implementation is the reference: it has the documented contract, the
// large suite, and a security core whose behaviour is reasoned about line by line
// in its own comments. So where they differ the TypeScript answer is the correct
// one, and this packet's job is to find the differences rather than to choose
// between them.
//
// ## WHY IT IS A SEPARATE FILE AND NOT `src/index.ts`
//
// `src/index.ts` only listens under `import.meta.main`, and its `runtimeOptions`
// reads a configuration out of the environment that registers an identity and,
// with `REDIS_URL`, a Redis — neither of which this packet ports. Comparing
// against that would compare the Go gateway with a configuration it cannot be
// built in, and every difference would be about the missing subsystems rather
// than about the substrate.
//
// So this file names the configurations explicitly, in one place, and both sides
// are built from the same list. A scenario added here is a scenario the Go side
// has to have an answer for; `bin/equivalence`'s runner refuses a scenario the
// Go side does not know, which is what keeps the two halves of this comparison
// from drifting apart into two lists that each look complete.
//
// ## IT IS NOT A TEST FILE
//
// Deliberately not `*.test.ts`: `bun test` must not try to run it, and
// `test/dockerStage.test.ts` counts the repository's test files and holds the
// image's COPY list to that count. A file named `*.test.ts` here would change a
// number that means something.
import { createApp, type AppOptions, type ProbeStatus } from "../../src/index";

// One named configuration. Both sides are handed the same name and must build
// the same thing from it.
export const SCENARIOS: Record<string, AppOptions> = {
  // Nothing configured. `createApp({})` registers the two probes and
  // `app.notFound`, and nothing else — every other operation in the document is
  // absent rather than refusing, which is the shape the Go side has to match.
  bare: {},

  // One dependency answering. `/readyz` renders `{"deps":{"identity":"ok"}}`, and
  // the ORDER of that object is part of the answer: the Go side marshals `deps`
  // by hand for exactly this reason.
  oneProbeOk: {
    // `ProbeStatus` and not a bare string literal: `async () => "ok"` widens to
    // `Promise<string>` under `strict`, which is a type error rather than a
    // behaviour, and a reference that does not typecheck is a reference CI will
    // not build.
    probes: { identity: async (): Promise<ProbeStatus> => "ok" },
  },

  // Three dependencies, two of which are down, one of which throws rather than
  // answering. Every one of those is one `unavailable`, none of them may take the
  // process down, and the failing one names nothing to the caller — the message
  // below carries a host, a port and a credential precisely so the comparison can
  // prove none of them reach a response body.
  probesDegraded: {
    probes: {
      // Insertion order is the response order, and these three names are
      // deliberately NOT in alphabetical order — a sorted list would render
      // identically whether the gateway preserves insertion order or sorts, and
      // the property would be untested. `internal/equivalence/scenarios.go`
      // declares the same three names in the same order and says why.
      redis: async (): Promise<ProbeStatus> => "ok",
      identity: async () => {
        throw new Error("dial tcp://identity.internal:8080: no route to host");
      },
      aperture: async (): Promise<ProbeStatus> => "unavailable",
    },
  },
};

// `GATEWAY_EQUIVALENCE_SCENARIO` names the scenario rather than argv, so the
// runner and the process agree through one channel and the command line carries
// only the port. An unknown name is a refusal rather than a fallback: silently
// serving `bare` would make a typo into a green that compared nothing.
const scenario = process.env.GATEWAY_EQUIVALENCE_SCENARIO ?? "bare";
const options = SCENARIOS[scenario];

if (options === undefined) {
  console.error(
    `reference: GATEWAY_EQUIVALENCE_SCENARIO=${scenario} names no scenario. ` +
      `Known: ${Object.keys(SCENARIOS).join(", ")}.`,
  );
  process.exit(2);
}

const port = Number(process.env.GATEWAY_EQUIVALENCE_PORT ?? 0);
if (!Number.isInteger(port) || port < 0 || port > 65535) {
  console.error(`reference: GATEWAY_EQUIVALENCE_PORT must be a port number, got ${process.env.GATEWAY_EQUIVALENCE_PORT}`);
  process.exit(2);
}

// The readiness line the runner waits for. It goes to stdout because that is the
// only channel a runner reading a subprocess's output has, and it is printed
// AFTER `Bun.serve` so its arrival means the socket is open — a runner that slept
// instead would be a race that passes on a fast machine and fails on a slow one.
const server = Bun.serve({ port, fetch: createApp(options).fetch });
console.log(`reference listening on http://localhost:${server.port} scenario=${scenario}`);