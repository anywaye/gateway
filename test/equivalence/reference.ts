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
// with `REDIS_URL`, a Redis — neither of which the routing scenarios need.
// Comparing against that would compare the Go gateway with a configuration it
// cannot be built in, and every difference would be about the missing subsystems
// rather than about the substrate.
//
// So this file names the configurations explicitly, in one place, and both sides
// are built from the same list. A scenario added here is a scenario the Go side
// has to have an answer for; the runner refuses a scenario the Go side does not
// know, which is what keeps the two halves of this comparison from drifting apart
// into two lists that each look complete.
//
// ## THE UPSTREAM, AND WHY IT IS AN ENVIRONMENT VARIABLE
//
// `GATEWAY_EQUIVALENCE_UPSTREAM` names a recording service the runner started. Both
// sides are pointed at the SAME process, so "the same request reached the same
// upstream" is a comparison rather than two inferences — which is the only way to
// compare the part of the security core that is not in a response body: which
// headers crossed, and what the caller's path was rebuilt into.
//
// It is a refusal rather than a default when unset. A routing scenario with no
// upstream would forward to nothing and compare two 503s, which looks like a pass
// and is the failure mode this file exists to prevent.
import { createApp, type AppOptions, type ProbeStatus } from "../../src/index";
import type { BffOptions } from "../../src/bff/auth";

// # THE BFF SCENARIOS, AND WHY THE REFERENCE HAS TO BE GIVEN A FETCH
//
// The four `/auth` routes only exist when `options.bff` is set, and that option
// needs an `identityUrl` AND — to compare anything but a `404` — an identity to
// answer. `BffOptions.fetch` is the seam for that, and it is the reference's own:
// `createBffAuth` takes a `FetchFn` precisely so its suite never opens a socket.
//
// So the scenarios below script identity's answers as a function, and the Go side
// gets the same script through its own `Doer` (see `internal/equivalence/
// scenarios.go`). The two are written in two languages that cannot see each
// other, which is the reason the scenario LIST is compared by reading this file's
// source rather than by sharing it.
//
// # EVERY FIXTURE IS A CONSTANT, AND THAT IS THE POINT
//
// `expires_at` is fixed, the ids are fixed, the tokens are fixed. A login body
// carries the expiry and the comparison is byte for byte, so a session that
// expired "in an hour" would render a different string on each side and fail for a
// reason that is not a port defect. Nothing random, nothing relative to now.
//
// # AND WHY `expires_at` IS NOT IN 2031
//
// `hono/cookie` REFUSES to serialise a cookie whose expiry is more than 400 days
// out — it throws, and `src/index.ts`'s `onError` turns that into a `500`. So the
// first draft of this fixture, `2031-03-04`, made the reference answer `500
// {"error":"internal_error"}` to a successful login while the Go service answered
// `200` and set the cookie.
//
// That is a real divergence between the two implementations and it is NOT a porting
// mistake on either side: the reference cannot issue a session longer than about a
// year, and the Go service can. Reproducing the cap in Go is a decision about
// session lifetimes, not a porting detail, so it goes in the report rather than
// into a line changed here to make a check green.
//
// `2027-01-15` is inside the 400-day window and in the future, which is the whole
// requirement. `TestTheFixtureExpiryIsInsideTheReferenceCookieWindow` on the Go
// side states the constraint and the failure date, so nobody discovers this by
// running the suite in a year.
//
// # WHAT THE SESSION ID IS NOT COMPARED AS A VALUE
//
// The session id is minted fresh by both implementations and is necessarily
// different. `internal/equivalence` compares headers as a SET OF NAMES plus
// `Content-Type`'s value, so `Set-Cookie`'s presence is compared and its value is
// not — which is what makes a login comparable at all. The id is checked where it
// matters, in `bff_test.go`, by asserting the cookie is the key the record is
// stored under.

const jsonAnswer = (status: number, body: unknown, headers: Record<string, string> = {}): Promise<Response> =>
  Promise.resolve(
    new Response(typeof body === "string" ? body : JSON.stringify(body), {
      status,
      headers: { "content-type": "application/json", ...headers },
    }),
  );

// One scripted identity, shared by every BFF scenario.
//
// A lookup keyed on the path rather than a `switch`, so an override is exactly one
// route and a scenario cannot accidentally change two. The keys are the four
// identity routes, and the Go side reads the same four out of `internal/httpapi`.
function scriptedIdentity(overrides: Record<string, () => Promise<Response>> = {}): NonNullable<BffOptions["fetch"]> {
  return async (input) => {
    const path = new URL(input instanceof Request ? input.url : input.toString()).pathname;
    const override = overrides[path];
    if (override !== undefined) return override();

    switch (path) {
      case "/healthz":
        return new Response("", { status: 200 });
      case "/v1/session":
        return jsonAnswer(200, { token: "identity-token-abcdef0123456789", expires_at: "2027-01-15T09:00:00.000Z" });
      case "/v1/me":
        return jsonAnswer(200, { id: "11111111-2222-3333-4444-555555555555", email: "a@example.test" });
      case "/v1/users":
        return jsonAnswer(201, { id: "11111111-2222-3333-4444-555555555555", email: "a@example.test" });
      default:
        return jsonAnswer(404, {});
    }
  };
}

// One named configuration. Both sides are handed the same name and must build the
// same thing from it.
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
      // identically whether the gateway preserves insertion order or sorts, and the
      // property would be untested. `internal/equivalence/scenarios.go`
      // declares the same three names in the same order and says why.
      redis: async (): Promise<ProbeStatus> => "ok",
      identity: async () => {
        throw new Error("dial tcp://identity.internal:8080: no route to host");
      },
      aperture: async (): Promise<ProbeStatus> => "unavailable",
    },
  },

  // # THE BROWSER SURFACE, AND THE `identity` PROBE IT REGISTERS
  //
  // One identity, healthy, and the four `/auth` routes mounted. This is the
  // scenario that compares the `201`/`200`/`204` bodies, the `Set-Cookie`, the
  // origin gate's `403`, and the body-shaped refusals — so it is the one that
  // says whether the port is the reference.
  //
  // The probe is registered by `bff` itself rather than named under `probes`,
  // because that is what `src/index.ts` does: `probes: { identity:
  // identityProbe(bff), … }`. Naming it in `probes` as well would render it TWICE
  // on the reference and once on the Go side, which is a difference in the thing
  // being configured rather than in the port.
  bff: {
    bff: {
      identityUrl: "http://identity.test",
      fetch: scriptedIdentity(),
    },
  },

  // Identity refuses the credential. The upstream body names a cause, and the
  // contract is that it does not reach the browser.
  bffBadCredentials: {
    bff: {
      identityUrl: "http://identity.test",
      fetch: scriptedIdentity({
        "/v1/session": () => jsonAnswer(401, { error: "invalid_credentials", detail: "that password is not correct" }),
      }),
    },
  },

  // An account that does not exist, refused with a DIFFERENT slug and a DIFFERENT
  // detail. The pair exists so the two must be indistinguishable through this
  // gateway: `bffBadCredentials` and this scenario must produce byte-identical
  // answers apart from `trace_id`, and `bff_test.go` asserts that directly.
  bffUnknownAccount: {
    bff: {
      identityUrl: "http://identity.test",
      fetch: scriptedIdentity({
        "/v1/session": () => jsonAnswer(401, { error: "no_such_user", detail: "no account has that email address" }),
      }),
    },
  },

  // A locked account, WITH its window. `423` and `Retry-After` are the mapping the
  // packet calls the contract, and `Retry-After` is one of the header names
  // `internal/equivalence` compares for presence.
  bffAccountLocked: {
    bff: {
      identityUrl: "http://identity.test",
      fetch: scriptedIdentity({
        "/v1/session": () => jsonAnswer(423, { error: "account_locked" }, { "Retry-After": "900" }),
      }),
    },
  },

  // Identity is up and returning 500 — the outage that used to pass through with no
  // log line at all, and the one `unusable()` exists for. `unreachable()` and
  // `unusable()` are two different 503s and this is the one that is NOT
  // "unreachable", so the two must not collapse.
  bffIdentityBroken: {
    bff: {
      identityUrl: "http://identity.test",
      fetch: scriptedIdentity({
        "/v1/session": () => jsonAnswer(500, "<html>identity: undefined is not a function</html>"),
        "/v1/me": () => jsonAnswer(500, "<html>identity: undefined is not a function</html>"),
        "/healthz": () => jsonAnswer(500, ""),
      }),
    },
  },

  // Identity answers 401 on `/v1/me`: it WITHDREW the token. The record is dropped
  // and the cookie cleared, and this scenario compares that shape rather than
  // asserting it.
  bffSessionWithdrawn: {
    bff: {
      identityUrl: "http://identity.test",
      fetch: scriptedIdentity({
        "/v1/me": () => jsonAnswer(401, { error: "unauthorized" }),
      }),
    },
  },
};

// The route table the two routing scenarios share, read out of the environment.
//
// Three entries and three different shapes, in the same order
// `internal/equivalence/scenarios.go` declares them:
//
//   * `/v1/pantry` — no credential. An entry whose absence of a token is
//     meaningful: the upstream must see NO `Authorization` at all.
//   * `/v1/pantry/imports` — a service credential, and a nested prefix so the
//     longest match wins.
//   * `/v1/catalog` — `public: true`. No token and no claims, which is the shape
//     MD18 ruled and the only way to answer without a caller credential.
//
// No entry declares `principal`. The assertion's four properties are covered by
// `internal/httpapi`'s own suite; minting one here would need a signing key on both
// sides and produce a `jti` that differs per mint, which cannot be compared byte for
// byte. That limit is stated in the report rather than hidden here.
function routes(): AppOptions["routes"] {
  const upstream = process.env.GATEWAY_EQUIVALENCE_UPSTREAM?.trim();
  if (!upstream) {
    throw new Error(
      "reference: GATEWAY_EQUIVALENCE_UPSTREAM is not set, so a routing scenario would " +
        "forward to nothing and compare two 503s — which looks like a pass. The runner " +
        "starts a recording upstream and names it here.",
    );
  }

  return {
    "/v1/pantry": { baseUrl: upstream },
    "/v1/pantry/imports": { baseUrl: upstream, token: "equivalence-service-token" },
    "/v1/catalog": { baseUrl: upstream, public: true },
  };
}

const probeForRouting = { redis: async (): Promise<ProbeStatus> => "ok" };

// A route table with **no credential gate**, which is the reference's own state
// when no `jwt` option is configured: `createApp` does not register the token gate,
// so an anonymous request is relayed. That is the configuration in which the
// pass-through's own answers can be compared with nothing above them to soften a
// difference.
SCENARIOS.routedUpstream = { probes: probeForRouting, routes: routes() };

// The same table with the gate in front of it, which is where the standing 401
// comes from: an anonymous caller to a private route, a public route that still
// answers, and a probe that still answers an orchestrator with no credential.
//
// The verifier is configured but never asked to verify anything: no case in the
// comparison carries a bearer token, so `requireJwt` refuses before it reads a key
// set and no JWKS is ever fetched. That is deliberate — the point is the gate's
// ANSWER and its POSITION, and a token that verified would need a key set both sides
// could reach, which is the auth packet's comparison to make.
SCENARIOS.gatedUpstream = {
  probes: probeForRouting,
  routes: routes(),
  jwt: { issuer: "https://identity.localhost", audience: "gateway" },
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

// The readiness line the runner waits for. It goes to stdout because that is
// the only channel a runner reading a subprocess's output has, and it is printed
// AFTER `Bun.serve` so its arrival means the socket is open — a runner that slept
// instead would be a race that passes on a fast machine and fails on a slow one.
const server = Bun.serve({ port, fetch: createApp(options).fetch });
console.log(`reference listening on http://localhost:${server.port} scenario=${scenario}`);