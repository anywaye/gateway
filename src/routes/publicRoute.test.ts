// A routed entry that declares itself public, through the running gateway.
//
// `table.test.ts` holds the field to its own promises — what a `public` value may
// be, and what a resolution says about a path. This file is the other half: the
// gate that reads it, wired the way a deployment runs it, answering the only
// question the flag exists to settle.
//
// ## WHY THIS FILE IS SEPARATE AND NOT A BLOCK IN `proxy.test.ts`
//
// The behaviour under test is the *interaction* of two things that live in
// different files — the route table (`table.ts`) and the token gate
// (`index.ts`) — and neither of them owns it. `proxy.test.ts` asserts what
// crosses to a service, all of it underneath the token gate: every case there
// passes a bearer token, because an app with no verifier serves the pass-through
// to anyone and that is correct and useless as a fixture. A case here does not
// pass a token at all, which is the case none of those can state.
//
// ## WHAT IS ASSERTED, AND THE ONE THAT MATTERS MOST
//
// Four of the tests below are about a public entry: it serves, it is counted, it
// leaks nothing, and it is refused a nonsense value. One is about every OTHER
// entry, and it is the one this packet can most plausibly break.
//
// The trap is that "the proxy path runs without `jwt.requireJwt`" is a sentence
// with three implementations and only one of them is the packet:
//
//   * `if (public)` — one named entry is open. This is the packet.
//   * `if (routes !== null)` — a table exists, so `/v1/*` is open. Everything
//     under the API surface, including `/v1/me` and every future route, with no
//     credential. This is not a weakened packet, it is a deleted gateway.
//   * `if (true)` — the same, and it needs no table at all.
//
// `a non-public entry still answers an anonymous caller with 401` is what tells
// those apart, which is why it is here and not somewhere convenient, and why the
// mutation evidence in REPORT-mvp-guard-public-route-01.md runs it against the
// second spelling rather than only against a missing feature.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { createApp, runtimeOptions } from "../index";
import type { RouteTable } from "./table";
import { DEFAULT_LIMIT_TABLE } from "../middleware/limits";
import { strictTable } from "../../test/limitTable";
import { signToken, startJwksServer, testKey, type JwksServer, type TestKey } from "../../test/jwksServer";

const AUDIENCE = "gateway-test";
const ACCOUNT = "3f2504e0-4f89-41d3-9a0c-0305e82c3301";

/**
 * One public read surface and one private one, under the same table.
 *
 * `/v1/catalog` is the shape the MVP needs — a service whose own OpenAPI says
 * `security: []` for the read path — and `/v1/catalog/imports` is the write
 * surface of that same service, which is NOT public. Shipping the flag with a
 * table that has only one entry in it would leave "and not the write path" as an
 * assumption rather than a measurement.
 */
const TABLE: RouteTable = {
  "/v1/catalog": { baseUrl: "http://catalog.test:8080", public: true },
  "/v1/catalog/imports": { baseUrl: "http://imports.test:8080" },
  "/v1/billing": { baseUrl: "http://billing.test:8080", token: "svc-billing" },
};

type Recorded = { url: string; method: string; headers: Headers };

/** An upstream double that records what it was handed and answers 200. */
function recorder(body: unknown = { items: [] }) {
  const calls: Recorded[] = [];

  return {
    calls,
    fetch: async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
      const request = input instanceof Request ? (init === undefined ? input : new Request(input, init)) : new Request(String(input), init);
      calls.push({ url: request.url, method: request.method, headers: new Headers(request.headers) });

      return Response.json(body);
    },
  };
}

let identity: JwksServer;
let key: TestKey;

beforeAll(async () => {
  key = await testKey("public-key");
  identity = await startJwksServer(key);
});

afterAll(() => identity.stop());

/** A gateway with routing on, a token verifier on, and the given upstream. */
const gateway = (upstream: ReturnType<typeof recorder>, over: Record<string, unknown> = {}) =>
  createApp({
    routes: TABLE,
    proxy: { fetch: upstream.fetch },
    jwt: { issuer: identity.issuer, audience: AUDIENCE },
    ...over,
  });

const token = async (): Promise<string> => {
  const seconds = (offset = 0) => Math.floor(Date.now() / 1000) + offset;

  return signToken(key, {
    iss: identity.issuer,
    aud: AUDIENCE,
    sub: ACCOUNT,
    account_id: ACCOUNT,
    iat: seconds(),
    exp: seconds(60),
    scope: "profile.read",
  });
};

// --------------------------------------------------------- the packet does something

describe("a public entry serves an anonymous caller", () => {
  test("no Authorization header at all, and the service is reached", async () => {
    // THE test the packet exists for. Without it there is no evidence any of the
    // rest happened: a flag that validates, resolves and documents while the gate
    // ignores it is a green suite describing a feature nobody can use.
    const upstream = recorder();

    const res = await gateway(upstream).request("/v1/catalog/items?limit=2");

    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ items: [] });
    expect(upstream.calls).toHaveLength(1);
    expect(upstream.calls[0]?.url).toBe("http://catalog.test:8080/items?limit=2");
  });

  test("a caller who sends a token is served too, and their token is not forwarded", async () => {
    // `public` is about what is *required*, not about what is *refused*. A public
    // entry that rejected a good token would be a second, worse flag: callers who
    // have a credential would be told they may not use it here.
    const upstream = recorder();

    const res = await gateway(upstream).request("/v1/catalog/items", {
      headers: { authorization: `Bearer ${await token()}` },
    });

    expect(res.status).toBe(200);
    // The credential rule is unchanged by the flag, and this is the assertion
    // that says so at the level a caller would notice it: what arrived upstream
    // carries no `authorization` at all.
    expect(upstream.calls[0]?.headers.get("authorization")).toBeNull();
  });

  test("the prefix itself answers, not only paths under it", async () => {
    // `/v1/catalog` is what an operator's health check and a service's own
    // discovery would call, and it is the case a naive `path.startsWith(prefix + "/")`
    // check drops.
    const upstream = recorder();

    const res = await gateway(upstream).request("/v1/catalog");

    expect(res.status).toBe(200);
    expect(upstream.calls[0]?.url).toBe("http://catalog.test:8080/");
  });
});

// ------------------------------------------------------------------ and everything else does not

describe("a non-public entry still answers an anonymous caller with 401", () => {
  test("the write surface of a public service is not public", async () => {
    // The case a broader implementation breaks first: same service, longer
    // prefix, and the openness of the shorter one must not be inherited.
    const upstream = recorder();

    const res = await gateway(upstream).request("/v1/catalog/imports/run");

    expect(res.status).toBe(401);
    expect(res.headers.get("content-type")).toContain("application/problem+json");
    expect(await res.json()).toMatchObject({ code: "unauthorized", detail: "a bearer token is required" });
    // Nothing was sent, so there is no upstream side effect to undo.
    expect(upstream.calls).toHaveLength(0);
  });

  test("a sibling service in the same table is not public either", async () => {
    const upstream = recorder();

    expect((await gateway(upstream).request("/v1/billing/invoices")).status).toBe(401);
    expect(upstream.calls).toHaveLength(0);
  });

  test("a bearer token still works on a non-public entry, so nothing regressed", async () => {
    // The other half of "unchanged": a route that requires a credential has to
    // keep accepting one, or the flag has broken the common path rather than
    // adding one.
    const upstream = recorder();

    const res = await gateway(upstream).request("/v1/billing/invoices", {
      headers: { authorization: `Bearer ${await token()}` },
    });

    expect(res.status).toBe(200);
    expect(upstream.calls[0]?.url).toBe("http://billing.test:8080/invoices");
  });

  test("gateway's own route is untouched, and the whole `/v1/*` surface is not opened", async () => {
    // The claim "one entry, by name". `/v1/me` is registered before the
    // pass-through and is served by gateway whatever the table says, and an
    // unrouted path under `/v1/` is a 401 rather than a pass-through.
    const upstream = recorder();
    const app = gateway(upstream);

    expect((await app.request("/v1/me")).status).toBe(401);
    expect((await app.request("/v1/unrouted")).status).toBe(401);
    expect((await app.request("/v1/unrouted", { headers: { authorization: `Bearer ${await token()}` } })).status).toBe(404);
    // `/auth` was never under the mount and does not become so.
    expect((await app.request("/auth/login", { method: "POST" })).status).toBe(404);
    expect(upstream.calls).toHaveLength(0);
  });

  test("a path the public prefix does not claim on a segment boundary is not open", async () => {
    // `/v1/catalogx` shares a name with the public prefix and shares no subtree
    // with it. If openness were checked with a plain `startsWith` on the raw
    // string rather than the table's own matching rule, this would be served.
    const upstream = recorder();

    expect((await gateway(upstream).request("/v1/catalogx/items")).status).toBe(401);
    expect(upstream.calls).toHaveLength(0);
  });
});

// ----------------------------------------------------------------------------- still bounded

describe("a public route is still rate limited", () => {
  test("the 429 arrives, and the refused request never reached the service", async () => {
    // Anonymous traffic has no account, so the bucket is the client address —
    // `ip:unknown` under `app.request()`, where there is no socket. That is the
    // honest key and it means every anonymous visitor to a public prefix shares
    // one budget. The limiter does not move for this packet, and this is the
    // measurement of that: unbounded anonymous traffic is not what `public`
    // means.
    const upstream = recorder();
    const app = gateway(upstream, { rateLimit: { limits: strictTable(2) } });

    expect((await app.request("/v1/catalog/items")).status).toBe(200);
    expect((await app.request("/v1/catalog/items")).status).toBe(200);

    const refused = await app.request("/v1/catalog/items");
    expect(refused.status).toBe(429);
    expect(refused.headers.get("retry-after")).toBeTruthy();
    // Two requests reached the service; the third was refused above the mount.
    expect(upstream.calls).toHaveLength(2);
  });

  test("the public prefix spends the `gateway-api` budget it shares with the rest of `/v1/`", async () => {
    // "Rate limiting does not change" is the packet's own words, and a per-route
    // allowance for a public prefix would be the quiet way to change it.
    //
    // Read off a refusal rather than off a success, and that is not a detail:
    // `proxy.ts` relays a service's answer as a FRESH `Response`, so the limiter's
    // headers set on the outgoing response do not survive a proxied 2xx and a 200
    // from a routed path carries no `RateLimit-*` at all. That is pre-existing and
    // is reported rather than fixed here; what it means for this packet is that the
    // 429 is the only routed response that can be asked what it was counted
    // against — and an anonymous caller hitting one has no other way to learn it.
    //
    // `RATE_LIMIT_REQUESTS` is not the lever here and its absence is the reason this
    // test derives its table instead: that variable overrides the general default
    // only, and `/v1/` has a *shipped route entry* of its own (`limits.ts:64`),
    // which a deployment cannot lower from the environment. So the table is built
    // from `DEFAULT_LIMIT_TABLE` with that one number reduced — the policy name is
    // read, not written, which is what makes the header assertion the point: it
    // proves the public prefix spends the same named budget as `/v1/me`, not an
    // anonymous bucket somebody invented for it.
    const shipped = DEFAULT_LIMIT_TABLE.routes?.["/v1/"]!;
    const limits = {
      default: DEFAULT_LIMIT_TABLE.default,
      routes: { ...DEFAULT_LIMIT_TABLE.routes, "/v1/": { ...shipped, limit: 2 } },
    };
    const upstream = recorder();
    const app = createApp({
      routes: TABLE,
      proxy: { fetch: upstream.fetch },
      rateLimit: { limits },
      jwt: { issuer: identity.issuer, audience: AUDIENCE },
    });

    expect((await app.request("/v1/catalog/items")).status).toBe(200);
    expect((await app.request("/v1/catalog/items")).status).toBe(200);

    const refused = await app.request("/v1/catalog/items");
    expect(refused.status).toBe(429);
    // q is 2 and the name is the shipped one, which together say "the public
    // prefix is inside `gateway-api`" rather than "there is a public allowance".
    expect(refused.headers.get("ratelimit-policy")).toBe(`"${shipped.policy}";q=2;w=${shipped.windowMs / 1000}`);
    expect(shipped.policy).toBe("gateway-api");
    expect(upstream.calls).toHaveLength(2);
  });

  test("an exhausted public budget does not lock the private surface out, and vice versa", async () => {
    // They are one bucket, which is the documented cost rather than an accident —
    // and it is worth pinning from both sides so a future split is a decision
    // rather than a side effect.
    const upstream = recorder();
    const app = gateway(upstream, { rateLimit: { limits: strictTable(1) } });

    expect((await app.request("/v1/catalog/items")).status).toBe(200);
    expect((await app.request("/v1/catalog/items")).status).toBe(429);
  });
});

// ------------------------------------------------------------------------- and leaks nothing

describe("a public entry does not leak the upstream credential", () => {
  test("a public route carries no upstream `authorization`, and the response names nothing", async () => {
    // Half of the answer is that it CANNOT carry one: `public: true` with a
    // `token` refuses to boot (`table.test.ts`), so there is no credential on a
    // public entry to leak. Half is that the proxy's allowlist still holds —
    // asserted here against the request that actually crossed, not against the
    // function that builds it, for the reason `proxy.ts` gives.
    const upstream = recorder();

    const res = await gateway(upstream).request("/v1/catalog/items");
    const body = await res.text();

    expect(upstream.calls[0]?.headers.get("authorization")).toBeNull();
    expect(body).not.toContain("catalog.test");
    // And nothing that would identify the deployment: a relayed `set-cookie` is
    // dropped by `proxy.ts`, and `cache-control: no-store` is added rather than
    // forwarded, so a public response cannot be cached into a shared cache by
    // accident either.
    expect(res.headers.get("set-cookie")).toBeNull();
  });

  test("a private entry's token does not come back to the caller either", async () => {
    // The flag is additive, so the pre-existing rule has to still hold on the
    // entry that does have a credential: gateway attaches it, and the caller never
    // learns it. Asserted on the response, not on the absence of an error.
    const upstream = recorder();

    const res = await gateway(upstream).request("/v1/billing/invoices", {
      headers: { authorization: `Bearer ${await token()}` },
    });
    const body = await res.text();

    expect(upstream.calls[0]?.headers.get("authorization")).toBe("Bearer svc-billing");
    expect(body).not.toContain("svc-billing");
    expect(res.headers.get("authorization")).toBeNull();
    expect(body).not.toContain("billing.test");
  });

  test("a caller's own credential is not reflected back either", async () => {
    // The confused-deputy line holds at the edge for anonymous callers too: what
    // a caller sends is theirs, and none of it crosses to the service.
    const upstream = recorder();
    const secret = await token();

    const res = await gateway(upstream).request("/v1/catalog/items", {
      headers: { authorization: `Bearer ${secret}`, cookie: "session=someone-elses" },
    });

    expect(res.status).toBe(200);
    expect(upstream.calls[0]?.headers.get("authorization")).toBeNull();
    expect(upstream.calls[0]?.headers.get("cookie")).toBeNull();
    expect(await res.text()).not.toContain(secret);
  });
});

// ------------------------------------------------------------------------- refused at startup

describe("startup refuses a `public` that does not mean what it says", () => {
  test("a string, through both the environment and the constructor", async () => {
    // The route table's own gate is the only gate — `runtimeOptions` re-reads it
    // rather than re-implementing it — so a shape refused through one is refused
    // through the other, and the assertion is made on both so that stays true.
    const cases = [
      JSON.stringify({ "/v1/catalog": { baseUrl: "http://c.test:8080", public: "true" } }),
      JSON.stringify({ "/v1/catalog": { baseUrl: "http://c.test:8080", public: 1 } }),
      JSON.stringify({ "/v1/catalog": { baseUrl: "http://c.test:8080", public: true, token: "svc" } }),
    ];

    for (const ROUTE_TABLE of cases) {
      expect(() => runtimeOptions({ ROUTE_TABLE }), ROUTE_TABLE).toThrow(RangeError);
      expect(() => createApp({ routes: JSON.parse(ROUTE_TABLE) as RouteTable }), ROUTE_TABLE).toThrow(RangeError);
    }
  });

  test("the refusal names the prefix and the value, so an operator can fix it", () => {
    let message = "";
    try {
      createApp({ routes: { "/v1/catalog": { baseUrl: "http://c.test", public: "true" } as never } });
    } catch (error) {
      message = (error as Error).message;
    }

    expect(message).toContain("/v1/catalog");
    expect(message).toContain('"true"');
    // It says what to type instead, which is the half an operator needs at 3am.
    expect(message).toContain("without quotes");
  });

  test("a table with a public entry still builds an app, and only then", () => {
    // The positive control for the two refusals above: the rule is about the
    // value, not about the word `public` appearing in a table.
    expect(() =>
      createApp({ routes: { "/v1/catalog": { baseUrl: "http://c.test", public: true } } }),
    ).not.toThrow();
  });
});