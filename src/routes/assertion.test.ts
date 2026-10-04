// The principal assertion, through the running gateway.
//
// `table.test.ts` holds `principal` to its own promises and `proxy.test.ts` holds
// the credential allowlist. This file is the interaction neither of them owns:
// the token gate resolving a caller, the table saying what the upstream needs, and
// the pass-through signing it — asserted **through the request that crossed**, not
// against the function that built it, for the reason `proxy.ts` gives about
// asserting on a recorded request rather than on a helper.
//
// ## MD19'S FOUR PROPERTIES, AND WHERE EACH ONE IS ANSWERED HERE
//
//   1. **Never on a public route.** Two describes. `a public route carries no
//      assertion` is the *send site*, and `a public entry that declares principal
//      claims refuses to boot` is the *configuration*, because MD19's property is
//      enforced in two places on purpose. `src/routes/proxy.test.ts` covers the
//      proxy's own gate; this file covers the whole gateway, including the boot
//      refusal, which is the one a caller would never see.
//   2. **Not the caller's token, ever.** `the assertion is not the caller's token,
//      byte for byte`, plus the two stronger readings of the same property: it
//      does not verify against *identity's* key set, and a caller who is refused
//      at the edge cannot get their token in front of a service either.
//   3. **Bound to the upstream, and short-lived.** `it does not verify for a
//      different upstream, or after expiry` — both halves, because "bound" and
//      "short-lived" fail independently and a test that checks only the audience
//      passes just as happily against a token good for a week.
//   4. **Minimal claims.** `the assertion carries the declared claims and nothing
//      else`, and the case that earns it: a claim the caller's token does not
//      carry is **omitted**, so pantry sees "no publisher record" rather than a
//      token that says something untrue.
//
// Plus the standing one MD18 promised, restated here rather than assumed:
// **an anonymous caller to a private route still gets 401** with the signing key
// configured. `publicRoute.test.ts` holds that with no key configured; this file
// holds it with one, because a feature that put a key in the path is exactly how
// it would break.
//
// ## WHY EVERY PROPERTY HAS A MUTATION RECORD
//
// REPORT-mvp-guard-principal-01.md carries one per property, with the file the
// change was made in and the diff printed, because a mutation nobody can see
// applied is a green that proves nothing. Each of the four was made absent, the
// suite was observed red **on the named test**, and the change was reverted.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { createPublicKey, generateKeyPairSync } from "node:crypto";
import { calculateJwkThumbprint, createLocalJWKSet, decodeProtectedHeader, exportJWK, jwtVerify } from "jose";
import { Hono } from "hono";
import { createApp } from "../index";
import { ASSERTION_HEADER, createAssertionMinter, readAssertionKey } from "./assertion";
import { createRouteProxy } from "./proxy";
import { ROUTE_MOUNT, type RouteTable } from "./table";
import type { AuthEnv } from "../middleware/jwt";
import { signToken, startJwksServer, testKey, type JwksServer, type TestKey } from "../../test/jwksServer";

const AUDIENCE = "gateway-test";
const CALLER = "3f2504e0-4f89-41d3-9a0c-0305e82c3301";
const PUBLISHER = "583454";

/**
 * One public read surface, one private surface that declares what it needs, and
 * one private surface that declares nothing.
 *
 * The third entry is not padding. "An upstream that declared no claims gets no
 * assertion" is the rule that keeps a credential from being handed to a service
 * that never asked for one, and it can only be measured against a sibling entry
 * in the *same* table that did declare — otherwise a test would pass with the
 * feature switched off entirely, which is the failure mode every test in this
 * file is written against.
 *
 * Two private entries also share the shape MD19 needs: `/v1/pantry/services` and
 * `/v1/other/thing` resolve to different origins, so an assertion minted for one
 * can be offered to the other and refused.
 */
const TABLE: RouteTable = {
  "/v1/catalog": { baseUrl: "http://catalog.test:8080", public: true },
  "/v1/pantry/services": { baseUrl: "http://pantry.test:8080", principal: ["sub", "github_id"] },
  "/v1/other/thing": { baseUrl: "http://other.test:9090", token: "svc-other", principal: ["account_id"] },
  "/v1/billing": { baseUrl: "http://billing.test:8080", token: "svc-billing" },
};

type Recorded = { url: string; method: string; headers: Headers };

/** An upstream double that records what it was handed and answers 200. */
function recorder(body: unknown = { ok: true }) {
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
let identityKey: TestKey;

/**
 * gateway's OWN signing key, as the configuration path produces it.
 *
 * Generated with Node rather than with `testKey` so the bytes go through the same
 * `createPrivateKey` path a real PEM takes, which is the thing that makes a
 * malformed key a startup error — a key built through jose's own API would skip
 * that code and leave it unmeasured.
 */
const signingPem = generateKeyPairSync("rsa", { modulusLength: 2048 }).privateKey.export({
  type: "pkcs8",
  format: "pem",
}) as string;

const signingKey = readAssertionKey(signingPem);

/**
 * gateway's key set, which is the only thing that may verify an assertion.
 *
 * Derived from the same PEM the gateway signs with rather than generated beside
 * it: two key pairs that happen to look alike are how a fixture ends up proving
 * nothing, because a token signed by one and verified against the other fails for
 * a reason the assertion has nothing to do with.
 */
let gatewayKeys: ReturnType<typeof createLocalJWKSet>;

beforeAll(async () => {
  identityKey = await testKey("identity-key");
  identity = await startJwksServer(identityKey);

  const bare = await exportJWK(createPublicKey(createPublicKey(signingPem).export({ type: "spki", format: "pem" })) as never);
  const kid = await calculateJwkThumbprint(bare as never, "sha256");
  gatewayKeys = createLocalJWKSet({ keys: [{ ...bare, kid, alg: "RS256", use: "sig" }] });
});

afterAll(() => identity.stop());

/** A gateway with routing, a token verifier and the assertion signer all on. */
const gateway = (upstream: ReturnType<typeof recorder>, over: Record<string, unknown> = {}) =>
  createApp({
    routes: TABLE,
    proxy: { fetch: upstream.fetch },
    jwt: { issuer: identity.issuer, audience: AUDIENCE },
    assertion: { key: signingKey },
    ...over,
  });

/** A caller's token, with `github_id` so the pantry surface has something to assert. */
const callerToken = async (claims: Record<string, unknown> = {}): Promise<string> => {
  const seconds = (offset = 0) => Math.floor(Date.now() / 1000) + offset;

  return signToken(identityKey, {
    iss: identity.issuer,
    aud: AUDIENCE,
    sub: CALLER,
    account_id: CALLER,
    github_id: PUBLISHER,
    scope: "profile.read catalog.read",
    iat: seconds(),
    exp: seconds(60),
    ...claims,
  });
};

/** The signed header a recorded upstream call was handed, or null. */
const asserted = (upstream: ReturnType<typeof recorder>, call = 0): string | null =>
  upstream.calls[call]?.headers.get(ASSERTION_HEADER) ?? null;

// ============================================================ property 1: never on a public route

describe("a public route carries no assertion", () => {
  test("the signed header is absent from a public prefix, with the signer configured", async () => {
    // THE test for property 1 at the send site, and the reason it is written
    // against a *public* entry in a table whose siblings declare claims: a test
    // with no private entries anywhere would pass with the feature switched off,
    // and a green that cannot tell those apart is not evidence.
    const upstream = recorder();

    const res = await gateway(upstream).request("/v1/catalog/items", {
      headers: { authorization: `Bearer ${await callerToken()}` },
    });

    expect(res.status).toBe(200);
    expect(upstream.calls).toHaveLength(1);
    expect(asserted(upstream)).toBeNull();
    // The whole header set, not just the one header under test. `/v1/catalog` is
    // a `public` entry, so it cannot carry a `token` (the table refuses the
    // combination), the caller sent no `accept`, and therefore an empty set is
    // the honest expectation — a `public` route crosses with *nothing* gateway
    // invented. Enumerating is what makes this an assertion about the absence of
    // every header rather than about one name.
    expect([...upstream.calls[0]!.headers.keys()]).toEqual([]);
  });

  test("an anonymous caller to a public prefix gets no assertion either", async () => {
    // The other half of the property. "Never on a public route" that meant "never
    // for an identified caller on a public route" would be a rule about tokens
    // rather than about routes, and the public route is defined by the *absence*
    // of a caller.
    const upstream = recorder();

    const res = await gateway(upstream).request("/v1/catalog/items");

    expect(res.status).toBe(200);
    expect(asserted(upstream)).toBeNull();
  });

  test("a public entry that declares principal claims refuses to boot", async () => {
    // The same property as a *configuration* refusal, and the half no caller
    // would ever observe. It is here because it is the gate that makes the send
    // site's check redundant rather than load-bearing, and a gate nobody reads
    // is a gate nobody maintains.
    expect(() =>
      createApp({
        routes: {
          "/v1/catalog": { baseUrl: "http://catalog.test:8080", public: true, principal: ["sub"] },
        } as RouteTable,
        jwt: { issuer: identity.issuer, audience: AUDIENCE },
        assertion: { key: signingKey },
      }),
    ).toThrow(RangeError);

    let message = "";
    try {
      createApp({
        routes: { "/v1/catalog": { baseUrl: "http://c.test:8080", public: true, principal: ["sub"] } } as RouteTable,
      });
    } catch (error) {
      message = (error as Error).message;
    }
    // It names both fields, because "drop principal" and "drop public" are the
    // two ways out and an operator needs to know they are both available.
    expect(message).toContain("/v1/catalog");
    expect(message).toContain("principal");
    expect(message).toContain("public");
    expect(message).toContain('drop "public"');
  });

  test("the send site refuses on its own, with a table `routeTable` would have refused", async () => {
    // Why this test exists at all, and it is the most important comment in the
    // file: **without it, the send site's half of property 1 is a green by
    // omission.**
    //
    // `routeTable` refuses `public` together with `principal`, so through
    // `createApp` there is no way to reach a public entry that declares claims —
    // and the test above, which uses the real table, would go green whether or not
    // `proxy.ts` checks `route.public` at all. A check that cannot be reached by
    // any input is not a check, and the report for this packet carries the
    // measured mutation that proves the difference: removing this one line turns
    // THIS test red while the one above stays green.
    //
    // So this builds the pass-through directly, the way `proxy.test.ts` does,
    // with a table that has not been through the validator, and asserts the
    // header is still absent. The validator and the send site are two gates; this
    // is what keeps the second one honest instead of decorative.
    const upstream = recorder();
    const app = new Hono<AuthEnv>();
    app.use(
      "*",
      async (c, next) => {
        c.set("principal", {
          sub: CALLER,
          accountId: CALLER,
          scope: ["catalog.read"],
          claims: { sub: CALLER, account_id: CALLER },
        });
        await next();
      },
    );
    app.use(
      ROUTE_MOUNT,
      createRouteProxy({
        routes: {
          "/v1/catalog": { baseUrl: "http://catalog.test:8080", public: true, principal: ["sub"] },
          "/v1/private": { baseUrl: "http://private.test:8080", principal: ["sub"] },
        } as RouteTable,
        fetch: upstream.fetch,
        assertion: createAssertionMinter({ key: signingKey }),
      }),
    );

    await app.request("/v1/catalog/items");
    // The control, in the same app and the same table: the private sibling DOES
    // get one. Without this the test would also pass if the minter were broken.
    await app.request("/v1/private/items");

    expect(upstream.calls).toHaveLength(2);
    expect(upstream.calls[0]?.headers.get(ASSERTION_HEADER)).toBeNull();
    expect(upstream.calls[1]?.headers.get(ASSERTION_HEADER)).not.toBeNull();
  });

  test("a longer private prefix under a public one still gets one, so the rule is per entry", async () => {
    // The negative control for the rule above, and the reason property 1 is "per
    // entry" rather than "per service". `/v1/catalog/imports` is the write
    // surface of the very service whose read surface is public; if the shortest
    // prefix won, this would be a second anonymous mount and a second route with
    // no assertion.
    const upstream = recorder();
    const app = createApp({
      routes: {
        "/v1/catalog": { baseUrl: "http://catalog.test:8080", public: true },
        "/v1/catalog/imports": { baseUrl: "http://imports.test:8080", principal: ["sub"] },
      } as RouteTable,
      proxy: { fetch: upstream.fetch },
      jwt: { issuer: identity.issuer, audience: AUDIENCE },
      assertion: { key: signingKey },
    });

    const res = await app.request("/v1/catalog/imports/run", {
      headers: { authorization: `Bearer ${await callerToken()}` },
    });

    expect(res.status).toBe(200);
    expect(asserted(upstream)).not.toBeNull();
  });
});

// ===================================================== property 2: not the caller's token, ever

describe("the assertion is not the caller's token, byte for byte", () => {
  test("the header is a different string, and not the caller's `Authorization`", async () => {
    const upstream = recorder();
    const secret = await callerToken();

    const res = await gateway(upstream).request("/v1/pantry/services", {
      headers: { authorization: `Bearer ${secret}` },
    });

    expect(res.status).toBe(200);
    const sent = asserted(upstream);
    expect(sent).not.toBeNull();
    // The byte-for-byte half, stated as the operator would find it: the string in
    // the signed header is not the string that came in on `Authorization`. This
    // is the check that would go red if someone ever "simplified" the assertion
    // into forwarding the caller's credential, which is the exact refactor MD19's
    // second property exists to stop.
    expect(sent).not.toBe(secret);
    expect(`Bearer ${sent}`).not.toBe(secret);
    // And it is a JWT gateway signed, not one identity signed.
    expect(decodeProtectedHeader(sent!).alg).toBe("RS256");
    expect(decodeProtectedHeader(sent!).kid).not.toBe(identityKey.kid);
    expect(await res.text()).not.toContain(secret);
  });

  test("it does not verify against identity's key set, only against gateway's", async () => {
    // The stronger reading of the same property, and the one that would catch a
    // future "let's just re-use the JWKS we already have" edit — which is the
    // tempting wrong answer, because gateway already holds that machinery.
    //
    // It is deliberately two assertions. A token that verifies under *neither* key
    // set would pass "not the caller's token" and fail every real use, so the
    // positive half is here to say the failure would be a refusal and not silence.
    const upstream = recorder();

    await gateway(upstream).request("/v1/pantry/services", {
      headers: { authorization: `Bearer ${await callerToken()}` },
    });

    const sent = asserted(upstream)!;
    const theirs = createLocalJWKSet({ keys: [identityKey.jwk] });
    const ours = gatewayKeys;

    await expect(jwtVerify(sent, theirs, { audience: "http://pantry.test:8080" })).rejects.toThrow();
    await expect(jwtVerify(sent, ours, { audience: "http://pantry.test:8080" })).resolves.toBeDefined();
  });

  test("a caller refused at the edge gets their token in front of no service at all", async () => {
    // The confused-deputy line, held at the level the reader cares about. A token
    // that does not verify never reaches the proxy, so it cannot be forwarded —
    // and an assertion is not a way around that, because the assertion is minted
    // from a principal the gate produced rather than from a header the caller
    // chose.
    const upstream = recorder();
    const forged = await signToken(await testKey("attacker-key"), {
      iss: identity.issuer,
      aud: AUDIENCE,
      sub: "somebody-else",
      account_id: "somebody-else",
      exp: Math.floor(Date.now() / 1000) + 60,
    });

    const res = await gateway(upstream).request("/v1/pantry/services", {
      headers: { authorization: `Bearer ${forged}` },
    });

    expect(res.status).toBe(401);
    expect(upstream.calls).toHaveLength(0);
  });
});

// ============================================== property 3: bound to the upstream, and short-lived

describe("it does not verify for a different upstream, or after expiry", () => {
  test("the audience is the upstream it was minted for, and another one refuses it", async () => {
    const upstream = recorder();

    await gateway(upstream).request("/v1/pantry/services", {
      headers: { authorization: `Bearer ${await callerToken()}` },
    });

    const sent = asserted(upstream)!;
    const keys = gatewayKeys;

    // Positive first, so a refusal below is evidence about the audience rather
    // than about a token that does not verify at all.
    await expect(
      jwtVerify(sent, keys, { audience: "http://pantry.test:8080", issuer: undefined }),
    ).resolves.toBeDefined();

    // The property: a leaked assertion is worth nothing on any other upstream.
    await expect(jwtVerify(sent, keys, { audience: "http://other.test:9090" })).rejects.toThrow();
    await expect(jwtVerify(sent, keys, { audience: "http://catalog.test:8080" })).rejects.toThrow();
  });

  test("an assertion minted for one upstream is not accepted by a sibling's verifier", async () => {
    // The same property measured the way a deployment would hit it: the recorded
    // request to `/v1/other/thing` carries its own assertion, and it is a
    // *different* one for the same caller on the same second. Both halves — a
    // per-request `jti`, and an audience that follows the route — are asserted on
    // the bytes that crossed rather than on the minter's return value.
    const upstream = recorder();

    await gateway(upstream).request("/v1/pantry/services", {
      headers: { authorization: `Bearer ${await callerToken()}` },
    });
    const forPantry = asserted(upstream, 0)!;

    await gateway(upstream).request("/v1/other/thing", {
      headers: { authorization: `Bearer ${await callerToken()}` },
    });
    const forOther = asserted(upstream, 1)!;

    expect(forOther).not.toBe(forPantry);
    const keys = gatewayKeys;
    await expect(jwtVerify(forPantry, keys, { audience: "http://other.test:9090" })).rejects.toThrow();
    await expect(jwtVerify(forOther, keys, { audience: "http://other.test:9090" })).resolves.toBeDefined();
    // And the service credential is still what `authorization` carries — two
    // credentials, two headers, neither having replaced the other.
    expect(upstream.calls[1]?.headers.get("authorization")).toBe("Bearer svc-other");
  });

  test("it stops verifying once the window has passed", async () => {
    // "Short-lived" is its own property and a test about the audience alone would
    // pass just as happily against a token good for a week. The clock is injected
    // so this is exact rather than approximate — a test that slept for the TTL
    // would be slow, and then skipped, and a skipped expiry test is the same
    // absent test with extra steps.
    let clock = 1_700_000_000_000;
    const upstream = recorder();
    const app = gateway(upstream, { assertion: { key: signingKey, ttlMs: 120_000, now: () => clock } });

    await app.request("/v1/pantry/services", { headers: { authorization: `Bearer ${await callerToken()}` } });
    const sent = asserted(upstream)!;
    const keys = gatewayKeys;

    const verdict = { issuer: undefined, audience: "http://pantry.test:8080" } as const;
    // One second past `exp`. jose compares against `exp` exclusive, so a token is
    // dead the instant its window closes rather than the instant after.
    //
    // `currentDate` is passed on BOTH checks rather than only the second. The
    // injected clock is a fixed epoch so the assertion is exact rather than
    // approximate, which means the token is minted in the past relative to the
    // wall clock — and a "before" check that let jose use the real now would be a
    // check that said "expired" and called it valid.
    const at = () => new Date(clock);
    const before = await jwtVerify(sent, keys, { ...verdict, currentDate: at() }).then(() => "valid", () => "refused");
    expect(before).toBe("valid");

    clock += 121_000;
    const after = await jwtVerify(sent, keys, { ...verdict, currentDate: at() }).then(() => "valid", () => "refused");
    expect(after).toBe("refused");
    // Named, because "refused" for any reason is the same word: this is expiry,
    // not a claim that stopped matching.
    await expect(jwtVerify(sent, keys, { ...verdict, currentDate: at() })).rejects.toMatchObject({
      code: "ERR_JWT_EXPIRED",
    });
  });

  test("a lifetime longer than the ceiling is refused at startup", async () => {
    // The ceiling is what makes "short-lived" a property rather than a default
    // somebody can configure away. `30d` has to be a refusal to boot naming the
    // maximum, or the default is the only thing enforcing it.
    expect(() =>
      createApp({
        routes: TABLE,
        jwt: { issuer: identity.issuer, audience: AUDIENCE },
        assertion: { key: signingKey, ttlMs: 86_400_000 },
      }),
    ).toThrow(/at most 600000/);
  });
});

// ============================================================ property 4: minimal claims

describe("the assertion carries the declared claims and nothing else", () => {
  test("the declared names are there, in the token's own shape, and the rest is not", async () => {
    const upstream = recorder();

    await gateway(upstream).request("/v1/pantry/services", {
      headers: { authorization: `Bearer ${await callerToken()}` },
    });

    const { payload } = await jwtVerify(asserted(upstream)!, gatewayKeys, {
      audience: "http://pantry.test:8080",
    });

    // What the upstream declared it needs. `github_id` is the claim MD19's ruling
    // is about: `pantry.current_publisher_id()` has nothing to compare without it,
    // which is the entire reason this header exists.
    expect(payload.sub).toBe(CALLER);
    expect(payload.github_id).toBe(PUBLISHER);
    // NOT declared, therefore NOT asserted — `account_id` and `scope` are on the
    // caller's token and are absent from the assertion. This is the assertion that
    // makes the word "minimal" mean something: a set that grew to "all the claims
    // the token had" would still verify, and would still work, and would have
    // quietly stopped being minimal.
    expect(payload).not.toHaveProperty("account_id");
    expect(payload).not.toHaveProperty("scope");
    // And the envelope is gateway's: an upstream knows who minted it, when, and for
    // how long.
    expect(Object.keys(payload).sort()).toEqual(["aud", "exp", "github_id", "iat", "iss", "jti", "sub"]);
  });

  test("a claim the caller's token does not carry is omitted rather than invented", async () => {
    // The case that earns MD19's "a publisher who has no row simply gets a
    // 404-shaped 'no publisher record'". That refusal only happens if a token with
    // no `github_id` reaches pantry as a token with no `github_id`. Inventing an
    // empty one, or refusing the request at the edge, would each replace it with
    // something the RLS predicates cannot express.
    const upstream = recorder();

    await gateway(upstream).request("/v1/pantry/services", {
      headers: { authorization: `Bearer ${await callerToken({ github_id: undefined })}` },
    });

    const { payload } = await jwtVerify(asserted(upstream)!, gatewayKeys, {
      audience: "http://pantry.test:8080",
    });

    expect(payload).not.toHaveProperty("github_id");
    expect(payload.sub).toBe(CALLER);
  });

  test("a route that declared no claims gets no assertion, even with the signer on", async () => {
    // The "no wildcard" half of the rule. `/v1/billing` in the table above is a
    // private entry that declared nothing, and its sibling declared two claims —
    // so this cannot pass by the feature being off.
    const upstream = recorder();

    const res = await gateway(upstream).request("/v1/billing/invoices", {
      headers: { authorization: `Bearer ${await callerToken()}` },
    });

    expect(res.status).toBe(200);
    expect(asserted(upstream)).toBeNull();
    // The service credential still crosses, so this is "no assertion" and not "no
    // credentials at all".
    expect(upstream.calls[0]?.headers.get("authorization")).toBe("Bearer svc-billing");
  });

  test("a deployment with no signing key sends nothing new", async () => {
    // The additive property, and the one that makes this safe to merge into a
    // running gateway: an unconfigured gateway forwards exactly the headers it
    // forwarded before this feature existed. Measured on `/v1/other/thing` rather
    // than on a route with no `token`, because that entry has a service credential
    // as well as a declaration — so the assertion can say "the service credential
    // crossed and the assertion did not", which is the distinction an operator
    // would be checking.
    const upstream = recorder();
    const app = createApp({
      routes: TABLE,
      proxy: { fetch: upstream.fetch },
      jwt: { issuer: identity.issuer, audience: AUDIENCE },
    });

    const res = await app.request("/v1/other/thing", {
      headers: { authorization: `Bearer ${await callerToken()}` },
    });

    expect(res.status).toBe(200);
    expect(asserted(upstream)).toBeNull();
    expect([...upstream.calls[0]!.headers.keys()]).toEqual(["authorization"]);
  });

  test("a reserved claim name is refused, so an entry cannot mint its own audience", async () => {
    // The check that keeps property 3 from being operator-defeatable: an entry
    // naming `aud` would be choosing which upstream its assertion verifies for,
    // which is the one thing gateway must decide. And the envelope spread in
    // `assertion.ts` is the second gate on the same property, so removing this
    // refusal does not make the audience writable — it makes the *configuration*
    // silently wrong instead.
    for (const name of ["aud", "iss", "exp", "nbf", "iat", "jti"]) {
      expect(
        () => createApp({ routes: { "/v1/x": { baseUrl: "http://x.test", principal: [name] } } as RouteTable }),
        name,
      ).toThrow(RangeError);
    }

    let message = "";
    try {
      createApp({ routes: { "/v1/x": { baseUrl: "http://x.test", principal: ["aud"] } } as RouteTable });
    } catch (error) {
      message = (error as Error).message;
    }
    expect(message).toContain('may not name "aud"');
  });

  test("an empty list and a wildcard are both refused, because neither is 'no claims'", async () => {
    // `[]` is refused because it is NOT the same as omitting the field, and the
    // difference is the whole contract. `"*"` is refused because it is the shape
    // that would quietly turn minimal claims into the caller's whole JWT — which is
    // the one outcome the field exists to prevent, arrived at by an operator who
    // thought they were being helpful.
    for (const principal of [[], ["*"], "sub", ["sub", "sub account_id"]] as unknown[]) {
      expect(
        () => createApp({ routes: { "/v1/x": { baseUrl: "http://x.test", principal } } as unknown as RouteTable }),
        JSON.stringify(principal),
      ).toThrow(RangeError);
    }

    let wildcard = "";
    try {
      createApp({ routes: { "/v1/x": { baseUrl: "http://x.test", principal: ["*"] } } as RouteTable });
    } catch (error) {
      wildcard = (error as Error).message;
    }
    expect(wildcard).toContain('may not name "*"');
  });
});

// ================================================= and MD18's promise still holds

describe("the published key set is the public half and nothing else", () => {
  test("it carries no private parameter, which `exportJWK` would otherwise have included", async () => {
    // A defect this packet FOUND IN ITS OWN FIRST DRAFT, so the tripwire earns its
    // place rather than decorating.
    //
    // `exportJWK` given a Node **private** `KeyObject` returns
    // `kty, n, e, d, p, q, dp, dq, qi` — the whole private key, RSA primes
    // included. The first draft of `publish` exported the private key it had been
    // handed, and nothing about the result would have looked wrong: the key id is
    // still correct, because RFC 7638 hashes only `e`, `kty` and `n`, and every
    // signature still verifies. So the only way to catch it is to name the fields.
    //
    // Asserted as an exact set rather than as "not to contain `d`", because the
    // failure mode is a *new* private parameter added by a library upgrade and an
    // exact list is what notices that.
    const minter = createAssertionMinter({ key: signingKey });

    expect(Object.keys(await minter.publicJwk()).sort()).toEqual(["alg", "e", "kid", "kty", "n", "use"]);
  });

  test("and it is the key the assertion actually signed with", async () => {
    // The positive half: a published key set that is not the signing key is also a
    // failure, and it would be a *quieter* one than the leak above — every upstream
    // would refuse every assertion rather than any upstream learning anything.
    const minter = createAssertionMinter({ key: signingKey });
    const jwk = await minter.publicJwk();
    const token = await minter.mint(
      { sub: CALLER, accountId: CALLER, scope: [], claims: { sub: CALLER } },
      { audience: "http://pantry.test:8080", claims: ["sub"] },
    );

    expect(decodeProtectedHeader(token).kid).toBe(jwk.kid);
    await expect(jwtVerify(token, createLocalJWKSet({ keys: [jwk] }), { audience: "http://pantry.test:8080" })).resolves.toBeDefined();
  });

  test("the key id defaults to the public key's thumbprint, and an explicit one is kept", async () => {
    // The default cannot be a constant, and it cannot be an operator-invented
    // string: two deployments both calling their key `gateway-1` is a key set in
    // which an upstream verifies against the wrong deployment's key, silently.
    // A thumbprint cannot collide across keys.
    const derived = await createAssertionMinter({ key: signingKey }).publicJwk();
    const named = await createAssertionMinter({ key: readAssertionKey(signingPem, "gateway-one") }).publicJwk();

    expect(derived.kid).not.toBe(named.kid);
    expect(named.kid).toBe("gateway-one");
    // It is a JWK thumbprint and not a hex digest of something else: 43 base64url
    // characters, no padding.
    expect(derived.kid).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });
});

describe("an anonymous caller to a private route still gets 401", () => {
  test("with the assertion signer configured, on a route that declares claims", async () => {
    // MD18 promised this and this feature is the most plausible way to break it:
    // the mint runs before the fetch, and a route that *wants* an assertion is
    // exactly the route where a refactor could mint one for nobody and let the
    // request through. `publicRoute.test.ts` holds the same answer with no signer
    // configured; holding it here is what makes it a property of the feature
    // rather than of the default.
    const upstream = recorder();

    const res = await gateway(upstream).request("/v1/pantry/services");

    expect(res.status).toBe(401);
    expect(res.headers.get("content-type")).toContain("application/problem+json");
    expect(await res.json()).toMatchObject({ code: "unauthorized", detail: "a bearer token is required" });
    // No service was contacted, so there is no upstream side effect to undo and no
    // assertion to have leaked.
    expect(upstream.calls).toHaveLength(0);
  });

  test("and a token that does not verify is refused before the signer is reached", async () => {
    // Ordering, stated as an outcome. The bearer gate is registered before the
    // pass-through, so a forged token never produces a mint — and an assertion is
    // gateway's signature, so one arriving from a caller rather than from a verified
    // principal would be the whole confused-deputy problem in one header.
    const upstream = recorder();

    expect(
      (await gateway(upstream).request("/v1/pantry/services", { headers: { authorization: "Bearer not-a-jwt" } })).status,
    ).toBe(401);
    expect(upstream.calls).toHaveLength(0);
  });
});