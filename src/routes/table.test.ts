// The route table, held to what it promises.
//
// Every case here is a negative one, and that is deliberate: a table that maps
// `/v1/pantry` to `http://pantry:8080` is not in doubt — `resolveRoute` returning
// the row is the trivial half. What is in doubt is every value an operator can
// type, because the failure mode of a routing table is a request that is
// authenticated and then goes somewhere nobody intended.
//
// The bar each case holds to is the one the rest of this repository holds to:
// a malformed value is a `RangeError` at construction, never a default that
// forwards somewhere, and the message names the field and the value.
import { describe, expect, test } from "bun:test";
import { isPublicRoute, resolveRoute, ROUTE_MOUNT, routeTable, type RouteTable } from "./table";

/** A table with one service, which is the shape most of these cases mutate. */
const one: RouteTable = { "/v1/pantry": { baseUrl: "http://pantry.test:8080" } };

describe("a valid table", () => {
  test("it keeps what it was given, with the trailing slash and the port", () => {
    // Trailing slashes are what an operator types out of habit, and dropping
    // them here is what stops them joining into `//v1/items` downstream. A table
    // that refused one would be a table whose error message teaches nothing.
    const checked = routeTable({ "/v1/pantry": { baseUrl: "http://pantry.test:8080/" } });

    expect(checked["/v1/pantry"]?.baseUrl).toBe("http://pantry.test:8080");
  });

  test("a token is carried, and its absence is not the same as an empty one", () => {
    expect(routeTable({ "/v1/pantry": { baseUrl: "http://p.test", token: "svc-pantry" } })["/v1/pantry"]).toEqual({
      baseUrl: "http://p.test",
      token: "svc-pantry",
    });
    // `token: undefined` and no `token` are the same upstream, and the check
    // keeps them that way: an entry with a key set to nothing is a deployment
    // that meant to configure a credential and did not.
    expect(routeTable({ "/v1/pantry": { baseUrl: "http://p.test", token: undefined } })["/v1/pantry"]).toEqual({
      baseUrl: "http://p.test",
      token: undefined,
    });
  });

  test("the whole API surface is a legal prefix", () => {
    // `/v1` claims every path under the mount, which is the shape a deployment
    // gets when one service owns the API surface — including gateway's own
    // `/v1/me`, which stays gateway's because it is registered first.
    expect(() => routeTable({ "/v1": { baseUrl: "http://identity.test" } })).not.toThrow();
  });

  test("the returned table is a copy, so neither side can add to it afterwards", () => {
    // `limitTable` returns a copy for this reason. A caller reaching into the
    // object the validator returned would add a prefix nothing checked, and a
    // caller reaching into the object it passed would change a validated table
    // into an unvalidated one without going near the validator.
    const input: RouteTable = { "/v1/pantry": { baseUrl: "http://pantry.test:8080" } };
    const table = routeTable(input);

    expect(table).not.toBe(input);
    table["/v1/billing"] = { baseUrl: "http://metadata.test" };
    expect(Object.keys(input)).toEqual(["/v1/pantry"]);

    input["/v1/secret"] = { baseUrl: "http://metadata.test" };
    expect(Object.keys(table)).toEqual(["/v1/pantry", "/v1/billing"]);
  });
});

describe("what refuses to boot", () => {
  test("an empty table, which forwards nothing and says so nowhere", () => {
    // `ROUTE_TABLE={}` is a plausible typo and an operator would find out from
    // 404s. A table with nothing in it is a configuration mistake, not a
    // deployment with no services, and the difference is worth a refusal.
    expect(() => routeTable({})).toThrow(RangeError);
    expect(() => routeTable({})).toThrow(/at least one prefix/);
  });

  test("a prefix outside the mount, which could never match", () => {
    // The mount is `/v1/*`, so `/auth/` and `/pantry/` are unreachable by
    // construction. Accepting one would be a table describing traffic gateway
    // does not forward — and the routes an operator would most want to add are
    // exactly the ones that must not be reachable without more thought.
    for (const prefix of ["/pantry", "/auth/", "/", "/v1alpha", "/V1/pantry"]) {
      expect(() => routeTable({ [prefix]: { baseUrl: "http://p.test" } }), prefix).toThrow(RangeError);
    }
  });

  test("a glob, because a prefix is a path and not a pattern", () => {
    for (const prefix of ["/v1/*", "/v1/p*", "/v1/pantry?"]) {
      expect(() => routeTable({ [prefix]: { baseUrl: "http://p.test" } }), prefix).toThrow(/not patterns/);
    }
  });

  test("a prefix carrying a traversal, in plain or encoded spelling", () => {
    // `%2e%2e` is `..` once decoded, and the pass-through rebuilds the upstream
    // path from decoded segments. A prefix written that way is a traversal
    // configured on purpose; it is refused here rather than discovered later.
    for (const prefix of ["/v1/../auth", "/v1/./pantry", "/v1/pantry/%2e%2e/.."]) {
      expect(() => routeTable({ [prefix]: { baseUrl: "http://p.test" } }), prefix).toThrow(/traversal/);
    }
  });

  test("`/v1/me`, which gateway serves before the pass-through can see it", () => {
    // A table claiming it describes a route that can never run. That is a
    // configuration error with no symptom at all — every request would be served
    // by gateway and the operator would believe their base URL had been used.
    expect(() => routeTable({ "/v1/me": { baseUrl: "http://identity.test" } })).toThrow(/gateway's own route/);
  });

  test("a base URL that is not an absolute http(s) origin", () => {
    // `new URL("pantry:8080")` parses — as the scheme `pantry:` — so the
    // protocol check is the one that catches an address written without a
    // scheme, which is the mistake an operator makes when composing one.
    const cases: [string, RegExp][] = [
      ["pantry:8080", /http\(s\)/],
      ["ftp://pantry.test", /http\(s\)/],
      ["file:///etc/passwd", /http\(s\)/],
      ["http://", /non-empty string|absolute URL/],
      ["", /non-empty string/],
    ];

    for (const [baseUrl, expected] of cases) {
      expect(() => routeTable({ "/v1/pantry": { baseUrl } }), baseUrl).toThrow(expected);
    }
  });

  test("a base URL carrying a path, a query or credentials", () => {
    // No path: the caller's path is appended, so a base with one puts
    // `/v1/items` somewhere nobody is serving it. No credentials in the
    // authority: a URL with a password in it is a URL that ends up in a log line
    // on the failure path this table exists to make diagnosable.
    for (const baseUrl of [
      "http://pantry.test/internal",
      "http://pantry.test?token=x",
      "http://pantry.test#frag",
      "http://user:secret@pantry.test",
    ]) {
      expect(() => routeTable({ "/v1/pantry": { baseUrl } }), baseUrl).toThrow(RangeError);
    }
  });

  test("a token that is empty or would inject a header", () => {
    // This value is written into an Authorization header verbatim, so a newline
    // in it is header injection arriving from the one place an operator trusts.
    // Refused rather than escaped: a token is gateway's own configuration and a
    // wrong one is a mistake to surface.
    for (const token of ["", "  ", "abc def", "abc\r\nX-Injected: yes", "abc\ndef"]) {
      expect(() => routeTable({ "/v1/pantry": { baseUrl: "http://p.test", token } }), JSON.stringify(token)).toThrow(
        RangeError,
      );
    }
  });

  test("a missing target is an error rather than a skip", () => {
    // `{"/v1/pantry": undefined as never}` is what a half-written table looks
    // like. Reading `target?.baseUrl` and getting undefined must still fail,
    // because the alternative is a route that silently forwards nowhere.
    expect(() => routeTable({ "/v1/pantry": undefined as never })).toThrow(RangeError);
  });

  test("a `public` that is not a boolean, which is the one that matters", () => {
    // `{"public":"true"}` is what an operator writes when they mean public and
    // have not checked that JSON has no booleans-as-strings. Coerced it is a
    // route serving anyone, so this is a refusal and not a truthiness check —
    // including for `"false"`, which would open the route as surely as `"true"`.
    for (const value of ["true", "false", 1, 0, "yes", null, [], {}]) {
      expect(() => routeTable({ "/v1/catalog": { baseUrl: "http://p.test", public: value as never } }), JSON.stringify(value))
        .toThrow(RangeError);
      expect(() => routeTable({ "/v1/catalog": { baseUrl: "http://p.test", public: value as never } }), JSON.stringify(value))
        .toThrow(/public must be true or false/);
    }
  });

  test("`public: true` with a token, which is two credentials and one undecided operator", () => {
    // `public` is about the CALLER and `token` is about the SERVICE. An entry
    // carrying both is a configuration where nobody reading it can say which of
    // the two was meant, so it refuses to boot rather than picking: picking
    // `public` hands an anonymous caller a credential-protected upstream, and
    // picking `token` answers 401 to a route the table calls open.
    expect(() =>
      routeTable({ "/v1/catalog": { baseUrl: "http://p.test", token: "svc", public: true } }),
    ).toThrow(RangeError);

    const [message] = (() => {
      try {
        routeTable({ "/v1/catalog": { baseUrl: "http://p.test", token: "svc", public: true } });
      } catch (error) {
        return [(error as Error).message];
      }
      return [""];
    })();

    // Both resolutions named, because an operator holding this error has to be
    // able to choose one without reading the source.
    expect(message).toContain("CALLER");
    expect(message).toContain("SERVICE");
    expect(message).toContain('Drop "token"');
    expect(message).toContain('drop "public"');
  });

  test("`public: false` with a token is ordinary, and `true` without one is ordinary", () => {
    // The refusal above is about the contradiction and not about the company a
    // field keeps. The two shapes that make sense must both boot, or the rule is
    // refusing configurations for tidiness.
    expect(routeTable({ "/v1/private": { baseUrl: "http://p.test", token: "svc", public: false } })).toEqual({
      "/v1/private": { baseUrl: "http://p.test", token: "svc", public: false },
    });
    expect(routeTable({ "/v1/catalog": { baseUrl: "http://p.test", public: true } })).toEqual({
      "/v1/catalog": { baseUrl: "http://p.test", token: undefined, public: true },
    });
  });
});

describe("resolution", () => {
  test("the longest matching prefix wins, and the order written is not the order used", () => {
    const table = routeTable({
      "/v1": { baseUrl: "http://all.test" },
      "/v1/pantry": { baseUrl: "http://pantry.test" },
      "/v1/pantry/imports": { baseUrl: "http://imports.test" },
    });

    expect(resolveRoute(table, "/v1/pantry/items")?.baseUrl).toBe("http://pantry.test");
    expect(resolveRoute(table, "/v1/pantry/imports/run")?.baseUrl).toBe("http://imports.test");
    expect(resolveRoute(table, "/v1/other")?.baseUrl).toBe("http://all.test");
  });

  test("a prefix matches on a segment boundary, so a sibling service is not reachable", () => {
    // The same rule `resolveLimit` applies, and the reason matters in both
    // places: `/v1/pantry` must not claim `/v1/pantryx`, or a new service
    // inherits a mount by sharing a name with an old one.
    const table = routeTable({ "/v1/pantry": { baseUrl: "http://pantry.test" } });

    expect(resolveRoute(table, "/v1/pantryx/items")).toBeNull();
    expect(resolveRoute(table, "/v1/pantry/items")).not.toBeNull();
    expect(resolveRoute(table, "/v1/pantry")).not.toBeNull();
  });

  test("the prefix itself matches, and a query is not part of the path", () => {
    const table = routeTable({ "/v1/pantry": { baseUrl: "http://pantry.test" } });

    expect(resolveRoute(table, "/v1/pantry?limit=1")?.prefix).toBe("/v1/pantry");
    expect(resolveRoute(table, "/v1/pantry/items?limit=1#top")?.prefix).toBe("/v1/pantry");
  });

  test("nothing claimed is null, which is the 404 the caller sees", () => {
    const table = routeTable({ "/v1/pantry": { baseUrl: "http://pantry.test" } });

    expect(resolveRoute(table, "/v1")).toBeNull();
    expect(resolveRoute(table, "/v1alpha/items")).toBeNull();
    expect(resolveRoute(table, "/auth/login")).toBeNull();
    expect(resolveRoute(table, "/v1/../auth/login")).toBeNull();
  });

  test("the resolved entry carries the credential, because the credential is per upstream", () => {
    // Which is the whole of the credential rule's configuration half: a service
    // has the credential gateway presents to it, and resolving a path cannot
    // substitute a caller's own.
    const table = routeTable({
      "/v1/pantry": { baseUrl: "http://pantry.test", token: "svc-pantry" },
      "/v1/other": { baseUrl: "http://other.test" },
    });

    expect(resolveRoute(table, "/v1/pantry/items")?.token).toBe("svc-pantry");
    expect(resolveRoute(table, "/v1/other/items")?.token).toBeUndefined();
  });
});

describe("whether a path is caller-anonymous", () => {
  const TABLE: RouteTable = {
    "/v1/catalog": { baseUrl: "http://catalog.test", public: true },
    "/v1/catalog/imports": { baseUrl: "http://imports.test" },
    "/v1/secret": { baseUrl: "http://secret.test" },
  };

  test("a public entry answers true and every other entry answers false", () => {
    const table = routeTable(TABLE);

    expect(isPublicRoute(table, "/v1/catalog")).toBe(true);
    expect(isPublicRoute(table, "/v1/catalog/items")).toBe(true);
    expect(isPublicRoute(table, "/v1/secret")).toBe(false);
    // Absent and `false` are the same answer, and nothing outside `/v1/` is ever
    // public whatever the table says.
    expect(isPublicRoute(table, "/v1/catalog?limit=1")).toBe(true);
    expect(isPublicRoute(table, "/auth/login")).toBe(false);
    expect(isPublicRoute(table, "/v1")).toBe(false);
  });

  test("openness is decided by the LONGEST match, exactly like the destination", () => {
    // The case that makes the rule worth stating: a public read surface with a
    // private write surface under it. If openness were decided by "any prefix
    // above me is public", `/v1/catalog/imports` would be open too — and the
    // write path of a public read service is precisely the route that must not be.
    const table = routeTable(TABLE);

    expect(resolveRoute(table, "/v1/catalog/imports/run")?.baseUrl).toBe("http://imports.test");
    expect(isPublicRoute(table, "/v1/catalog/imports/run")).toBe(false);
    expect(isPublicRoute(table, "/v1/catalog/imports")).toBe(false);
    // And the sibling-prefix boundary still holds, so `/v1/catalogx` is neither
    // claimed by the public entry nor reachable through it.
    expect(isPublicRoute(table, "/v1/catalogx/items")).toBe(false);
  });

  test("the flag rides along on the resolved entry, so the two answers cannot differ", () => {
    // One resolver, one winner, two properties. A `public` looked up by a second
    // scan is a second opinion about which prefix claimed the path, and the one
    // packet that must not exist is the pair of them disagreeing.
    const table = routeTable(TABLE);

    expect(resolveRoute(table, "/v1/catalog/items")).toEqual({
      prefix: "/v1/catalog",
      baseUrl: "http://catalog.test",
      public: true,
    });
    expect(resolveRoute(table, "/v1/secret/items")?.public).toBeUndefined();
  });
});

describe("the mount this table is written for", () => {
  test("it is the API surface, and every shipped prefix lives under it", () => {
    // Derived from the table rather than restated, so a prefix added outside
    // the mount fails here as well as at construction — a check that stops
    // reading its own scope and reports success is worse than no check.
    expect(ROUTE_MOUNT).toBe("/v1/*");

    const table = routeTable({
      "/v1": { baseUrl: "http://all.test" },
      "/v1/pantry": { baseUrl: "http://pantry.test" },
    });

    for (const prefix of Object.keys(table)) {
      expect(prefix).toMatch(/^\/v1(\/|$)/);
    }
  });
});