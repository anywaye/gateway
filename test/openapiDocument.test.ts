import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { createApp, PROBE_PATHS } from "../src/index";
import { memoryApiKeyStore } from "../src/middleware/apiKey";
import { RATE_LIMIT_HEADERS } from "../src/middleware/rateLimit";
import {
  describeDrift,
  diff,
  documentHeader,
  documentOperations,
  infoVersion,
  MOUNT_METHOD,
  normaliseOperation,
  openapiVersion,
  responseStatuses,
  routerSurface,
} from "./openapiPaths";

const DOCUMENT_PATH = "openapi/v1.yaml";

const EXCLUSIONS = new Map<string, string>([
  [
    normaliseOperation(MOUNT_METHOD, "/v1/*"),
    "the `/v1/*` prefix itself: the bearer-token gate is mounted on it, and the pass-through to the " +
      "services behind gateway is mounted on it whenever a route table is configured. Neither is an " +
      "operation — each has no method and no response of its own, so there is nothing to document — and " +
      "a routed subtree is not describable as operations anyway: the paths under it belong to the service, " +
      "and which ones exist is decided by configuration rather than by this file. Excluded as this exact " +
      "method+path pair and NOT as a `/v1/` prefix, so a route added under `/v1/` next year is still " +
      "required to be in the document.",
  ],
  [
    normaliseOperation(MOUNT_METHOD, "/*"),
    "the whole-app mounts: the API-key gate and the rate limiter, both on `*`. Neither is an " +
      "operation, and each is a different gate, so they collapse onto one key here. Excluded " +
      "as this exact method+path pair; a route at the root is a `GET` or a `POST` and is not " +
      "covered by it.",
  ],
]);

const app = createApp({
  jwt: { issuer: "https://identity.localhost", audience: "gateway" },
  bff: { identityUrl: "http://identity.invalid:8080" },
  apiKeys: { keys: memoryApiKeyStore() },
  rateLimit: {},
  routes: { "/v1/pantry": { baseUrl: "http://pantry.invalid:8080", token: "not-a-real-token" } },
});

const surface = routerSurface(app.routes);

const document = readFileSync(fileURLToPath(new URL(`../${DOCUMENT_PATH}`, import.meta.url)), "utf8");
const documented = documentOperations(document, DOCUMENT_PATH);
const drift = diff(documented, surface.operations, EXCLUSIONS);

describe("the document and the router", () => {
  test("the document was read, and it describes something", () => {
    expect(documented.size).toBeGreaterThan(0);
  });

  test("the router was read, and it serves something", () => {
    expect(surface.operations.size).toBeGreaterThan(0);
  });

  test("every operation the document describes is a route the router serves", () => {
    expect(drift.documentedNotServed).toEqual([]);
  });

  test("every route the router serves is an operation the document describes", () => {
    expect(drift.unexplained).toEqual([]);
  });
});

describe("the document is a document core's conventions accept", () => {
  test("it declares OpenAPI 3.1.0, which is the version the fleet publishes", () => {
    expect(openapiVersion(document, DOCUMENT_PATH)).toBe("3.1.0");
  });

  test("it declares `info.version`, and this is a new document so it starts at 1.0.0", () => {
    expect(infoVersion(document, DOCUMENT_PATH)).toBe("1.0.0");
  });

  test("the media types it names are the two gateway actually emits", async () => {
    const named = new Set([...document.matchAll(/^\s*application\/([a-z+]+):\s*$/gm)].map((m) => `application/${m[1]}`));

    expect([...named].sort()).toEqual(["application/json", "application/problem+json"]);

    const notFound = await createApp().request("/no-such-route");

    expect(notFound.status).toBe(404);
    expect(notFound.headers.get("content-type")).toContain("application/json");
  });
});

describe("the error responses, which are the interesting part", () => {
  const statuses = responseStatuses(document, DOCUMENT_PATH);

  test("the problem envelope is one component, referenced rather than restated", () => {
    expect(document).toContain("application/problem+json");
    expect(document).toMatch(/^ {4}Problem:$/m);
    const bodies = [...document.matchAll(/application\/problem\+json:\n(?:\s*.*\n)*?\s*\$ref: '#\/components\/schemas\/Problem'/g)];
    expect(bodies.length).toBeGreaterThan(0);
  });

  test("every operation the limiter counts declares the 429, and the probes do not", () => {
    const without = [...documented.keys()].filter((key) => !(statuses.get(key) ?? []).includes("429"));
    const probes = [...documented.keys()].filter((key) => PROBE_PATHS.has(surface.operations.get(key)?.path ?? ""));

    expect(without.sort()).toEqual(probes.sort());
    expect(probes).toHaveLength(2);
  });

  test("every operation the document describes declares a 500, and that one is not a problem document", () => {
    expect([...statuses.keys()].sort()).toEqual([...documented.keys()].sort());
    for (const [key, declared] of statuses) {
      expect(declared, `${key} declares no 500`).toContain("500");
    }
  });

  test("the document names every rate-limit field the limiter announces", () => {
    for (const name of [...RATE_LIMIT_HEADERS, "Retry-After"]) {
      expect(document, `${DOCUMENT_PATH} never names ${name}`).toContain(name);
    }
  });
});

describe("the mount exclusions", () => {
  test("every entry the app registered is one the reader reported, in order", () => {
    expect(surface.entries).toEqual(
      app.routes.map((route) => ({
        method: route.method.toUpperCase(),
        path: route.path,
        kind: route.method.toUpperCase() === MOUNT_METHOD ? "mount" : "operation",
      })),
    );
  });

  test("the mounts are the two the header names, and nothing else", () => {
    expect([...surface.mounts.keys()].sort()).toEqual([...EXCLUSIONS.keys()].sort());
  });

  test("a declared omission still names a mount the app registers", () => {
    for (const key of EXCLUSIONS.keys()) {
      expect(surface.mounts.has(key), `the exclusion for ${key} names a mount the app does not register`).toBe(true);
    }
  });
  test("the exclusions cover no operation, so they cannot swallow a future route", () => {
    for (const [key] of EXCLUSIONS) expect(key.startsWith(`${MOUNT_METHOD} `)).toBe(true);
    for (const key of surface.operations.keys()) expect(EXCLUSIONS.has(key)).toBe(false);
  });

  test("`GET /v1/me` is documented rather than excluded, which is the live proof", () => {
    expect(documented.has("GET /v1/me")).toBe(true);
    expect(surface.operations.has("GET /v1/me")).toBe(true);
    expect(EXCLUSIONS.has("GET /v1/me")).toBe(false);
  });

  test("the document's header names every mount the check excludes", () => {
    const header = documentHeader(document);

    for (const key of EXCLUSIONS.keys()) {
      expect(header, `${DOCUMENT_PATH} leaves ${key} out, and its header does not say so`).toContain(key);
    }
  });
});

describe("when it fails, the message says what to do", () => {
  test("the drift message names both sides, with the two fixes each", () => {
    const message = describeDrift(drift);

    expect(message).toBe("");
    expect(describeDrift({ ...drift, unexplained: [surface.operations.get("GET /v1/me")!] })).toContain(
      "document it in `openapi/v1.yaml`",
    );
  });
});
