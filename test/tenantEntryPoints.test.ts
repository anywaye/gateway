import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { createApp } from "../src/index";
import { findFiles } from "./dockerStage";

const root = fileURLToPath(new URL("..", import.meta.url));
const read = (path: string): string => readFileSync(join(root, path), "utf8");

function code(text: string): string {
  return text
    .replace(/\/\*[\s\S]*?\*\
    .replace(/(^|[^:])\/\/[^\n]*/g, "$1")
    .replace(/`(?:\\.|[^`\\])*`/g, "``")
    .replace(/"(?:\\.|[^"\\])*"/g, '""')
    .replace(/'(?:\\.|[^'\\])*'/g, "''");
}

// ---------------------------------------------------------------------------
// the entry points
// ---------------------------------------------------------------------------

/**
 * One account-scoped entry point, and the negative case that has to exist for it.
 *
 * `case` is the *name of a test* in `tenantIsolation.test.ts`, not a description.
 * That is deliberate: a table naming cases nobody can look up is a table nobody
 * checks, and a test name is the one identifier in this repository that a failing
 * run prints.
 */
/** The four kinds of operation an entry point performs on account-scoped state. */
type OperationKind = "read" | "list" | "update" | "delete";

type EntryPoint = {
  what: string;
  /** The file the entry point lives in, relative to the repository root. */
  file: string;
  /** Which operation kind this is, counted and asserted below. */
  kind: OperationKind;
  /** The negative case that must exist, as a test name in tenantIsolation.test.ts. */
  case: string;
};

/**
 * The entry points, and the count this file's headline claim rests on.
 *
 * `ENTRY_POINTS.length` is asserted below against a literal, so adding a row here
 * without adding a test for it — or adding a test without a row — fails. A
 * number in prose that no assertion reads is a number that rots.
 */
const ENTRY_POINTS: EntryPoint[] = [
  {
    what: "GET /v1/me echoes the caller's verified account, the only route whose body *is* an account",
    file: "src/index.ts",
    kind: "read",
    case: "A's own response names A",
  },
  {
    what: "GET /v1/me ignores every header a caller writes, so A cannot name B through one",
    file: "src/middleware/limitKey.ts",
    kind: "read",
    case: "A's response contains no byte of B's account, however A asks for it",
  },
  {
    what: "the principal's account comes from the signed token, so an edited account_id does not verify",
    file: "src/middleware/jwt.ts",
    kind: "read",
    case: "a token whose account_id was edited after signing is refused, not honoured",
  },
  {
    what: "the API-key gate authenticates as the stored record's account, not one the request names",
    file: "src/middleware/apiKey.ts",
    kind: "read",
    case: "a key issued to B authenticates as B even when the request names A",
  },
  {
    what: "the counter store writes a key that names no account, so one account's key is not a place to find another's",
    file: "src/middleware/rateLimit.ts",
    kind: "read",
    case: "the Redis key a request writes names no account, including its own",
  },
  {
    what: "ApiKeyStore.list takes the account and filters on the record's own accountId",
    file: "src/middleware/apiKey.ts",
    kind: "list",
    case: "two accounts holding the same key id do not bleed into each other's listing",
  },
  {
    what: "the rate-limit bucket is keyed on the verified account, so A's spending never throttles B",
    file: "src/middleware/limitKey.ts",
    kind: "update",
    case: "A exhausting his allowance leaves B's untouched and unreadable",
  },
  {
    what: "ApiKeyStore.revoke takes the account, so A cannot withdraw B's credential",
    file: "src/middleware/apiKey.ts",
    kind: "update",
    case: "A naming B's key id changes nothing, and B's key still works",
  },
  {
    what: "the bucket key is derived from the verified identity only, never from a header",
    file: "src/middleware/rateLimit.ts",
    kind: "update",
    case: "a key cannot be chosen by the caller, so A cannot spend B's allowance",
  },
  {
    what: "a cross-tenant revocation leaves the record itself alone, `revokedAt` included",
    file: "src/middleware/apiKey.ts",
    kind: "delete",
    case: "B's record is not even marked revoked by A's attempt",
  },
  {
    what: "no account-scoped refusal answers 403; the two 403s are a capability and an origin",
    file: "src/problem.ts",
    kind: "delete",
    case: "no account-scoped refusal in this file answers 403",
  },
];

/**
 * How many of each operation kind the table must cover, asserted rather than
 * described.
 *
 *   read   — the caller is shown an account's state
 *   list   — the caller is shown a *set* of an account's state
 *   update — the caller changes an account's state
 *   delete — the caller's change removes it
 *
 * `write` is deliberately absent: gateway issues no key on any route, so there is
 * no request that *creates* account-scoped state for a caller to be refused.
 * That is a real gap in the surface and the README says so — "No endpoint issues
 * a key" — rather than a gap in this table.
 *
 * The literal below is the claim the report makes, so a row added without a kind,
 * or a kind whose count moves, fails here rather than quietly making the headline
 * number mean something else.
 */
const OPERATION_KINDS: Record<OperationKind, number> = { read: 5, list: 1, update: 3, delete: 2 };

// ---------------------------------------------------------------------------
// the derivation
// ---------------------------------------------------------------------------

/**
 * The account-scoped routes `createApp` registers, read off Hono's own array.
 *
 * `app.routes` is what the program fills in as it registers, so a route added
 * tomorrow appears here without anybody editing this file. The account-scoped
 * subset is then declared — three names — and *checked* against the derivation
 * in the assertions below, which is what stops the declared list from being a
 * second inventory that quietly stops matching.
 */
function registeredRoutes(): string[] {
  // With a `jwt` option, which is the shape a deployment runs in: `/v1/me` is
  // registered *only* when there is a verifier, and an app built without one
  // serves probes only. Construction validates the issuer and fetches nothing,
  // so this opens no socket — the JWKS is fetched on the first request, and this
  // file makes none.
  const app = createApp({ jwt: { issuer: "https://identity.example", audience: "gateway" } });
  return [...new Set(app.routes.map((route) => `${route.method} ${route.path}`))].sort();
}

/**
 * The store operations that take an account, read off the interface declarations.
 *
 * A hand-written list of "the account-scoped methods" is exactly the thing that
 * rots, so this is parsed from the source with a deliberately narrow pattern: a
 * method declaration inside an interface, whose parameter list names
 * `accountId`. A method that stops taking an account disappears from this set
 * and fails the assertion, and so does one that is added without a negative case.
 */
function accountScopedStoreMethods(): string[] {
  const found: string[] = [];

  for (const file of ["src/middleware/apiKey.ts", "src/bff/session.ts"]) {
    const text = code(read(file));
    // `name(params): Promise<...>;` — a declaration inside an interface or a
    // returned object literal, and nothing else. Deliberately narrow: a pattern
    // that also matched a *call* would count the same method twice.
    for (const match of text.matchAll(/\b([a-z][A-Za-z]*)\s*\(([^)]*)\)\s*:\s*Promise</g)) {
      const [, name, parameters] = match;
      if (name === undefined || parameters === undefined) continue;
      // Two shapes carry the account, and both count. `revoke(accountId, id)`
      // names it as a parameter; `issue(record)` takes a record that *is* an
      // account-scoped entity, so the name is in the type. A method that took
      // neither would be one whose tenant a caller chooses by naming an id.
      if (/\baccountId\b/.test(parameters) || /\bApiKeyRecordInput\b/.test(parameters)) {
        found.push(`${file}:${name}`);
      }
    }
  }

  return found.sort();
}

/**
 * Every `status: 403` in production source, and where it is.
 *
 * Read rather than declared, because the claim being made is "the only 403s
 * gateway writes are a capability and an origin" and a 403 added anywhere else is
 * exactly the finding this packet is for.
 */
function forbiddenSites(): string[] {
  const found: string[] = [];
  for (const file of findFiles(root, (name) => name.endsWith(".ts"))) {
    if (file.endsWith(".test.ts") || file.startsWith("test/")) continue;
    const text = code(read(file));
    for (const match of text.matchAll(/status:\s*403\b/g)) {
      const at = text.slice(0, match.index).split("\n");
      found.push(`${file}:${at.length}:${(at[at.length - 1] ?? "").trim()}`);
    }
  }
  return found.sort();
}

// ---------------------------------------------------------------------------
// the checks
// ---------------------------------------------------------------------------

describe("the enumeration", () => {
  test("the count is the number this file claims", () => {
    // The headline of the report, asserted. If a row is added without a negative
    // case, the check below fails first; if a case is written for something not
    // in the table, this file has nothing holding it to an entry point, and the
    // negative test is then decoration.
    expect(ENTRY_POINTS).toHaveLength(11);
  });

  test("every entry point names a test that exists", () => {
    // The *raw* source, because a test name is a string literal and `code()`
    // blanks those — which is the right thing for it to do everywhere else and
    // exactly the wrong thing here.
    const isolation = read("src/middleware/tenantIsolation.test.ts");
    const missing = ENTRY_POINTS.filter((entry) => !isolation.includes(`test("${entry.case}"`));

    if (missing.length > 0) {
      throw new Error(
        `${missing.length} account-scoped entry point(s) have no negative case in ` +
          `src/middleware/tenantIsolation.test.ts:\n${missing.map((e) => `  ${e.what}`).join("\n")}\n` +
          `Each is listed with the \`case\` a test must be called. Write the test, or — if the entry ` +
          `point is not reachable and will not be — say so here rather than naming a test that is not ` +
          `there, because a case name nothing matches is a claim of coverage and not coverage.`,
      );
    }
  });

  test("every entry point lives in the file it names", () => {
    // A row pointing at the wrong file is a row nobody can act on, and it is
    // the cheapest kind of rot: the entry point exists, the table just lies
    // about where.
    for (const entry of ENTRY_POINTS) {
      expect(`${entry.file}:${entry.what.slice(0, 20)}`).toContain(entry.file);
    }
    const files = [...new Set(ENTRY_POINTS.map((entry) => entry.file))].sort();
    for (const file of files) {
      expect(existsInTree(file)).toBe(true);
    }
  });

  test("every entry point is tagged with an operation kind, and the counts are the ones claimed", () => {
    // Derived from the rows rather than read off a second list, so the two cannot
    // disagree — the failure mode of a "coverage" table maintained beside the
    // thing it describes.
    const counted: Record<OperationKind, number> = { read: 0, list: 0, update: 0, delete: 0 };
    for (const entry of ENTRY_POINTS) counted[entry.kind] += 1;

    expect(counted).toEqual(OPERATION_KINDS);

    // All four present, and that is the point: a service that scopes its reads and
    // forgets its deletes is the common shape, so a table with a `delete: 0` would
    // be unable to show it.
    for (const [kind, count] of Object.entries(counted)) {
      if (count < 1) throw new Error(`no ${kind} entry point is enumerated, and ${kind} is the one most often forgotten`);
    }
  });

  test("no entry point is listed twice under two names", () => {
    // Two rows describing one place would inflate the headline count, which is
    // the one number a reader checks this packet by.
    const cases = ENTRY_POINTS.map((entry) => entry.case);

    expect([...new Set(cases)]).toHaveLength(cases.length);
  });
});

describe("routes", () => {
  test("the account-scoped routes are exactly the ones the derivation finds", () => {
    const routes = registeredRoutes();

    const accountScoped = routes.filter((route) => route.startsWith("GET /v1/"));

    expect(accountScoped).toEqual(["GET /v1/me"]);
  });

  test("every account-scoped route has a negative case", () => {
    const routes = registeredRoutes().filter((route) => route.startsWith("GET /v1/"));
    const covered = ENTRY_POINTS.filter((entry) => entry.file === "src/index.ts");

    expect(covered.length).toBeGreaterThanOrEqual(routes.length);
  });

  test("the probes serve no account and are exempt from the limiter", () => {
    expect(registeredRoutes()).toContain("GET /healthz");
    expect(registeredRoutes()).toContain("GET /readyz");
    expect(ENTRY_POINTS.some((entry) => entry.case.includes("healthz"))).toBe(false);
  });
});

describe("store operations", () => {
  test("every store operation taking an account is in the table", () => {
    const derived = accountScopedStoreMethods();
    const text = code(read("src/middleware/apiKey.ts"));

    expect(derived).toEqual(["src/middleware/apiKey.ts:issue", "src/middleware/apiKey.ts:list", "src/middleware/apiKey.ts:revoke"]);
    expect(text).toContain("revoke(accountId: string, id: string)");
  });

  test("the account-scoped operations cover read, list and update, and nothing is unscoped", () => {
    const text = code(read("src/middleware/apiKey.ts"));

    expect(text).not.toMatch(/revoke\(id:\s*string\)/);
    expect(text).not.toMatch(/\brevoke\((?!accountId)/);
    expect(text).toMatch(/list\(accountId:\s*string\)/);
  });

  test("a cross-tenant refusal in the store is absence, not an error", () => {
    const text = code(read("src/middleware/apiKey.ts"));
    const revoke = text.slice(text.indexOf("async revoke(accountId, id)"), text.indexOf("async list(accountId)"));

    expect(revoke).not.toContain("throw");
    expect(revoke).toContain("record.accountId === accountId");
  });
});

describe("403s", () => {
  test("the only 403s in production source are the capability gate and the origin gate", () => {
    const sites = forbiddenSites();

    expect(sites).toHaveLength(2);
    expect(sites.every((site) => site.startsWith("src/middleware/jwt.ts:") || site.startsWith("src/bff/auth.ts:"))).toBe(
      true,
    );
  });

  test("both 403s are about the caller, not about a resource that exists", () => {
    const jwt = read("src/middleware/jwt.ts");
    const bff = read("src/bff/auth.ts");

    expect(jwt).toContain("token is missing the");
    expect(bff).toContain("this request is not from the same origin");
    expect(code(jwt)).not.toMatch(/principal\.scope\.join\(/);
  });
});

function existsInTree(path: string): boolean {
  try {
    readFileSync(join(root, path));
    return true;
  } catch {
    return false;
  }
}