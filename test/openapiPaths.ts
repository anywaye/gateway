
export type Operation = {
  method: string;
  path: string;
  label: string;
  line?: number;
};

export type Mount = { method: string; path: string; label: string };

export type RouterEntry = { method: string; path: string; kind: "operation" | "mount" };

export type RouterSurface = {
  operations: Map<string, Operation>;
  mounts: Map<string, Mount>;
  entries: RouterEntry[];
};

const METHODS = ["get", "head", "post", "put", "patch", "delete", "options", "trace"] as const;

const PATH_ITEM_FIELDS = ["summary", "description", "servers", "parameters", "$ref"] as const;

export const MOUNT_METHOD = "ALL";

type Line = { indent: number; text: string; number: number };

export function normaliseOperation(method: string, path: string): string {
  return `${normaliseMethod(method)} ${normalisePath(path)}`;
}

export function normaliseMethod(method: string): string {
  return method.toUpperCase();
}

export function normalisePath(path: string): string {
  const rewritten = path
    .split("/")
    .map((segment) => (/^[:{]/.test(segment) ? "{}" : segment))
    .join("/");

  return rewritten.length > 1 ? rewritten.replace(/\/+$/, "") : rewritten;
}

export function documentOperations(contents: string, name: string): Map<string, Operation> {
  const lines = significant(contents);
  const block = pathsBlock(lines, name);
  const [pathLevel, methodLevel] = levels(block, name);

  const operations = new Map<string, Operation>();

  for (const group of groups(block, pathLevel)) {
    const key = keyOf(group[0].text);

    if (!key.startsWith("/")) {
      if (pathItemField(key)) continue;
      throw new Error(
        `${name}:${group[0].number} — \`${key}\` is not a valid OpenAPI path. Every key directly ` +
          `under \`paths:\` is a path starting with \`/\`, or a field of the Path Item Object ` +
          `(${PATH_ITEM_FIELDS.join(", ")}, x-…). This reader refuses the document rather than ` +
          `guessing which was meant, because a misspelled sibling is a document that describes no ` +
          `route and an empty result would agree with a router that serves several.`,
      );
    }

    const found: string[] = [];
    for (const line of group.filter((candidate) => candidate.indent === methodLevel)) {
      const key2 = keyOf(line.text);
      if (pathItemField(key2)) continue;
      if (!isMethod(key2)) {
        throw new Error(
          `${name}:${group[0].number} — \`${key2}\` is not an OpenAPI operation. A key directly ` +
            `under a path is one of ${METHODS.join(", ")}, or a field of the Path Item Object. ` +
            `Reading it as anything else would put a route in the menu that no client can call.`,
        );
      }
      found.push(key2);
    }

    if (found.length === 0) {
      throw new Error(
        `${name}:${group[0].number} — the path \`${key}\` has no operation under it. A path item ` +
          `with no operation is nothing a client can be generated from, and skipping it would leave ` +
          `this check agreeing with a document that says nothing about a route the router serves.`,
      );
    }

    for (const method of found) {
      const operationKey = normaliseOperation(method, key);
      const previous = operations.get(operationKey);
      if (previous !== undefined) {
        throw new Error(
          `${name}:${group[0].number} — two operations both read as ${operationKey}: \`${previous.label}\` and ` +
            `\`${method} ${key}\`. They normalise onto one route, so a check that could not see the ` +
            `collision would be blind to it.`,
        );
      }
      operations.set(operationKey, {
        method: normaliseMethod(method),
        path: key,
        label: `${normaliseMethod(method)} ${key}`,
        line: group[0].number,
      });
    }
  }

  return operations;
}

export function responseStatuses(contents: string, name: string): Map<string, string[]> {
  const lines = significant(contents);
  const block = pathsBlock(lines, name);
  const [pathLevel, methodLevel] = levels(block, name);
  const statuses = new Map<string, string[]>();

  for (const group of groups(block, pathLevel)) {
    const path = keyOf(group[0].text);
    if (!path.startsWith("/")) continue;

    const methodLines = group
      .map((line, index) => ({ line, index }))
      .filter(({ line }) => line.indent === methodLevel && isMethod(keyOf(line.text)));

    for (const { line, index } of methodLines) {
      const method = keyOf(line.text);
      const label = `${normaliseMethod(method)} ${path}`;
      const next = methodLines.find((candidate) => candidate.index > index)?.index ?? group.length;
      const body = group.slice(index + 1, next);
      const responses = body.find((candidate) => candidate.indent > methodLevel && keyOf(candidate.text) === "responses");
      if (responses === undefined) {
        throw new Error(
          `${name}:${group[0].number} — the operation \`${label}\` has no \`responses:\` block. An ` +
            `operation with no responses is nothing a client can be generated from, and reading it as ` +
            `one that answers nothing is the same shape as a check over an empty set.`,
        );
      }

      const start = body.indexOf(responses);
      const inside = body.slice(start + 1).filter((candidate) => candidate.indent > responses.indent);
      const first = inside.length === 0 ? -1 : Math.min(...inside.map((candidate) => candidate.indent));
      const found = inside
        .filter((candidate) => candidate.indent === first)
        .map((candidate) => keyOf(candidate.text))
        .filter((key) => /^\d{3}$/.test(key));

      if (found.length === 0) {
        throw new Error(
          `${name}:${responses.number} — \`${label}\` declares no responses: nothing at all is ` +
            `listed under its \`responses:\` key. An operation that can answer nothing and an ` +
            `operation whose responses were lost to a reformat are the same file, and only one of ` +
            `them is true.`,
        );
      }

      statuses.set(label, found);
    }
  }

  return statuses;
}

export function documentHeader(contents: string): string {
  const lines = contents.split("\n");
  const index = lines.findIndex((line) => line.trimStart().startsWith("openapi:"));
  if (index < 0) return lines.join("\n");

  return `${lines.slice(0, index).join("\n")}\n`;
}

export function openapiVersion(contents: string, name: string): string {
  const value = topLevelScalar(contents, name, "openapi");
  if (value === null) {
    throw new Error(`${name} declares no \`openapi:\` version. The document's dialect is the one thing a reader cannot assume.`);
  }
  return value;
}

export function infoVersion(contents: string, name: string): string {
  const lines = significant(contents);
  const info = lines.find((line) => line.indent === 0 && line.text === "info:");
  if (info === undefined) throw new Error(`${name} has no top-level \`info:\` key, and so no info.version.`);

  const version = lines.find((line) => line.indent > 0 && keyOf(line.text) === "version");
  if (version === undefined) {
    throw new Error(
      `${name}:${info.number} — \`info:\` has no \`info.version\`. core's conventions ` +
        `require it, and a reader that reported null would agree with a document that forgot it.`,
    );
  }

  const value = valueOf(version.text);
  if (value === "") throw new Error(`${name}:${version.number} — \`info.version\` is present and empty.`);

  return value;
}

export function surfaceOf(routes: readonly { path: string; method: string }[], who: string): RouterSurface {
  if (routes.length === 0) {
    throw new Error(
      `${who} serves no routes at all. A router-reading check that finds nothing agrees with a ` +
        `document-reading check that finds no paths, and two empty sets always agree.`,
    );
  }

  const operations = new Map<string, Operation>();
  const mounts = new Map<string, Mount>();
  const entries: RouterEntry[] = [];

  for (const route of routes) {
    const method = normaliseMethod(route.method);
    const key = normaliseOperation(method, route.path);
    const mount = method === MOUNT_METHOD;

    if (!mount && !isMethod(method)) {
      throw new Error(
        `${who} registers \`${method} ${route.path}\`, which is neither one of ${normaliseMethods()} nor ` +
          `the \`${MOUNT_METHOD}\` Hono records a middleware mount with. This reader will not guess which ` +
          `kind of thing that is: a misfiled entry is either a route no client can call or a mount ` +
          `hiding inside a carve-out.`,
      );
    }

    entries.push({ method, path: route.path, kind: mount ? "mount" : "operation" });

    if (mount) {
      mounts.set(key, { method, path: route.path, label: key });
    } else {
      operations.set(key, { method, path: route.path, label: key });
    }
  }

  return { operations, mounts, entries };
}

export function routerSurface(routes: readonly { path: string; method: string }[]): RouterSurface {
  return surfaceOf(routes, "the Hono app");
}

export type Drift = {
  documentedNotServed: Operation[];
  servedNotDocumented: Operation[];
  unexplained: Operation[];
  excluded: (Operation & { reason: string })[];
};

export function diff(
  document: Map<string, Operation>,
  router: Map<string, Operation>,
  exclusions: ReadonlyMap<string, string> = new Map(),
): Drift {
  const missing = [...router.keys()].filter((key) => !document.has(key));
  const explained = missing.filter((key) => exclusions.has(key));
  const unexplained = missing.filter((key) => !exclusions.has(key));

  return {
    documentedNotServed: [...document.keys()].filter((key) => !router.has(key)).map((key) => document.get(key)!),
    servedNotDocumented: missing.map((key) => router.get(key)!),
    unexplained: unexplained.map((key) => router.get(key)!),
    excluded: explained.map((key) => ({ ...router.get(key)!, reason: exclusions.get(key)! })),
  };
}

export function describeDrift(found: Drift): string {
  return [
    section(
      found.documentedNotServed,
      "the document describes",
      "the router does not serve",
      "An endpoint in the menu that answers 404 is a product configured against a route that does not exist, and they find out at their outage.",
      [
        "The route is real and shipping — add it to `src/index.ts`.",
        "The operation is not shipping — delete it from `openapi/v1.yaml`.",
      ],
    ),
    section(
      found.unexplained,
      "the router serves",
      "the document does not describe",
      "A route nobody documented is a route the next generated client will not have, so the surface grows and the contract does not.",
      [
        "The route is part of gateway's public surface — document it in `openapi/v1.yaml`.",
        "The route is not meant to be public — say so in the document's header, and name it in this test's exclusion list, rather than leaving it to be found.",
      ],
    ),
    exclusionsNote(found.excluded),
  ]
    .filter((part) => part !== null && part !== "")
    .join("\n\n");
}


function significant(contents: string): Line[] {
  return contents
    .split("\n")
    .map((raw, index) => ({ raw, number: index + 1 }))
    .filter(({ raw }) => {
      const trimmed = raw.trimStart();
      return trimmed !== "" && !trimmed.startsWith("#");
    })
    .map(({ raw, number }) => ({
      indent: raw.length - raw.trimStart().length,
      text: raw.trim().replace(/\s+#.*$/, ""),
      number,
    }));
}

function pathsBlock(lines: Line[], name: string): Line[] {
  const index = lines.findIndex((line) => line.indent === 0 && line.text === "paths:");
  if (index < 0) {
    throw new Error(
      `${name} has no top-level \`paths:\` key. A reader that cannot find the document's paths finds ` +
        `none, and a check over none passes — so this is an error, not an empty result.`,
    );
  }

  const block: Line[] = [];
  for (const line of lines.slice(index + 1)) {
    if (line.indent === 0) break;
    block.push(line);
  }

  if (block.length === 0) {
    throw new Error(
      `${name} documents no operations: nothing is under its \`paths:\` key. Two readers that both ` +
        `find nothing agree, which is how a check over nothing goes green.`,
    );
  }

  return block;
}

function levels(block: Line[], name: string): [number, number] {
  const found = [...new Set(block.map((line) => line.indent))].sort((a, b) => a - b);
  if (found.length < 2 || found[0] === undefined || found[1] === undefined) {
    throw new Error(
      `${name} documents no operations: what is under \`paths:\` is one indentation level deep, so ` +
        `there is no operation level below the path items.`,
    );
  }

  return [found[0], found[1]];
}

function groups(block: Line[], pathLevel: number): [Line, ...Line[]][] {
  const out: [Line, ...Line[]][] = [];
  for (const line of block) {
    if (line.indent === pathLevel || out.length === 0) out.push([line]);
    else out[out.length - 1]?.push(line);
  }

  return out;
}

function topLevelScalar(contents: string, name: string, key: string): string | null {
  for (const line of significant(contents)) {
    if (line.indent !== 0 || keyOf(line.text) !== key) continue;
    const value = valueOf(line.text);

    return value === "" ? null : value;
  }

  return null;
}

function keyOf(text: string): string {
  const key = /^([^:]*?):(\s|$)/.exec(text)?.[1]?.trim() ?? text;

  return /^(['"]).*\1$/.test(key) ? key.slice(1, -1) : key;
}

function valueOf(text: string): string {
  return text.replace(/^[^:]*?:/, "").trim();
}

/** The eight names as HTTP spells them, for a message about a route. */
function normaliseMethods(): string {
  return METHODS.map(normaliseMethod).join(", ");
}

/**
 * Is this one of the eight method names?
 *
 * Case-insensitive, and deliberately so: the document spells its methods the
 * way YAML requires (`get:`, lower case) and Hono records them the way HTTP
 * spells them (`GET`). Both spellings are legitimate in their own file, so
 * normalising here is the difference between one reader that understands two
 * notations and one that only understands the first — and a reader that only
 * understood the document's spelling would raise on the router's every time.
 */
function isMethod(key: string): boolean {
  return (METHODS as readonly string[]).includes(key.toLowerCase());
}

function pathItemField(key: string): boolean {
  return (PATH_ITEM_FIELDS as readonly string[]).includes(key) || key.startsWith("x-");
}

// --- reporting -----------------------------------------------------------

function section(offenders: Operation[], subject: string, absence: string, why: string, fixes: string[]): string {
  if (offenders.length === 0) return "";

  return [
    `${subject} ${count(offenders)} ${absence}.`,
    `  ${why}`,
    "  Offending operations:",
    ...offenders.map((operation) => `    ${operation.label}`),
    "  To fix this, do one of the two things:",
    ...fixes.map((fix, index) => `    ${index + 1}. ${fix}`),
    "  This check is `test/openapiDocument.test.ts`; the reader is `test/openapiPaths.ts`.",
  ].join("\n");
}

function exclusionsNote(excluded: (Operation & { reason: string })[]): string {
  if (excluded.length === 0) return "";

  return [
    "Declared omissions — the router serves these and the document does not, on purpose:",
    ...excluded.map((operation) => `  ${operation.label} — ${operation.reason}`),
  ].join("\n");
}

function count(offenders: Operation[]): string {
  return `${offenders.length} operation${offenders.length === 1 ? "" : "s"}`;
}
