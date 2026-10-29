
import { readdirSync } from "node:fs";
import { join } from "node:path";

export type Stage = {
  readonly base: string;
  readonly instructions: readonly string[];
};

const FROM = /^FROM\s+(\S+)(?:\s+AS\s+(\S+))?\s*$/i;
const COPY = /^COPY\s+(.*)$/i;

const NOT_TREE = new Set([".git", "node_modules", "coverage", "dist", "vendor"]);

const PRE_STAGE = "";
const UNNAMED = "(unnamed)";

export function parseStages(dockerfile: string): Record<string, Stage> {
  const stages: Record<string, Stage> = {};
  let base = "";
  let instructions: string[] = [];
  let name: string | null = null;

  const close = (): void => {
    if (name === null) {
      if (instructions.length > 0) stages[PRE_STAGE] = { base: "", instructions };
    } else {
      stages[name] = { base, instructions };
    }
  };

  dockerfile.split("\n").forEach((raw, index) => {
    const line = raw.trim();
    if (line === "" || line.startsWith("#")) return;

    if (line.endsWith("\\")) {
      throw new Error(
        `Dockerfile line ${index + 1} is continued onto the next one, and this reader does ` +
          `not follow continuations: it would read one instruction as two, and the one that ` +
          `decided what the image holds would be the wrong half.\n  ${line}`,
      );
    }

    const from = FROM.exec(line);
    if (from === null) {
      instructions.push(line);
      return;
    }

    close();
    name = from[2] ?? UNNAMED;
    base = from[1] ?? "";
    instructions = [];
  });
  close();

  return stages;
}

export function stageChain(stages: Record<string, Stage>, name: string): string[] {
  const chain: string[] = [];
  const seen = new Set<string>();
  let current: string | undefined = name;

  while (current !== undefined) {
    const stage: Stage | undefined = stages[current];
    if (stage === undefined) {
      if (chain.length === 0) throw new Error(`this Dockerfile has no stage named \`${name}\``);
      return chain.reverse();
    }
    if (seen.has(current)) {
      throw new Error(`stage \`${current}\` is its own ancestor: ${[...chain, current].join(" -> ")}`);
    }
    seen.add(current);
    chain.push(current);
    current = stages[stage.base] === undefined ? undefined : stage.base;
  }

  return chain.reverse();
}

export function copySources(instructions: readonly string[]): string[] {
  const sources: string[] = [];

  for (const instruction of instructions) {
    const args = COPY.exec(instruction)?.[1];
    if (args === undefined) continue;

    const words = args.split(/\s+/).filter((word) => word !== "");
    if (words[0]?.startsWith("[")) {
      throw new Error(
        `COPY in its JSON-array form is not read by this reader, and reading it as a ` +
          `shell-form list would name sources it does not contain: ${instruction}`,
      );
    }
    if (words.some((word) => word.startsWith("--from="))) continue;

    const paths: string[] = [];
    for (let i = 0; i < words.length; i += 1) {
      const word = words[i];
      if (word === undefined) continue;
      if (!word.startsWith("--")) {
        paths.push(word);
      } else if (!word.includes("=")) {
        i += 1;
      }
    }

    for (const source of paths.slice(0, -1)) sources.push(source);
  }

  return sources;
}

export function copiesInto(dockerfile: string, stage: string): string[] {
  const stages = parseStages(dockerfile);
  return stageChain(stages, stage).flatMap((name) => copySources(stages[name]?.instructions ?? []));
}

export function covers(sources: readonly string[], path: string): boolean {
  return sources.some((source) => {
    const from = source.replace(/\/+$/, "").replace(/^\.\
    return from === "." || from === path || path.startsWith(`${from}/`);
  });
}

export function findFiles(root: string, keep: (name: string) => boolean): string[] {
  const found: string[] = [];

  const walk = (dir: string, prefix: string): void => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      if (NOT_TREE.has(entry.name)) continue;
      const path = prefix === "" ? entry.name : `${prefix}/${entry.name}`;
      if (entry.isDirectory()) walk(join(dir, entry.name), path);
      else if (keep(entry.name)) found.push(path);
    }
  };
  walk(root, "");

  return found.sort();
}

export function findTestFiles(root: string): string[] {
  return findFiles(root, (name) => name.endsWith(".test.ts"));
}
