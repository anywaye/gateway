import type { LimitTable } from "../src/middleware/limits";

export function strictTable(limit: number, windowMs = 60_000): LimitTable {
  return { default: { limit, windowMs, policy: "test" }, routes: {} };
}
