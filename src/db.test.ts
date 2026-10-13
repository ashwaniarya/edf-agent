import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { format } from "node:util";
import { types } from "pg";

const URL = "postgresql://edf:hunter2@db.internal:5432/edf";

describe("getPool", () => {
  beforeEach(() => {
    vi.resetModules();
    vi.stubEnv("DATABASE_URL", URL);
  });
  afterEach(() => {
    vi.unstubAllEnvs();
    vi.restoreAllMocks();
  });

  it("handles idle-client errors (Postgres restart, failover, DROP ... WITH (FORCE)) instead of crashing the process, logging only the code", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const { getPool } = await import("./db");
    const pool = getPool()!;
    const err = Object.assign(new Error(`terminating connection for ${URL}`), { code: "57P01" });
    expect(() => pool.emit("error", err)).not.toThrow();
    expect(warn).toHaveBeenCalled();
    const logged = warn.mock.calls.map((a) => format(...a)).join("\n");
    expect(logged).toContain("57P01");
    expect(logged).not.toMatch(/hunter2|db\.internal|terminating|\n\s+at /);
    await pool.end();
  });

  it("parses int8 as a number when it is safe (Better Auth's rateLimit.lastRequest), so X-Retry-After is arithmetic, not string concatenation", async () => {
    const { getPool } = await import("./db");
    const pool = getPool()!;
    const parse = pool.options.types!.getTypeParser(types.builtins.INT8, "text") as (v: string) => unknown;
    expect(parse("1791880778984")).toBe(1791880778984);
    expect(parse("9223372036854775807")).toBe("9223372036854775807"); // beyond 2^53: keep the exact string
    // Other types keep node-pg's defaults.
    expect((pool.options.types!.getTypeParser(types.builtins.INT4, "text") as (v: string) => unknown)("42")).toBe(42);
    expect((pool.options.types!.getTypeParser(types.builtins.NUMERIC, "text") as (v: string) => unknown)("1.50")).toBe("1.50");
    // The process-wide parser is left alone.
    expect(types.getTypeParser(types.builtins.INT8, "text")("1")).toBe("1");
    await pool.end();
  });
});
