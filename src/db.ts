import { Pool, types } from "pg";

// node-pg returns int8 as a string. Better Auth stores rateLimit.lastRequest (epoch ms) as int8 and computes
// `lastRequest + windowMs - now` for X-Retry-After, which string-concatenates into nonsense. Epoch-ms values
// fit in 2^53, so return a Number (not a BigInt, which JSON.stringify rejects) and keep larger values as exact
// strings. Scoped to this pool; the process-wide pg.types parser is left alone.
const parseInt8 = (value: string) => {
  const n = Number(value);
  return Number.isSafeInteger(n) ? n : value;
};
const getTypeParser = ((oid: number, format?: "text" | "binary") =>
  oid === types.builtins.INT8 && format !== "binary" ? parseInt8 : types.getTypeParser(oid, format)) as typeof types.getTypeParser;

let pool: Pool | undefined;

export function getPool(): Pool | null {
  if (!process.env.DATABASE_URL) return null;
  if (!pool) {
    pool = new Pool({ connectionString: process.env.DATABASE_URL, max: 5, types: { getTypeParser } });
    // An idle client's error (Postgres restart, failover, a reset connection) is emitted on the pool; without a
    // listener it is an uncaught exception that kills the server. The pool drops the client; log only the code.
    pool.on("error", (e) => console.warn("[db] idle client error:", (e as { code?: string }).code ?? e.name));
  }
  return pool;
}
