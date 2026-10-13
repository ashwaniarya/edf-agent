import type { Pool } from "pg";
import { getMigrations } from "better-auth/db/migration";
import { buildAuthOptions } from "./options";

export type MigrationSummary = { created: string[]; altered: string[]; indexes: number };

// The schema does not depend on the origin; mcp() only needs a valid resource URL.
const SCHEMA_ONLY_ORIGIN = "https://schema-only.invalid";

/** Brings the Better Auth schema up to date. Idempotent and serialised across replicas by an advisory lock. */
export async function migrateAuthSchema(pool: Pool): Promise<MigrationSummary> {
  const lock = await pool.connect();
  try {
    await lock.query("select pg_advisory_lock(hashtext('edf-agent:migrate'))");
    const options = buildAuthOptions({ pool, baseURL: SCHEMA_ONLY_ORIGIN, mcpResource: `${SCHEMA_ONLY_ORIGIN}/api/mcp` });
    const { toBeCreated, toBeAdded, toBeAddedIndexes, runMigrations } = await getMigrations(options);
    await runMigrations();
    return { created: toBeCreated.map((t) => t.table), altered: toBeAdded.map((t) => t.table), indexes: toBeAddedIndexes.length };
  } finally {
    await lock.query("select pg_advisory_unlock(hashtext('edf-agent:migrate'))").catch(() => {});
    lock.release();
  }
}
