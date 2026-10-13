import { Pool } from "pg";
import { migrateAuthSchema } from "../src/auth/migrate";

const url = process.env.DATABASE_URL;
if (!url) {
  if (process.env.REQUIRE_DB === "true") {
    console.error("[migrate] DATABASE_URL is required when REQUIRE_DB=true");
    process.exit(1);
  }
  console.log("[migrate] DATABASE_URL not set; skipping");
  process.exit(0);
}

const pool = new Pool({ connectionString: url, max: 3 });
try {
  const { created, altered, indexes } = await migrateAuthSchema(pool);
  console.log(
    created.length + altered.length + indexes
      ? `[migrate] create=${created.join(",") || "-"} alter=${altered.join(",") || "-"} indexes=${indexes}`
      : "[migrate] schema up to date",
  );
} catch (e) {
  console.error("[migrate] failed:", e instanceof Error ? e.message : "unknown error");
  process.exitCode = 1;
} finally {
  await pool.end();
}
