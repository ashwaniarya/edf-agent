import { getHealth } from "@/src/health/health";
import { getPool } from "@/src/db";
import { readAuthEnv } from "@/src/config/env";

export const dynamic = "force-dynamic";

export async function GET() {
  const pool = getPool();
  const authEnv = readAuthEnv();
  const { status, body } = await getHealth({
    pingDb: pool ? async () => void (await pool.query("select 1")) : null,
    requireDb: process.env.REQUIRE_DB === "true",
    version: process.env.RAILWAY_GIT_COMMIT_SHA?.slice(0, 7) ?? process.env.APP_VERSION ?? "dev",
    authProblems: authEnv.ok ? [] : authEnv.problems,
  });
  return Response.json(body, { status, headers: { "cache-control": "no-store" } });
}
