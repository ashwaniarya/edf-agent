import { execFile } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const ROOT = fileURLToPath(new URL("../", import.meta.url));
// Nothing listens on port 1, so a migration that picked the URL up fails fast instead of touching a database.
const UNREACHABLE = "postgresql://edf:hunter2@127.0.0.1:1/edf";

/** Runs scripts/migrate.ts from `cwd` with only PATH, NODE_ENV=production (as on Railway) and `env` set: no exported DATABASE_URL. */
function migrate(cwd: string, env: Record<string, string> = {}) {
  return new Promise<{ code: number; out: string }>((resolve) => {
    execFile(join(ROOT, "node_modules/.bin/tsx"), [join(ROOT, "scripts/migrate.ts")], { cwd, env: { PATH: process.env.PATH, NODE_ENV: "production", ...env } }, (error, stdout, stderr) =>
      resolve({ code: error ? Number(error.code ?? 1) : 0, out: `${stdout}${stderr}` }),
    );
  });
}

describe("scripts/migrate.ts", { timeout: 30_000 }, () => {
  it("reads DATABASE_URL from the same .env files `next start` loads, instead of skipping and leaving the app unmigrated", async () => {
    const dir = mkdtempSync(join(tmpdir(), "edf-migrate-"));
    writeFileSync(join(dir, ".env.local"), `DATABASE_URL=${UNREACHABLE}\n`);
    const { code, out } = await migrate(dir);
    expect(out).not.toContain("skipping");
    expect(out).toContain("[migrate] failed");
    expect(code).toBe(1);
    expect(out).not.toContain("hunter2");
  });

  it("lets an exported DATABASE_URL (Railway's variables) win over the .env files", async () => {
    const dir = mkdtempSync(join(tmpdir(), "edf-migrate-"));
    writeFileSync(join(dir, ".env.local"), `DATABASE_URL=${UNREACHABLE}\n`);
    const { code, out } = await migrate(dir, { DATABASE_URL: "postgresql://edf:hunter2@127.0.0.1:2/edf" });
    expect(code).toBe(1);
    expect(out).toContain("127.0.0.1:2");
    expect(out).not.toContain("127.0.0.1:1");
  });

  it("still skips when no DATABASE_URL is set anywhere (local `npm start` without a database)", async () => {
    const { code, out } = await migrate(mkdtempSync(join(tmpdir(), "edf-migrate-")));
    expect(out).toContain("DATABASE_URL not set; skipping");
    expect(code).toBe(0);
  });

  it("still refuses to start without a database when REQUIRE_DB=true", async () => {
    const { code, out } = await migrate(mkdtempSync(join(tmpdir(), "edf-migrate-")), { REQUIRE_DB: "true" });
    expect(out).toContain("DATABASE_URL is required");
    expect(code).toBe(1);
  });
});
