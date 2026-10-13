import { afterEach, describe, expect, it, vi } from "vitest";
import { readAuthEnv } from "./env";

const SECRET = "s".repeat(32);
const deployed = { REQUIRE_DB: "true", NODE_ENV: "production" };

describe("readAuthEnv (deployed: REQUIRE_DB=true)", () => {
  it("accepts an https origin and a 32+ char secret and derives issuer, resource and jwks url", () => {
    const r = readAuthEnv({ ...deployed, BETTER_AUTH_URL: "https://edf.example.com", BETTER_AUTH_SECRET: SECRET });
    expect(r).toEqual({
      ok: true,
      config: {
        baseURL: "https://edf.example.com",
        secret: SECRET,
        issuer: "https://edf.example.com/api/auth",
        mcpResource: "https://edf.example.com/api/mcp",
        jwksUrl: "https://edf.example.com/api/auth/jwks",
      },
    });
  });

  it("normalises a trailing slash to the bare origin", () => {
    const r = readAuthEnv({ ...deployed, BETTER_AUTH_URL: "https://edf.example.com/", BETTER_AUTH_SECRET: SECRET });
    expect(r.ok && r.config.mcpResource).toBe("https://edf.example.com/api/mcp");
  });

  it("verifies tokens against the in-container JWKS when PORT is set (no hairpin through the edge)", () => {
    const r = readAuthEnv({ ...deployed, PORT: "8080", BETTER_AUTH_URL: "https://edf.example.com", BETTER_AUTH_SECRET: SECRET });
    expect(r.ok && r.config.jwksUrl).toBe("http://127.0.0.1:8080/api/auth/jwks");
  });

  it("reports a missing BETTER_AUTH_URL", () => {
    const r = readAuthEnv({ ...deployed, BETTER_AUTH_SECRET: SECRET });
    expect(r).toEqual({ ok: false, problems: ["BETTER_AUTH_URL_MISSING"] });
  });

  it("rejects a non-https BETTER_AUTH_URL", () => {
    const r = readAuthEnv({ ...deployed, BETTER_AUTH_URL: "http://edf.example.com", BETTER_AUTH_SECRET: SECRET });
    expect(r).toEqual({ ok: false, problems: ["BETTER_AUTH_URL_INSECURE"] });
  });

  it("allows http only for loopback hosts off-platform (a local `npm start` with REQUIRE_DB=true)", () => {
    for (const url of ["http://localhost:3000", "http://127.0.0.1:3000", "http://[::1]:3000"]) {
      expect(readAuthEnv({ ...deployed, BETTER_AUTH_URL: url, BETTER_AUTH_SECRET: SECRET }).ok).toBe(true);
    }
  });

  it("rejects a loopback BETTER_AUTH_URL, http or https, when running on Railway (e.g. .env.example's value pasted in)", () => {
    for (const platform of [{ RAILWAY_PROJECT_ID: "p" }, { RAILWAY_ENVIRONMENT_ID: "e" }, { RAILWAY_SERVICE_ID: "s" }, { RAILWAY_PUBLIC_DOMAIN: "edf-dev.up.railway.app" }]) {
      for (const url of ["http://localhost:3000", "https://localhost", "http://127.0.0.1:3000", "http://127.1.2.3", "http://[::1]:3000", "https://app.localhost", "http://0.0.0.0:3000"]) {
        expect(readAuthEnv({ ...deployed, ...platform, BETTER_AUTH_URL: url, BETTER_AUTH_SECRET: SECRET })).toEqual({
          ok: false,
          problems: ["BETTER_AUTH_URL_LOOPBACK"],
        });
      }
    }
    expect(readAuthEnv({ ...deployed, RAILWAY_PROJECT_ID: "p", BETTER_AUTH_URL: "https://edf.example.com", BETTER_AUTH_SECRET: SECRET }).ok).toBe(true);
  });

  it("rejects a BETTER_AUTH_URL that is not a bare origin", () => {
    for (const url of ["not a url", "https://edf.example.com/app", "https://edf.example.com?x=1", "https://u:p@edf.example.com"]) {
      expect(readAuthEnv({ ...deployed, BETTER_AUTH_URL: url, BETTER_AUTH_SECRET: SECRET })).toEqual({
        ok: false,
        problems: ["BETTER_AUTH_URL_INVALID"],
      });
    }
  });

  it("reports a missing or short BETTER_AUTH_SECRET", () => {
    expect(readAuthEnv({ ...deployed, BETTER_AUTH_URL: "https://edf.example.com" })).toEqual({
      ok: false,
      problems: ["BETTER_AUTH_SECRET_MISSING"],
    });
    expect(readAuthEnv({ ...deployed, BETTER_AUTH_URL: "https://edf.example.com", BETTER_AUTH_SECRET: "short" })).toEqual({
      ok: false,
      problems: ["BETTER_AUTH_SECRET_TOO_SHORT"],
    });
  });

  it("reports every problem at once and never echoes values", () => {
    const r = readAuthEnv({ ...deployed, BETTER_AUTH_URL: "http://leaky.example.com", BETTER_AUTH_SECRET: "hunter2" });
    expect(r).toEqual({ ok: false, problems: ["BETTER_AUTH_URL_INSECURE", "BETTER_AUTH_SECRET_TOO_SHORT"] });
    expect(JSON.stringify(r)).not.toMatch(/hunter2|leaky/);
  });
});

describe("readAuthEnv (local)", () => {
  it("falls back to dev defaults when nothing is set", () => {
    const r = readAuthEnv({ NODE_ENV: "development" });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.config.baseURL).toBe("http://localhost:3000");
    expect(r.config.mcpResource).toBe("http://localhost:3000/api/mcp");
    expect(r.config.secret.length).toBeGreaterThanOrEqual(32);
  });

  it("accepts a short secret locally", () => {
    expect(readAuthEnv({ NODE_ENV: "development", BETTER_AUTH_SECRET: "dev" }).ok).toBe(true);
  });

  it("still rejects a malformed BETTER_AUTH_URL", () => {
    expect(readAuthEnv({ NODE_ENV: "development", BETTER_AUTH_URL: "https://x.example.com/path" })).toEqual({
      ok: false,
      problems: ["BETTER_AUTH_URL_INVALID"],
    });
  });

  it("refuses the dev secret under NODE_ENV=production even without REQUIRE_DB", () => {
    expect(readAuthEnv({ NODE_ENV: "production", BETTER_AUTH_URL: "http://localhost:3000" })).toEqual({
      ok: false,
      problems: ["BETTER_AUTH_SECRET_MISSING"],
    });
  });
});

describe("GET /api/health surfaces auth config", () => {
  afterEach(() => vi.unstubAllEnvs());

  async function health() {
    const { GET } = await import("@/app/api/health/route");
    const res = await GET();
    return { status: res.status, body: await res.json() };
  }

  it("returns 503 with a reason code (not the value) when deployed without BETTER_AUTH_URL", async () => {
    vi.stubEnv("REQUIRE_DB", "true");
    vi.stubEnv("DATABASE_URL", "");
    vi.stubEnv("BETTER_AUTH_URL", "");
    vi.stubEnv("BETTER_AUTH_SECRET", "a-very-secret-value-that-must-not-leak");
    const { status, body } = await health();
    expect(status).toBe(503);
    expect(body.auth).toBe("misconfigured");
    expect(body.problems).toEqual(["BETTER_AUTH_URL_MISSING"]);
    expect(JSON.stringify(body)).not.toContain("a-very-secret-value");
  });

  it("returns 503 BETTER_AUTH_URL_LOOPBACK on Railway when BETTER_AUTH_URL is a localhost origin", async () => {
    vi.stubEnv("REQUIRE_DB", "true");
    vi.stubEnv("RAILWAY_PROJECT_ID", "p");
    vi.stubEnv("DATABASE_URL", "");
    vi.stubEnv("BETTER_AUTH_URL", "http://localhost:3000");
    vi.stubEnv("BETTER_AUTH_SECRET", "a-very-secret-value-that-must-not-leak");
    const { status, body } = await health();
    expect(status).toBe(503);
    expect(body.problems).toEqual(["BETTER_AUTH_URL_LOOPBACK"]);
  });

  it("reports auth ok locally with dev defaults", async () => {
    vi.stubEnv("REQUIRE_DB", "");
    vi.stubEnv("DATABASE_URL", "");
    vi.stubEnv("BETTER_AUTH_URL", "");
    vi.stubEnv("BETTER_AUTH_SECRET", "");
    const { status, body } = await health();
    expect(status).toBe(200);
    expect(body.auth).toBe("ok");
  });
});
