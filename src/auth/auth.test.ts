import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { withAuth } from "./auth";

const SECRET = "x-secret-value-that-must-not-appear-anywhere";

describe("withAuth when deployed without a valid auth config", () => {
  let logged: ReturnType<typeof vi.spyOn>;
  beforeEach(() => {
    vi.stubEnv("REQUIRE_DB", "true");
    vi.stubEnv("BETTER_AUTH_URL", "");
    vi.stubEnv("BETTER_AUTH_SECRET", SECRET);
    vi.stubEnv("DATABASE_URL", "");
    logged = vi.spyOn(console, "error").mockImplementation(() => {});
  });
  afterEach(() => {
    vi.unstubAllEnvs();
    vi.restoreAllMocks();
  });

  it("answers 503 without details and never runs the handler", async () => {
    const handler = vi.fn();
    const res = await withAuth(handler);
    expect(res.status).toBe(503);
    expect(handler).not.toHaveBeenCalled();
    expect(await res.json()).toEqual({ error: "auth_unavailable" });
    expect(JSON.stringify(logged.mock.calls)).toContain("BETTER_AUTH_URL_MISSING");
    expect(JSON.stringify(logged.mock.calls)).not.toContain(SECRET);
  });

  it("keeps discovery routes at 503 with CORS rather than a 500", async () => {
    const { GET } = await import("@/app/.well-known/oauth-protected-resource/[[...path]]/route");
    const res = await GET(new Request("https://edf.test/.well-known/oauth-protected-resource/api/mcp"));
    expect(res.status).toBe(503);
    expect(res.headers.get("access-control-allow-origin")).toBe("*");
  });
});
