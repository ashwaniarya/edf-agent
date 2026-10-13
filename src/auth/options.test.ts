import { describe, expect, it } from "vitest";
import type { Pool } from "pg";
import { buildAuthOptions } from "./options";

const options = () => buildAuthOptions({ pool: {} as Pool, baseURL: "https://edf.test", mcpResource: "https://edf.test/api/mcp", secret: "s".repeat(32) });

describe("buildAuthOptions", () => {
  it("takes the public JWKS out of the shared per-IP limiter (every in-container verifier fetch is keyed 127.0.0.1)", () => {
    expect(options().rateLimit.customRules["/jwks"]).toBe(false);
  });

  it("does not mount the managed-client endpoints, so clients are only minted through rate-limited /oauth2/register or CIMD", () => {
    expect(options().disabledPaths).toEqual(
      expect.arrayContaining(["/oauth2/create-client", "/oauth2/update-client", "/oauth2/client/rotate-secret", "/oauth2/delete-client"]),
    );
    // The consent page needs these two.
    expect(options().disabledPaths).not.toContain("/oauth2/public-client");
    expect(options().disabledPaths).not.toContain("/oauth2/consent");
  });
});
