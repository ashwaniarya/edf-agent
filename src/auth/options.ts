import type { Pool } from "pg";
import type { BetterAuthOptions } from "better-auth";
import { createAuthMiddleware } from "better-auth/api";
import { jwt } from "better-auth/plugins";
import { mcp } from "@better-auth/mcp";
import { cimd } from "@better-auth/cimd";
import { fetchClientMetadataResource } from "@better-auth/cimd/node";
import { withNativeApplicationTypeDefault } from "./registration";

export type AuthOptionsInput = {
  pool: Pool;
  /** Public origin; Better Auth serves under `${baseURL}/api/auth`, which is also the issuer. */
  baseURL: string;
  /** Canonical MCP resource; tokens are audience-bound to it. */
  mcpResource: string;
  secret?: string;
};

/** Pure options builder: constructing `betterAuth()` is left to the caller. */
export function buildAuthOptions({ pool, baseURL, mcpResource, secret }: AuthOptionsInput) {
  return {
    appName: "EDF Agent",
    baseURL,
    secret,
    trustedOrigins: [baseURL],
    database: pool,
    emailAndPassword: { enabled: true, minPasswordLength: 10 },
    // The jwt plugin's session-JWT endpoint is not part of the OAuth flow.
    disabledPaths: ["/token"],
    telemetry: { enabled: false },
    rateLimit: { enabled: true, storage: "database", window: 60, max: 100 },
    advanced: { ipAddress: { ipAddressHeaders: ["x-forwarded-for", "x-real-ip"] } },
    hooks: {
      before: createAuthMiddleware(async (ctx) => {
        if (ctx.path !== "/oauth2/register") return;
        const body = withNativeApplicationTypeDefault(ctx.body);
        if (body) return { context: { body } };
      }),
    },
    plugins: [
      jwt({ disableSettingJwtHeader: true }),
      mcp({
        resource: mcpResource,
        loginPage: "/sign-in",
        consentPage: "/consent",
        signup: { page: "/sign-up" },
        // No client_credentials: every access token's `sub` is a user id.
        grantTypes: ["authorization_code", "refresh_token"],
        allowDynamicClientRegistration: true,
        allowUnauthenticatedClientRegistration: true,
        rateLimit: { register: { window: 60, max: 5 } },
      }),
      cimd({ fetchClientMetadataResource, metadataProfile: "mcp-2026-07-28" }),
    ],
  } satisfies BetterAuthOptions;
}
