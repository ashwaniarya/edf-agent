import type { Pool } from "pg";
import type { BetterAuthOptions } from "better-auth";
import { APIError, createAuthMiddleware } from "better-auth/api";
import { jwt } from "better-auth/plugins";
import { mcp } from "@better-auth/mcp";
import { cimd } from "@better-auth/cimd";
import { fetchClientMetadataResource } from "@better-auth/cimd/node";
import { findUntrustedWebRedirect, validateMcpRedirectUri, withNativeApplicationTypeDefault } from "./registration";

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
    disabledPaths: [
      // The jwt plugin's session-JWT endpoint is not part of the OAuth flow.
      "/token",
      // Managed-client endpoints: unused here, and they would let any signed-in user mint or repoint
      // clients outside the /oauth2/register rate limit.
      "/oauth2/create-client",
      "/oauth2/update-client",
      "/oauth2/client/rotate-secret",
      "/oauth2/delete-client",
    ],
    telemetry: { enabled: false },
    rateLimit: {
      enabled: true,
      storage: "database",
      window: 60,
      max: 100,
      // The key set is public and cheap. Every in-container verifier fetch arrives as 127.0.0.1, so a shared
      // bucket would let forged-kid tokens (each forces a refetch) starve key loading for valid tokens.
      customRules: { "/jwks": false },
    },
    advanced: { ipAddress: { ipAddressHeaders: ["x-forwarded-for", "x-real-ip"] } },
    hooks: {
      before: createAuthMiddleware(async (ctx) => {
        if (ctx.path !== "/oauth2/register") return;
        const untrusted = findUntrustedWebRedirect(ctx.body);
        if (untrusted) {
          throw new APIError("BAD_REQUEST", {
            error: "invalid_redirect_uri",
            error_description: `redirect_uri ${untrusted} is not allowed: use a loopback http callback (localhost, 127.0.0.1, [::1]), a reverse-domain private-use scheme, or an allow-listed https host`,
          });
        }
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
        // Registration is open, so a registered redirect is not trusted by itself: authorize never sends a
        // browser (even with an early error) to a redirect outside loopback/allow-listed hosts (RFC 9700 §4.11.2).
        validateRedirectUri: validateMcpRedirectUri,
      }),
      cimd({ fetchClientMetadataResource, metadataProfile: "mcp-2026-07-28" }),
    ],
  } satisfies BetterAuthOptions;
}
