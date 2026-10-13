import { createMcpProtectedRequestHandler } from "@better-auth/mcp";
import type { DpopReplayStore } from "better-auth/oauth2";
import type { JWTPayload } from "jose";
import { errorName, jsonRpcError } from "@/src/http/jsonrpc";

/** Caller identity derived only from a verified access token. */
export type McpIdentity = { userId: string; clientId: string; scopes: string[] };

export type McpGuardOptions = {
  issuer: string;
  /** Canonical MCP resource; must equal the token audience and mcp({ resource }). */
  resource: string;
  jwksUrl: string;
  dpopReplayStore?: DpopReplayStore;
};

export type McpGuardedHandler = (request: Request, identity: McpIdentity) => Promise<Response>;

export function protectedResourceMetadataUrl(resource: string): string {
  const url = new URL(resource);
  return `${url.origin}/.well-known/oauth-protected-resource${url.pathname.replace(/\/$/, "")}`;
}

export function identityFromClaims(claims: JWTPayload): McpIdentity | null {
  if (typeof claims.sub !== "string" || !claims.sub) return null;
  const clientId = typeof claims.azp === "string" ? claims.azp : typeof claims.client_id === "string" ? claims.client_id : "";
  const scopes = typeof claims.scope === "string" ? claims.scope.split(" ").filter(Boolean) : [];
  return { userId: claims.sub, clientId, scopes };
}

/**
 * Verifies the bearer token (signature, issuer, audience, expiry) and hands the
 * handler an identity taken from the token alone. Every auth failure, including
 * verifier/JWKS errors, is a 401 with an RFC 9728 challenge and a fixed body.
 */
export function createMcpGuard(options: McpGuardOptions, handler: McpGuardedHandler): (request: Request) => Promise<Response> {
  const metadataUrl = protectedResourceMetadataUrl(options.resource);
  const unauthorized = (invalidToken: boolean) =>
    jsonRpcError(401, -32000, "Unauthorized", {
      "www-authenticate": `Bearer ${invalidToken ? 'error="invalid_token", ' : ""}resource_metadata="${metadataUrl}"`,
    });

  const authenticated = new WeakSet<Request>();
  const verified = createMcpProtectedRequestHandler(
    {
      issuer: options.issuer,
      audience: options.resource,
      jwksUrl: options.jwksUrl,
      dpop: options.dpopReplayStore ? { replayStore: options.dpopReplayStore } : undefined,
    },
    async (request, claims) => {
      const identity = identityFromClaims(claims);
      if (!identity) return unauthorized(true);
      authenticated.add(request);
      try {
        return await handler(request, identity);
      } catch (e) {
        console.error("[mcp] handler failed:", errorName(e));
        return jsonRpcError(500, -32603, "Internal error");
      }
    },
  );

  return async (request) => {
    const hasCredentials = request.headers.has("authorization");
    let res: Response;
    try {
      res = await verified(request);
    } catch (e) {
      console.warn("[mcp-auth] token verification error:", errorName(e));
      return unauthorized(true);
    }
    if (res.status === 401 && !authenticated.has(request)) return unauthorized(hasCredentials);
    return res;
  };
}
