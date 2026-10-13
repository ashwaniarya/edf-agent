import { McpServer, createMcpHandler, type AuthInfo, type CallToolResult, type ServerContext } from "@modelcontextprotocol/server";
import type { McpIdentity } from "@/src/auth/mcp-guard";
import type { UserDirectory } from "@/src/auth/users";
import { whoami, whoamiTool } from "./tools/whoami";

export type McpDeps = { users: UserDirectory };

/** The SDK never reads `token` on this path, so the raw bearer token stays out of handlers. */
function toAuthInfo(identity: McpIdentity): AuthInfo {
  return { token: "", clientId: identity.clientId, scopes: identity.scopes, extra: { userId: identity.userId } };
}

function identityFrom(ctx: ServerContext): McpIdentity | null {
  const info = ctx.http?.authInfo;
  const userId = info?.extra?.userId;
  if (!info || typeof userId !== "string") return null;
  return { userId, clientId: info.clientId, scopes: info.scopes };
}

const unauthenticated: CallToolResult = { isError: true, content: [{ type: "text", text: "Not signed in." }] };

export function buildMcpServer(deps: McpDeps): McpServer {
  const server = new McpServer({ name: "edf-agent", version: "0.1.0" });
  server.registerTool(whoamiTool.name, whoamiTool.config, async (_args, ctx) => {
    const identity = identityFrom(ctx);
    return identity ? whoami(deps, identity) : unauthenticated;
  });
  return server;
}

/** Serves both MCP eras: 2026-07-28 natively and 2025-era requests statelessly. */
export function createMcpEndpoint(deps: McpDeps) {
  const handler = createMcpHandler(() => buildMcpServer(deps), {
    legacy: "stateless",
    maxSubscriptions: 0,
    onerror: (e) => console.warn("[mcp] request rejected:", e.name),
  });
  return (request: Request, identity: McpIdentity) => handler.fetch(request, { authInfo: toAuthInfo(identity) });
}
