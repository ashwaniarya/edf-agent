import { createMcpGuard, type McpGuardOptions } from "@/src/auth/mcp-guard";
import type { UserDirectory } from "@/src/auth/users";
import { errorName, jsonRpcError } from "@/src/http/jsonrpc";
import { createMcpEndpoint } from "./server";

export type McpRouteDeps = { guard: McpGuardOptions; users: UserDirectory };

/** Route handlers for /api/mcp. Dependencies load lazily so `next build` never needs env. */
export function createMcpRoute(loadDeps: () => McpRouteDeps | Promise<McpRouteDeps>) {
  let ready: Promise<(request: Request) => Promise<Response>> | undefined;
  const init = async () => {
    const deps = await loadDeps();
    return createMcpGuard(deps.guard, createMcpEndpoint({ users: deps.users }));
  };

  async function POST(request: Request): Promise<Response> {
    let guarded;
    try {
      guarded = await (ready ??= init());
    } catch (e) {
      ready = undefined;
      console.error("[mcp] unavailable:", errorName(e));
      return jsonRpcError(503, -32603, "Service unavailable");
    }
    return guarded(request);
  }

  const methodNotAllowed = async () => jsonRpcError(405, -32000, "Method not allowed.", { allow: "POST" });

  return { POST, GET: methodNotAllowed, DELETE: methodNotAllowed };
}
