/** Builds MCP requests the way Claude Code sends them, for both protocol eras. */
export const LEGACY_VERSION = "2025-11-25";
export const MODERN_VERSION = "2026-07-28";

type Params = Record<string, unknown>;
let nextId = 1;

export function legacyRequest(url: string, method: string, params: Params = {}, headers: Record<string, string> = {}) {
  const id = nextId++;
  const request = new Request(url, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
      ...(method === "initialize" ? {} : { "mcp-protocol-version": LEGACY_VERSION }),
      ...headers,
    },
    body: JSON.stringify({ jsonrpc: "2.0", id, method, params }),
  });
  return { id, request };
}

export function legacyInitialize(url: string, headers: Record<string, string> = {}) {
  return legacyRequest(url, "initialize", { protocolVersion: LEGACY_VERSION, capabilities: {}, clientInfo: { name: "test", version: "1" } }, headers);
}

export function modernRequest(url: string, method: string, params: Params = {}, headers: Record<string, string> = {}) {
  const id = nextId++;
  const name: Record<string, string> = method === "tools/call" ? { "mcp-name": String(params.name) } : {};
  const request = new Request(url, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
      "mcp-protocol-version": MODERN_VERSION,
      "mcp-method": method,
      ...name,
      ...headers,
    },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id,
      method,
      params: {
        ...params,
        _meta: {
          "io.modelcontextprotocol/protocolVersion": MODERN_VERSION,
          "io.modelcontextprotocol/clientCapabilities": {},
          "io.modelcontextprotocol/clientInfo": { name: "test", version: "1" },
        },
      },
    }),
  });
  return { id, request };
}

/** Reads the JSON-RPC message with `id` from a JSON or SSE response. */
export async function rpcMessage(res: Response, id: number) {
  const type = res.headers.get("content-type") ?? "";
  const text = await res.text();
  if (!type.includes("text/event-stream")) return JSON.parse(text);
  for (const event of text.split(/\r?\n\r?\n/)) {
    const data = event.split(/\r?\n/).filter((l) => l.startsWith("data:")).map((l) => l.slice(5).trimStart()).join("\n");
    if (!data) continue;
    const msg = JSON.parse(data);
    if (msg.id === id) return msg;
  }
  throw new Error(`no JSON-RPC response with id ${id} in SSE stream`);
}
