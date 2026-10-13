export type SmokeResult = { pass: true; version: string } | { pass: false; reason: string };
export type AuthSmokeResult = { pass: true; resource: string } | { pass: false; reason: string };
type Fetch = (input: string, init?: RequestInit) => Promise<Response>;

const trim = (baseUrl: string) => baseUrl.replace(/\/+$/, "");

export async function smokeCheck(baseUrl: string, fetchFn: Fetch = fetch): Promise<SmokeResult> {
  const url = `${trim(baseUrl)}/api/health`;
  try {
    const res = await fetchFn(url);
    const body = (await res.json().catch(() => ({}))) as { ok?: boolean; db?: boolean | null; version?: string };
    if (res.status !== 200 || body.ok !== true) return { pass: false, reason: `status ${res.status}` };
    if (body.db !== true) return { pass: false, reason: `db=${body.db}` };
    return { pass: true, version: body.version ?? "unknown" };
  } catch (e) {
    return { pass: false, reason: (e as Error).message };
  }
}

/** MCP clients can discover the OAuth server, and /api/mcp refuses anonymous calls with an RFC 9728 challenge. */
export async function authSmokeCheck(baseUrl: string, fetchFn: Fetch = fetch): Promise<AuthSmokeResult> {
  const base = trim(baseUrl);
  try {
    const prm = await fetchFn(`${base}/.well-known/oauth-protected-resource`);
    const meta = (await prm.json().catch(() => ({}))) as { resource?: unknown };
    if (prm.status !== 200 || typeof meta.resource !== "string" || !meta.resource) {
      return { pass: false, reason: `protected-resource metadata: status ${prm.status}, resource=${typeof meta.resource}` };
    }

    const mcp = await fetchFn(`${base}/api/mcp`, {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json, text/event-stream" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "smoke", version: "1" } } }),
    });
    if (mcp.status !== 401) return { pass: false, reason: `POST /api/mcp without a token returned ${mcp.status}, expected 401` };
    if (!/resource_metadata="[^"]+"/.test(mcp.headers.get("www-authenticate") ?? "")) {
      return { pass: false, reason: "POST /api/mcp 401 has no WWW-Authenticate resource_metadata" };
    }
    return { pass: true, resource: meta.resource };
  } catch (e) {
    return { pass: false, reason: (e as Error).message };
  }
}
