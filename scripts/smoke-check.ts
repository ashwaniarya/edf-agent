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

type ResourceMetadata = { resource?: unknown; authorization_servers?: unknown };

/**
 * MCP clients can discover the OAuth server, and /api/mcp refuses anonymous calls with an RFC 9728 challenge.
 * Every advertised URL must be on the origin being smoked: discovery is built from BETTER_AUTH_URL, so a value
 * copied from another environment (or left on another domain) serves the other environment's resource and issuer,
 * which clients such as Claude Code refuse.
 */
export async function authSmokeCheck(baseUrl: string, fetchFn: Fetch = fetch): Promise<AuthSmokeResult> {
  try {
    const origin = new URL(baseUrl).origin;
    const resource = `${origin}/api/mcp`;
    const issuer = `${origin}/api/auth`;
    const metadataUrl = `${origin}/.well-known/oauth-protected-resource/api/mcp`;
    const hint = "(BETTER_AUTH_URL must be this origin)";

    const checkMetadata = async (url: string): Promise<string | null> => {
      const res = await fetchFn(url);
      const meta = (await res.json().catch(() => ({}))) as ResourceMetadata;
      if (res.status !== 200 || typeof meta.resource !== "string" || !meta.resource) {
        return `protected-resource metadata ${url}: status ${res.status}, resource=${typeof meta.resource}`;
      }
      if (meta.resource !== resource) return `protected-resource metadata advertises ${meta.resource}, expected ${resource} ${hint}`;
      const as = Array.isArray(meta.authorization_servers) ? meta.authorization_servers[0] : undefined;
      if (as !== issuer) return `protected-resource metadata names authorization server ${String(as)}, expected ${issuer} ${hint}`;
      return null;
    };

    const rootProblem = await checkMetadata(`${origin}/.well-known/oauth-protected-resource`);
    if (rootProblem) return { pass: false, reason: rootProblem };

    const mcp = await fetchFn(resource, {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json, text/event-stream" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "smoke", version: "1" } } }),
    });
    if (mcp.status !== 401) return { pass: false, reason: `POST /api/mcp without a token returned ${mcp.status}, expected 401` };
    const named = /resource_metadata="([^"]+)"/.exec(mcp.headers.get("www-authenticate") ?? "")?.[1];
    if (!named) return { pass: false, reason: "POST /api/mcp 401 has no WWW-Authenticate resource_metadata" };
    if (named !== metadataUrl) return { pass: false, reason: `401 challenge names ${named}, expected ${metadataUrl} ${hint}` };

    // The URL the challenge names is the one clients actually fetch.
    const suffixedProblem = await checkMetadata(metadataUrl);
    if (suffixedProblem) return { pass: false, reason: suffixedProblem };

    const as = await fetchFn(`${origin}/.well-known/oauth-authorization-server/api/auth`);
    const asMeta = (await as.json().catch(() => ({}))) as { issuer?: unknown };
    if (as.status !== 200 || asMeta.issuer !== issuer) {
      return { pass: false, reason: `authorization-server metadata: status ${as.status}, issuer ${String(asMeta.issuer)}, expected ${issuer} ${hint}` };
    }
    return { pass: true, resource };
  } catch (e) {
    return { pass: false, reason: (e as Error).message };
  }
}
