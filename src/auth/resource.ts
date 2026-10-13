/**
 * RFC 8707 `resource` handling for an authorization server whose only OAuth-protected resource is
 * /api/mcp. Better Auth mints a JWT (aud = resource) only when a resource is bound to the grant;
 * without one it mints an opaque token that /api/mcp can never verify, and the client loops on
 * re-authentication. Clients that predate RFC 8707 omit `resource`, and some send the URL they were
 * configured with, trailing slash included.
 *
 * Returns the parameters with `resource` defaulted (when `fill`) and the MCP URL canonicalized, or
 * null when nothing changes.
 */
export function withMcpResource(params: unknown, mcpResource: string, { fill }: { fill: boolean }): Record<string, unknown> | null {
  if (!params || typeof params !== "object") return null;
  const src = params as Record<string, unknown>;
  const current = src.resource;
  if (current === undefined || current === "" || (Array.isArray(current) && current.length === 0)) {
    return fill ? { ...src, resource: mcpResource } : null;
  }
  const canonical = (v: unknown) => (v === `${mcpResource}/` ? mcpResource : v);
  const next = Array.isArray(current) ? current.map(canonical) : canonical(current);
  return JSON.stringify(next) === JSON.stringify(current) ? null : { ...src, resource: next };
}
