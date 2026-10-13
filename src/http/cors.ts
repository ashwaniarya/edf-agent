/** Discovery documents are public; browser-based MCP clients fetch them cross-origin. */
const DISCOVERY_CORS: Record<string, string> = {
  "access-control-allow-origin": "*",
  "access-control-allow-methods": "GET, OPTIONS",
  "access-control-allow-headers": "content-type, authorization, mcp-protocol-version",
  "access-control-max-age": "86400",
};

export function withDiscoveryCors(res: Response): Response {
  const out = new Response(res.body, res);
  for (const [k, v] of Object.entries(DISCOVERY_CORS)) out.headers.set(k, v);
  return out;
}

export const discoveryPreflight = () => new Response(null, { status: 204, headers: DISCOVERY_CORS });

export const notFound = () => withDiscoveryCors(Response.json({ error: "not_found" }, { status: 404 }));
