import { withAuth } from "@/src/auth/auth";
import { discoveryPreflight, notFound, withDiscoveryCors } from "@/src/http/cors";

export const dynamic = "force-dynamic";

// RFC 9728: the path-suffixed URL is what the 401 challenge points at; some clients probe the root.
const SERVED = new Set(["/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/api/mcp"]);

export async function GET(request: Request) {
  if (!SERVED.has(new URL(request.url).pathname)) return notFound();
  return withDiscoveryCors(await withAuth((auth) => auth.handler(request)));
}

export const OPTIONS = discoveryPreflight;
