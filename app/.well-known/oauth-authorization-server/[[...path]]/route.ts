import { oauthProviderAuthServerMetadata } from "@better-auth/oauth-provider";
import { withAuth } from "@/src/auth/auth";
import { discoveryPreflight, notFound, withDiscoveryCors } from "@/src/http/cors";

export const dynamic = "force-dynamic";

// RFC 8414 path insertion for issuer `${origin}/api/auth`, plus the root for clients that skip RFC 9728.
const SERVED = new Set(["/.well-known/oauth-authorization-server", "/.well-known/oauth-authorization-server/api/auth"]);

export async function GET(request: Request) {
  if (!SERVED.has(new URL(request.url).pathname)) return notFound();
  return withDiscoveryCors(await withAuth((auth) => oauthProviderAuthServerMetadata(auth)(request)));
}

export const OPTIONS = discoveryPreflight;
