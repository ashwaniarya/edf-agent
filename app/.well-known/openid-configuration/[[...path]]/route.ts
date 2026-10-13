import { oauthProviderOpenIdConfigMetadata } from "@better-auth/oauth-provider";
import { withAuth } from "@/src/auth/auth";
import { discoveryPreflight, notFound, withDiscoveryCors } from "@/src/http/cors";

export const dynamic = "force-dynamic";

const SERVED = new Set(["/.well-known/openid-configuration", "/.well-known/openid-configuration/api/auth"]);

export async function GET(request: Request) {
  if (!SERVED.has(new URL(request.url).pathname)) return notFound();
  return withDiscoveryCors(await withAuth((auth) => oauthProviderOpenIdConfigMetadata(auth)(request)));
}

export const OPTIONS = discoveryPreflight;
