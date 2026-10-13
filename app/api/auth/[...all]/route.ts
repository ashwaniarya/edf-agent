import { withAuth } from "@/src/auth/auth";
import { onPublicOrigin } from "@/src/http/public-request";

export const dynamic = "force-dynamic";

// The token and userinfo endpoints check DPoP proofs against request.url, which Next sets to its internal URL.
const handle = (request: Request) => withAuth((auth, config) => auth.handler(onPublicOrigin(request, config.baseURL)));

export { handle as GET, handle as POST };
