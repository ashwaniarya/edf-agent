import { createDpopReplayStore } from "better-auth/oauth2";
import { getAuth } from "@/src/auth/auth";
import { userDirectoryFrom } from "@/src/auth/users";
import { requireAuthConfig } from "@/src/config/env";
import { createMcpRoute } from "@/src/mcp/route";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export const { POST, GET, DELETE } = createMcpRoute(async () => {
  const config = requireAuthConfig();
  const auth = getAuth();
  const { internalAdapter } = await auth.$context;
  return {
    guard: {
      issuer: config.issuer,
      resource: config.mcpResource,
      jwksUrl: config.jwksUrl,
      dpopReplayStore: createDpopReplayStore(internalAdapter),
    },
    users: userDirectoryFrom(auth),
  };
});
