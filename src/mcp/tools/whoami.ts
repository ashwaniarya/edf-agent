import { z } from "zod";
import type { CallToolResult } from "@modelcontextprotocol/server";
import type { McpIdentity } from "@/src/auth/mcp-guard";
import type { UserDirectory } from "@/src/auth/users";

const output = z.object({ userId: z.string(), email: z.string().optional(), name: z.string().optional() });

export const whoamiTool = {
  name: "whoami",
  config: {
    title: "Who am I",
    description:
      "Returns the EDF Agent account this connection is signed in as: the user id, plus the email and name when the email and profile scopes were granted.",
    inputSchema: z.strictObject({}),
    outputSchema: output,
    annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: false },
  },
};

const toolError = (text: string): CallToolResult => ({ isError: true, content: [{ type: "text", text }] });

export async function whoami(deps: { users: UserDirectory }, identity: McpIdentity): Promise<CallToolResult> {
  let user;
  try {
    user = await deps.users.findById(identity.userId);
  } catch (e) {
    console.error("[mcp] whoami lookup failed:", e instanceof Error ? e.name : "unknown");
    return toolError("whoami failed. Try again later.");
  }
  if (!user) return toolError("The signed-in account no longer exists. Re-authenticate.");

  // Mirror the consent screen and Better Auth's userinfo: identity fields only for the scopes that were granted.
  const result: z.infer<typeof output> = { userId: user.id };
  if (identity.scopes.includes("email")) result.email = user.email;
  if (identity.scopes.includes("profile")) result.name = user.name;
  return { content: [{ type: "text", text: JSON.stringify(result) }], structuredContent: result };
}
