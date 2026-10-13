import { z } from "zod";
import type { CallToolResult } from "@modelcontextprotocol/server";
import type { McpIdentity } from "@/src/auth/mcp-guard";
import type { UserDirectory } from "@/src/auth/users";

const output = z.object({ userId: z.string(), email: z.string(), name: z.string() });

export const whoamiTool = {
  name: "whoami",
  config: {
    title: "Who am I",
    description: "Returns the EDF Agent account (user id, email, name) that this connection is signed in as.",
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

  const result: z.infer<typeof output> = { userId: user.id, email: user.email, name: user.name };
  return { content: [{ type: "text", text: JSON.stringify(result) }], structuredContent: result };
}
