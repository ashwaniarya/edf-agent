import { headers } from "next/headers";
import { redirect } from "next/navigation";
import { getAuth } from "@/src/auth/auth";
import { requireAuthConfig } from "@/src/config/env";
import { SignOutButton } from "./sign-out-button";

export const dynamic = "force-dynamic";
export const metadata = { title: "Dashboard · EDF Agent" };

export default async function DashboardPage() {
  const session = await getAuth().api.getSession({ headers: await headers() });
  if (!session) redirect("/sign-in");
  const { mcpResource } = requireAuthConfig();

  return (
    <main style={{ fontFamily: "system-ui", padding: 24, display: "grid", gap: 12 }}>
      <h1>EDF Agent</h1>
      <p>
        Signed in as <strong>{session.user.email}</strong>
      </p>
      <p>Connect Claude Code:</p>
      <pre style={{ background: "#f4f4f4", padding: 12, overflowX: "auto" }}>claude mcp add --transport http edf {mcpResource}</pre>
      <div>
        <SignOutButton />
      </div>
    </main>
  );
}
