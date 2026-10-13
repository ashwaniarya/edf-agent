"use client";
import { useEffect, useState } from "react";
import { authClient, authErrorMessage } from "@/src/auth/client";

const SCOPE_LABELS: Record<string, string> = {
  openid: "Confirm your identity",
  profile: "See your name",
  email: "See your email address",
  offline_access: "Stay connected without asking you to sign in again",
};

type ConsentRequest = { clientId: string; scopes: string[]; redirectHost: string };

function readRequest(search: string): ConsentRequest {
  const q = new URLSearchParams(search);
  let redirectHost = "";
  try {
    redirectHost = new URL(q.get("redirect_uri") ?? "").host;
  } catch {}
  return { clientId: q.get("client_id") ?? "", scopes: (q.get("scope") ?? "").split(" ").filter(Boolean), redirectHost };
}

export function ConsentForm() {
  const [request, setRequest] = useState<ConsentRequest | null>(null);
  const [clientName, setClientName] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    const r = readRequest(window.location.search);
    setRequest(r);
    if (r.clientId) {
      authClient.oauth2.publicClient({ query: { client_id: r.clientId } }).then(({ data }) => setClientName(data?.client_name ?? null));
    }
  }, []);

  async function decide(accept: boolean) {
    setBusy(true);
    setError(null);
    const { error } = await authClient.oauth2.consent({ accept });
    if (error) {
      setBusy(false);
      setError(authErrorMessage(error));
    }
  }

  if (!request) return null;
  if (!request.clientId) return <p>This authorization request is incomplete. Start again from your MCP client.</p>;

  return (
    <div style={{ display: "grid", gap: 12, maxWidth: 480 }}>
      <p>
        <strong>{clientName ?? "An application"}</strong> wants to connect to your EDF Agent account.
      </p>
      <ul>
        <li>Act as you through the EDF Agent tools</li>
        {request.scopes.filter((s) => SCOPE_LABELS[s]).map((s) => <li key={s}>{SCOPE_LABELS[s]}</li>)}
      </ul>
      {request.redirectHost && (
        <p style={{ fontSize: 14 }}>
          You will be returned to <code>{request.redirectHost}</code>. Only allow this if you just started the connection yourself.
        </p>
      )}
      {error && <p role="alert" style={{ color: "#b00020", margin: 0 }}>{error}</p>}
      <div style={{ display: "flex", gap: 8 }}>
        <button onClick={() => decide(true)} disabled={busy}>Allow</button>
        <button onClick={() => decide(false)} disabled={busy}>Deny</button>
      </div>
    </div>
  );
}
