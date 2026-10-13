"use client";
import { createAuthClient } from "better-auth/react";
import { oauthProviderClient } from "@better-auth/oauth-provider/client";

/** oauthProviderClient forwards the signed authorize query (window.location.search) on POSTs, resuming an OAuth flow after sign-in. */
export const authClient = createAuthClient({ plugins: [oauthProviderClient()] });

export function authErrorMessage(error: { code?: string; message?: string; status?: number } | null | undefined): string {
  const text = `${error?.code ?? ""} ${error?.message ?? ""}`.toLowerCase();
  if (text.includes("signature") || text.includes("expired")) {
    return "This sign-in request has expired. Start again from Claude Code (run /mcp and choose Authenticate).";
  }
  if (error?.status === 429) return "Too many attempts. Wait a few seconds and try again.";
  return error?.message || "Something went wrong. Try again.";
}
