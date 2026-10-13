"use client";
import { authClient } from "@/src/auth/client";

export function SignOutButton() {
  return <button onClick={async () => { await authClient.signOut(); window.location.assign("/sign-in"); }}>Sign out</button>;
}
