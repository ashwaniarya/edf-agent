"use client";
import { useEffect, useState, type FormEvent } from "react";
import { authClient, authErrorMessage } from "@/src/auth/client";

type Mode = "sign-in" | "sign-up";

export function CredentialsForm({ mode }: { mode: Mode }) {
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [search, setSearch] = useState("");
  useEffect(() => setSearch(window.location.search), []);

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    const form = new FormData(event.currentTarget);
    const email = String(form.get("email"));
    const password = String(form.get("password"));
    const { data, error } =
      mode === "sign-in"
        ? await authClient.signIn.email({ email, password })
        : await authClient.signUp.email({ email, password, name: String(form.get("name")) });
    if (error) {
      setBusy(false);
      return setError(authErrorMessage(error));
    }
    // During an OAuth sign-in the server answers {redirect: true, url} and the client navigates to consent itself.
    if (data && "redirect" in data && data.redirect) return;
    window.location.assign("/dashboard");
  }

  const other = mode === "sign-in" ? { href: "/sign-up", label: "Create an account" } : { href: "/sign-in", label: "I already have an account" };

  return (
    <form onSubmit={onSubmit} style={{ display: "grid", gap: 12, maxWidth: 360 }}>
      {mode === "sign-up" && (
        <label>
          Name
          <input name="name" required autoComplete="name" style={{ display: "block", width: "100%" }} />
        </label>
      )}
      <label>
        Email
        <input name="email" type="email" required autoComplete="email" style={{ display: "block", width: "100%" }} />
      </label>
      <label>
        Password
        <input
          name="password"
          type="password"
          required
          minLength={10}
          autoComplete={mode === "sign-in" ? "current-password" : "new-password"}
          style={{ display: "block", width: "100%" }}
        />
      </label>
      {error && <p role="alert" style={{ color: "#b00020", margin: 0 }}>{error}</p>}
      <button type="submit" disabled={busy}>{mode === "sign-in" ? "Sign in" : "Create account"}</button>
      <a href={`${other.href}${search}`}>{other.label}</a>
    </form>
  );
}
