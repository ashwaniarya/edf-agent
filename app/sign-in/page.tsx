import { CredentialsForm } from "@/app/_components/credentials-form";

export const metadata = { title: "Sign in · EDF Agent" };

export default function SignInPage() {
  return (
    <main style={{ fontFamily: "system-ui", padding: 24 }}>
      <h1>Sign in to EDF Agent</h1>
      <CredentialsForm mode="sign-in" />
    </main>
  );
}
