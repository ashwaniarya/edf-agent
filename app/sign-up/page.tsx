import { CredentialsForm } from "@/app/_components/credentials-form";

export const metadata = { title: "Create account · EDF Agent" };

export default function SignUpPage() {
  return (
    <main style={{ fontFamily: "system-ui", padding: 24 }}>
      <h1>Create your EDF Agent account</h1>
      <CredentialsForm mode="sign-up" />
    </main>
  );
}
