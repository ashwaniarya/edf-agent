import { ConsentForm } from "./consent-form";

export const metadata = { title: "Authorize · EDF Agent" };

export default function ConsentPage() {
  return (
    <main style={{ fontFamily: "system-ui", padding: 24 }}>
      <h1>Authorize access</h1>
      <ConsentForm />
    </main>
  );
}
