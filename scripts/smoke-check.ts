export type SmokeResult = { pass: true; version: string } | { pass: false; reason: string };
type Fetch = (input: string) => Promise<Response>;

export async function smokeCheck(baseUrl: string, fetchFn: Fetch = fetch): Promise<SmokeResult> {
  const url = `${baseUrl.replace(/\/+$/, "")}/api/health`;
  try {
    const res = await fetchFn(url);
    const body = (await res.json().catch(() => ({}))) as { ok?: boolean; db?: boolean | null; version?: string };
    if (res.status !== 200 || body.ok !== true) return { pass: false, reason: `status ${res.status}` };
    if (body.db !== true) return { pass: false, reason: `db=${body.db}` };
    return { pass: true, version: body.version ?? "unknown" };
  } catch (e) {
    return { pass: false, reason: (e as Error).message };
  }
}
