import { describe, expect, it, vi } from "vitest";

vi.mock("@/src/auth/auth", () => ({
  withAuth: (fn: (auth: unknown, config: unknown) => Promise<Response>) =>
    fn(
      { handler: async (req: Request) => Response.json({ url: req.url, method: req.method, body: await req.text(), dpop: req.headers.get("dpop") }) },
      { baseURL: "https://edf.example.com" },
    ),
}));

describe("/api/auth/[...all] route", () => {
  it("hands Better Auth the request on the public origin, so DPoP htu checks at the token endpoint match the advertised URL", async () => {
    const { POST } = await import("@/app/api/auth/[...all]/route");
    const res = await POST(
      new Request("https://localhost:3477/api/auth/oauth2/token", { method: "POST", headers: { dpop: "proof" }, body: "grant_type=refresh_token" }),
    );
    expect(await res.json()).toEqual({
      url: "https://edf.example.com/api/auth/oauth2/token",
      method: "POST",
      body: "grant_type=refresh_token",
      dpop: "proof",
    });
  });
});
