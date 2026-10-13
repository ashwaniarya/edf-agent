import { describe, expect, it } from "vitest";
import { onPublicOrigin } from "./public-request";

describe("onPublicOrigin", () => {
  it("moves Next's internal request URL onto the public origin, keeping path, query, method, headers and body", async () => {
    // `next start` builds route-handler request.url as `${proto}://localhost:${PORT}${path}`, whatever the Host.
    const internal = new Request("https://localhost:3477/api/auth/oauth2/token?x=1", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", dpop: "proof", "x-forwarded-for": "203.0.113.9" },
      body: "grant_type=authorization_code&code=abc",
    });
    const pub = onPublicOrigin(internal, "https://edf.example.com");
    expect(pub.url).toBe("https://edf.example.com/api/auth/oauth2/token?x=1");
    expect(pub.method).toBe("POST");
    expect(pub.headers.get("dpop")).toBe("proof");
    expect(pub.headers.get("x-forwarded-for")).toBe("203.0.113.9");
    expect(await pub.text()).toBe("grant_type=authorization_code&code=abc");
  });

  it("handles bodiless requests", () => {
    const pub = onPublicOrigin(new Request("http://localhost:3000/api/auth/jwks"), "https://edf.example.com");
    expect(pub.url).toBe("https://edf.example.com/api/auth/jwks");
    expect(pub.method).toBe("GET");
    expect(pub.body).toBeNull();
  });

  it("returns the same request when it is already on the public origin", () => {
    const req = new Request("https://edf.example.com/api/mcp", { method: "POST", body: "{}" });
    expect(onPublicOrigin(req, "https://edf.example.com")).toBe(req);
  });
});
