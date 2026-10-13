import { describe, expect, it } from "vitest";
import { findUntrustedWebRedirect, isTrustedRedirect, validateMcpRedirectUri, withNativeApplicationTypeDefault } from "./registration";

const claudeCodeV1 = {
  client_name: "Claude Code (edf)",
  redirect_uris: ["http://localhost:53682/callback"],
  grant_types: ["authorization_code", "refresh_token"],
  response_types: ["code"],
  token_endpoint_auth_method: "none",
};

describe("withNativeApplicationTypeDefault", () => {
  it("marks a client with only loopback http redirects as native (Claude Code omits application_type)", () => {
    expect(withNativeApplicationTypeDefault(claudeCodeV1)).toEqual({ ...claudeCodeV1, application_type: "native" });
    for (const uri of ["http://127.0.0.1:3118/callback", "http://[::1]:5000/cb"]) {
      expect(withNativeApplicationTypeDefault({ redirect_uris: [uri] })).toMatchObject({ application_type: "native" });
    }
  });

  it("treats private-use URI schemes as native", () => {
    expect(withNativeApplicationTypeDefault({ redirect_uris: ["com.example.edf:/oauth"] })).toMatchObject({ application_type: "native" });
  });

  it("leaves web-style registrations and explicit choices alone", () => {
    for (const body of [
      { redirect_uris: ["https://app.example.com/callback"] },
      { redirect_uris: ["http://localhost:1/cb", "https://app.example.com/cb"] },
      { redirect_uris: ["http://localhost.evil.example/cb"] },
      { redirect_uris: ["https://localhost/cb"] },
      { redirect_uris: [] },
      { redirect_uris: "http://localhost/cb" },
      { ...claudeCodeV1, application_type: "web" },
    ]) {
      expect(withNativeApplicationTypeDefault(body)).toBeNull();
    }
  });

  it("ignores non-object bodies", () => {
    expect(withNativeApplicationTypeDefault(undefined)).toBeNull();
    expect(withNativeApplicationTypeDefault("x")).toBeNull();
  });
});

describe("isTrustedRedirect (authorize-time trust: no auto-redirects to hosts anyone could register)", () => {
  it("trusts loopback http callbacks on any port (Claude Code, other native CLIs)", () => {
    for (const uri of ["http://localhost:53682/callback", "http://127.0.0.1:1/cb", "http://[::1]:5000/cb", "http://localhost/callback"]) {
      expect(isTrustedRedirect(uri)).toBe(true);
    }
  });

  it("trusts https callbacks only on allow-listed hosts (claude.ai web connectors)", () => {
    expect(isTrustedRedirect("https://claude.ai/api/mcp/auth_callback")).toBe(true);
    expect(isTrustedRedirect("https://claude.com/api/mcp/auth_callback")).toBe(true);
    for (const uri of [
      "https://evil.example/landing",
      "https://claude.ai.evil.example/cb",
      "https://evilclaude.ai/cb",
      "https://localhost/cb",
      "https://user:pass@claude.ai/cb",
    ]) {
      expect(isTrustedRedirect(uri)).toBe(false);
    }
  });

  it("rejects non-loopback http, unparsable and script-capable URIs", () => {
    for (const uri of ["http://evil.example/cb", "http://localhost.evil.example/cb", "not a url", "", "javascript:alert(1)", "data:text/html,x", "file:///etc/passwd"]) {
      expect(isTrustedRedirect(uri)).toBe(false);
    }
  });

  it("trusts reverse-domain private-use schemes (validated by Better Auth at registration)", () => {
    expect(isTrustedRedirect("com.example.edf:/oauth")).toBe(true);
  });
});

describe("validateMcpRedirectUri (mcp({ validateRedirectUri }))", () => {
  it("requires both the registered-URI match and a trusted target", () => {
    expect(validateMcpRedirectUri("https://evil.example/landing", ["https://evil.example/landing"], true)).toBe(false);
    expect(validateMcpRedirectUri("http://localhost:40000/callback", ["http://localhost:53682/callback"], true)).toBe(true);
    expect(validateMcpRedirectUri("http://localhost:40000/callback", ["http://localhost:53682/other"], false)).toBe(false);
  });
});

describe("findUntrustedWebRedirect (registration-time check)", () => {
  it("names the first http(s) redirect that is not trusted", () => {
    expect(findUntrustedWebRedirect({ redirect_uris: ["http://localhost:1/cb", "https://evil.example/landing"] })).toBe("https://evil.example/landing");
    expect(findUntrustedWebRedirect({ redirect_uris: ["http://evil.example/cb"] })).toBe("http://evil.example/cb");
  });

  it("accepts Claude Code and claude.ai registrations", () => {
    expect(findUntrustedWebRedirect(claudeCodeV1)).toBeNull();
    expect(findUntrustedWebRedirect({ redirect_uris: ["https://claude.ai/api/mcp/auth_callback"] })).toBeNull();
  });

  it("leaves private-use schemes and malformed bodies to Better Auth's own validation", () => {
    expect(findUntrustedWebRedirect({ redirect_uris: ["cursor://anysphere.cursor-mcp/oauth/callback"] })).toBeNull();
    expect(findUntrustedWebRedirect({ redirect_uris: "https://evil.example/x" })).toBeNull();
    expect(findUntrustedWebRedirect(undefined)).toBeNull();
  });
});
