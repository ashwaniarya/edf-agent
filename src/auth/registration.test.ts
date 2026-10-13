import { describe, expect, it } from "vitest";
import { withNativeApplicationTypeDefault } from "./registration";

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
