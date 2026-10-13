import { describe, expect, it } from "vitest";
import { withMcpResource } from "./resource";

const MCP = "https://edf.test/api/mcp";

describe("withMcpResource (RFC 8707 resource defaulting for the only protected resource)", () => {
  it("fills a missing or empty resource when asked to, so pre-RFC 8707 clients still get a JWT for /api/mcp", () => {
    expect(withMcpResource({ client_id: "c" }, MCP, { fill: true })).toEqual({ client_id: "c", resource: MCP });
    expect(withMcpResource({ client_id: "c", resource: "" }, MCP, { fill: true })).toEqual({ client_id: "c", resource: MCP });
    expect(withMcpResource({ client_id: "c", resource: [] }, MCP, { fill: true })).toEqual({ client_id: "c", resource: MCP });
  });

  it("leaves a missing resource alone when not filling (the token endpoint falls back to the grant's stored resource)", () => {
    expect(withMcpResource({ grant_type: "refresh_token" }, MCP, { fill: false })).toBeNull();
  });

  it("canonicalizes a trailing-slash MCP URL, alone or in a list", () => {
    expect(withMcpResource({ resource: `${MCP}/` }, MCP, { fill: false })).toEqual({ resource: MCP });
    expect(withMcpResource({ resource: [`${MCP}/`, "https://edf.test/api/auth/oauth2/userinfo"] }, MCP, { fill: true })).toEqual({
      resource: [MCP, "https://edf.test/api/auth/oauth2/userinfo"],
    });
  });

  it("returns null when nothing changes, and ignores non-object input", () => {
    expect(withMcpResource({ resource: MCP }, MCP, { fill: true })).toBeNull();
    expect(withMcpResource({ resource: "https://other.example/api" }, MCP, { fill: true })).toBeNull();
    expect(withMcpResource(undefined, MCP, { fill: true })).toBeNull();
    expect(withMcpResource("resource=x", MCP, { fill: true })).toBeNull();
  });
});
