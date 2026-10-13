import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import type { UserDirectory } from "@/src/auth/users";
import { startLocalJwks, type LocalJwks } from "@/tests/support/local-jwks";
import { LEAK, logged } from "@/tests/support/logs";
import { LEGACY_VERSION, MODERN_VERSION, legacyInitialize, legacyRequest, modernRequest, rpcMessage } from "@/tests/support/mcp-rpc";
import { createMcpRoute } from "./route";

const ORIGIN = "https://edf.test";
const ISSUER = `${ORIGIN}/api/auth`;
const RESOURCE = `${ORIGIN}/api/mcp`;

const users: UserDirectory = {
  findById: async (id) =>
    ({
      user_A: { id: "user_A", email: "a@example.com", name: "Asha" },
      user_B: { id: "user_B", email: "b@example.com", name: "Bala" },
    })[id] ?? null,
};

let jwks: LocalJwks;
let route: ReturnType<typeof createMcpRoute>;
let bearer: (sub: string) => Promise<Record<string, string>>;

beforeAll(async () => {
  jwks = await startLocalJwks();
  route = createMcpRoute(() => ({ guard: { issuer: ISSUER, resource: RESOURCE, jwksUrl: jwks.url() }, users }));
  bearer = async (sub) => ({
    authorization: `Bearer ${await jwks.sign({ iss: ISSUER, aud: [RESOURCE, `${ISSUER}/oauth2/userinfo`], sub, azp: "client_1", scope: "openid profile email offline_access" })}`,
  });
});
afterAll(() => jwks.close());
afterEach(() => vi.restoreAllMocks());

async function send({ id, request }: { id: number; request: Request }) {
  const res = await route.POST(request);
  expect(res.status).toBe(200);
  return rpcMessage(res, id);
}

describe("POST /api/mcp — 2025-11-25 (stateless legacy; Claude Code's fallback after a 401 and its v1 runtime)", () => {
  it("initializes without a session id", async () => {
    const { id, request } = legacyInitialize(RESOURCE, await bearer("user_A"));
    const res = await route.POST(request);
    expect(res.status).toBe(200);
    expect(res.headers.get("mcp-session-id")).toBeNull();
    expect(res.headers.get("content-type")).toContain("text/event-stream");
    const msg = await rpcMessage(res, id);
    expect(msg.result.protocolVersion).toBe(LEGACY_VERSION);
    expect(msg.result.serverInfo.name).toBe("edf-agent");
    expect(msg.result.capabilities.tools).toBeDefined();
  });

  it("lists whoami with an empty input schema", async () => {
    const msg = await send(legacyRequest(RESOURCE, "tools/list", {}, await bearer("user_A")));
    const tool = msg.result.tools.find((t: { name: string }) => t.name === "whoami");
    expect(tool).toBeDefined();
    expect(tool.inputSchema.properties ?? {}).toEqual({});
  });

  it("calls whoami and returns the token subject's own account", async () => {
    const msg = await send(legacyRequest(RESOURCE, "tools/call", { name: "whoami", arguments: {} }, await bearer("user_A")));
    expect(msg.result.structuredContent).toEqual({ userId: "user_A", email: "a@example.com", name: "Asha" });
  });

  it("ignores no input: a userId argument is rejected, never used to look up someone else", async () => {
    const msg = await send(legacyRequest(RESOURCE, "tools/call", { name: "whoami", arguments: { userId: "user_B" } }, await bearer("user_A")));
    expect(msg.result.isError).toBe(true);
    expect(JSON.stringify(msg)).not.toContain("b@example.com");
  });
});

describe("POST /api/mcp — 2026-07-28 (Claude Code's default negotiation)", () => {
  it("answers server/discover", async () => {
    const { id, request } = modernRequest(RESOURCE, "server/discover", {}, await bearer("user_A"));
    const res = await route.POST(request);
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toContain("application/json");
    const msg = await rpcMessage(res, id);
    expect(msg.result.supportedVersions).toContain(MODERN_VERSION);
  });

  it("lists and calls whoami for each caller's own identity", async () => {
    const list = await send(modernRequest(RESOURCE, "tools/list", {}, await bearer("user_A")));
    expect(list.result.tools.map((t: { name: string }) => t.name)).toContain("whoami");

    const a = await send(modernRequest(RESOURCE, "tools/call", { name: "whoami", arguments: {} }, await bearer("user_A")));
    expect(a.result.structuredContent).toEqual({ userId: "user_A", email: "a@example.com", name: "Asha" });
    const b = await send(modernRequest(RESOURCE, "tools/call", { name: "whoami", arguments: {} }, await bearer("user_B")));
    expect(b.result.structuredContent).toEqual({ userId: "user_B", email: "b@example.com", name: "Bala" });
  });
});

describe("/api/mcp route edges", () => {
  it("rejects a token from the right key and audience but another issuer (route-level issuer wiring)", async () => {
    const token = await jwks.sign({ iss: "https://dev.edf.test/api/auth", aud: RESOURCE, sub: "user_A", azp: "client_1" });
    const res = await route.POST(legacyInitialize(RESOURCE, { authorization: `Bearer ${token}` }).request);
    expect(res.status).toBe(401);
    expect(res.headers.get("www-authenticate")).toContain('error="invalid_token"');
  });

  it("challenges unauthenticated initialize and server/discover probes with 401", async () => {
    for (const { request } of [legacyInitialize(RESOURCE), modernRequest(RESOURCE, "server/discover")]) {
      const res = await route.POST(request);
      expect(res.status).toBe(401);
      expect(res.headers.get("www-authenticate")).toContain(`resource_metadata="${ORIGIN}/.well-known/oauth-protected-resource/api/mcp"`);
    }
  });

  it("answers GET and DELETE with 405 and Allow: POST", async () => {
    for (const handler of [route.GET, route.DELETE]) {
      const res = await handler();
      expect(res.status).toBe(405);
      expect(res.headers.get("allow")).toBe("POST");
    }
  });

  it("answers 503 without details when dependencies cannot be loaded, and retries on the next request", async () => {
    const error = vi.spyOn(console, "error").mockImplementation(() => {});
    let attempts = 0;
    const flaky = createMcpRoute(() => {
      attempts++;
      throw new Error("BETTER_AUTH_SECRET=hunter2 missing");
    });
    const res = await flaky.POST(legacyInitialize(RESOURCE).request);
    expect(res.status).toBe(503);
    expect(await res.text()).not.toContain("hunter2");
    await flaky.POST(legacyInitialize(RESOURCE).request);
    expect(attempts).toBe(2);
    expect(error).toHaveBeenCalled();
    expect(logged(error)).not.toMatch(LEAK);
  });
});
