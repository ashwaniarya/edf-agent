import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import type { JWTPayload } from "jose";
import { startLocalJwks, type LocalJwks } from "@/tests/support/local-jwks";
import { createMcpGuard, type McpIdentity } from "./mcp-guard";

const ISSUER = "https://edf.test/api/auth";
const RESOURCE = "https://edf.test/api/mcp";
const METADATA = 'resource_metadata="https://edf.test/.well-known/oauth-protected-resource/api/mcp"';

let jwks: LocalJwks;
beforeAll(async () => void (jwks = await startLocalJwks()));
afterAll(() => jwks.close());
afterEach(() => vi.restoreAllMocks());

const accessToken = (claims: JWTPayload = {}, opts?: { exp?: string | number; foreign?: boolean }) =>
  jwks.sign(
    {
      iss: ISSUER,
      aud: [RESOURCE, `${ISSUER}/oauth2/userinfo`],
      sub: "user_A",
      azp: "client_1",
      client_id: "client_1",
      scope: "openid profile email offline_access",
      ...claims,
    },
    opts,
  );

function setup(jwksPath = "/jwks", handler?: (req: Request, id: McpIdentity) => Promise<Response>) {
  const seen: McpIdentity[] = [];
  const inner = handler ?? (async (_req: Request, id: McpIdentity) => (seen.push(id), Response.json({ ok: true })));
  const guard = createMcpGuard({ issuer: ISSUER, resource: RESOURCE, jwksUrl: jwks.url(jwksPath) }, inner);
  const call = (authorization?: string) =>
    guard(new Request(RESOURCE, { method: "POST", headers: authorization ? { authorization } : {}, body: "{}" }));
  return { call, seen };
}

async function expectUnauthorized(res: Response, { invalidToken }: { invalidToken: boolean }) {
  expect(res.status).toBe(401);
  const challenge = res.headers.get("www-authenticate") ?? "";
  expect(challenge).toMatch(/^Bearer /);
  expect(challenge).toContain(METADATA);
  if (invalidToken) expect(challenge).toContain('error="invalid_token"');
  else expect(challenge).not.toContain("error=");
  expect(await res.json()).toEqual({ jsonrpc: "2.0", error: { code: -32000, message: "Unauthorized" }, id: null });
}

describe("createMcpGuard", () => {
  it("answers a request without Authorization with 401 and an RFC 9728 resource_metadata challenge", async () => {
    const { call, seen } = setup();
    await expectUnauthorized(await call(), { invalidToken: false });
    expect(seen).toEqual([]);
  });

  it("rejects malformed credentials with 401 invalid_token", async () => {
    const { call, seen } = setup();
    for (const header of ["Bearer not-a-jwt", "Bearer a.b.c", "Basic dXNlcjpwYXNz"]) {
      await expectUnauthorized(await call(header), { invalidToken: true });
    }
    expect(seen).toEqual([]);
  });

  it("rejects an expired token with 401 invalid_token", async () => {
    const { call, seen } = setup();
    const token = await accessToken({}, { exp: Math.floor(Date.now() / 1000) - 60 });
    await expectUnauthorized(await call(`Bearer ${token}`), { invalidToken: true });
    expect(seen).toEqual([]);
  });

  it("rejects a token signed by another key and a token with a tampered signature", async () => {
    const { call, seen } = setup();
    await expectUnauthorized(await call(`Bearer ${await accessToken({}, { foreign: true })}`), { invalidToken: true });
    const [h, p, s] = (await accessToken()).split(".");
    const tampered = `${h}.${p}.${s.startsWith("A") ? "B" : "A"}${s.slice(1)}`;
    await expectUnauthorized(await call(`Bearer ${tampered}`), { invalidToken: true });
    expect(seen).toEqual([]);
  });

  it("rejects a token minted for another environment (issuer/audience mismatch) and an id_token", async () => {
    const { call, seen } = setup();
    const otherEnv = await jwks.sign({ iss: "https://dev.edf.test/api/auth", aud: "https://dev.edf.test/api/mcp", sub: "user_A" });
    await expectUnauthorized(await call(`Bearer ${otherEnv}`), { invalidToken: true });
    const idToken = await jwks.sign({ iss: ISSUER, aud: "client_1", sub: "user_A" });
    await expectUnauthorized(await call(`Bearer ${idToken}`), { invalidToken: true });
    expect(seen).toEqual([]);
  });

  it("answers 401 (never 500) without leaking internals when the verifier throws on a failing JWKS endpoint", async () => {
    const logged = vi.spyOn(console, "warn").mockImplementation(() => {});
    vi.spyOn(console, "error").mockImplementation(() => {});
    for (const path of ["/jwks-500", "/jwks-malformed"]) {
      const { call, seen } = setup(path);
      const token = await accessToken();
      const res = await call(`Bearer ${token}`);
      const text = await res.clone().text();
      await expectUnauthorized(res, { invalidToken: true });
      expect(text).not.toMatch(/jwks|hunter2|failed|nope/i);
      expect(seen).toEqual([]);
      expect(logged).toHaveBeenCalled();
      expect(JSON.stringify(logged.mock.calls)).not.toContain(token);
    }
  });

  it("rejects a verified token that has no subject", async () => {
    const { call, seen } = setup();
    const token = await jwks.sign({ iss: ISSUER, aud: RESOURCE, azp: "client_1" });
    await expectUnauthorized(await call(`Bearer ${token}`), { invalidToken: true });
    expect(seen).toEqual([]);
  });

  it("passes the identity from the verified token's sub, azp and scope to the handler", async () => {
    const { call, seen } = setup();
    const res = await call(`Bearer ${await accessToken({ sub: "user_A" })}`);
    expect(res.status).toBe(200);
    expect(seen).toEqual([{ userId: "user_A", clientId: "client_1", scopes: ["openid", "profile", "email", "offline_access"] }]);
  });

  it("turns a handler crash into a generic 500, not a 401 that would trigger re-authentication", async () => {
    vi.spyOn(console, "error").mockImplementation(() => {});
    const { call } = setup("/jwks", async () => {
      throw new Error("db password=hunter2");
    });
    const res = await call(`Bearer ${await accessToken()}`);
    expect(res.status).toBe(500);
    expect(await res.text()).not.toContain("hunter2");
  });
});
