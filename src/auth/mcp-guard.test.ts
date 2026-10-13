import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { SignJWT, exportJWK, generateKeyPair, type CryptoKey, type JWK, type JWTPayload } from "jose";
import { createMcpGuard, type McpIdentity } from "./mcp-guard";

const ISSUER = "https://edf.test/api/auth";
const RESOURCE = "https://edf.test/api/mcp";
const METADATA = 'resource_metadata="https://edf.test/.well-known/oauth-protected-resource/api/mcp"';

let server: Server;
let base = "";
let signingKey: CryptoKey;
let foreignKey: CryptoKey;
let publicJwk: JWK;

beforeAll(async () => {
  const pair = await generateKeyPair("EdDSA", { extractable: true });
  signingKey = pair.privateKey;
  foreignKey = (await generateKeyPair("EdDSA")).privateKey;
  publicJwk = { ...(await exportJWK(pair.publicKey)), kid: "k1", alg: "EdDSA" };

  server = createServer((req, res) => {
    const send = (status: number, body: string) => res.writeHead(status, { "content-type": "application/json" }).end(body);
    if (req.url === "/jwks") return send(200, JSON.stringify({ keys: [publicJwk] }));
    if (req.url === "/jwks-500") return send(500, JSON.stringify({ error: "db password=hunter2" }));
    if (req.url === "/jwks-malformed") return send(200, JSON.stringify({ keys: "nope" }));
    send(404, "{}");
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

afterAll(() => new Promise<void>((r) => server.close(() => r())));
afterEach(() => vi.restoreAllMocks());

function sign(claims: JWTPayload, opts: { key?: CryptoKey; exp?: string | number } = {}) {
  return new SignJWT({ azp: "client_1", client_id: "client_1", scope: "openid profile email offline_access", ...claims })
    .setProtectedHeader({ alg: "EdDSA", kid: "k1" })
    .setIssuer(ISSUER)
    .setAudience([RESOURCE, `${ISSUER}/oauth2/userinfo`])
    .setSubject("user_A")
    .setIssuedAt()
    .setExpirationTime(opts.exp ?? "5m")
    .sign(opts.key ?? signingKey);
}

function setup(jwksPath = "/jwks", handler?: (req: Request, id: McpIdentity) => Promise<Response>) {
  const seen: McpIdentity[] = [];
  const inner = handler ?? (async (_req: Request, id: McpIdentity) => (seen.push(id), Response.json({ ok: true })));
  const guard = createMcpGuard({ issuer: ISSUER, resource: RESOURCE, jwksUrl: `${base}${jwksPath}` }, inner);
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
  const body = await res.json();
  expect(body).toEqual({ jsonrpc: "2.0", error: { code: -32000, message: "Unauthorized" }, id: null });
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
    const token = await sign({}, { exp: Math.floor(Date.now() / 1000) - 60 });
    await expectUnauthorized(await call(`Bearer ${token}`), { invalidToken: true });
    expect(seen).toEqual([]);
  });

  it("rejects a token signed by another key and a token with a tampered signature", async () => {
    const { call, seen } = setup();
    await expectUnauthorized(await call(`Bearer ${await sign({}, { key: foreignKey })}`), { invalidToken: true });
    const [h, p, s] = (await sign({})).split(".");
    const tampered = `${h}.${p}.${s.startsWith("A") ? "B" : "A"}${s.slice(1)}`;
    await expectUnauthorized(await call(`Bearer ${tampered}`), { invalidToken: true });
    expect(seen).toEqual([]);
  });

  it("rejects a token minted for another environment (issuer/audience mismatch) and an id_token", async () => {
    const { call, seen } = setup();
    const otherEnv = await new SignJWT({ scope: "openid" })
      .setProtectedHeader({ alg: "EdDSA", kid: "k1" })
      .setIssuer("https://dev.edf.test/api/auth")
      .setAudience("https://dev.edf.test/api/mcp")
      .setSubject("user_A")
      .setExpirationTime("5m")
      .sign(signingKey);
    await expectUnauthorized(await call(`Bearer ${otherEnv}`), { invalidToken: true });
    const idToken = await new SignJWT({}).setProtectedHeader({ alg: "EdDSA", kid: "k1" }).setIssuer(ISSUER)
      .setAudience("client_1").setSubject("user_A").setExpirationTime("5m").sign(signingKey);
    await expectUnauthorized(await call(`Bearer ${idToken}`), { invalidToken: true });
    expect(seen).toEqual([]);
  });

  it("answers 401 (never 500) without leaking internals when the verifier throws on a failing JWKS endpoint", async () => {
    const logged = vi.spyOn(console, "warn").mockImplementation(() => {});
    vi.spyOn(console, "error").mockImplementation(() => {});
    for (const path of ["/jwks-500", "/jwks-malformed"]) {
      const { call, seen } = setup(path);
      const token = await sign({});
      const res = await call(`Bearer ${token}`);
      const text = await res.clone().text();
      await expectUnauthorized(res, { invalidToken: true });
      expect(text).not.toMatch(/jwks|hunter2|failed|nope/i);
      expect(seen).toEqual([]);
      expect(JSON.stringify(logged.mock.calls)).not.toContain(token);
    }
  });

  it("rejects a verified token that has no subject", async () => {
    const { call, seen } = setup();
    const token = await new SignJWT({ azp: "client_1" }).setProtectedHeader({ alg: "EdDSA", kid: "k1" })
      .setIssuer(ISSUER).setAudience(RESOURCE).setExpirationTime("5m").sign(signingKey);
    await expectUnauthorized(await call(`Bearer ${token}`), { invalidToken: true });
    expect(seen).toEqual([]);
  });

  it("passes the identity from the verified token's sub, azp and scope to the handler", async () => {
    const { call, seen } = setup();
    const res = await call(`Bearer ${await sign({ sub: "user_A" })}`);
    expect(res.status).toBe(200);
    expect(seen).toEqual([{ userId: "user_A", clientId: "client_1", scopes: ["openid", "profile", "email", "offline_access"] }]);
  });

  it("turns a handler crash into a generic 500, not a 401 that would trigger re-authentication", async () => {
    vi.spyOn(console, "error").mockImplementation(() => {});
    const { call } = setup("/jwks", async () => {
      throw new Error("db password=hunter2");
    });
    const res = await call(`Bearer ${await sign({})}`);
    expect(res.status).toBe(500);
    expect(await res.text()).not.toContain("hunter2");
  });
});
