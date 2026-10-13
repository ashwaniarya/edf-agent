import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { createHash, randomBytes } from "node:crypto";
import { fileURLToPath } from "node:url";
import pg from "pg";
import { decodeJwt } from "jose";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { legacyInitialize, legacyRequest, modernRequest, rpcMessage } from "@/tests/support/mcp-rpc";

const ADMIN_URL = process.env.TEST_DATABASE_URL;
if (!ADMIN_URL) console.warn("[integration] TEST_DATABASE_URL is not set; skipping the S1 auth-flow suite.");

const ROOT = fileURLToPath(new URL("../../", import.meta.url));

const claude = vi.hoisted(() => {
  const id = "https://claude.ai/oauth/claude-code-client-metadata";
  return {
    id,
    document: {
      client_id: id,
      client_name: "Claude Code",
      client_uri: "https://claude.ai",
      redirect_uris: ["http://localhost/callback", "http://127.0.0.1/callback"],
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      token_endpoint_auth_method: "none",
    },
  };
});

// The real transport pins DNS to claude.ai over node:https; serve Claude Code's published document instead.
vi.mock("@better-auth/cimd/node", () => ({
  fetchClientMetadataResource: async (input: RequestInfo | URL) => {
    const url = input instanceof Request ? input.url : String(input);
    if (url !== claude.id) return new Response("not found", { status: 404 });
    return new Response(JSON.stringify(claude.document), {
      status: 200,
      headers: { "content-type": "application/json", "cache-control": "max-age=300" },
    });
  },
}));

type Route = Record<string, unknown>;

describe.skipIf(!ADMIN_URL)("S1: Claude Code signs in over OAuth and calls whoami", { timeout: 30_000 }, () => {
  const dbName = `edf_it_${randomBytes(4).toString("hex")}`;
  let admin: pg.Pool;
  let databaseUrl = "";
  let server: Server;
  let BASE = "";
  let MCP = "";
  let ISSUER = "";
  const users: Record<"A" | "B", { id: string; email: string; ip: string; cookie: string; access: string; refresh: string }> = {
    A: { id: "", email: "asha@example.com", ip: "203.0.113.10", cookie: "", access: "", refresh: "" },
    B: { id: "", email: "bala@example.com", ip: "203.0.113.11", cookie: "", access: "", refresh: "" },
  };
  let dcrClientId = "";

  beforeAll(async () => {
    admin = new pg.Pool({ connectionString: ADMIN_URL, max: 1 });
    await admin.query(`create database ${dbName}`);
    const u = new URL(ADMIN_URL!);
    u.pathname = `/${dbName}`;
    databaseUrl = u.toString();

    server = createServer((req, res) =>
      void dispatch(req, res).catch((e) => {
        console.error("[integration] dispatch failed:", e);
        res.writeHead(500).end();
      }),
    );
    await new Promise<void>((r) => server.listen(0, r));
    BASE = `http://localhost:${(server.address() as AddressInfo).port}`;
    MCP = `${BASE}/api/mcp`;
    ISSUER = `${BASE}/api/auth`;

    vi.stubEnv("DATABASE_URL", databaseUrl);
    vi.stubEnv("BETTER_AUTH_URL", BASE);
    vi.stubEnv("BETTER_AUTH_SECRET", randomBytes(32).toString("base64"));
    vi.stubEnv("REQUIRE_DB", "");
    vi.stubEnv("PORT", "");
  });

  afterAll(async () => {
    server?.closeAllConnections();
    await new Promise<void>((r) => server?.close(() => r()));
    const { getPool } = await import("@/src/db");
    await getPool()?.end();
    await admin?.query(`drop database if exists ${dbName} with (force)`);
    await admin?.end();
    vi.unstubAllEnvs();
  });

  async function routes(): Promise<[(path: string) => boolean, Route][]> {
    return [
      [(p) => p.startsWith("/api/auth/"), await import("@/app/api/auth/[...all]/route")],
      [(p) => p === "/api/mcp", await import("@/app/api/mcp/route")],
      [(p) => /^\/\.well-known\/oauth-protected-resource(\/|$)/.test(p), await import("@/app/.well-known/oauth-protected-resource/[[...path]]/route")],
      [(p) => /^\/\.well-known\/oauth-authorization-server(\/|$)/.test(p), await import("@/app/.well-known/oauth-authorization-server/[[...path]]/route")],
      [(p) => /^\/\.well-known\/openid-configuration(\/|$)/.test(p), await import("@/app/.well-known/openid-configuration/[[...path]]/route")],
    ];
  }

  async function dispatch(req: IncomingMessage, res: ServerResponse) {
    const chunks: Buffer[] = [];
    for await (const c of req) chunks.push(c as Buffer);
    const headers = new Headers();
    for (const [k, v] of Object.entries(req.headers)) if (typeof v === "string") headers.set(k, v);
    const request = new Request(new URL(req.url!, BASE), {
      method: req.method,
      headers,
      body: ["GET", "HEAD"].includes(req.method!) ? undefined : Buffer.concat(chunks),
    });
    const path = new URL(request.url).pathname;
    const route = (await routes()).find(([match]) => match(path))?.[1];
    const handler = route?.[request.method] as ((req: Request) => Promise<Response>) | undefined;
    const response = handler ? await handler(request) : new Response("not found", { status: 404 });
    res.statusCode = response.status;
    response.headers.forEach((v, k) => k !== "set-cookie" && res.setHeader(k, v));
    const cookies = response.headers.getSetCookie();
    if (cookies.length) res.setHeader("set-cookie", cookies);
    res.end(Buffer.from(await response.arrayBuffer()));
  }

  const cookieOf = (res: Response) => res.headers.getSetCookie().map((c) => c.split(";")[0]).join("; ");

  function browserPost(path: string, body: unknown, who: { ip: string; cookie?: string }) {
    return fetch(`${BASE}${path}`, {
      method: "POST",
      headers: { "content-type": "application/json", origin: BASE, "x-forwarded-for": who.ip, ...(who.cookie ? { cookie: who.cookie } : {}) },
      body: JSON.stringify(body),
    });
  }

  function pkce() {
    const verifier = randomBytes(32).toString("base64url");
    return { verifier, challenge: createHash("sha256").update(verifier).digest("base64url") };
  }

  /** Browser leg: authorize -> sign-in (resumes the signed request) -> consent -> callback with code. */
  async function authorize(who: (typeof users)["A"], clientId: string, redirectUri: string, scope: string | null) {
    const { verifier, challenge } = pkce();
    const state = randomBytes(8).toString("hex");
    const q = new URLSearchParams({
      response_type: "code",
      client_id: clientId,
      redirect_uri: redirectUri,
      state,
      code_challenge: challenge,
      code_challenge_method: "S256",
      resource: MCP,
      prompt: "consent",
    });
    if (scope) q.set("scope", scope);

    const start = await fetch(`${BASE}/api/auth/oauth2/authorize?${q}`, { redirect: "manual", headers: { "x-forwarded-for": who.ip } });
    const loginUrl = new URL(start.status === 302 ? start.headers.get("location")! : (await start.json()).url, BASE);
    expect(loginUrl.pathname).toBe("/sign-in");
    expect(loginUrl.searchParams.get("sig")).toBeTruthy();

    const signIn = await browserPost("/api/auth/sign-in/email", { email: who.email, password: "correct horse battery", oauth_query: loginUrl.search.slice(1) }, who);
    expect(signIn.status).toBe(200);
    who.cookie = cookieOf(signIn);
    const consentUrl = new URL((await signIn.json()).url, BASE);
    expect(consentUrl.pathname).toBe("/consent");
    expect(consentUrl.searchParams.get("client_id")).toBe(clientId);

    const consent = await browserPost("/api/auth/oauth2/consent", { accept: true, oauth_query: consentUrl.search.slice(1) }, who);
    expect(consent.status).toBe(200);
    const callback = new URL((await consent.json()).url);
    expect(`${callback.origin}${callback.pathname}`).toBe(redirectUri);
    expect(callback.searchParams.get("state")).toBe(state);
    expect(callback.searchParams.get("iss")).toBe(ISSUER);

    const token = await fetch(`${BASE}/api/auth/oauth2/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code: callback.searchParams.get("code")!,
        code_verifier: verifier,
        redirect_uri: redirectUri,
        client_id: clientId,
        resource: MCP,
      }),
    });
    expect(token.status).toBe(200);
    const body = await token.json();
    who.access = body.access_token;
    who.refresh = body.refresh_token;
    return body as { access_token: string; refresh_token?: string; id_token?: string; token_type: string };
  }

  async function whoami(token: string, era: "legacy" | "modern" = "modern") {
    const auth = { authorization: `Bearer ${token}` };
    const call = era === "legacy"
      ? legacyRequest(MCP, "tools/call", { name: "whoami", arguments: {} }, auth)
      : modernRequest(MCP, "tools/call", { name: "whoami", arguments: {} }, auth);
    const res = await fetch(call.request);
    return { status: res.status, res, msg: res.status === 200 ? await rpcMessage(res, call.id) : null };
  }

  it("migrates with the deploy script, and a second run is a no-op", async () => {
    const run = () =>
      promisify(execFile)(`${ROOT}node_modules/.bin/tsx`, ["scripts/migrate.ts"], {
        cwd: ROOT,
        env: { PATH: process.env.PATH, NODE_ENV: "production", DATABASE_URL: databaseUrl },
      });
    const first = await run();
    expect(first.stdout).toMatch(/create=.*user.*oauthClient/);
    const second = await run();
    expect(second.stdout).toContain("up to date");
    const { rows } = await admin.query("select 1"); // admin still healthy
    expect(rows).toHaveLength(1);
  });

  it("challenges an unauthenticated MCP request with 401 pointing at RFC 9728 metadata", async () => {
    for (const { request } of [legacyInitialize(MCP), modernRequest(MCP, "server/discover")]) {
      const res = await fetch(request);
      expect(res.status).toBe(401);
      expect(res.headers.get("www-authenticate")).toContain(`resource_metadata="${BASE}/.well-known/oauth-protected-resource/api/mcp"`);
    }
  });

  it("serves protected-resource metadata at the challenged URL and the root, with CORS", async () => {
    for (const path of ["/.well-known/oauth-protected-resource/api/mcp", "/.well-known/oauth-protected-resource"]) {
      const res = await fetch(`${BASE}${path}`, { headers: { origin: "https://inspector.example" } });
      expect(res.status).toBe(200);
      expect(res.headers.get("access-control-allow-origin")).toBe("*");
      expect(await res.json()).toMatchObject({ resource: MCP, authorization_servers: [ISSUER], bearer_methods_supported: ["header"] });
    }
    const preflight = await fetch(`${BASE}/.well-known/oauth-protected-resource/api/mcp`, { method: "OPTIONS" });
    expect(preflight.status).toBe(204);
    expect(preflight.headers.get("access-control-allow-methods")).toContain("GET");
  });

  it("serves authorization-server metadata (path-inserted and root) with PKCE, DCR and CIMD, with CORS", async () => {
    for (const path of ["/.well-known/oauth-authorization-server/api/auth", "/.well-known/oauth-authorization-server"]) {
      const res = await fetch(`${BASE}${path}`);
      expect(res.status).toBe(200);
      expect(res.headers.get("access-control-allow-origin")).toBe("*");
      const meta = await res.json();
      expect(meta).toMatchObject({
        issuer: ISSUER,
        authorization_endpoint: `${ISSUER}/oauth2/authorize`,
        token_endpoint: `${ISSUER}/oauth2/token`,
        registration_endpoint: `${ISSUER}/oauth2/register`,
        client_id_metadata_document_supported: true,
        code_challenge_methods_supported: ["S256"],
        grant_types_supported: ["authorization_code", "refresh_token"],
      });
      expect(meta.response_types_supported).toContain("code");
      expect(meta.token_endpoint_auth_methods_supported).toContain("none");
    }
    expect((await fetch(`${BASE}/.well-known/oauth-authorization-server/nope`)).status).toBe(404);
    const oidc = await fetch(`${BASE}/.well-known/openid-configuration/api/auth`);
    expect(oidc.status).toBe(200);
    expect((await oidc.json()).issuer).toBe(ISSUER);
  });

  it("signs up users A and B", async () => {
    for (const key of ["A", "B"] as const) {
      const who = users[key];
      const res = await browserPost("/api/auth/sign-up/email", { email: who.email, password: "correct horse battery", name: `User ${key}` }, who);
      expect(res.status).toBe(200);
      who.id = (await res.json()).user.id;
      expect(who.id).toBeTruthy();
    }
  });

  it("registers Claude Code through DCR without application_type (defaults to native for loopback redirects)", async () => {
    const res = await fetch(`${BASE}/api/auth/oauth2/register`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-forwarded-for": "198.51.100.1" },
      body: JSON.stringify({
        client_name: "Claude Code (edf)",
        redirect_uris: ["http://localhost:53682/callback"],
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
        token_endpoint_auth_method: "none",
      }),
    });
    expect(res.status).toBe(201);
    const client = await res.json();
    expect(client.application_type).toBe("native");
    expect(client.client_secret).toBeUndefined();
    dcrClientId = client.client_id;
  });

  it("user A authorizes the DCR client (scope=offline_access, PKCE S256, resource) and gets a JWT bound to /api/mcp", async () => {
    const tokens = await authorize(users.A, dcrClientId, "http://localhost:53682/callback", "offline_access");
    expect(tokens.token_type.toLowerCase()).toBe("bearer");
    expect(tokens.refresh_token).toBeTruthy();
    const claims = decodeJwt(tokens.access_token);
    expect(claims.iss).toBe(ISSUER);
    expect([claims.aud].flat()).toContain(MCP);
    expect(claims.sub).toBe(users.A.id);
  });

  it("A's token calls whoami over both protocol eras and gets A", async () => {
    for (const era of ["modern", "legacy"] as const) {
      const { status, msg } = await whoami(users.A.access, era);
      expect(status).toBe(200);
      expect(msg.result.structuredContent).toEqual({ userId: users.A.id, email: users.A.email, name: "User A" });
    }
    const list = modernRequest(MCP, "tools/list", {}, { authorization: `Bearer ${users.A.access}` });
    const listed = await rpcMessage(await fetch(list.request), list.id);
    expect(listed.result.tools.map((t: { name: string }) => t.name)).toContain("whoami");
  });

  it("user B signs in through Claude Code's CIMD client id (any loopback port) and whoami returns B", async () => {
    const tokens = await authorize(users.B, claude.id, "http://localhost:61234/callback", null);
    expect(decodeJwt(tokens.access_token).sub).toBe(users.B.id);
    const { status, msg } = await whoami(users.B.access);
    expect(status).toBe(200);
    expect(msg.result.structuredContent).toEqual({ userId: users.B.id, email: users.B.email, name: "User B" });
  });

  it("refreshes A's token and the new access token still resolves to A", async () => {
    const res = await fetch(`${BASE}/api/auth/oauth2/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: users.A.refresh, client_id: dcrClientId, resource: MCP }),
    });
    expect(res.status).toBe(200);
    const { access_token } = await res.json();
    const { msg } = await whoami(access_token);
    expect(msg.result.structuredContent.userId).toBe(users.A.id);
  });

  it("rejects A's token with a tampered signature (401, never 500)", async () => {
    const [h, p, s] = users.A.access.split(".");
    const tampered = `${h}.${p}.${s.startsWith("A") ? "B" : "A"}${s.slice(1)}`;
    const { status, res } = await whoami(tampered);
    expect(status).toBe(401);
    expect(res.headers.get("www-authenticate")).toContain('error="invalid_token"');
    const forged = `${h}.${Buffer.from(JSON.stringify({ ...decodeJwt(users.A.access), sub: users.B.id })).toString("base64url")}.${s}`;
    expect((await whoami(forged)).status).toBe(401);
  });

  it("rate-limits client registration per client IP", async () => {
    const register = () =>
      fetch(`${BASE}/api/auth/oauth2/register`, {
        method: "POST",
        headers: { "content-type": "application/json", "x-forwarded-for": "198.51.100.77" },
        body: JSON.stringify({ redirect_uris: ["http://localhost:1/callback"], token_endpoint_auth_method: "none" }),
      });
    const statuses = [];
    for (let i = 0; i < 6; i++) statuses.push((await register()).status);
    expect(statuses.slice(0, 5)).toEqual([201, 201, 201, 201, 201]);
    expect(statuses[5]).toBe(429);
    expect((await fetch(`${BASE}/api/auth/oauth2/register`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-forwarded-for": "198.51.100.78" },
      body: JSON.stringify({ redirect_uris: ["http://localhost:1/callback"], token_endpoint_auth_method: "none" }),
    })).status).toBe(201);
  });
});
