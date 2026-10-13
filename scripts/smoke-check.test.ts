import { describe, expect, it } from "vitest";
import { authSmokeCheck, smokeCheck } from "./smoke-check";

const res = (status: number, body: unknown) => async () => new Response(JSON.stringify(body), { status });

describe("smokeCheck", () => {
  it("passes when health is ok and db is up", async () => {
    const r = await smokeCheck("https://x", res(200, { ok: true, db: true, version: "a" }));
    expect(r).toEqual({ pass: true, version: "a" });
  });
  it("fails when db is down", async () => {
    const r = await smokeCheck("https://x", res(503, { ok: false, db: false, version: "a" }));
    expect(r.pass).toBe(false);
  });
  it("fails when db is not configured (prod must have a db)", async () => {
    const r = await smokeCheck("https://x", res(200, { ok: true, db: null, version: "a" }));
    expect(r.pass).toBe(false);
  });
  it("fails, not throws, on network error", async () => {
    const r = await smokeCheck("https://x", async () => { throw new Error("ENOTFOUND"); });
    expect(r).toMatchObject({ pass: false });
  });
  it("calls /api/health without double slashes", async () => {
    let url = "";
    await smokeCheck("https://x/", async (u) => { url = String(u); return new Response("{}"); });
    expect(url).toBe("https://x/api/health");
  });
});

type Served = Partial<Record<"prm" | "prmSuffixed" | "mcp" | "as", Response>>;

/** A deployment whose discovery documents are all built from `configured` (its BETTER_AUTH_URL). */
function fakeEnv(overrides: Served = {}, configured = "https://x") {
  const prm = { resource: `${configured}/api/mcp`, authorization_servers: [`${configured}/api/auth`] };
  const challenge = `Bearer resource_metadata="${configured}/.well-known/oauth-protected-resource/api/mcp"`;
  const calls: { url: string; method: string; headers: Headers }[] = [];
  const fetchFn = async (url: string, init?: RequestInit) => {
    calls.push({ url, method: init?.method ?? "GET", headers: new Headers(init?.headers) });
    const path = new URL(url).pathname;
    if (path === "/.well-known/oauth-protected-resource") return overrides.prm ?? Response.json(prm);
    if (path === "/.well-known/oauth-protected-resource/api/mcp") return overrides.prmSuffixed ?? Response.json(prm);
    if (path === "/.well-known/oauth-authorization-server/api/auth") return overrides.as ?? Response.json({ issuer: `${configured}/api/auth` });
    if (path === "/api/mcp") return overrides.mcp ?? new Response("{}", { status: 401, headers: { "www-authenticate": challenge } });
    return new Response("not found", { status: 404 });
  };
  return { fetchFn, calls };
}

const challengedBy = (metadataUrl: string) => new Response("{}", { status: 401, headers: { "www-authenticate": `Bearer resource_metadata="${metadataUrl}"` } });

describe("authSmokeCheck", () => {
  it("passes when discovery and the 401 challenge all name this origin", async () => {
    const { fetchFn, calls } = fakeEnv();
    expect(await authSmokeCheck("https://x/", fetchFn)).toEqual({ pass: true, resource: "https://x/api/mcp" });
    expect(calls.map((c) => `${c.method} ${c.url}`)).toEqual([
      "GET https://x/.well-known/oauth-protected-resource",
      "POST https://x/api/mcp",
      "GET https://x/.well-known/oauth-protected-resource/api/mcp",
      "GET https://x/.well-known/oauth-authorization-server/api/auth",
    ]);
    expect(calls[1].headers.get("authorization")).toBeNull();
  });

  it("fails when the deployment advertises another environment's origin (BETTER_AUTH_URL copied from prod)", async () => {
    const r = await authSmokeCheck("https://edf-dev.example", fakeEnv({}, "https://edf-prod.example").fetchFn);
    expect(r.pass).toBe(false);
    expect("reason" in r && r.reason).toMatch(/https:\/\/edf-prod\.example\/api\/mcp.*expected https:\/\/edf-dev\.example\/api\/mcp.*BETTER_AUTH_URL/);
  });

  it("fails when the metadata is missing or has no resource", async () => {
    expect((await authSmokeCheck("https://x", fakeEnv({ prm: new Response("nope", { status: 404 }) }).fetchFn)).pass).toBe(false);
    expect((await authSmokeCheck("https://x", fakeEnv({ prm: Response.json({}) }).fetchFn)).pass).toBe(false);
    expect((await authSmokeCheck("https://x", fakeEnv({ prm: new Response("<html>") }).fetchFn)).pass).toBe(false);
  });

  it("fails when the metadata names another resource or authorization server", async () => {
    const otherResource = Response.json({ resource: "https://other/api/mcp", authorization_servers: ["https://x/api/auth"] });
    expect((await authSmokeCheck("https://x", fakeEnv({ prm: otherResource }).fetchFn)).pass).toBe(false);
    const otherAs = Response.json({ resource: "https://x/api/mcp", authorization_servers: ["https://other/api/auth"] });
    expect((await authSmokeCheck("https://x", fakeEnv({ prm: otherAs }).fetchFn)).pass).toBe(false);
  });

  it("fails when /api/mcp answers an anonymous call with anything but 401", async () => {
    const r = await authSmokeCheck("https://x", fakeEnv({ mcp: Response.json({ result: {} }) }).fetchFn);
    expect(r).toEqual({ pass: false, reason: "POST /api/mcp without a token returned 200, expected 401" });
  });

  it("fails when the 401 has no resource_metadata challenge, or names another host's metadata", async () => {
    const bare = new Response("{}", { status: 401, headers: { "www-authenticate": "Bearer" } });
    expect((await authSmokeCheck("https://x", fakeEnv({ mcp: bare }).fetchFn)).pass).toBe(false);
    const other = challengedBy("https://other/.well-known/oauth-protected-resource/api/mcp");
    expect((await authSmokeCheck("https://x", fakeEnv({ mcp: other }).fetchFn)).pass).toBe(false);
  });

  it("fails when the metadata URL the challenge names (the one clients fetch) is missing or disagrees", async () => {
    expect((await authSmokeCheck("https://x", fakeEnv({ prmSuffixed: new Response("nope", { status: 404 }) }).fetchFn)).pass).toBe(false);
    const other = Response.json({ resource: "https://other/api/mcp", authorization_servers: ["https://x/api/auth"] });
    expect((await authSmokeCheck("https://x", fakeEnv({ prmSuffixed: other }).fetchFn)).pass).toBe(false);
  });

  it("fails when the authorization server metadata names another issuer", async () => {
    expect((await authSmokeCheck("https://x", fakeEnv({ as: Response.json({ issuer: "https://other/api/auth" }) }).fetchFn)).pass).toBe(false);
    expect((await authSmokeCheck("https://x", fakeEnv({ as: new Response("nope", { status: 404 }) }).fetchFn)).pass).toBe(false);
  });

  it("fails, not throws, on network error", async () => {
    const r = await authSmokeCheck("https://x", async () => { throw new Error("ENOTFOUND"); });
    expect(r).toMatchObject({ pass: false });
  });
});
