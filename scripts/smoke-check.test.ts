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

const PRM = { resource: "https://x/api/mcp", authorization_servers: ["https://x/api/auth"] };
const CHALLENGE = 'Bearer resource_metadata="https://x/.well-known/oauth-protected-resource/api/mcp"';

function fakeEnv(overrides: { prm?: Response; mcp?: Response } = {}) {
  const calls: { url: string; method: string; headers: Headers }[] = [];
  const fetchFn = async (url: string, init?: RequestInit) => {
    calls.push({ url, method: init?.method ?? "GET", headers: new Headers(init?.headers) });
    if (url.endsWith("/.well-known/oauth-protected-resource")) return overrides.prm ?? Response.json(PRM);
    if (url.endsWith("/api/mcp")) return overrides.mcp ?? new Response("{}", { status: 401, headers: { "www-authenticate": CHALLENGE } });
    return new Response("not found", { status: 404 });
  };
  return { fetchFn, calls };
}

describe("authSmokeCheck", () => {
  it("passes when protected-resource metadata is served and /api/mcp challenges anonymous calls", async () => {
    const { fetchFn, calls } = fakeEnv();
    expect(await authSmokeCheck("https://x/", fetchFn)).toEqual({ pass: true, resource: "https://x/api/mcp" });
    expect(calls.map((c) => `${c.method} ${c.url}`)).toEqual([
      "GET https://x/.well-known/oauth-protected-resource",
      "POST https://x/api/mcp",
    ]);
    expect(calls[1].headers.get("authorization")).toBeNull();
  });

  it("fails when the metadata is missing or has no resource", async () => {
    expect((await authSmokeCheck("https://x", fakeEnv({ prm: new Response("nope", { status: 404 }) }).fetchFn)).pass).toBe(false);
    expect((await authSmokeCheck("https://x", fakeEnv({ prm: Response.json({}) }).fetchFn)).pass).toBe(false);
    expect((await authSmokeCheck("https://x", fakeEnv({ prm: new Response("<html>") }).fetchFn)).pass).toBe(false);
  });

  it("fails when /api/mcp answers an anonymous call with anything but 401", async () => {
    const r = await authSmokeCheck("https://x", fakeEnv({ mcp: Response.json({ result: {} }) }).fetchFn);
    expect(r).toEqual({ pass: false, reason: "POST /api/mcp without a token returned 200, expected 401" });
  });

  it("fails when the 401 has no resource_metadata challenge", async () => {
    const r = await authSmokeCheck("https://x", fakeEnv({ mcp: new Response("{}", { status: 401, headers: { "www-authenticate": "Bearer" } }) }).fetchFn);
    expect(r.pass).toBe(false);
  });

  it("fails, not throws, on network error", async () => {
    const r = await authSmokeCheck("https://x", async () => { throw new Error("ENOTFOUND"); });
    expect(r).toMatchObject({ pass: false });
  });
});
