import { describe, expect, it } from "vitest";
import { smokeCheck } from "./smoke-check";

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
