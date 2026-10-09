import { describe, expect, it } from "vitest";
import { getHealth } from "./health";

const ok = async () => {};
const boom = async () => {
  throw new Error("ECONNREFUSED");
};

describe("getHealth", () => {
  it("reports ok when the database responds", async () => {
    const h = await getHealth({ pingDb: ok, version: "abc123" });
    expect(h).toEqual({ status: 200, body: { ok: true, db: true, version: "abc123" } });
  });

  it("reports 503 and db:false when the database is down", async () => {
    const h = await getHealth({ pingDb: boom, version: "abc123" });
    expect(h.status).toBe(503);
    expect(h.body).toEqual({ ok: false, db: false, version: "abc123" });
  });

  it("does not leak the database error message", async () => {
    const h = await getHealth({ pingDb: boom, version: "v" });
    expect(JSON.stringify(h.body)).not.toContain("ECONNREFUSED");
  });

  it("treats a hung database as down after the timeout", async () => {
    const hang = () => new Promise<void>(() => {});
    const h = await getHealth({ pingDb: hang, version: "v", timeoutMs: 20 });
    expect(h.status).toBe(503);
    expect(h.body.db).toBe(false);
  });

  it("reports db:null (not checked) when no database is configured", async () => {
    const h = await getHealth({ pingDb: null, version: "v" });
    expect(h).toEqual({ status: 200, body: { ok: true, db: null, version: "v" } });
  });

  it("returns 503 when no database is configured but one is required", async () => {
    const h = await getHealth({ pingDb: null, version: "v", requireDb: true });
    expect(h).toEqual({ status: 503, body: { ok: false, db: null, version: "v" } });
  });
});
