import { describe, expect, it, vi } from "vitest";
import { z } from "zod";
import type { UserDirectory, UserRecord } from "@/src/auth/users";
import { whoami, whoamiTool } from "./whoami";

const A: UserRecord = { id: "user_A", email: "a@example.com", name: "Asha" };
const B: UserRecord = { id: "user_B", email: "b@example.com", name: "Bala" };
const users = (...records: UserRecord[]): UserDirectory => ({
  findById: vi.fn(async (id: string) => records.find((u) => u.id === id) ?? null),
});
const identity = (userId: string) => ({ userId, clientId: "client_1", scopes: [] });
const text = (r: { content: unknown[] }) => (r.content[0] as { text: string }).text;

describe("whoami", () => {
  it("returns the caller's own userId, email and name, looked up by the verified userId", async () => {
    const dir = users(A, B);
    const r = await whoami({ users: dir }, identity("user_B"));
    expect(dir.findById).toHaveBeenCalledWith("user_B");
    expect(r.isError).toBeFalsy();
    expect(r.structuredContent).toEqual({ userId: "user_B", email: "b@example.com", name: "Bala" });
    expect(JSON.parse(text(r))).toEqual({ userId: "user_B", email: "b@example.com", name: "Bala" });
  });

  it("declares no input at all, so a caller cannot ask about another user", () => {
    const input = whoamiTool.config.inputSchema;
    expect(z.toJSONSchema(input)).toMatchObject({ type: "object", properties: {} });
    expect(input.safeParse({}).success).toBe(true);
    expect(input.safeParse({ userId: "user_A" }).success).toBe(false);
  });

  it("returns a tool error (not a throw) for an unknown user", async () => {
    const r = await whoami({ users: users(A) }, identity("user_gone"));
    expect(r.isError).toBe(true);
    expect(r.structuredContent).toBeUndefined();
    expect(text(r)).not.toContain("user_A");
  });

  it("returns a generic tool error when the lookup fails, without leaking the cause", async () => {
    vi.spyOn(console, "error").mockImplementation(() => {});
    const failing: UserDirectory = { findById: async () => { throw new Error("connect ECONNREFUSED 10.0.0.5 password=hunter2"); } };
    const r = await whoami({ users: failing }, identity("user_A"));
    expect(r.isError).toBe(true);
    expect(text(r)).not.toMatch(/ECONNREFUSED|hunter2|10\.0\.0\.5/);
  });
});
