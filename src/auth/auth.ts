import type { Pool } from "pg";
import { betterAuth } from "better-auth";
import { getPool } from "@/src/db";
import { AuthConfigError, requireAuthConfig, type AuthConfig } from "@/src/config/env";
import { errorName } from "@/src/http/jsonrpc";
import { buildAuthOptions } from "./options";

const createAuth = (pool: Pool, config: AuthConfig) => betterAuth(buildAuthOptions({ pool, ...config }));
export type Auth = ReturnType<typeof createAuth>;

let instance: { auth: Auth; config: AuthConfig } | undefined;

function load() {
  if (instance) return instance;
  const config = requireAuthConfig();
  const pool = getPool();
  if (!pool) throw new Error("DATABASE_URL is not set");
  return (instance = { auth: createAuth(pool, config), config });
}

/** Lazily built so `next build` and the health route never construct auth without env. */
export function getAuth(): Auth {
  return load().auth;
}

/** Runs `fn` with the auth instance and its config, or answers 503 (reason logged, never returned) when auth can't be built. */
export async function withAuth(fn: (auth: Auth, config: AuthConfig) => Response | Promise<Response>): Promise<Response> {
  let loaded: { auth: Auth; config: AuthConfig };
  try {
    loaded = load();
  } catch (e) {
    console.error("[auth] unavailable:", e instanceof AuthConfigError ? e.problems.join(",") : errorName(e));
    return Response.json({ error: "auth_unavailable" }, { status: 503, headers: { "cache-control": "no-store" } });
  }
  return fn(loaded.auth, loaded.config);
}
