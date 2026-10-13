export type AuthConfig = {
  /** Public origin of this environment, no trailing slash. */
  baseURL: string;
  secret: string;
  /** OAuth issuer (`iss` of every access token). */
  issuer: string;
  /** Canonical MCP resource (`aud` of MCP access tokens). */
  mcpResource: string;
  jwksUrl: string;
};

export type EnvProblem =
  | "BETTER_AUTH_URL_MISSING"
  | "BETTER_AUTH_URL_INVALID"
  | "BETTER_AUTH_URL_INSECURE"
  | "BETTER_AUTH_SECRET_MISSING"
  | "BETTER_AUTH_SECRET_TOO_SHORT";

export type AuthEnvResult = { ok: true; config: AuthConfig } | { ok: false; problems: EnvProblem[] };

type Env = Record<string, string | undefined>;

const DEV_URL = "http://localhost:3000";
const DEV_SECRET = "edf-agent-local-development-only-secret-not-for-deploys";
const MIN_SECRET_LENGTH = 32;
const LOOPBACK = new Set(["localhost", "127.0.0.1", "[::1]"]);

export class AuthConfigError extends Error {
  constructor(readonly problems: EnvProblem[]) {
    super(`auth misconfigured: ${problems.join(", ")}`);
    this.name = "AuthConfigError";
  }
}

function parseOrigin(raw: string): { origin: string } | { problem: EnvProblem } {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return { problem: "BETTER_AUTH_URL_INVALID" };
  }
  if (url.username || url.password || url.search || url.hash || raw.includes("?") || url.pathname !== "/") {
    return { problem: "BETTER_AUTH_URL_INVALID" };
  }
  if (url.protocol === "https:" || (url.protocol === "http:" && LOOPBACK.has(url.hostname))) return { origin: url.origin };
  return { problem: url.protocol === "http:" ? "BETTER_AUTH_URL_INSECURE" : "BETTER_AUTH_URL_INVALID" };
}

/** Validates auth env. Problems are reason codes only; values are never echoed. */
export function readAuthEnv(env: Env = process.env): AuthEnvResult {
  const deployed = env.REQUIRE_DB === "true";
  const problems: EnvProblem[] = [];

  let baseURL = DEV_URL;
  if (env.BETTER_AUTH_URL) {
    const parsed = parseOrigin(env.BETTER_AUTH_URL);
    if ("problem" in parsed) problems.push(parsed.problem);
    else baseURL = parsed.origin;
  } else if (deployed) {
    problems.push("BETTER_AUTH_URL_MISSING");
  }

  let secret = env.BETTER_AUTH_SECRET ?? "";
  if (!secret) {
    if (deployed || env.NODE_ENV === "production") problems.push("BETTER_AUTH_SECRET_MISSING");
    else secret = DEV_SECRET;
  } else if (deployed && secret.length < MIN_SECRET_LENGTH) {
    problems.push("BETTER_AUTH_SECRET_TOO_SHORT");
  }

  if (problems.length) return { ok: false, problems };

  const port = env.PORT && /^\d+$/.test(env.PORT) ? env.PORT : undefined;
  return {
    ok: true,
    config: {
      baseURL,
      secret,
      issuer: `${baseURL}/api/auth`,
      mcpResource: `${baseURL}/api/mcp`,
      jwksUrl: port ? `http://127.0.0.1:${port}/api/auth/jwks` : `${baseURL}/api/auth/jwks`,
    },
  };
}

export function requireAuthConfig(env: Env = process.env): AuthConfig {
  const r = readAuthEnv(env);
  if (!r.ok) throw new AuthConfigError(r.problems);
  return r.config;
}
