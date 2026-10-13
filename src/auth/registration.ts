const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

/**
 * https callbacks we are willing to send a browser to. Registration is open (DCR and CIMD), so a
 * registered https redirect proves nothing about who owns it; only these hosts are trusted.
 * claude.ai and claude.com are Claude's web connector callbacks.
 */
const TRUSTED_HTTPS_REDIRECT_HOSTS = new Set(["claude.ai", "claude.com"]);

/** Schemes that can run script or read local data in a browser; never redirect to them. */
const UNSAFE_SCHEMES = new Set(["javascript:", "data:", "vbscript:", "file:", "blob:", "about:"]);

function parse(uri: unknown): URL | null {
  if (typeof uri !== "string") return null;
  try {
    return new URL(uri);
  } catch {
    return null;
  }
}

function isNativeRedirect(uri: unknown): boolean {
  const url = parse(uri);
  if (!url) return false;
  if (url.protocol === "http:") return LOOPBACK_HOSTS.has(url.hostname);
  return url.protocol !== "https:";
}

/**
 * RFC 7591 defaults a missing application_type to "web", which forbids the
 * loopback http redirects native clients such as Claude Code register. Returns
 * the body with application_type "native" when every redirect is native-only,
 * or null to leave the registration untouched.
 */
export function withNativeApplicationTypeDefault(body: unknown): Record<string, unknown> | null {
  if (!body || typeof body !== "object") return null;
  const b = body as Record<string, unknown>;
  const uris = b.redirect_uris;
  if (b.application_type !== undefined || !Array.isArray(uris) || uris.length === 0 || !uris.every(isNativeRedirect)) return null;
  return { ...b, application_type: "native" };
}

/**
 * Whether the authorization server may send a browser to `uri` (RFC 9700 §4.11.2): loopback http
 * (native apps, any port), https on an allow-listed host, or a private-use scheme. Better Auth only
 * registers reverse-domain private-use schemes, and callers also require the URI to be registered.
 */
export function isTrustedRedirect(uri: string): boolean {
  const url = parse(uri);
  if (!url || url.username || url.password) return false;
  if (url.protocol === "http:") return LOOPBACK_HOSTS.has(url.hostname);
  if (url.protocol === "https:") return TRUSTED_HTTPS_REDIRECT_HOSTS.has(url.hostname);
  return !UNSAFE_SCHEMES.has(url.protocol);
}

/**
 * `validateRedirectUri` for mcp(): the request must match a registered URI (Better Auth's default,
 * including the loopback any-port rule) and point somewhere trusted. When this returns false the
 * authorize endpoint sends the user to the local error page instead of the requested redirect,
 * including for early errors (bad scope, missing PKCE) raised before any sign-in or consent.
 */
export function validateMcpRedirectUri(uri: string, _registered: readonly string[], defaultResult: boolean): boolean {
  return defaultResult && isTrustedRedirect(uri);
}

/**
 * Registration-time counterpart of {@link isTrustedRedirect} for http(s) redirects, so a client that
 * could never complete a flow gets a clear 400 instead of a client id. Returns the first untrusted
 * http(s) redirect, or null. Private-use schemes and malformed bodies are left to Better Auth.
 */
export function findUntrustedWebRedirect(body: unknown): string | null {
  if (!body || typeof body !== "object") return null;
  const uris = (body as Record<string, unknown>).redirect_uris;
  if (!Array.isArray(uris)) return null;
  for (const uri of uris) {
    const url = parse(uri);
    if (url && (url.protocol === "http:" || url.protocol === "https:") && !isTrustedRedirect(uri)) return uri;
  }
  return null;
}
