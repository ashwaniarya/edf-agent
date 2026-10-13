const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

function isNativeRedirect(uri: unknown): boolean {
  if (typeof uri !== "string") return false;
  let url: URL;
  try {
    url = new URL(uri);
  } catch {
    return false;
  }
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
