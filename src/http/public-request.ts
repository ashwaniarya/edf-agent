/**
 * `next start` builds a route handler's request.url as `${x-forwarded-proto}://localhost:${PORT}${path}`
 * and ignores the Host header, so behind Railway's proxy request.url is never the public URL. DPoP
 * (RFC 9449) compares a proof's `htu` with request.url, and clients sign the advertised public URLs.
 * Returns the request rebuilt on `origin` (path and query kept), or the same request when it already is.
 */
export function onPublicOrigin(request: Request, origin: string): Request {
  const current = new URL(request.url);
  const target = new URL(current.pathname + current.search, origin);
  if (target.href === current.href) return request;
  const hasBody = request.method !== "GET" && request.method !== "HEAD";
  return new Request(target, {
    method: request.method,
    headers: request.headers,
    body: hasBody ? request.body : null,
    signal: request.signal,
    redirect: "manual",
    ...(hasBody ? { duplex: "half" } : {}),
  } as RequestInit);
}
