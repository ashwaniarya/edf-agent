import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { SignJWT, exportJWK, generateKeyPair, type CryptoKey, type JWTPayload } from "jose";

export type LocalJwks = {
  /** Serves `{keys}` at /jwks, a 500 at /jwks-500 and a malformed set at /jwks-malformed. */
  url: (path?: string) => string;
  sign: (claims: JWTPayload & { iss: string; aud: string | string[] }, opts?: { exp?: string | number; foreign?: boolean }) => Promise<string>;
  close: () => Promise<void>;
};

export async function startLocalJwks(): Promise<LocalJwks> {
  const { privateKey, publicKey } = await generateKeyPair("EdDSA", { extractable: true });
  const foreignKey: CryptoKey = (await generateKeyPair("EdDSA")).privateKey;
  const jwk = { ...(await exportJWK(publicKey)), kid: "k1", alg: "EdDSA" };

  const server = createServer((req, res) => {
    const send = (status: number, body: unknown) => res.writeHead(status, { "content-type": "application/json" }).end(JSON.stringify(body));
    if (req.url === "/jwks") return send(200, { keys: [jwk] });
    if (req.url === "/jwks-500") return send(500, { error: "db password=hunter2" });
    if (req.url === "/jwks-malformed") return send(200, { keys: "nope" });
    send(404, {});
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;

  return {
    url: (path = "/jwks") => `${base}${path}`,
    sign: ({ iss, aud, ...claims }, opts = {}) =>
      new SignJWT(claims)
        .setProtectedHeader({ alg: "EdDSA", kid: "k1" })
        .setIssuer(iss)
        .setAudience(aud)
        .setIssuedAt()
        .setExpirationTime(opts.exp ?? "5m")
        .sign(opts.foreign ? foreignKey : privateKey),
    close: () => new Promise<void>((r) => server.close(() => r())),
  };
}
