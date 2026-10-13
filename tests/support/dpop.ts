import { createHash, randomUUID } from "node:crypto";
import { SignJWT, calculateJwkThumbprint, exportJWK, generateKeyPair } from "jose";

export type DpopKey = {
  /** RFC 7638 thumbprint; the `cnf.jkt` of tokens bound to this key. */
  jkt: string;
  /** An RFC 9449 proof for one request; pass the access token when presenting it to a resource. */
  proof: (htm: string, htu: string, accessToken?: string) => Promise<string>;
};

export async function createDpopKey(): Promise<DpopKey> {
  const { privateKey, publicKey } = await generateKeyPair("ES256");
  const jwk = await exportJWK(publicKey);
  return {
    jkt: await calculateJwkThumbprint(jwk, "sha256"),
    proof: (htm, htu, accessToken) =>
      new SignJWT({ htm, htu, jti: randomUUID(), ...(accessToken ? { ath: createHash("sha256").update(accessToken).digest("base64url") } : {}) })
        .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk })
        .setIssuedAt()
        .sign(privateKey),
  };
}
