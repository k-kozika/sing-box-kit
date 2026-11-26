import { createPrivateKey, createPublicKey } from "node:crypto";

export function deriveX25519PublicKey(privateKey: Uint8Array): Buffer {
  if (privateKey.length !== 32) throw new RangeError("X25519 private key must be 32 bytes");

  // RFC 8410 PKCS#8 header for a 32-byte X25519 private key.
  const header = Buffer.from("302e020100300506032b656e04220420", "hex");
  const key = createPrivateKey({
    key: Buffer.concat([header, privateKey]),
    format: "der",
    type: "pkcs8",
  });
  return Buffer.from(createPublicKey(key).export({ format: "jwk" }).x!, "base64url");
}

export function pem(label: string, data: Buffer): string {
  const lines = data.toString("base64").match(/.{1,64}/g) ?? [];
  return [`-----BEGIN ${label}-----`, ...lines, `-----END ${label}-----`, ""].join("\n");
}
