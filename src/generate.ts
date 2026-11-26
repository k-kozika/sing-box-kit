import { createECDH, createHmac, randomBytes, randomUUID } from "node:crypto";
import { serverCertificate } from "./internal/certificate";
import { deriveX25519PublicKey } from "./internal/crypto";
import { encodeEchKeyPair } from "./internal/ech";

export function uuid(): string {
  return randomUUID();
}

export function random(length: number): Uint8Array {
  if (!Number.isSafeInteger(length) || length < 0) {
    throw new RangeError("Random byte length must be a non-negative integer");
  }
  return randomBytes(length);
}

export function randomHex(length: number): string {
  return Buffer.from(random(length)).toString("hex");
}

export function randomBase64(length: number): string {
  return Buffer.from(random(length)).toString("base64");
}

export function randomBase64Url(length: number): string {
  return Buffer.from(random(length)).toString("base64url");
}

export function x25519PublicKey(privateKey: Uint8Array): Uint8Array {
  return deriveX25519PublicKey(privateKey);
}

export function x25519KeyPair(): { privateKey: Uint8Array; publicKey: Uint8Array } {
  const privateKey = randomBytes(32);
  privateKey[0] = privateKey[0]! & 248;
  privateKey[31] = (privateKey[31]! & 127) | 64;
  return { privateKey, publicKey: x25519PublicKey(privateKey) };
}

export function reality() {
  const { privateKey, publicKey } = x25519KeyPair();
  return {
    privateKey: Buffer.from(privateKey).toString("base64url"),
    publicKey: Buffer.from(publicKey).toString("base64url"),
  };
}

export function wireguard() {
  const { privateKey, publicKey } = x25519KeyPair();
  return {
    privateKey: Buffer.from(privateKey).toString("base64"),
    publicKey: Buffer.from(publicKey).toString("base64"),
  };
}

export function vapidKeyPair() {
  const key = createECDH("prime256v1");
  const publicKey = key.generateKeys();
  const privateKey = Buffer.alloc(32);
  const scalar = key.getPrivateKey();
  scalar.copy(privateKey, privateKey.length - scalar.length);
  return {
    privateKey: privateKey.toString("base64url"),
    publicKey: publicKey.toString("base64url"),
  };
}

export function tailcatKeyPair() {
  const { privateKey, publicKey } = wireguard();
  const discoPrivateKey = createHmac("sha256", Buffer.from(privateKey, "base64"))
    .update("github.com/tailscale/tailcat disco key v1")
    .digest();
  const bytes = Buffer.from(publicKey, "base64");
  const groups = Array.from({ length: 5 }, (_, index) =>
    bytes.readUInt16BE(index * 2).toString(16),
  );
  const address = new URL(`http://[fd7a:115c:a1e0:${groups.join(":")}]`).hostname.slice(1, -1);
  return {
    privateKey,
    publicKey,
    discoKey: Buffer.from(x25519PublicKey(discoPrivateKey)).toString("base64"),
    preSharedKey: randomBase64(32),
    address,
  };
}

export function echKeyPair(publicName: string) {
  const name = Buffer.from(publicName);
  if (name.length < 1 || name.length > 255) {
    throw new RangeError("ECH public name must be between 1 and 255 bytes");
  }

  const { privateKey, publicKey } = x25519KeyPair();
  return encodeEchKeyPair(name, privateKey, publicKey);
}

export function tlsKeyPair(serverName: string, months = 1) {
  return serverCertificate(serverName, months);
}
