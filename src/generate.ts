import { serverCertificate } from "./internal/certificate";
import { deriveX25519PublicKey, randomBytes } from "./internal/crypto";
import { encodeEchKeyPair } from "./internal/ech";

export function uuid(): string {
  return globalThis.crypto.randomUUID();
}

export function random(length: number): Uint8Array {
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

export function x25519PublicKey(privateKey: Uint8Array): Promise<Uint8Array> {
  return deriveX25519PublicKey(privateKey);
}

export async function x25519KeyPair() {
  const privateKey = randomBytes(32);
  privateKey[0] = privateKey[0]! & 248;
  privateKey[31] = (privateKey[31]! & 127) | 64;
  return { privateKey, publicKey: await x25519PublicKey(privateKey) };
}

export async function reality() {
  const { privateKey, publicKey } = await x25519KeyPair();
  return {
    privateKey: Buffer.from(privateKey).toString("base64url"),
    publicKey: Buffer.from(publicKey).toString("base64url"),
  };
}

export async function wireguard() {
  const { privateKey, publicKey } = await x25519KeyPair();
  return {
    privateKey: Buffer.from(privateKey).toString("base64"),
    publicKey: Buffer.from(publicKey).toString("base64"),
  };
}

export async function vapidKeyPair() {
  const { subtle } = globalThis.crypto;
  const key = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
    "sign",
    "verify",
  ]);
  const { d: privateKey } = await subtle.exportKey("jwk", key.privateKey);
  const publicKey = await subtle.exportKey("raw", key.publicKey);
  return { privateKey: privateKey!, publicKey: Buffer.from(publicKey).toString("base64url") };
}

export async function tailcatKeyPair() {
  const { privateKey, publicKey } = await x25519KeyPair();
  const { subtle } = globalThis.crypto;
  const hmacKey = await subtle.importKey(
    "raw",
    Buffer.from(privateKey),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const discoLabel = new TextEncoder().encode("github.com/tailscale/tailcat disco key v1");
  const discoPrivateKey = new Uint8Array(await subtle.sign("HMAC", hmacKey, discoLabel));
  const bytes = Buffer.from(publicKey);
  const groups = Array.from({ length: 5 }, (_, index) =>
    bytes.readUInt16BE(index * 2).toString(16),
  );
  const address = new URL(`http://[fd7a:115c:a1e0:${groups.join(":")}]`).hostname.slice(1, -1);
  return {
    privateKey: Buffer.from(privateKey).toString("base64"),
    publicKey: bytes.toString("base64"),
    discoKey: Buffer.from(await x25519PublicKey(discoPrivateKey)).toString("base64"),
    preSharedKey: randomBase64(32),
    address,
  };
}

export async function echKeyPair(publicName: string) {
  const name = Buffer.from(publicName);
  if (name.length < 1 || name.length > 255) {
    throw new RangeError("ECH public name must be between 1 and 255 bytes");
  }

  const { privateKey, publicKey } = await x25519KeyPair();
  return encodeEchKeyPair(name, privateKey, publicKey);
}

export function tlsKeyPair(serverName: string, months = 1) {
  return serverCertificate(serverName, months);
}
