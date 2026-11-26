import { base64, base64url, hex } from "@peculiar/utils/encoding";
import { serverCertificate } from "./internal/certificate";
import { deriveX25519PublicKey, randomBytes } from "./internal/crypto";
import { encodeEchKeyPair } from "./internal/ech";

function uuid(): string {
  return globalThis.crypto.randomUUID();
}

function random(length: number): Uint8Array {
  return randomBytes(length);
}

function randomHex(length: number): string {
  return hex.encode(random(length));
}

function randomBase64(length: number): string {
  return base64.encode(random(length));
}

function randomBase64Url(length: number): string {
  return base64url.encode(random(length));
}

function x25519PublicKey(privateKey: Uint8Array): Promise<Uint8Array> {
  return deriveX25519PublicKey(privateKey);
}

async function x25519KeyPair() {
  const privateKey = randomBytes(32);
  privateKey[0] = privateKey[0]! & 248;
  privateKey[31] = (privateKey[31]! & 127) | 64;
  return { privateKey, publicKey: await x25519PublicKey(privateKey) };
}

async function reality() {
  const { privateKey, publicKey } = await x25519KeyPair();
  return {
    privateKey: base64url.encode(privateKey),
    publicKey: base64url.encode(publicKey),
  };
}

async function wireguard() {
  const { privateKey, publicKey } = await x25519KeyPair();
  return {
    privateKey: base64.encode(privateKey),
    publicKey: base64.encode(publicKey),
  };
}

async function vapidKeyPair() {
  const { subtle } = globalThis.crypto;
  const key = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
    "sign",
    "verify",
  ]);
  const { d: privateKey } = await subtle.exportKey("jwk", key.privateKey);
  const publicKey = await subtle.exportKey("raw", key.publicKey);
  return { privateKey: privateKey!, publicKey: base64url.encode(publicKey) };
}

async function tailcatKeyPair() {
  const { privateKey, publicKey } = await x25519KeyPair();
  const { subtle } = globalThis.crypto;
  const hmacKey = await subtle.importKey(
    "raw",
    privateKey,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const discoLabel = new TextEncoder().encode("github.com/tailscale/tailcat disco key v1");
  const discoPrivateKey = new Uint8Array(await subtle.sign("HMAC", hmacKey, discoLabel));
  const view = new DataView(publicKey.buffer, publicKey.byteOffset, publicKey.byteLength);
  const groups = Array.from({ length: 5 }, (_, index) => view.getUint16(index * 2).toString(16));
  const address = new URL(`http://[fd7a:115c:a1e0:${groups.join(":")}]`).hostname.slice(1, -1);
  return {
    privateKey: base64.encode(privateKey),
    publicKey: base64.encode(publicKey),
    discoKey: base64.encode(await x25519PublicKey(discoPrivateKey)),
    preSharedKey: randomBase64(32),
    address,
  };
}

async function echKeyPair(publicName: string) {
  const name = new TextEncoder().encode(publicName);
  if (name.length < 1 || name.length > 255) {
    throw new RangeError("ECH public name must be between 1 and 255 bytes");
  }

  const { privateKey, publicKey } = await x25519KeyPair();
  return encodeEchKeyPair(name, privateKey, publicKey);
}

function tlsKeyPair(serverName: string, months = 1) {
  return serverCertificate(serverName, months);
}

export const generate = {
  uuid,
  random,
  randomHex,
  randomBase64,
  randomBase64Url,
  x25519KeyPair,
  x25519PublicKey,
  reality,
  wireguard,
  vapidKeyPair,
  tailcatKeyPair,
  echKeyPair,
  tlsKeyPair,
} as const;
