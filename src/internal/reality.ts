import { fail } from "../schema";
import { deriveX25519PublicKey } from "./crypto";

function encodeKey(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes))
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/, "");
}

function decodeKey(input: unknown, path: string): Uint8Array {
  if (typeof input !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(input))
    fail(path, "expected an unpadded 32-byte Base64url key");
  const bytes = Uint8Array.from(atob(input.replaceAll("-", "+").replaceAll("_", "/")), (byte) =>
    byte.charCodeAt(0),
  );
  if (encodeKey(bytes) !== input) fail(path, "expected an unpadded 32-byte Base64url key");
  return bytes;
}

export async function validateRealityKeyPair(
  { privateKey, publicKey }: { privateKey?: unknown; publicKey?: unknown },
  path: string,
): Promise<void> {
  const privateBytes = decodeKey(privateKey, `${path}.privateKey`);
  decodeKey(publicKey, `${path}.publicKey`);
  if (encodeKey(await deriveX25519PublicKey(privateBytes)) !== publicKey)
    fail(`${path}.publicKey`, "does not match private key");
}
