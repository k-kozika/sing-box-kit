import { base64url } from "@peculiar/utils/encoding";
import { fail } from "../schema";
import { deriveX25519PublicKey } from "./crypto";

function decodeKey(input: unknown, path: string): Uint8Array {
  if (typeof input !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(input))
    fail(path, "expected an unpadded 32-byte Base64url key");
  const bytes = base64url.decode(input);
  if (base64url.encode(bytes) !== input) fail(path, "expected an unpadded 32-byte Base64url key");
  return bytes;
}

export async function validateRealityKeyPair(
  { privateKey, publicKey }: { privateKey?: unknown; publicKey?: unknown },
  path: string,
): Promise<void> {
  const privateBytes = decodeKey(privateKey, `${path}.privateKey`);
  decodeKey(publicKey, `${path}.publicKey`);
  if (base64url.encode(await deriveX25519PublicKey(privateBytes)) !== publicKey)
    fail(`${path}.publicKey`, "does not match private key");
}
