export function randomBytes(length: number): Uint8Array<ArrayBuffer> {
  if (!Number.isSafeInteger(length) || length < 0) {
    throw new RangeError("Random byte length must be a non-negative integer");
  }

  const bytes = new Uint8Array(length);
  // Web Crypto limits each getRandomValues call to 65,536 bytes.
  for (let offset = 0; offset < bytes.length; offset += 65_536) {
    globalThis.crypto.getRandomValues(bytes.subarray(offset, offset + 65_536));
  }
  return bytes;
}

export async function deriveX25519PublicKey(
  privateKey: Uint8Array,
): Promise<Uint8Array<ArrayBuffer>> {
  if (privateKey.length !== 32) throw new RangeError("X25519 private key must be 32 bytes");

  const { subtle } = globalThis.crypto;
  // RFC 8410 PKCS#8 header for a 32-byte X25519 private key.
  const header = Buffer.from("302e020100300506032b656e04220420", "hex");
  const key = await subtle.importKey(
    "pkcs8",
    Buffer.concat([header, privateKey]),
    "X25519",
    false,
    ["deriveBits"],
  );

  // X25519 with the standard base point yields the corresponding public key.
  const basePoint = new Uint8Array(32);
  basePoint[0] = 9;
  const publicKey = await subtle.importKey("raw", basePoint, "X25519", false, []);
  return new Uint8Array(await subtle.deriveBits({ name: "X25519", public: publicKey }, key, 256));
}

export function pem(label: string, data: Buffer): string {
  const lines = data.toString("base64").match(/.{1,64}/g) ?? [];
  return [`-----BEGIN ${label}-----`, ...lines, `-----END ${label}-----`, ""].join("\n");
}
