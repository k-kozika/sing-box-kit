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
  const header = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20,
  ];
  const pkcs8 = new Uint8Array(header.length + privateKey.length);
  pkcs8.set(header);
  pkcs8.set(privateKey, header.length);
  const key = await subtle.importKey("pkcs8", pkcs8, "X25519", false, ["deriveBits"]);

  // X25519 with the standard base point yields the corresponding public key.
  const basePoint = new Uint8Array(32);
  basePoint[0] = 9;
  const publicKey = await subtle.importKey("raw", basePoint, "X25519", false, []);
  return new Uint8Array(await subtle.deriveBits({ name: "X25519", public: publicKey }, key, 256));
}
