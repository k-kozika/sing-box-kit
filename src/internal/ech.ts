import { encodePem } from "./x509";

function uint16(value: number): Buffer {
  const bytes = Buffer.alloc(2);
  bytes.writeUInt16BE(value);
  return bytes;
}

function vector16(bytes: Uint8Array): Buffer<ArrayBuffer> {
  return Buffer.concat([uint16(bytes.length), bytes]);
}

export function encodeEchKeyPair(name: Buffer, privateKey: Uint8Array, publicKey: Uint8Array) {
  const contents = Buffer.concat([
    Buffer.from([0]), // Configuration ID.
    uint16(0x0020), // DHKEM(X25519, HKDF-SHA256).
    vector16(publicKey),
    vector16(Buffer.from("000100010001000200010003", "hex")), // HKDF-SHA256 and three AEADs.
    Buffer.from([0, name.length]), // Maximum name length and public name length.
    name,
    uint16(0), // No extensions.
  ]);
  const config = Buffer.concat([uint16(0xfe0d), vector16(contents)]);
  return {
    config: encodePem(vector16(config), "ECH CONFIGS"),
    key: encodePem(Buffer.concat([vector16(privateKey), vector16(config)]), "ECH KEYS"),
  };
}
