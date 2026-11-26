import { concatToUint8Array } from "@peculiar/utils/bytes";
import { hex } from "@peculiar/utils/encoding";
import { pem } from "@peculiar/utils/pem";

const cipherSuites = hex.decode("000100010001000200010003"); // HKDF-SHA256 and three AEADs.

function uint16(value: number): Uint8Array {
  const bytes = new Uint8Array(2);
  new DataView(bytes.buffer).setUint16(0, value);
  return bytes;
}

function vector16(bytes: Uint8Array): Uint8Array {
  return concatToUint8Array([uint16(bytes.length), bytes]);
}

export function encodeEchKeyPair(name: Uint8Array, privateKey: Uint8Array, publicKey: Uint8Array) {
  const contents = concatToUint8Array([
    Uint8Array.of(0), // Configuration ID.
    uint16(0x0020), // DHKEM(X25519, HKDF-SHA256).
    vector16(publicKey),
    vector16(cipherSuites),
    Uint8Array.of(0, name.length), // Maximum name length and public name length.
    name,
    uint16(0), // No extensions.
  ]);
  const config = vector16(concatToUint8Array([uint16(0xfe0d), vector16(contents)]));
  return {
    config: pem.encode("ECH CONFIGS", config),
    key: pem.encode("ECH KEYS", concatToUint8Array([vector16(privateKey), config])),
  };
}
