# Generate credentials and key pairs

The generators use `globalThis.crypto` in Bun and Node.js. UUID and random byte generators return immediately. Key generation and public-key derivation return promises.

```ts
import { generate } from "sing-box-kit";

const uuid = generate.uuid();
const { privateKey, publicKey } = await generate.reality();
const shortId = generate.randomHex(8);
```

Use the Reality private key in the server's `private_key` field and the public key in the client's `public_key` field. Use the same short ID on both sides.

| Function                                         | Result                                                                                              |
| ------------------------------------------------ | --------------------------------------------------------------------------------------------------- |
| `generate.uuid()`                                | UUID v4 string                                                                                      |
| `generate.random(length)`                        | Random bytes as a `Uint8Array`                                                                      |
| `generate.randomHex(length)`                     | Lowercase hexadecimal string                                                                        |
| `generate.randomBase64(length)`                  | Standard padded Base64 string                                                                       |
| `generate.randomBase64Url(length)`               | Unpadded Base64url string                                                                           |
| `await generate.x25519KeyPair()`                 | Raw 32-byte `privateKey` and `publicKey`                                                            |
| `await generate.x25519PublicKey(privateKey)`     | Raw public key derived from a 32-byte `Uint8Array`                                                  |
| `await generate.reality()`                       | `privateKey` and `publicKey` as unpadded Base64url                                                  |
| `await generate.wireguard()`                     | `privateKey` and `publicKey` as standard padded Base64                                              |
| `await generate.vapidKeyPair()`                  | P-256 `privateKey` and uncompressed `publicKey` as unpadded Base64url                               |
| `await generate.tailcatKeyPair()`                | Padded Base64 `privateKey`, `publicKey`, `discoKey`, and `preSharedKey`, plus an IPv6 `address`     |
| `await generate.echKeyPair(publicName)`          | PEM `config` for the client and PEM `key` for the server                                            |
| `await generate.tlsKeyPair(serverName, months?)` | PEM `privateKey` and self-signed `certificate` for a DNS name or IP address. Defaults to one month. |

Random lengths count bytes before encoding. Tailcat configuration requires sing-box 1.15 or later.
