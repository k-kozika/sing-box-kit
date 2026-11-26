# Generate credentials and key pairs

Import the synchronous generators from `sing-box-kit`. They use the Bun and Node.js standard library.

```ts
import { Reality, RandomHex, UUID } from "sing-box-kit";

const uuid = UUID();
const { privateKey, publicKey } = Reality();
const shortId = RandomHex(8);
```

Use the Reality private key in the server's `private_key` field and the public key in the client's `public_key` field. Use the same short ID on both sides.

| Function                          | Result                                                                                              |
| --------------------------------- | --------------------------------------------------------------------------------------------------- |
| `UUID()`                          | UUID v4 string                                                                                      |
| `Random(length)`                  | Random bytes as a `Uint8Array`                                                                      |
| `RandomHex(length)`               | Lowercase hexadecimal string                                                                        |
| `RandomBase64(length)`            | Standard padded Base64 string                                                                       |
| `RandomBase64Url(length)`         | Unpadded Base64url string                                                                           |
| `X25519KeyPair()`                 | Raw 32-byte `privateKey` and `publicKey`                                                            |
| `x25519PublicKey(privateKey)`     | Raw public key derived from a 32-byte `Uint8Array`                                                  |
| `Reality()`                       | `privateKey` and `publicKey` as unpadded Base64url                                                  |
| `Wireguard()`                     | `privateKey` and `publicKey` as standard padded Base64                                              |
| `VapidKeyPair()`                  | P-256 `privateKey` and uncompressed `publicKey` as unpadded Base64url                               |
| `TailcatKeyPair()`                | Padded Base64 `privateKey`, `publicKey`, `discoKey`, and `preSharedKey`, plus an IPv6 `address`     |
| `ECHKeyPair(publicName)`          | PEM `config` for the client and PEM `key` for the server                                            |
| `TLSKeyPair(serverName, months?)` | PEM `privateKey` and self-signed `certificate` for a DNS name or IP address. Defaults to one month. |

Random lengths count bytes before encoding. Tailcat configuration requires sing-box 1.15 or later.
