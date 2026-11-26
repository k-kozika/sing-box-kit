# Generate server and client proxy configurations

A `proxyProfile` defines the public connection address and the settings both ends need to agree on. Call `.server()` to build the inbound for all configured users and `.client()` with a specific `User` to build that user's outbound. Add each resource to its own `compile()` call.

```ts
import { compile, proxyProfile, user } from "sing-box-kit";

const alice = user({
  name: "alice",
  credentials: { vless: { uuid: "00000000-0000-4000-8000-000000000001" } },
});
const bob = user({
  name: "bob",
  credentials: { vless: { uuid: "00000000-0000-4000-8000-000000000002" } },
});
const proxy = proxyProfile.vless({
  users: [alice, bob],
  connect: { host: "edge.example", port: 443 },
  transport: { type: "grpc", service_name: "proxy" },
  tls: { mode: "tls" },
});

const incoming = proxy
  .server({
    tag: "incoming",
    tls: { certificate_path: "cert.pem", key_path: "key.pem" },
  })
  .listen("0.0.0.0", { port: 8443 });
const outgoing = proxy.client(alice, { tag: "outgoing" });

const serverConfig = compile({ inbounds: [incoming] });
const aliceConfig = compile({ outbounds: [outgoing] });
```

Reuse the same `User` object when selecting a client or calling `.authUser()` on the returned inbound. Each protocol has its own credential entry on `User`. The profile uses that entry wherever the same user and protocol appear. Serialize the generated client config when distributing it. The profile inputs can contain every user's credentials and the server's private key.

Supply a `tag` to each `.server()` and `.client()` call. Set listen fields in `.server({ tag, listen: { address, port } })` or chain `.listen(address, { port })`. On the client, pass dial fields in the call or chain `.dial()`.

## Transport and TLS

VMess, VLESS, and Trojan default to TCP. Select `http`, `ws`, `grpc`, `httpupgrade`, or `quic` with `transport.type`. Set shared parameters such as the gRPC service name in the profile. Set side-specific `transport.headers` for HTTP, WebSocket, and HTTPUpgrade, or transport timeouts for HTTP and gRPC. Use `options` on `.server()` and `.client()` for other protocol-specific fields, such as VLESS packet encoding on the client.

For regular TLS, the client uses the public host as the verification name by default. Set `tls.serverName` when it differs. Set `tls.alpn` in the profile to send the same list to both ends. V2Ray QUIC requires regular TLS.

For VLESS REALITY, use `tls: { mode: "reality", serverName, handshake: { host, port }, keyPair: { privateKey, publicKey }, shortId }`. To accept multiple short IDs, use `shortIds` and pass `shortId` in the client options.

## Protocol versions and shared keys

| Protocol  | Profile setting                                                                                                                                       |
| --------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| SOCKS     | `version: "4"`, `"4a"`, or `"5"` (default). For SOCKS4 and SOCKS4a username-only authentication, set `credentials.socks.password` to an empty string. |
| ShadowTLS | `version: 1` for no authentication, `2` for a shared `password`, or `3` (default) for `users`. Set `handshake` and `serverName` in the profile.       |
| Snell     | `version: 5` builds a v5 inbound and a compatible v4 outbound. `version: 6` (default) uses v6 on both ends. Set the shared `psk` in the profile.      |

Call `.client({ tag })` when the profile uses no authentication or a shared key with no per-user credential.

With Snell `version: 5` and `obfs_mode: "http"`, set the v4 outbound's obfuscation host in the client call's `options.obfs_host`.

## Shadowsocks SSM and Hysteria2 Realm

For Shadowsocks 2022 AES with multiple users, put the server key in `serverKey` and each user key in `credentials.shadowsocks.password`. For SSM-managed users, set `managed: true`, register the returned inbound with `service.ssmApi()`, and pass a `User` with the issued key to `.client()`. User registration takes place separately through SSM.

For Hysteria or Hysteria2 port hopping, use `connect: { host, ports: ["443:444", "8443:8443"] }` and configure the corresponding server-side port forwarding. For Hysteria2 Realm, provide `realm: { server_url, realm_id, stun_servers, token }` in place of `connect` and specify the Hysteria2 server's certificate name in `tls.serverName`. Both sides use the shared Realm settings. Set `realm.token` on an individual generation call when it uses a different token.
