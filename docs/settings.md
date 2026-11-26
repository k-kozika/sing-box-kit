# Shared settings

Each builder exposes the shared methods and fields available for its kind in the pinned sing-box schema. See [Build and validate a configuration](configuration.md) for how to register and reference the finished values.

## Listen fields

`.listen(address, { port, ...options })` writes `listen` and `listen_port`. You can omit `port`, omit the address with `.listen({ port, ...options })`, or pass `undefined` for the address. A listen `detour` takes a registered inbound. TUN can use `.listen({ netns, udp_timeout })`.

```ts
import { compile, inbound } from "sing-box-kit";

const mixed = inbound.mixed({ tag: "mixed" }).listen("127.0.0.1", { port: 1080, reuse_addr: true });
compile({ inbounds: [mixed] });
```

## Dial fields

`.dial(options)` accepts the supported Dial Fields. On dialers with `detour`, supply a registered outbound or endpoint. Put any non-zero connection timeout or namespace setting on the detour target. An otherwise empty direct outbound is invalid as an explicit dial detour. A WireGuard endpoint with a dial detour requires a zero or omitted `listen_port`.

In Listen and Dial Fields, a typed `netns` value resolves to a registered namespace tag. A string passes through as supplied. sing-box looks for a registered tag before treating the string as an OS name or path.

## DNS resolvers

Supply a registered DNS server to `domain_resolver` or `route.default_domain_resolver` directly or as `{ server: resolver, ...options }`. A TCP, UDP, TLS, HTTPS, HTTP/3, or QUIC DNS server configured with a hostname needs its own resolver or an explicit detour.

## TLS profiles

Use `.tls(options)` for the kind's TLS fields, such as `outbound.http({ tag: "proxy" }).tls({ server_name: "proxy.example", alpn: ["h2"] })`. For configurations with an `enabled` field the builder defaults it to `true` and preserves an explicit `false`. OpenConnect and OpenVPN take their own TLS options.

Standard inbound and outbound TLS builders also accept side-tagged profiles. Use `side: "server"` with a `certificate_path` and `key_path` pair or a registered `certificate_provider`. Use `side: "client"` with optional `server_name` and `certificate_path` settings.

Naive builders and proxy profiles negotiate ALPN automatically. Omit `alpn` from their TLS settings.

### VLESS with REALITY

On the inbound, set `server_name` and pass `reality: { private_key, short_id, handshake }`. The handshake has its own `server`, `server_port`, and optional Dial Fields. On the outbound, set the VLESS `server` and `server_port` for the connection, set the TLS `server_name` for verification, and pass `reality: { public_key, short_id }`. SBKit enables uTLS for that client profile.

REALITY keys are unpadded Base64url strings for 32-byte keys. Short IDs are even-length hexadecimal strings of up to 16 characters, including the empty string. The inbound accepts a string or an array of strings. Keep the private key in the server configuration and share the public key and a selected short ID with the client.
