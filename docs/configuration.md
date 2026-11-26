# Configuration reference

Create resources with the factories exported from the project root. Pass type-specific options to the factory and use the supported `.listen()`, `.dial()`, and `.tls()` methods for shared settings.

## Factories and registration

The pinned sing-box v1.14.4 schema contains 77 kinds with a `type` discriminator. The package also exports a standalone `httpClient()` factory.

| Package export        | Factory methods                                                                                                                                                                                        | Register in             |
| --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ----------------------- |
| `inbound`             | `anytls`, `cloudflared`, `direct`, `http`, `hysteria`, `hysteria2`, `mixed`, `naive`, `redirect`, `shadowsocks`, `shadowtls`, `snell`, `socks`, `tproxy`, `trojan`, `tuic`, `tun`, `vless`, `vmess`    | `inbounds`              |
| `outbound`            | `anytls`, `block`, `bridge`, `direct`, `http`, `hysteria`, `hysteria2`, `naive`, `selector`, `shadowsocks`, `shadowtls`, `snell`, `socks`, `ssh`, `tor`, `trojan`, `tuic`, `urltest`, `vless`, `vmess` | `outbounds`             |
| `endpoint`            | `openconnect`, `openvpnClient`, `openvpnServer`, `tailscale`, `wireguard`                                                                                                                              | `endpoints`             |
| `service`             | `api`, `ccm`, `derp`, `hysteriaRealm`, `ocm`, `oomKiller`, `resolved`, `ssmApi`, `usbipClient`, `usbipServer`                                                                                          | `services`              |
| `dnsServer`           | `dhcp`, `fakeip`, `h3`, `hosts`, `https`, `local`, `mdns`, `openconnect`, `openvpn`, `quic`, `resolved`, `tailscale`, `tcp`, `tls`, `udp`                                                              | `dns.servers`           |
| `ruleSet`             | `inline`, `local`, `remote`                                                                                                                                                                            | `route.rule_set`        |
| `certificateProvider` | `acme`, `cloudflareOriginCa`, `tailscale`                                                                                                                                                              | `certificate_providers` |
| `networkNamespace`    | `default`, `unshare`                                                                                                                                                                                   | `network_namespaces`    |
| `httpClient()`        | Call directly. Supply a tag to register it.                                                                                                                                                            | `http_clients`          |

Snell inbounds take `version: 5` or `6`. Snell outbounds take `version: 4` or `6`. The version selects which options you can supply. USB/IP Server accepts `devices` with the default provider, written as `provider: "default"`, `provider: ""`, or by omitting `provider`. Supply `provider: "dynamic"` to select the dynamic provider.

Builder methods return new values. Register and reference the same final value after applying the settings. If you rebuild a resource with the same tag, rebuild any references to it. Apply each settings method at most once per chain.

`compile(input)` preserves list order, checks tag collisions and reference capabilities, and returns a `SingBoxConfig` suitable for `JSON.stringify()`. Outbounds and endpoints share a tag scope. Services without explicit tags use their zero-based list position for collision checks.

Use `validateConfig(value)` to check an existing JSON configuration against the pinned schema. This accepts raw tag strings and checks schema constraints. Use `compile()` for SBKit's registration, reference, and dependency checks.

## Shared settings

Each builder exposes the shared methods and fields available for its kind in the pinned schema.

- `.listen(address, { port, ...options })` writes `listen` and `listen_port`. Omit the port, omit the address with `.listen({ port, ...options })`, or pass `undefined` for the address. A listen `detour` takes a registered inbound. TUN can use `.listen({ netns, udp_timeout })`.
- `.dial(options)` accepts the supported Dial Fields. On dialers with `detour`, supply a registered outbound or endpoint. Put any non-zero connection timeout or namespace setting on the detour target. An otherwise empty direct outbound cannot be used as an explicit dial detour. WireGuard also disallows a non-zero `listen_port` with a dial detour.
- In Listen and Dial Fields, a typed `netns` value resolves to a registered namespace tag. A string passes through as supplied. sing-box looks for a registered tag before treating it as an OS name or path.
- Supply a DNS server to `domain_resolver` or `route.default_domain_resolver` directly or as `{ server: resolver, ...options }`. A TCP, UDP, TLS, HTTPS, HTTP/3, or QUIC DNS server configured with a hostname needs its own resolver or an explicit detour.

```ts
import { compile, endpoint, inbound, outbound } from "sing-box-kit";

const mixed = inbound.mixed({ tag: "mixed" }).listen("127.0.0.1", { port: 1080, reuse_addr: true });
const tailscale = endpoint.tailscale({ tag: "tail", advertise_exit_node: true });
const direct = outbound.direct({ tag: "direct" }).dial({ bind_interface: "eth0" });

compile({
  inbounds: [mixed],
  endpoints: [tailscale],
  outbounds: [direct],
  dns: { strategy: "prefer_ipv4" },
  route: { final: direct },
});
```

Set DNS and route options directly under `dns` and `route` in `compile()`. Pass `$schema`, `log`, `ntp`, `certificate`, and `experimental` at the root. The compiler preserves JSON field names and explicit values such as `false`, `0`, and empty arrays.

## TLS profiles

Use `.tls(options)` for the kind's TLS fields, such as `outbound.http({ tag: "proxy" }).tls({ server_name: "proxy.example", alpn: ["h2"] })`. For configurations with an `enabled` field the builder defaults it to `true` and preserves an explicit `false`. OpenConnect and OpenVPN take their own TLS options.

Standard inbound and outbound TLS builders also accept side-tagged profiles. Use `side: "server"` with a `certificate_path` and `key_path` pair or a registered `certificate_provider`. Use `side: "client"` with optional `server_name` and `certificate_path` settings.

VLESS also supports REALITY on both sides. On the inbound, set `server_name` and pass `reality: { private_key, short_id, handshake }`. The handshake has its own `server`, `server_port`, and optional Dial Fields. On the outbound, set the VLESS `server` and `server_port` for the connection, set the TLS `server_name` for verification, and pass `reality: { public_key, short_id }`. SBKit enables uTLS for that client profile.

REALITY keys are unpadded Base64url strings for 32-byte keys. Short IDs are even-length hexadecimal strings of up to 16 characters, including the empty string. The inbound accepts a string or an array of strings. Keep the private key in the server configuration and share the public key and a selected short ID with the client.

VLESS builders take `transport` and `multiplex` in the factory options.

## Typed references

Pass the final registered resource wherever SBKit expects a reference. This includes references inside objects, maps, and arrays. OpenConnect DNS takes an `endpoint.openconnect()` value, OpenVPN DNS takes an `endpoint.openvpnClient()` value, and Resolved DNS takes a tagged `service.resolved()` value. DERP accepts a Tailscale endpoint or an array of those endpoints in `verify_client_endpoint`.

## HTTP clients and services

The API service defaults to loopback `127.0.0.1`. Omitting TLS uses plaintext TCP, and an omitted or empty `secret` allows unauthenticated connections. `dashboard` accepts a boolean, path string, or settings object. Set `enabled: true` to enable the dashboard in object form.

The dashboard and remote rule-sets accept either a tagged client registered in `http_clients`, an untagged `httpClient()` builder, or an inline HTTP settings object. The inline object supports the sing-box HTTP client shape without `tag`, with SBKit references for `detour`, `domain_resolver`, and typed `netns`. The dashboard uses its own default settings when its client is omitted. Set `route.default_http_client` to a registered client or let sing-box use the first registered client as its default.

The SSM API service accepts a non-empty `servers` map from HTTP paths starting with `/` to registered Shadowsocks inbounds. Use static multi-user Shadowsocks with a non-empty `users` list or managed Shadowsocks with `managed: true`. The `none` method is available for single-user Shadowsocks. Managed mode requires an omitted or empty static user list.

## Groups and rule-sets

Selectors and URL tests take a non-empty `outbounds` list of egress references with unique tags. A selector's optional `default` must be a member of that list.

Inline rule-sets take a single tag and at least one `HeadlessRule`. Local and remote rule-sets infer `source` from a `.json` file and `binary` from a `.srs` file. For remote URLs the path determines the format. Supply `format` explicitly for other paths.

Local and remote rule-sets support multiple tags. Put `{tag}` in the local `path`, or in the remote `url` and any supplied `initial_path`. Use a single-tag rule-set when matching a rule-set in a route or DNS rule.

See [Route and DNS rules](rules.md) for condition and action examples.
