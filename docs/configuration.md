# Configuration reference

Create resources with the factories exported from the project root. Pass type-specific options to the factory and use the supported `.listen()`, `.dial()`, and `.tls()` methods for shared settings.

## Factories and registration

| Factories | Register in |
| --- | --- |
| `inbound.mixed()`, `inbound.socks()`, `inbound.shadowsocks()`, `inbound.vless()` | `inbounds` |
| `outbound.direct()`, `outbound.vless()`, `outbound.selector()`, `outbound.urltest()` | `outbounds` |
| `endpoint.tailscale()`, `endpoint.wireguard()` | `endpoints` |
| `service.api()`, `service.ssmApi()` | `services` |
| Tagged `httpClient()` | `http_clients` |
| `dnsServer.tcp()`, `dnsServer.udp()`, `dnsServer.tls()`, `dnsServer.https()`, `dnsServer.tailscale()` | `dns.servers` |
| `ruleSet.inline()`, `ruleSet.local()`, `ruleSet.remote()` | `route.rule_set` |
| `certificateProvider.tailscale()` | `certificate_providers` |
| `networkNamespace.default()`, `networkNamespace.unshare()` | `network_namespaces` |

Builder methods return new values. Register and reference the same final value after applying the settings. If you rebuild a resource with the same tag, rebuild any references to it. Apply each settings method at most once per chain.

`compile(input)` preserves list order, checks tag collisions and reference capabilities, and returns a `SingBoxConfig` suitable for `JSON.stringify()`. Outbounds and endpoints share a tag scope. Services without explicit tags use their zero-based list position for collision checks.

Use `validateConfig(value)` to check an existing JSON configuration against the pinned schema. This accepts raw tag strings and checks schema constraints. Use `compile()` for the Kit's registration, reference, and dependency checks.

## Shared settings

- `.listen(address, { port })` emits `listen` and `listen_port`. To forward traffic from an inbound, pass a compatible regular inbound as `detour`. Tailscale and WireGuard endpoints can match inbound rule conditions and serve as egress.
- `.dial(options)` accepts `connect_timeout`, `domain_resolver`, and `netns`. On dialers that accept `detour`, supply an outbound or endpoint. Put any non-zero timeout or namespace setting on the detour target. An otherwise empty direct outbound cannot be used as an explicit dial detour. WireGuard also disallows a non-zero `listen_port` with a dial detour.
- In Listen and Dial Fields, a typed `netns` value resolves to a registered namespace tag. A string passes through as supplied. sing-box looks for a registered tag before treating it as an OS name or path.
- Supply a DNS server to `domain_resolver` or `route.default_domain_resolver` directly or as `{ server: resolver, ...options }`. A TCP, UDP, TLS, or HTTPS DNS server configured with a hostname needs its own resolver or an explicit detour.

## TLS profiles

On supported builders, `.tls(profile)` enables TLS. Use `side: "server"` with a `certificate_path` and `key_path` pair or a registered `certificate_provider`. Use `side: "client"` with optional `server_name` and `certificate_path` settings.

VLESS also supports REALITY on both sides. On the inbound, set `server_name` and pass `reality: { private_key, short_id, handshake }`. The handshake has its own `server`, `server_port`, and optional Dial Fields. On the outbound, set the VLESS `server` and `server_port` for the connection, set the TLS `server_name` for verification, and pass `reality: { public_key, short_id }`. The Kit enables uTLS for that client profile.

REALITY keys are unpadded Base64url strings for 32-byte keys. Short IDs are even-length hexadecimal strings of up to 16 characters, including the empty string. The inbound accepts a string or an array of strings. Keep the private key in the server configuration and share the public key and a selected short ID with the client.

## HTTP clients and services

The API service defaults to loopback `127.0.0.1`. Omitting TLS uses plaintext TCP, and an omitted or empty `secret` allows unauthenticated connections. `dashboard` accepts a boolean, path string, or settings object. Set `enabled: true` to enable the dashboard in object form.

The dashboard and remote rule-sets accept either a tagged client registered in `http_clients`, an untagged `httpClient()` builder, or an inline HTTP settings object. The inline object supports the sing-box HTTP client shape without `tag`, with Kit references for `detour`, `domain_resolver`, and typed `netns`. The dashboard uses its own default settings when its client is omitted. Set `route.default_http_client` to a registered client or let sing-box use the first registered client as its default.

The SSM API service accepts a non-empty `servers` map from HTTP paths starting with `/` to registered Shadowsocks inbounds. Use static multi-user Shadowsocks with a non-empty `users` list or managed Shadowsocks with `managed: true`. The `none` method is available for single-user Shadowsocks. Managed mode requires an omitted or empty static user list.

## Groups and rule-sets

Selectors and URL tests take a non-empty `outbounds` list of egress references with unique tags. A selector's optional `default` must be a member of that list.

Inline rule-sets take a single tag and at least one `HeadlessRule`. Local and remote rule-sets infer `source` from a `.json` file and `binary` from a `.srs` file. For remote URLs the path determines the format. Supply `format` explicitly for other paths.

Local and remote rule-sets support multiple tags. Put `{tag}` in the local `path`, or in the remote `url` and any supplied `initial_path`. Use a single-tag rule-set when matching a rule-set in a route or DNS rule.

See [Route and DNS rules](rules.md) for condition and action examples.
