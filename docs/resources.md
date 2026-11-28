# Resource factories and registration

Choose a factory from the table and register its finished value in the corresponding `compile()` list. The pinned sing-box schema contains 77 kinds with a `type` discriminator. SBKit also exports a standalone `httpClient()` factory.

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

## Inbounds and outbounds

Snell inbounds take `version: 5` or `6`. Snell outbounds take `version: 4` or `6`. The version selects which options you can supply.

VLESS builders take `transport` and `multiplex` in the factory options. See [TLS profiles](settings.md#tls-profiles) for configuring REALITY.

Selectors and URL tests take a non-empty `outbounds` list of egress references with unique tags. A selector's optional `default` must be a member of that list.

## DNS servers

`dnsServer.openconnect()` takes an `endpoint.openconnect()` value, `dnsServer.openvpn()` takes an `endpoint.openvpnClient()` value, and `dnsServer.resolved()` takes a tagged `service.resolved()` value. See [DNS resolvers](settings.md#dns-resolvers) for hostname resolution and [DNS rules](dns-rules.md) for selecting a server.

## Services

The API service defaults to loopback `127.0.0.1`. Omitting TLS uses plaintext TCP, and an omitted or empty `secret` allows unauthenticated connections. `dashboard` accepts a boolean, path string, or settings object. Set `enabled: true` to enable the dashboard in object form. The dashboard uses its own default settings when its HTTP client is omitted.

DERP accepts a Tailscale endpoint or an array of those endpoints in `verify_client_endpoint`.

The SSM API service accepts a non-empty `servers` map from HTTP paths starting with `/` to registered Shadowsocks inbounds. Use static multi-user Shadowsocks with a non-empty `users` list or managed Shadowsocks with `managed: true`. The `none` method is available for single-user Shadowsocks. Managed mode requires an omitted or empty static user list.

USB/IP Server accepts `devices` with the default provider, written as `provider: "default"`, `provider: ""`, or by omitting `provider`. Supply `provider: "dynamic"` to select the dynamic provider.

## HTTP clients

The API dashboard and remote rule-sets accept a tagged client registered in `http_clients`, an untagged `httpClient()` builder, or an inline HTTP settings object. The inline object supports the sing-box HTTP client fields other than `tag`, including SBKit references for `detour`, `domain_resolver`, and `netns`. Set `route.default_http_client` to a registered client or let sing-box use the first registered client as its default.

## Rule-sets

Inline rule-sets take a single tag and at least one `HeadlessRule`. Local and remote rule-sets infer `source` from a `.json` file and `binary` from a `.srs` file. For remote URLs the path determines the format. Supply `format` explicitly for other paths.

Local and remote rule-sets support multiple tags. Put `{tag}` in the local `path`, or in the remote `url` and any supplied `initial_path`. Use a single-tag rule-set when matching a rule-set in a route or DNS rule.
