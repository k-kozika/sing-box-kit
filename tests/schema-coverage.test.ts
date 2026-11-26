import { expect, test } from "bun:test";
import {
  certificateProvider,
  compile,
  dns,
  dnsServer,
  endpoint,
  httpClient,
  inbound,
  networkNamespace,
  outbound,
  route,
  Rule,
  service,
} from "../index";
import type { CompileInput, DnsRuleAction, MatchFields, RouteRuleAction } from "../index";

test("emits dns.strategy and all root settings without dropping explicit values", () => {
  const resolver = dnsServer.local({ tag: "local" });
  const direct = outbound.direct({ tag: "direct" }).dial({ connect_timeout: "5s" });
  const config = compile({
    $schema: "https://sing-box.sagernet.org/schema.json",
    ntp: { enabled: false, server: "192.0.2.123", server_port: 0, detour: direct },
    certificate: { store: "none", certificate: [] },
    outbounds: [direct],
    route: {
      final: direct,
      auto_detect_interface: false,
      default_mark: 0,
      default_network_type: [],
    },
    dns: {
      servers: [resolver],
      final: resolver,
      strategy: "ipv4_only",
      reverse_mapping: false,
      cache_capacity: 0,
    },
  });
  expect(JSON.parse(JSON.stringify(config))).toEqual({
    $schema: "https://sing-box.sagernet.org/schema.json",
    ntp: { enabled: false, server: "192.0.2.123", server_port: 0, detour: "direct" },
    certificate: { store: "none", certificate: [] },
    outbounds: [{ type: "direct", tag: "direct", connect_timeout: "5s" }],
    route: {
      final: "direct",
      auto_detect_interface: false,
      default_mark: 0,
      default_network_type: [],
    },
    dns: {
      servers: [{ type: "local", tag: "local" }],
      final: "local",
      strategy: "ipv4_only",
      reverse_mapping: false,
      cache_capacity: 0,
    },
  });
});

test("emits Tailscale exit-node options and WireGuard MTU", () => {
  const tail = endpoint.tailscale({
    tag: "tailscale",
    advertise_exit_node: true,
    advertise_routes: [],
    exit_node_allow_lan_access: false,
  });
  const wireguard = endpoint.wireguard({
    tag: "wireguard",
    address: ["192.0.2.1/32"],
    private_key: "example",
    mtu: 1420,
    listen_port: 0,
    peers: [],
  });
  expect(compile({ endpoints: [tail, wireguard] }).endpoints).toEqual([
    {
      type: "tailscale",
      tag: "tailscale",
      advertise_exit_node: true,
      advertise_routes: [],
      exit_node_allow_lan_access: false,
    },
    {
      type: "wireguard",
      tag: "wireguard",
      address: ["192.0.2.1/32"],
      private_key: "example",
      mtu: 1420,
      listen_port: 0,
      peers: [],
    },
  ]);
});

test("supports Mixed listener reuse and omitted address or port", () => {
  const inbounds = [
    inbound.mixed({ tag: "both" }).listen("127.0.0.1", { port: 1080, reuse_addr: true }),
    inbound.mixed({ tag: "address" }).listen("127.0.0.1", { tcp_fast_open: false }),
    inbound.mixed({ tag: "port" }).listen(undefined, { port: 0 }),
    inbound.mixed({ tag: "options" }).listen({ tcp_multi_path: false }),
    inbound.tun({ tag: "tun" }).listen({ udp_timeout: 0, netns: "/run/netns/example" }),
  ];
  expect(compile({ inbounds }).inbounds).toEqual([
    { type: "mixed", tag: "both", listen: "127.0.0.1", listen_port: 1080, reuse_addr: true },
    { type: "mixed", tag: "address", listen: "127.0.0.1", tcp_fast_open: false },
    { type: "mixed", tag: "port", listen_port: 0 },
    { type: "mixed", tag: "options", tcp_multi_path: false },
    { type: "tun", tag: "tun", udp_timeout: 0, netns: "/run/netns/example" },
  ]);
});

test("emits VLESS transport, multiplex, and type-specific TLS and Dial Fields", () => {
  const transport = { type: "ws", path: "/proxy" } as const;
  const multiplex = { enabled: false } as const;
  const incoming = inbound
    .vless({ tag: "incoming", users: [], transport, multiplex })
    .tls({ enabled: false, alpn: ["h2"] });
  const outgoing = outbound
    .vless({
      tag: "outgoing",
      server: "192.0.2.1",
      server_port: 443,
      uuid: "00000000-0000-4000-8000-000000000001",
      transport,
      multiplex,
    })
    .dial({ tcp_fast_open: false, fallback_delay: "0s" })
    .tls({ alpn: [], server_name: "example.test" });
  expect(compile({ inbounds: [incoming], outbounds: [outgoing] })).toEqual({
    inbounds: [
      {
        type: "vless",
        tag: "incoming",
        users: [],
        transport,
        multiplex,
        tls: { enabled: false, alpn: ["h2"] },
      },
    ],
    outbounds: [
      {
        type: "vless",
        tag: "outgoing",
        server: "192.0.2.1",
        server_port: 443,
        uuid: "00000000-0000-4000-8000-000000000001",
        transport,
        multiplex,
        tcp_fast_open: false,
        fallback_delay: "0s",
        tls: { enabled: true, alpn: [], server_name: "example.test" },
      },
    ],
  });
});

test("matches ICMP and route CIDRs and retains DNS response CIDR validation", () => {
  const server = dnsServer.local({ tag: "local" });
  const compiled = compile({
    dns: {
      servers: [server],
      rules: [
        dns.rule({ action: "evaluate", server, tag: "check" }),
        dns.rule(
          Rule.match({ match_response: "check", ip_cidr: ["192.0.2.0/24"], query_dnssec: false }),
          { action: "respond" },
        ),
      ],
    },
    route: {
      rules: [
        route.rule(Rule.match({ network: "icmp", ip_cidr: "192.0.2.0/24" }), {
          action: "reject",
          method: "reply",
        }),
        route.rule(Rule.match({ ip_cidr: "192.0.2.1/32", source_port: 0, invert: false }), {
          action: "reject",
        }),
      ],
    },
  });
  expect(compiled.route?.rules).toEqual([
    { network: "icmp", ip_cidr: "192.0.2.0/24", action: "reject", method: "reply" },
    { ip_cidr: "192.0.2.1/32", source_port: 0, invert: false, action: "reject" },
  ]);
  expect(compiled.dns?.rules).toEqual([
    { action: "evaluate", server: "local", tag: "check" },
    { match_response: "check", ip_cidr: ["192.0.2.0/24"], query_dnssec: false, action: "respond" },
  ]);
  expect(() =>
    Rule.match({ ip_cidr: "192.0.2.0/24", query_type: "A" } as unknown as MatchFields),
  ).toThrow("match_response");
  expect(() =>
    compile({
      dns: {
        rules: [
          dns.rule(Rule.match({ match_response: "unknown", ip_cidr: "192.0.2.0/24" }), {
            action: "respond",
          }),
        ],
      },
    }),
  ).toThrow("earlier named evaluate");
});

test("emits route destination overrides, sniff, and resolve", () => {
  const direct = outbound.direct({ tag: "direct" });
  const server = dnsServer.local({ tag: "local" });
  const overrides = { override_address: "192.0.2.2", override_port: 0 };
  const output = compile({
    outbounds: [direct],
    dns: { servers: [server] },
    route: {
      rules: [
        route.rule({ action: "sniff", sniffer: ["tls", "http"], timeout: "300ms" }),
        route.rule({ action: "resolve", server, strategy: "prefer_ipv4", rewrite_ttl: 0 }),
        route.rule({ action: "route-options", ...overrides }),
        route.rule({ action: "bypass", ...overrides, outbound: direct }),
        route.rule({ action: "route", ...overrides, outbound: direct }),
      ],
    },
  });
  expect(output.route?.rules).toEqual([
    { action: "sniff", sniffer: ["tls", "http"], timeout: "300ms" },
    { action: "resolve", server: "local", strategy: "prefer_ipv4", rewrite_ttl: 0 },
    { action: "route-options", ...overrides },
    { action: "bypass", ...overrides, outbound: "direct" },
    { action: "route", ...overrides, outbound: "direct" },
  ]);
});

test("expands typed references from singleton, object, map, and array positions", () => {
  const resolver = dnsServer.local({ tag: "local" });
  const space = networkNamespace.unshare({ tag: "ns" });
  const direct = outbound.direct({ tag: "dialer" }).dial({ bind_interface: "lo" });
  const listener = inbound.mixed({ tag: "listener" });
  const tail = endpoint.tailscale({ tag: "tail" });
  const oc = endpoint.openconnect({ tag: "oc" }).tls({ insecure: false });
  const ovpn = endpoint.openvpnClient({ tag: "ovpn" }).tls({ server_name: "vpn.example.test" });
  const resolved = service.resolved({ tag: "resolved" }).listen({ port: 0, netns: space });
  const client = httpClient({ tag: "client" }).dial({ domain_resolver: { server: resolver } });
  const cert = certificateProvider.acme({ tag: "acme", http_client: client });
  const http = inbound.http({ tag: "http" }).tls({
    certificate_provider: { type: "acme", http_client: { detour: direct } },
  });
  const shadow = inbound.shadowtls({
    tag: "shadow",
    handshake_for_server_name: {
      "example.test": { server: "192.0.2.2", detour: direct },
    },
  });
  const derp = service.derp({
    verify_client_endpoint: [tail],
    mesh_with: [{ server: "192.0.2.2", detour: direct }],
    stun: { netns: space, detour: listener },
  });
  const out = compile({
    network_namespaces: [space],
    inbounds: [listener, http, shadow],
    outbounds: [direct],
    endpoints: [tail, oc, ovpn],
    services: [resolved, derp],
    certificate_providers: [cert],
    http_clients: [client],
    dns: {
      servers: [
        resolver,
        dnsServer.openconnect({ tag: "oc-dns", endpoint: oc }),
        dnsServer.openvpn({ tag: "ovpn-dns", endpoint: ovpn }),
        dnsServer.resolved({ tag: "resolved-dns", service: resolved }),
      ],
    },
  });
  expect(out.inbounds?.slice(1)).toEqual([
    {
      type: "http",
      tag: "http",
      tls: {
        enabled: true,
        certificate_provider: { type: "acme", http_client: { detour: "dialer" } },
      },
    },
    {
      type: "shadowtls",
      tag: "shadow",
      handshake_for_server_name: { "example.test": { server: "192.0.2.2", detour: "dialer" } },
    },
  ]);
  expect(out.endpoints?.slice(1)).toEqual([
    { type: "openconnect", tag: "oc", tls: { insecure: false } },
    { type: "openvpn-client", tag: "ovpn", tls: { server_name: "vpn.example.test" } },
  ]);
  expect(out.services).toEqual([
    { type: "resolved", tag: "resolved", listen_port: 0, netns: "ns" },
    {
      type: "derp",
      verify_client_endpoint: ["tail"],
      mesh_with: [{ server: "192.0.2.2", detour: "dialer" }],
      stun: { netns: "ns", detour: "listener" },
    },
  ]);
  expect(out.certificate_providers).toEqual([{ type: "acme", tag: "acme", http_client: "client" }]);
  expect(out.http_clients).toEqual([{ tag: "client", domain_resolver: { server: "local" } }]);
  expect(out.dns?.servers?.slice(1)).toEqual([
    { type: "openconnect", tag: "oc-dns", endpoint: "oc" },
    { type: "openvpn", tag: "ovpn-dns", endpoint: "ovpn" },
    { type: "resolved", tag: "resolved-dns", service: "resolved" },
  ]);
});

test("rejects extra keys, incompatible branches and conflicting rule scopes at runtime", () => {
  expect(() =>
    endpoint.tailscale({ tag: "tail", extra: false } as Parameters<typeof endpoint.tailscale>[0]),
  ).toThrow("extra");
  expect(() => inbound.mixed({ tag: "mixed" }).listen({ spam: true } as never)).toThrow("spam");
  expect(() => outbound.http({ tag: "http" }).dial({ invalid: 1 } as never)).toThrow("invalid");
  expect(() => endpoint.openvpnClient({ tag: "ovpn" }).tls({ enabled: true } as never)).toThrow(
    "tls.enabled",
  );
  expect(() => inbound.snell({ tag: "snell", version: 4 } as never)).toThrow("version");
  expect(() => outbound.snell({ tag: "snell", version: 6, obfs_mode: "tls" } as never)).toThrow(
    "obfs_mode",
  );
  expect(() => service.usbipServer({ provider: "dynamic", devices: [] } as never)).toThrow(
    "devices",
  );
  expect(() => service.usbipServer({ provider: "unknown" } as never)).toThrow("provider");
  expect(() => dns.rule(Rule.match({ network: ["icmp"] }) as never, { action: "reject" })).toThrow(
    "scope",
  );
  expect(() => dns.rule({ action: "reject", method: "reply" } as unknown as DnsRuleAction)).toThrow(
    "method",
  );
  expect(() =>
    route.rule({ action: "resolve", server: "local" } as unknown as RouteRuleAction),
  ).toThrow("server");
  expect(() => compile({ dns: { strategy: "ipv4_only", extra: false } } as CompileInput)).toThrow(
    "dns.extra",
  );
});

test("reports paths for wrong kinds and unregistered final references", () => {
  const tail = endpoint.tailscale({ tag: "tail" });
  const oc = endpoint.openconnect({ tag: "oc" });
  const ocFinal = oc.tls({ insecure: false });
  const ovpnServer = endpoint.openvpnServer({ tag: "ovpn" });
  const api = service.api({ tag: "api" });
  const client = httpClient({ tag: "client" });
  expect(() =>
    compile({
      endpoints: [tail],
      dns: {
        servers: [dnsServer.openconnect({ tag: "dns", endpoint: tail as unknown as typeof oc })],
      },
    }),
  ).toThrow(/dns\.servers\[0\]\.endpoint.*openconnect-endpoint/);
  expect(() =>
    compile({
      endpoints: [ocFinal],
      dns: { servers: [dnsServer.openconnect({ tag: "dns", endpoint: oc })] },
    }),
  ).toThrow(/dns\.servers\[0\]\.endpoint.*unregistered/);
  expect(() =>
    compile({
      endpoints: [ovpnServer],
      dns: { servers: [dnsServer.openvpn({ tag: "dns", endpoint: ovpnServer as never })] },
    }),
  ).toThrow(/dns\.servers\[0\]\.endpoint.*openvpn-client-endpoint/);
  expect(() =>
    compile({
      services: [api],
      dns: { servers: [dnsServer.resolved({ tag: "dns", service: api as never })] },
    }),
  ).toThrow(/dns\.servers\[0\]\.service.*resolved-service/);
  expect(() => compile({ services: [service.derp({ verify_client_endpoint: [tail] })] })).toThrow(
    /services\[0\]\.verify_client_endpoint\[0\].*unregistered/,
  );
  expect(() =>
    compile({ endpoints: [oc], services: [service.derp({ verify_client_endpoint: oc as never })] }),
  ).toThrow(/services\[0\]\.verify_client_endpoint.*tailscale-endpoint/);
  expect(() =>
    compile({
      certificate_providers: [
        certificateProvider.acme({
          tag: "acme",
          http_client: client,
        }),
      ],
    }),
  ).toThrow(/certificate_providers\[0\]\.http_client.*unregistered/);
});

test("validates interface conditions and preferred resource capabilities", () => {
  const oc = endpoint.openconnect({ tag: "oc" });
  const ovpn = endpoint.openvpnClient({ tag: "ovpn" });
  const bridge = outbound.bridge({ tag: "bridge" });
  const hosts = dnsServer.hosts({ tag: "hosts" });
  const mdns = dnsServer.mdns({ tag: "mdns" });
  const routeRule = route.rule(
    Rule.match({
      network_interface_address: { wifi: ["192.0.2.0/24"] },
      preferred_by: [oc, ovpn, bridge],
    }),
    { action: "reject" },
  );
  const dnsRule = dns.rule(Rule.match({ preferred_by: [hosts, mdns] }), { action: "reject" });
  const config = compile({
    endpoints: [oc, ovpn],
    outbounds: [bridge],
    route: { rules: [routeRule] },
    dns: { servers: [hosts, mdns], rules: [dnsRule] },
  });
  expect(config.route?.rules).toEqual([
    {
      network_interface_address: { wifi: ["192.0.2.0/24"] },
      preferred_by: ["oc", "ovpn", "bridge"],
      action: "reject",
    },
  ]);
  expect(config.dns?.rules).toEqual([{ preferred_by: ["hosts", "mdns"], action: "reject" }]);
  expect(() =>
    Rule.match({ network_interface_address: { cable: "192.0.2.0/24" } } as never),
  ).toThrow("network_interface_address");
});
