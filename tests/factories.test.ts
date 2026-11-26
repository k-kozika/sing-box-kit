import { expect, test } from "bun:test";
import {
  certificateProvider,
  compile,
  dnsServer,
  endpoint,
  httpClient,
  inbound,
  networkNamespace,
  outbound,
  ruleSet,
  service,
  validateConfig,
} from "../index";
import type { SingBoxConfig } from "../index";
import schema from "../schema/sing-box.json";

interface SchemaEntry {
  type?: string;
  $ref?: string;
  oneOf?: readonly SchemaEntry[];
  anyOf?: readonly SchemaEntry[];
  items?: SchemaEntry;
  properties?: Record<string, SchemaEntry | undefined>;
  const?: string | number;
  enum?: readonly (string | number)[];
}

const definitions: Record<string, SchemaEntry> = schema.$defs;
const registrations = {
  inbounds: inbound,
  outbounds: outbound,
  endpoints: endpoint,
  services: service,
  http_clients: { httpClient },
  certificate_providers: certificateProvider,
  network_namespaces: networkNamespace,
  "dns.servers": dnsServer,
  "route.rule_set": ruleSet,
};

function dereference(node: SchemaEntry): SchemaEntry {
  return node.$ref ? definitions[node.$ref.split("/").at(-1)!]! : node;
}

// Traverse the snapshot from its registration paths independently of the Kit generator.
function schemaLeaves(node: SchemaEntry): SchemaEntry[] {
  const resolved = dereference(node);
  const branches = [...(resolved.oneOf ?? []), ...(resolved.anyOf ?? [])];
  return branches.length ? branches.flatMap(schemaLeaves) : [resolved];
}

function leavesAt(path: string): SchemaEntry[] {
  const root: SchemaEntry = schema;
  const registration = path
    .split(".")
    .reduce((node, key) => dereference(node).properties![key]!, root);
  return schemaLeaves(registration.items!);
}

function canonicalKind(node: SchemaEntry): string {
  const type = node.properties?.type;
  return String(type?.const ?? type?.enum?.find(Boolean) ?? "http-client");
}

function publicName(kind: string): string {
  const [first, ...rest] = kind.split("-");
  return first + rest.map((part) => part[0]!.toUpperCase() + part.slice(1)).join("");
}

test("the package root exposes exactly the 77 kinds in the pinned schema", () => {
  let total = 0;
  for (const [path, factories] of Object.entries(registrations)) {
    const names = new Set(leavesAt(path).map((node) => publicName(canonicalKind(node))));
    expect(Object.keys(factories).sort()).toEqual([...names].sort());
    for (const factory of Object.values(factories)) expect(typeof factory).toBe("function");
    // HTTPClient has a standalone factory but no type discriminator.
    total += leavesAt(path)[0]?.properties?.type ? names.size : 0;
  }
  expect(total).toBe(77);
});

function allKinds(): SingBoxConfig {
  const direct = outbound.direct({ tag: "direct" });
  const tail = endpoint.tailscale({ tag: "tailscale" });
  const oc = endpoint.openconnect({ tag: "openconnect" });
  const ovpn = endpoint.openvpnClient({ tag: "openvpn-client" });
  const resolved = service.resolved({ tag: "resolved" });
  const ss = inbound.shadowsocks({ tag: "shadowsocks", method: "aes-128-gcm", managed: true });
  const server = "192.0.2.53";
  return compile({
    inbounds: [
      inbound.anytls({ tag: "anytls" }),
      inbound.cloudflared({ tag: "cloudflared" }),
      inbound.direct({ tag: "direct" }),
      inbound.http({ tag: "http" }),
      inbound.hysteria({ tag: "hysteria" }),
      inbound.hysteria2({ tag: "hysteria2" }),
      inbound.mixed({ tag: "mixed" }),
      inbound.naive({ tag: "naive" }),
      inbound.redirect({ tag: "redirect" }),
      ss,
      inbound.shadowtls({ tag: "shadowtls" }),
      inbound.snell({ tag: "snell-5", version: 5, obfs_mode: "http" }),
      inbound.snell({ tag: "snell-6", version: 6, mode: "default" }),
      inbound.socks({ tag: "socks" }),
      inbound.tproxy({ tag: "tproxy" }),
      inbound.trojan({ tag: "trojan" }),
      inbound.tuic({ tag: "tuic" }),
      inbound.tun({ tag: "tun" }),
      inbound.vless({ tag: "vless", users: [] }),
      inbound.vmess({ tag: "vmess" }),
    ],
    outbounds: [
      outbound.anytls({ tag: "anytls" }),
      outbound.block({ tag: "block" }),
      outbound.bridge({ tag: "bridge" }),
      direct,
      outbound.http({ tag: "http" }),
      outbound.hysteria({ tag: "hysteria" }),
      outbound.hysteria2({ tag: "hysteria2" }),
      outbound.naive({ tag: "naive" }),
      outbound.selector({ tag: "selector", outbounds: [direct], default: direct }),
      outbound.shadowsocks({ tag: "shadowsocks" }),
      outbound.shadowtls({ tag: "shadowtls" }),
      outbound.snell({ tag: "snell-4", version: 4, obfs_mode: "tls" }),
      outbound.snell({ tag: "snell-6", version: 6, mode: "default" }),
      outbound.socks({ tag: "socks" }),
      outbound.ssh({ tag: "ssh" }),
      outbound.tor({ tag: "tor" }),
      outbound.trojan({ tag: "trojan" }),
      outbound.tuic({ tag: "tuic" }),
      outbound.urltest({ tag: "urltest", outbounds: [direct] }),
      outbound.vless({
        tag: "vless",
        server,
        server_port: 443,
        uuid: "00000000-0000-4000-8000-000000000001",
      }),
      outbound.vmess({ tag: "vmess" }),
    ],
    endpoints: [
      oc,
      ovpn,
      endpoint.openvpnServer({ tag: "openvpn-server" }),
      tail,
      endpoint.wireguard({ tag: "wireguard", address: ["192.0.2.1/32"], private_key: "key" }),
    ],
    services: [
      service.api(),
      service.ccm(),
      service.derp({ verify_client_endpoint: [tail] }),
      service.hysteriaRealm(),
      service.ocm(),
      service.oomKiller(),
      resolved,
      service.ssmApi({ servers: { "/": ss } }),
      service.usbipClient(),
      service.usbipServer({ tag: "usbip-default", provider: "default", devices: [] }),
      service.usbipServer({ tag: "usbip-dynamic", provider: "dynamic" }),
      service.usbipServer({ tag: "usbip-empty-provider", provider: "", devices: [] }),
      service.usbipServer({ tag: "usbip-implicit-provider", devices: [] }),
    ],
    dns: {
      servers: [
        dnsServer.dhcp({ tag: "dhcp" }),
        dnsServer.fakeip({ tag: "fakeip" }),
        dnsServer.h3({ tag: "h3", server }),
        dnsServer.hosts({ tag: "hosts" }),
        dnsServer.https({ tag: "https", server }),
        dnsServer.local({ tag: "local" }),
        dnsServer.mdns({ tag: "mdns" }),
        dnsServer.openconnect({ tag: "openconnect", endpoint: oc }),
        dnsServer.openvpn({ tag: "openvpn", endpoint: ovpn }),
        dnsServer.quic({ tag: "quic", server }),
        dnsServer.resolved({ tag: "resolved", service: resolved }),
        dnsServer.tailscale({ tag: "tailscale", endpoint: tail }),
        dnsServer.tcp({ tag: "tcp", server }),
        dnsServer.tls({ tag: "tls", server }),
        dnsServer.udp({ tag: "udp", server }),
      ],
    },
    certificate_providers: [
      certificateProvider.acme({ tag: "acme" }),
      certificateProvider.cloudflareOriginCa({ tag: "cloudflare-origin-ca" }),
      certificateProvider.tailscale({ tag: "tailscale", endpoint: tail }),
    ],
    network_namespaces: [
      networkNamespace.default({ tag: "default", path: "/run/netns/example" }),
      networkNamespace.unshare({ tag: "unshare" }),
    ],
    route: {
      rule_set: [
        ruleSet.inline({ tag: "inline", rules: [{ domain: "example.test" }] }),
        ruleSet.local({ tag: "local", path: "set.json" }),
        ruleSet.remote({ tag: "remote", url: "https://example.test/set.srs" }),
      ],
    },
    http_clients: [httpClient({ tag: "http", engine: "go" })],
  });
}

test("constructs every kind and discriminated branch through the public API", () => {
  const output = allKinds();
  expect(validateConfig(output)).toBe(output);
  const emitted = {
    inbounds: output.inbounds,
    outbounds: output.outbounds,
    endpoints: output.endpoints,
    services: output.services,
    http_clients: output.http_clients,
    certificate_providers: output.certificate_providers,
    network_namespaces: output.network_namespaces,
    "dns.servers": output.dns?.servers,
    "route.rule_set": output.route?.rule_set,
  };
  for (const [path, entries] of Object.entries(emitted)) {
    const leaves = leavesAt(path);
    const kinds = new Set(leaves.map(canonicalKind));
    const typeOf = (entry: { type?: string }) =>
      entry.type ?? (path === "http_clients" ? "http-client" : "<missing type>");
    const actual = new Set(entries?.map((entry) => typeOf(entry as { type?: string })));
    expect([...actual].sort()).toEqual([...kinds].sort());
    for (const leaf of leaves) {
      const discriminator = ["version", "provider"].find(
        (key) =>
          leaf.properties?.[key]?.const !== undefined ||
          (canonicalKind(leaf) === "usbip-server" && leaf.properties?.[key]?.enum),
      );
      if (!discriminator) continue;
      const property = leaf.properties![discriminator]!;
      for (const label of property.enum ?? [property.const]) {
        expect(
          entries?.some(
            (entry) =>
              typeOf(entry as { type?: string }) === canonicalKind(leaf) &&
              (entry as Record<string, unknown>)[discriminator] === label,
          ),
        ).toBe(true);
      }
    }
  }
  expect(output.services?.slice(-4)).toEqual([
    { type: "usbip-server", tag: "usbip-default", provider: "default", devices: [] },
    { type: "usbip-server", tag: "usbip-dynamic", provider: "dynamic" },
    { type: "usbip-server", tag: "usbip-empty-provider", provider: "", devices: [] },
    { type: "usbip-server", tag: "usbip-implicit-provider", devices: [] },
  ]);
});
