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
  proxyProfile,
  route,
  Rule,
  ruleSet,
  service,
  user,
  validateConfig,
} from "../index";
import type {
  CompileInput,
  DnsRuleAction,
  RouteRuleAction,
  RuleAction,
  SingBoxConfig,
} from "../index";

const direct = outbound.direct({ tag: "out" }).dial({ connect_timeout: "5s" });
const client = httpClient({ tag: "client", headers: { "my-header": ["one", "two"] } }).dial({
  detour: direct,
});
const mixed = inbound.mixed({ tag: "mixed" });
const vless = outbound.vless({
  tag: "proxy",
  server: "host.example",
  server_port: 443,
  uuid: "uuid",
});
const serverTls = { side: "server", certificate_path: "cert.pem", key_path: "key.pem" } as const;
const clientTls = { side: "client", certificate_path: "ca.pem" } as const;
const config: SingBoxConfig = compile({
  log: { level: "debug" },
  experimental: { cache_file: { enabled: true } },
  outbounds: [direct, vless.tls(clientTls)],
  inbounds: [mixed.listen("127.0.0.1", { port: 1080 }).tls(serverTls)],
  services: [
    service
      .api({ dashboard: { http_client: client } })
      .listen("127.0.0.1", { port: 9090 })
      .tls(serverTls),
  ],
  http_clients: [client],
});
validateConfig(config);
const empty: CompileInput = {};
compile(empty);

// @ts-expect-error A direct outbound requires a tag.
outbound.direct({});
// @ts-expect-error VLESS requires a UUID.
outbound.vless({ tag: "proxy", server: "host.example", server_port: 443 });
// @ts-expect-error Listen fields belong in .listen().
inbound.mixed({ tag: "mixed", listen_port: 1080 });
// @ts-expect-error Shared Dial Fields belong in .dial().
httpClient({ connect_timeout: "5s" });
// @ts-expect-error Direct outbounds have no detour.
direct.dial({ detour: vless });
// @ts-expect-error Direct outbounds have no TLS.
direct.tls(clientTls);
// @ts-expect-error HTTP clients cannot listen.
client.listen("127.0.0.1", { port: 1080 });
// @ts-expect-error Mixed accepts server-side TLS only.
mixed.tls(clientTls);
// @ts-expect-error The outbound accepts client-side TLS only.
vless.tls(serverTls);
// @ts-expect-error Certificate and key paths must be supplied together.
service.api().tls({ side: "server", certificate_path: "cert.pem" });
// @ts-expect-error A raw tag cannot stand in for an SBKit reference.
vless.dial({ detour: "out" });
// @ts-expect-error HTTP client registration requires a tagged value.
compile({ http_clients: [httpClient()] });
// @ts-expect-error A raw inline HTTP object cannot have a tag.
service.api({ dashboard: { http_client: { tag: "inline", version: 2 } } });
// @ts-expect-error Raw detour tags are also disallowed in inline objects.
service.api({ dashboard: { http_client: { detour: "out" } } });
const _invalidRule: NonNullable<NonNullable<SingBoxConfig["route"]>["rules"]>[number] = {
  action: "reject",
  // @ts-expect-error Generated rule types reject unknown keys.
  unknown: true,
};

const ns = networkNamespace.unshare({ tag: "ns" });
const ts = endpoint.tailscale({ tag: "ts" }).dial({ netns: ns });
const wg = endpoint.wireguard({ tag: "wg", address: ["192.0.2.3/32"], private_key: "key" });
const provider = certificateProvider.tailscale({ tag: "cert", endpoint: ts });
const udp = dnsServer.udp({ tag: "udp", server: "192.0.2.53" });
const preferred = dnsServer.tailscale({ tag: "tdns", endpoint: ts });
const https = dnsServer
  .https({ tag: "doh", server: "resolver.example", path: "/dns-query" })
  .dial({ domain_resolver: { server: udp, rewrite_ttl: 0 } })
  .tls(clientTls);
dnsServer.tls({ tag: "dot", server: "192.0.2.54" }).tls({ side: "client" });
const selector = outbound.selector({ tag: "select", outbounds: [direct, wg], default: wg });
outbound.urltest({ tag: "test", outbounds: [direct, wg] });
const inline = ruleSet.inline({ tag: "domains", rules: [{ domain_suffix: ["example.test"] }] });
const local = ruleSet.local({ tag: ["first", "second"], path: "/tmp/{tag}.srs" });
const remote = ruleSet.remote({
  tag: "remote",
  url: "https://example.test/set.json",
  http_client: {
    version: 2,
    tls: { enabled: true },
    stream_receive_window: "32KiB",
    detour: direct,
  },
});
const sharedCondition = Rule.match({
  inbound: [mixed, ts],
  rule_set: [inline, remote],
  port: [53, 853],
});
const routeCondition = Rule.match({ client: "chrome", preferred_by: [ts, wg] });
const dnsCondition = Rule.match({ query_type: 1, preferred_by: preferred });
const optionalPreference: { domain: string; preferred_by?: typeof preferred } = {
  domain: "example.test",
};
route.rule(sharedCondition.and(routeCondition), { action: "route", outbound: selector });
dns.rule(sharedCondition.or(dnsCondition), { action: "route", server: https });
dns.rule(Rule.match(optionalPreference), { action: "respond" });
// @ts-expect-error The optional preference can make the condition DNS-only.
route.rule(Rule.match(optionalPreference), { action: "reject" });
const routeAction: RouteRuleAction = { action: "reject", method: "drop" };
const dnsAction: DnsRuleAction = { action: "respond" };
const action: RuleAction<"dns"> = dnsAction;
route.rule(routeAction);
dns.rule(action);
compile({
  endpoints: [ts, wg],
  network_namespaces: [ns],
  certificate_providers: [provider],
  route: {
    rule_set: [inline, local, remote],
    default_domain_resolver: udp,
    default_http_client: client,
    final: wg,
  },
  dns: { servers: [udp, https, preferred], final: udp },
});
// @ts-expect-error Endpoint detours are outbound-only.
mixed.listen("127.0.0.1", { port: 1080, detour: ts });
service.api().listen("127.0.0.1", { port: 9090, detour: mixed });
// @ts-expect-error The provider requires a Tailscale endpoint.
certificateProvider.tailscale({ tag: "cert", endpoint: wg });
// @ts-expect-error UDP has no TLS builder.
udp.tls(clientTls);
// @ts-expect-error A DNS server is not an egress.
compile({ route: { final: udp } });
// @ts-expect-error Untagged HTTP clients are inline only.
compile({ route: { default_http_client: httpClient() } });
// @ts-expect-error Multi-tag rule-sets do not select a tag for matching.
Rule.match({ rule_set: local });
// @ts-expect-error Ordinary DNS transports lack preferred domains.
Rule.match({ preferred_by: https });
// @ts-expect-error Egress and DNS transport references cannot be mixed.
Rule.match({ preferred_by: [wg, preferred] });
// @ts-expect-error A leaf cannot combine route-only and DNS-only fields.
Rule.match({ client: "chrome", query_type: "A" });
// @ts-expect-error The conditions have disjoint scopes.
routeCondition.and(dnsCondition);
// @ts-expect-error The conditions have disjoint scopes after composition.
sharedCondition.or(routeCondition).not().or(dnsCondition);
// @ts-expect-error The condition is route-only.
dns.rule(routeCondition, { action: "respond" });
// @ts-expect-error The condition is DNS-only.
route.rule(Rule.match({ preferred_by: preferred }), { action: "reject" });
// @ts-expect-error The condition is route-only.
dns.rule(Rule.match({ preferred_by: wg }), { action: "respond" });
// @ts-expect-error Actions are not match fields.
Rule.match({ domain: "example.test", action: "reject" });
// @ts-expect-error Conditions do not accept extra fields through variables either.
const _matchAction = Rule.match({ domain: "example.test", action: "reject" } as {
  domain: string;
  action: string;
});
// @ts-expect-error Route's route action requires an outbound.
route.rule({ action: "route" });
// @ts-expect-error DNS evaluate needs a DNS server.
dns.rule({ action: "evaluate", server: direct });
// @ts-expect-error A route action cannot contain DNS settings.
route.rule({ action: "reject", race: true });
// @ts-expect-error A rule in the DNS list must have been made by dns.rule.
compile({ dns: { rules: [route.rule({ action: "reject" })] } });

const alice = user({
  name: "alice",
  credentials: {
    mixed: { password: "pw" },
    shadowsocks: { password: "pw" },
    socks: { password: "pw" },
    vless: { uuid: "uuid" },
  },
});
const ssm = inbound.shadowsocks({ tag: "ss", method: "aes-128-gcm", managed: true });
const staticSs = inbound
  .shadowsocks({ tag: "ss2", method: "aes-128-gcm", users: [alice] })
  .listen("127.0.0.1", { port: 1080 });
const single = inbound.shadowsocks({ tag: "single", method: "none" });
const vlessIn = inbound.vless({ tag: "vless-in", users: [alice] });
const socks = inbound.socks({ tag: "socks", users: [alice] });
inbound.mixed({ tag: "mixed", users: [alice] });
service
  .ssmApi({ servers: { "/": ssm, "/static": staticSs } })
  .tls({ side: "server", certificate_provider: provider });
dns.rule(socks.authUser(alice).or(staticSs.authUser(alice)), { action: "route", server: udp });
route.rule(vlessIn.authUser(alice), { action: "bypass", outbound: wg });
Rule.match({ auth_user: ["", "alice"] });
// @ts-expect-error Single-user Shadowsocks lacks the management capability.
service.ssmApi({ servers: { "/": single } });
// @ts-expect-error Managed mode is incompatible with static users.
inbound.shadowsocks({
  tag: "ss",
  method: "aes-128-gcm",
  managed: true,
  users: [alice],
});
// @ts-expect-error The none method is only for single-user mode.
inbound.shadowsocks({ tag: "ss", method: "none", users: [alice] });
// @ts-expect-error Credentials belong in user().
inbound.mixed({ tag: "mixed", users: [{ user: alice, password: "pw" }] });
// @ts-expect-error Credentials belong in user().
inbound.socks({ tag: "socks", users: [{ user: alice, password: "pw" }] });
// @ts-expect-error Credentials belong in user().
inbound.shadowsocks({ tag: "ss", method: "aes-128-gcm", users: [{ user: alice, password: "pw" }] });
// @ts-expect-error Credentials belong in user().
inbound.vless({ tag: "vless", users: [{ user: alice, uuid: "uuid" }] });
// @ts-expect-error A per-user VLESS credential is a UUID.
user({ name: "alice", credentials: { vless: { password: "secret" } } });
// @ts-expect-error SOCKS has no TLS method.
socks.tls(serverTls);
vless.tls({
  side: "client",
  server_name: "cover.example",
  // @ts-expect-error REALITY server credentials cannot be sent to a client profile.
  reality: { private_key: "key", short_id: "" },
});
const mixedTlsProfile = {
  side: "server",
  server_name: "cover.example",
  certificate_path: "cert.pem",
  key_path: "key.pem",
  reality: {
    private_key: "key",
    short_id: "",
    handshake: { server: "example.test", server_port: 443 },
  },
} as const;
// @ts-expect-error Certificate files cannot be mixed with REALITY.
vlessIn.tls(mixedTlsProfile);

const openconnect = endpoint.openconnect({ tag: "oc" }).tls({ insecure: false });
const openvpn = endpoint.openvpnClient({ tag: "ovpn" }).tls({ server_name: "vpn.example.test" });
const resolved = service.resolved({ tag: "resolved" }).listen({ reuse_addr: true });
const derp = service.derp({ verify_client_endpoint: [ts], stun: { detour: mixed } });
compile({
  endpoints: [openconnect, openvpn, ts],
  services: [resolved, derp],
  inbounds: [mixed.listen(undefined, { port: 0 })],
  dns: {
    servers: [
      dnsServer.openconnect({ tag: "oc-dns", endpoint: openconnect }),
      dnsServer.openvpn({ tag: "ovpn-dns", endpoint: openvpn }),
      dnsServer.resolved({ tag: "resolved-dns", service: resolved }),
    ],
    strategy: "ipv4_only",
  },
  route: {
    rules: [
      route.rule(Rule.match({ network: ["icmp"], ip_cidr: "192.0.2.0/24" }), {
        action: "reject",
        method: "reply",
      }),
      route.rule({ action: "route-options", override_address: "192.0.2.1", override_port: 0 }),
      route.rule({ action: "resolve", server: udp }),
    ],
  },
  ntp: { detour: direct, enabled: false },
  certificate: { store: "none", certificate: [] },
});
inbound.snell({ tag: "snell-v5", version: 5, obfs_mode: "http" });
inbound.snell({ tag: "snell-v6", version: 6, mode: "default" });
outbound.snell({ tag: "snell-v4", version: 4, reuse: true, obfs_host: "example.test" });
outbound.snell({ tag: "snell-v6", version: 6, mode: "default" });
service.usbipServer({ devices: [] });
service.usbipServer({ provider: "dynamic" });
// @ts-expect-error Snell requires an explicit version.
inbound.snell({ tag: "snell" });
// @ts-expect-error This version belongs to an outbound.
inbound.snell({ tag: "snell", version: 4 });
// @ts-expect-error Mode is a version 6 option, even when passed through a variable.
inbound.snell({ tag: "snell", version: 5, mode: "default" } as const);
// @ts-expect-error Obfuscation is a version 4 outbound option.
outbound.snell({ tag: "snell", version: 6, obfs_mode: "tls" });
// @ts-expect-error Dynamic USB/IP cannot specify devices.
service.usbipServer({ provider: "dynamic", devices: [] } as const);
// @ts-expect-error USB/IP provider values are schema discriminators.
service.usbipServer({ provider: "unknown" });
// @ts-expect-error Unknown type-specific fields are rejected.
endpoint.wireguard({ tag: "wg", address: [], private_key: "x", packet_size: 1420 });
// @ts-expect-error Shared Listen Fields belong to the listener's schema.
resolved.listen({ connect_timeout: "1s" });
// @ts-expect-error OpenVPN TLS options lack the enabled field.
openvpn.tls({ enabled: true });
// @ts-expect-error A DERP verification endpoint must be Tailscale.
service.derp({ verify_client_endpoint: [openconnect] });
// @ts-expect-error A nested listen detour requires an inbound, rather than an endpoint.
service.derp({ stun: { detour: ts } });
// @ts-expect-error OpenConnect DNS takes an OpenConnect endpoint.
dnsServer.openconnect({ tag: "bad", endpoint: openvpn });
// @ts-expect-error OpenVPN DNS takes a client endpoint.
dnsServer.openvpn({ tag: "bad", endpoint: endpoint.openvpnServer({ tag: "server" }) });
// @ts-expect-error Resolved DNS takes a tagged Resolved service.
dnsServer.resolved({ tag: "bad", service: service.resolved() });
// @ts-expect-error A nested dial detour requires an egress.
certificateProvider.acme({ tag: "bad", http_client: { detour: mixed } });
// @ts-expect-error ICMP is a route condition.
dns.rule(Rule.match({ network: "icmp" }), { action: "reject" });
// @ts-expect-error Without response matching, ip_cidr is a route condition.
dns.rule(Rule.match({ ip_cidr: "192.0.2.0/24" }), { action: "reject" });
// @ts-expect-error A DNS response condition cannot be applied to a route.
route.rule(Rule.match({ match_response: true, ip_cidr: "192.0.2.0/24" }), { action: "reject" });
// @ts-expect-error These match fields have disjoint scopes.
Rule.match({ query_type: "A", network: "icmp" });
// @ts-expect-error DNS reject has no ICMP reply method.
dns.rule({ action: "reject", method: "reply" });
// @ts-expect-error Route resolve uses a typed DNS server.
route.rule({ action: "resolve", server: direct });
// @ts-expect-error Destination overrides only apply to route actions.
dns.rule({ action: "route", server: udp, override_port: 0 });
// @ts-expect-error DNS settings are limited to the pinned schema.
compile({ dns: { bogus: false } });
// @ts-expect-error Interface-address map keys are limited to the schema's interface types.
Rule.match({ network_interface_address: { cable: "192.0.2.0/24" } });
// @ts-expect-error The OpenVPN server endpoint lacks preferred routes.
Rule.match({ preferred_by: endpoint.openvpnServer({ tag: "server" }) });

const profileAlice = user({ name: "alice", credentials: { vless: { uuid: "id" } } });
const profileConnect = { host: "example.test", port: 443 };
const profileServer = { tag: "in", listen: { port: 8443 } };
const grpc = proxyProfile.vless({
  connect: profileConnect,
  users: [profileAlice],
  transport: { type: "grpc", service_name: "proxy" },
});
const grpcInbound = grpc.server(profileServer);
compile({
  inbounds: [grpcInbound],
  outbounds: [grpc.client(profileAlice, { tag: "grpc" })],
  route: { rules: [route.rule(grpcInbound.authUser(profileAlice), { action: "reject" })] },
});

const managedProfile = proxyProfile.shadowsocks({
  connect: profileConnect,
  managed: true,
  method: "aes-128-gcm",
});
const ssmInbound = managedProfile.server({ tag: "managed" }).listen({ port: 8388 });
service.ssmApi({ servers: { "/": ssmInbound } });

// @ts-expect-error Inbound tags identify generated resources.
grpc.server();
// @ts-expect-error Outbound tags identify generated resources.
grpc.client(profileAlice, {});
// @ts-expect-error Version belongs to the profile.
grpc.server({ ...profileServer, version: 3 });
// @ts-expect-error The helper owns the selected UUID.
grpc.client(profileAlice, { tag: "client", options: { uuid: "other-id" } });
// @ts-expect-error The helper owns the shared service name.
grpc.client(profileAlice, { tag: "client", transport: { service_name: "other" } });
// @ts-expect-error A static profile always needs a User selection.
grpc.client({ tag: "client" });
// @ts-expect-error QUIC requires regular TLS.
proxyProfile.vmess({ connect: profileConnect, users: [profileAlice], transport: { type: "quic" } });
proxyProfile.shadowtls({
  version: 2,
  connect: profileConnect,
  serverName: "cover.test",
  handshake: { server: "cover.test", server_port: 443 },
  // @ts-expect-error ShadowTLS v2 uses a shared password.
  users: [profileAlice],
});
// @ts-expect-error Snell profile v5 selects the compatible client v4 automatically.
proxyProfile.snell({ connect: profileConnect, psk: "example-psk", version: 4 });
