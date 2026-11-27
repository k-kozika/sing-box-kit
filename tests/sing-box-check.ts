import { $ } from "bun";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  compile,
  dns,
  dnsServer,
  inbound,
  outbound,
  proxyProfile,
  route,
  Rule,
  service,
  user,
} from "../index";
import type { CompileInput } from "../index";
import pinned from "../schema/version.json";

const binary = process.env.SING_BOX ?? "sing-box";
const version = (await $`${binary} version`.quiet().text()).trim();
if (
  version.split("\n")[0] !== `sing-box version ${pinned.version}` ||
  !version.split("\n").includes(`Revision: ${pinned.revision}`)
) {
  throw new Error(`Expected sing-box ${pinned.version} at ${pinned.revision}. Got:\n${version}`);
}

const local = dnsServer.local({ tag: "local" });
const direct = outbound.direct({ tag: "direct" }).dial({ connect_timeout: "5s" });
const proxy = inbound.mixed({ tag: "mixed" }).listen("127.0.0.1", { port: 1080, reuse_addr: true });
const testAddress = Rule.match({ network: "icmp", ip_cidr: "192.0.2.0/24" });
const proxyTraffic = Rule.match({ inbound: proxy, domain_suffix: "example.test" });
const uuid = "00000000-0000-4000-8000-000000000001";
const transport = { type: "ws", path: "/proxy" } as const;

const configs: Record<string, ReturnType<typeof compile>> = {
  routing: compile({
    inbounds: [proxy],
    outbounds: [direct],
    dns: { servers: [local], final: local, strategy: "prefer_ipv4" },
    route: {
      final: direct,
      rules: [
        route.rule(testAddress, { action: "reject", method: "reply" }),
        route.rule(proxyTraffic, { action: "sniff", sniffer: "http" }),
        route.rule(proxyTraffic, { action: "resolve", server: local }),
        route.rule(proxyTraffic, { action: "route-options", override_address: "192.0.2.2" }),
        route.rule(proxyTraffic, { action: "route", outbound: direct, override_port: 8080 }),
      ],
    },
  }),
  vless: compile({
    inbounds: [
      inbound
        .vless({
          tag: "incoming",
          users: [user({ name: "fixture", credentials: { vless: { uuid } } })],
          transport,
          multiplex: { enabled: false },
        })
        .listen("127.0.0.1", { port: 8443 }),
    ],
    outbounds: [
      outbound
        .vless({
          tag: "outgoing",
          server: "192.0.2.1",
          server_port: 8443,
          uuid,
          transport,
          multiplex: { enabled: false },
        })
        .tls({ enabled: false }),
    ],
    dns: {
      servers: [local],
      rules: [
        dns.rule({ action: "evaluate", server: local }),
        dns.rule(Rule.match({ match_response: true, ip_cidr: "192.0.2.0/24" }), {
          action: "respond",
        }),
      ],
    },
  }),
};

const pem = await $`${binary} generate tls-keypair edge.example`.quiet().text();
const certificate = pem.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/)?.[0];
const key = pem.match(/-----BEGIN PRIVATE KEY-----[\s\S]+?-----END PRIVATE KEY-----/)?.[0];
if (!certificate || !key) throw new Error("Expected a TLS fixture certificate and private key");
const realityKeys = await $`${binary} generate reality-keypair`.quiet().text();
const privateKey = realityKeys.match(/^PrivateKey: (\S+)$/m)?.[1];
const publicKey = realityKeys.match(/^PublicKey: (\S+)$/m)?.[1];
if (!privateKey || !publicKey) throw new Error("Expected a REALITY fixture key pair");

const connect = { host: "192.0.2.1", port: 443 };
const tls = { mode: "tls", serverName: "edge.example" } as const;
const serverSettings = { tag: "in", listen: { address: "127.0.0.1", port: 8443 } };
const serverTls = { ...serverSettings, tls: { certificate, key } };
const clientSettings = { tag: "out" };
const clientTls = { ...clientSettings, tls: { certificate } };
const serverKey = Buffer.alloc(16, 1).toString("base64");
const password = "fixture-password";
const alice = user({
  name: "alice",
  credentials: {
    anytls: { password },
    http: { password },
    hysteria: { auth_str: password },
    hysteria2: { password },
    naive: { password },
    shadowsocks: { password: Buffer.alloc(16, 2).toString("base64") },
    shadowtls: { password },
    snell: { userkey: "fixture-user-key" },
    socks: { password },
    trojan: { password },
    tuic: { uuid, password },
    vless: { uuid },
    vmess: { uuid, alter_id: 0 },
  },
});
const shared = { connect, users: [alice] } as const;
const secure = { ...shared, tls };

function checkPair(
  name: string,
  incoming: NonNullable<CompileInput["inbounds"]>[number],
  outgoing: NonNullable<CompileInput["outbounds"]>[number],
  services?: CompileInput["services"],
) {
  configs[`${name}-server`] = compile({ inbounds: [incoming], services });
  configs[`${name}-client`] = compile({ outbounds: [outgoing] });
}

const anytls = proxyProfile.anytls(secure);
checkPair("anytls", anytls.server(serverTls), anytls.client(alice, clientTls));
const http = proxyProfile.http(shared);
checkPair("http", http.server(serverSettings), http.client(alice, clientSettings));
const bandwidth = { options: { up_mbps: 10, down_mbps: 10 } };
const hysteria = proxyProfile.hysteria(secure);
checkPair(
  "hysteria",
  hysteria.server({ ...serverTls, ...bandwidth }),
  hysteria.client(alice, { ...clientTls, ...bandwidth }),
);
const hysteria2 = proxyProfile.hysteria2(secure);
checkPair("hysteria2", hysteria2.server(serverTls), hysteria2.client(alice, clientTls));
const hopping = proxyProfile.hysteria2({
  ...secure,
  connect: { host: connect.host, ports: ["443:444", "8443:8443"] },
});
checkPair("hysteria2-port-hopping", hopping.server(serverTls), hopping.client(alice, clientTls));
const realm = proxyProfile.hysteria2({
  users: [alice],
  tls,
  realm: {
    server_url: "https://realm.example",
    realm_id: "edge",
    token: password,
    stun_servers: ["192.0.2.53"],
  },
});
checkPair("hysteria2-realm", realm.server(serverTls), realm.client(alice, clientTls));
const naive = proxyProfile.naive(secure);
checkPair("naive", naive.server(serverTls), naive.client(alice, clientTls));
const ssSingle = proxyProfile.shadowsocks({ connect, method: "aes-128-gcm", password });
checkPair(
  "shadowsocks-single",
  ssSingle.server({ tag: "in" }).listen("127.0.0.1", { port: 8443 }),
  ssSingle.client(clientSettings),
);
const ssStatic = proxyProfile.shadowsocks({
  ...shared,
  method: "2022-blake3-aes-128-gcm",
  serverKey,
});
checkPair(
  "shadowsocks-static",
  ssStatic.server(serverSettings),
  ssStatic.client(alice, clientSettings),
);
const ssManaged = proxyProfile.shadowsocks({
  connect,
  method: "2022-blake3-aes-128-gcm",
  serverKey,
  managed: true,
});
const managedInbound = ssManaged.server(serverSettings);
checkPair("shadowsocks-managed", managedInbound, ssManaged.client(alice, clientSettings), [
  service.ssmApi({ servers: { "/": managedInbound } }).listen("127.0.0.1", { port: 8080 }),
]);
const shadowTls = {
  connect,
  handshake: { server: "192.0.2.2", server_port: 443 },
  serverName: "edge.example",
};
const shadow1 = proxyProfile.shadowtls({ ...shadowTls, version: 1 });
checkPair("shadowtls-v1", shadow1.server(serverSettings), shadow1.client(clientTls));
const shadow2 = proxyProfile.shadowtls({ ...shadowTls, version: 2, password });
checkPair("shadowtls-v2", shadow2.server(serverSettings), shadow2.client(clientTls));
const shadow3 = proxyProfile.shadowtls({ ...shadowTls, users: [alice] });
checkPair("shadowtls-v3", shadow3.server(serverSettings), shadow3.client(alice, clientTls));
for (const version of [5, 6] as const) {
  const snell = proxyProfile.snell({ ...shared, psk: password, version });
  checkPair(`snell-v${version}`, snell.server(serverSettings), snell.client(alice, clientSettings));
}
const socksUser = user({ name: "alice", credentials: { socks: { password: "" } } });
for (const version of ["4", "4a", "5"] as const) {
  const selected = version === "5" ? alice : socksUser;
  const socks = proxyProfile.socks({ connect, users: [selected], version });
  checkPair(
    `socks-v${version}`,
    socks.server(serverSettings),
    socks.client(selected, clientSettings),
  );
}
const trojan = proxyProfile.trojan(secure);
checkPair("trojan", trojan.server(serverTls), trojan.client(alice, clientTls));
const tuic = proxyProfile.tuic(secure);
checkPair("tuic", tuic.server(serverTls), tuic.client(alice, clientTls));
for (const transport of [
  { type: "tcp" },
  { type: "http", host: "edge.example", path: "/proxy" },
  { type: "ws", path: "/proxy" },
  { type: "grpc", service_name: "proxy" },
  { type: "httpupgrade", host: "edge.example", path: "/proxy" },
  { type: "quic" },
] as const) {
  for (const kind of ["vmess", "vless"] as const) {
    const profile = proxyProfile[kind]({ ...secure, transport });
    checkPair(
      `${kind}-${transport.type}`,
      profile.server(serverTls),
      profile.client(alice, clientTls),
    );
  }
}
const reality = await proxyProfile.vless({
  ...shared,
  tls: {
    mode: "reality",
    serverName: "edge.example",
    handshake: { host: "192.0.2.2", port: 443 },
    keyPair: { privateKey, publicKey },
    shortId: "1122",
  },
});
checkPair("vless-reality", reality.server(serverSettings), reality.client(alice, clientSettings));

const directory = await mkdtemp(join(tmpdir(), "sing-box-kit-check-"));
try {
  for (const [name, config] of Object.entries(configs)) {
    const path = join(directory, `${name}.json`);
    await Bun.write(path, JSON.stringify(config));
    await $`${binary} check -c ${path}`;
    console.log(`sing-box ${pinned.version} accepted ${name}`);
  }
} finally {
  await rm(directory, { recursive: true, force: true });
}
