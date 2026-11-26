import { $ } from "bun";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { compile, dns, dnsServer, inbound, outbound, route, Rule, user } from "../index";
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

const configs = {
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
