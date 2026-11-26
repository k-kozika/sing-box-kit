import { describe, expect, test } from "bun:test";
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
  ruleSet,
  service,
  user,
  validateConfig,
} from "../index";
import type { CompileInput, DnsRuleAction, MatchFields, RouteRuleAction } from "../index";
import { createResource, resourceData } from "../src/resource";
import type { DnsServer, Resource } from "../src/resource";
import type { Fields } from "../src/type-utils";
import type { Dial, HttpClientInput, InboundListener, RealityServerTls } from "../src/settings";

const address = "127.0.0.1";
const uuid = "7d3b1a30-35ce-48f3-8846-0dbcba70b0d1";
const serverTls = { side: "server", certificate_path: "server.pem", key_path: "key.pem" } as const;
const clientTls = { side: "client", certificate_path: "ca.pem" } as const;
const direct = (tag = "egress") => outbound.direct({ tag }).dial({ connect_timeout: "5s" });
const proxy = (tag = "proxy") =>
  outbound.vless({ tag, server: "proxy.example", server_port: 443, uuid });
const udp = (tag = "resolver") => dnsServer.udp({ tag, server: "192.0.2.53" });
const doh = (tag = "https", server = "192.0.2.54") =>
  dnsServer.https({ tag, server, path: "/dns-query" });

describe("pinned schema and Phase 1", () => {
  test("validates raw input without mutating it, coercing it, or requiring registered tags", () => {
    const input = Object.freeze({
      outbounds: Object.freeze([Object.freeze({ type: "vless", detour: "unregistered" })]),
      route: Object.freeze({
        rules: Object.freeze([Object.freeze({ action: "route", outbound: "any" })]),
      }),
      http_clients: Object.freeze([
        Object.freeze({ headers: Object.freeze({ arbitrary: ["a", "b"] }) }),
      ]),
    });
    const before = JSON.stringify(input);
    expect(Object.is(validateConfig(input), input)).toBe(true);
    expect(JSON.stringify(input)).toBe(before);
    expect(() =>
      validateConfig({ route: { rules: [{ action: "reject", unknown: true }] } }),
    ).toThrow();
    expect(() => validateConfig({ inbounds: [{ type: "mixed", listen_port: "9090" }] })).toThrow();
    expect(() =>
      validateConfig({ outbounds: [{ type: "direct", connect_timeout: "5 seconds" }] }),
    ).toThrow();
    expect(compile({})).toEqual({});
  });

  test("assembles the dashboard example and copies log and experimental settings", () => {
    const egress = direct("dashboard-egress");
    const client = httpClient({ tag: "dashboard-client" }).dial({ detour: egress });
    const admin = service
      .api({ tag: "admin", secret: "test", dashboard: { enabled: true, http_client: client } })
      .listen(address, { port: 9090 })
      .tls(serverTls);
    const log = { level: "debug" } as const;
    const experimental = { cache_file: { enabled: true } };
    const compiled = compile({
      outbounds: [egress],
      http_clients: [client],
      services: [admin],
      log,
      experimental,
    });
    expect(compiled).toEqual({
      log: { level: "debug" },
      experimental: { cache_file: { enabled: true } },
      outbounds: [{ type: "direct", tag: "dashboard-egress", connect_timeout: "5s" }],
      http_clients: [{ tag: "dashboard-client", detour: "dashboard-egress" }],
      services: [
        {
          type: "api",
          tag: "admin",
          secret: "test",
          listen: address,
          listen_port: 9090,
          dashboard: { enabled: true, http_client: "dashboard-client" },
          tls: { enabled: true, certificate_path: "server.pem", key_path: "key.pem" },
        },
      ],
    });
    experimental.cache_file.enabled = false;
    expect(compiled.experimental?.cache_file?.enabled).toBe(true);
    expect(compiled.log).not.toBe(log);
  });

  test("keeps every dashboard form and HTTP client order and omission", () => {
    const services = [
      service.api({ dashboard: true }),
      service.api({ dashboard: false }),
      service.api({ dashboard: "/dashboard" }),
      service.api({ dashboard: { enabled: true } }),
      service.api(),
    ];
    expect(compile({ services })).toEqual({
      services: [
        { type: "api", dashboard: true },
        { type: "api", dashboard: false },
        { type: "api", dashboard: "/dashboard" },
        { type: "api", dashboard: { enabled: true } },
        { type: "api" },
      ],
    });
    expect(compile({ http_clients: [] })).toEqual({ http_clients: [] });
    expect(
      compile({ http_clients: [httpClient({ tag: "b" }), httpClient({ tag: "a" })] }).http_clients,
    ).toEqual([{ tag: "b" }, { tag: "a" }]);
    expect(compile({ http_clients: [httpClient({ tag: "default" })], route: {} }).route).toEqual(
      {},
    );
  });

  test("keeps optional TLS client verification name and trust settings independent", () => {
    const plain = { side: "client" } as const;
    expect(
      compile({
        outbounds: [proxy().tls(plain), proxy("with-ca").tls(clientTls)],
        http_clients: [
          httpClient({ tag: "default" }).tls(plain),
          httpClient({ tag: "ca" }).tls(clientTls),
        ],
      }),
    ).toMatchObject({
      outbounds: [
        { tls: { enabled: true } },
        { tls: { enabled: true, certificate_path: "ca.pem" } },
      ],
      http_clients: [
        { tls: { enabled: true } },
        { tls: { enabled: true, certificate_path: "ca.pem" } },
      ],
    });
    expect(compile({ outbounds: [proxy().tls(plain)] }).outbounds?.[0]).toHaveProperty("tls", {
      enabled: true,
    });
    expect(() =>
      service
        .api()
        .tls({ side: "server", certificate_path: "cert" } as unknown as typeof serverTls),
    ).toThrow("key_path");
    expect(() => inbound.mixed({ tag: "m" }).tls(clientTls as unknown as typeof serverTls)).toThrow(
      "tls.side",
    );
  });

  test("builds immutable, independent values and rejects duplicate groups and extra keys", () => {
    const base = inbound.mixed({ tag: "mixed" });
    const a = base.listen(address, { port: 1080 }).tls(serverTls);
    const b = base.tls(serverTls).listen(address, { port: 1080 });
    expect(a).not.toBe(b);
    expect(Object.isFrozen(a)).toBe(true);
    expect(JSON.stringify(compile({ inbounds: [a] }))).toBe(
      JSON.stringify(compile({ inbounds: [b] })),
    );
    expect(compile({ inbounds: [base] }).inbounds).toEqual([{ type: "mixed", tag: "mixed" }]);
    expect(() => a.listen(address, { port: 5500 })).toThrow("settings group already applied");
    expect(() => a.tls(serverTls)).toThrow("settings group already applied");
    expect(() => direct().dial({})).toThrow("settings group already applied");
    const bad = { tag: "mixed", listen_port: 123 };
    expect(() => inbound.mixed(bad)).toThrow("listen_port");
    const badDial = { detour: proxy(), connect_timeout: "5s" };
    expect(() => outbound.direct({ tag: "bad" }).dial(badDial)).toThrow("detour");
  });

  test("rejects empty tags and catches collisions with implicit service tags", () => {
    expect(() => outbound.direct({ tag: "" })).toThrow("tag");
    expect(() => httpClient({ tag: "" })).toThrow("tag");
    expect(() => service.api({ tag: "" })).toThrow("tag");
    expect(() => compile({ services: [service.api(), service.api({ tag: "0" })] })).toThrow(
      /services\[1\]\.tag.*duplicate.*"0"/,
    );
    expect(() => compile({ services: [service.api({ tag: "1" }), service.api()] })).toThrow(
      /services\[1\]\.tag.*duplicate.*"1"/,
    );
  });

  test("requires registration of the actual final value and its capability", () => {
    const egress = direct();
    const client = httpClient({ tag: "client" }).dial({ detour: egress });
    expect(() => compile({ http_clients: [client] })).toThrow(
      /http_clients\[0\]\.detour.*unregistered/,
    );
    expect(() => compile({ http_clients: [client], outbounds: [direct()] })).toThrow(
      "unregistered",
    );
    const initial = outbound.direct({ tag: "out" });
    const final = initial.dial({ connect_timeout: "5s" });
    const old = proxy().dial({ detour: initial });
    expect(() => compile({ outbounds: [old, final] })).toThrow(
      /outbounds\[0\]\.detour.*unregistered/,
    );
    const target = inbound.mixed({ tag: "bad-target" });
    const wrong = httpClient({ tag: "wrong" }).dial({ detour: target as unknown as typeof egress });
    expect(() => compile({ http_clients: [wrong], inbounds: [target] })).toThrow(
      /http_clients\[0\]\.detour.*egress.*"bad-target"/,
    );
    const api = service.api({ dashboard: { http_client: client } });
    expect(() => compile({ services: [api], outbounds: [egress] })).toThrow(
      "services[0].dashboard.http_client",
    );
  });

  test("supports inline HTTP settings and untagged builders", () => {
    const egress = direct();
    const inline = httpClient().dial({ detour: egress }).tls(clientTls);
    const raw = {
      version: 2,
      detour: egress,
      tls: { enabled: true, server_name: "name.example" },
      stream_receive_window: "32KiB",
      headers: { "x-test": ["one"] },
    } as const;
    expect(
      compile({
        outbounds: [egress],
        services: [
          service.api({ dashboard: { http_client: inline } }),
          service.api({ dashboard: { http_client: raw } }),
        ],
      }).services,
    ).toEqual([
      {
        type: "api",
        dashboard: {
          http_client: { detour: "egress", tls: { enabled: true, certificate_path: "ca.pem" } },
        },
      },
      {
        type: "api",
        dashboard: { http_client: { ...raw, headers: { "x-test": ["one"] }, detour: "egress" } },
      },
    ]);
    for (const http_client of [inline, raw]) {
      expect(() => compile({ services: [service.api({ dashboard: { http_client } })] })).toThrow(
        "services[0].dashboard.http_client.detour",
      );
    }
    expect(() => compile({ http_clients: [inline] } as unknown as CompileInput)).toThrow(
      "http_clients[0].tag",
    );
    expect(() =>
      service.api({
        dashboard: { http_client: { version: 2, tag: "x" } as unknown as HttpClientInput },
      }),
    ).toThrow("http_client.tag");
    expect(() =>
      service.api({ dashboard: { http_client: { detour: "raw" } as unknown as HttpClientInput } }),
    ).toThrow("http_client.detour");
  });

  test("detects effectively empty direct detours for VLESS, HTTP clients, and DoH", () => {
    const base = outbound.direct({ tag: "egress" });
    function inputs(egress: typeof base): CompileInput[] {
      return [
        { outbounds: [egress, proxy().dial({ detour: egress })] },
        {
          outbounds: [egress],
          http_clients: [httpClient({ tag: "client" }).dial({ detour: egress })],
        },
        {
          outbounds: [egress],
          services: [
            service.api({ dashboard: { http_client: httpClient().dial({ detour: egress }) } }),
          ],
        },
        {
          outbounds: [egress],
          services: [service.api({ dashboard: { http_client: { detour: egress } } })],
        },
        { outbounds: [egress], dns: { servers: [doh().dial({ detour: egress })] } },
      ];
    }
    for (const egress of [
      base,
      base.dial({}),
      base.dial({ connect_timeout: "0" }),
      base.dial({ connect_timeout: "0s" }),
      base.dial({ connect_timeout: "-0h0.0s" }),
    ]) {
      for (const input of inputs(egress))
        expect(() => compile(input)).toThrow(/detour.*empty direct/);
    }
    for (const input of inputs(base.dial({ connect_timeout: "5s" })))
      expect(() => compile(input)).not.toThrow();
    expect(() => base.dial({ connect_timeout: "five seconds" })).toThrow("connect_timeout");
    expect(() => proxy().dial({ detour: direct(), connect_timeout: "3s" })).toThrow(
      "connect_timeout",
    );
    expect(() => proxy().dial({ detour: direct(), connect_timeout: "0s" })).not.toThrow();
  });
});

describe("Phase 2 resources and references", () => {
  test("assembles every resource family in its registration list", () => {
    const wireguard = endpoint.wireguard({
      tag: "wg",
      address: ["192.0.2.3/32"],
      private_key: "test",
    });
    const tail = endpoint.tailscale({ tag: "tail", accept_routes: true, listen_port: 41641 });
    const provider = certificateProvider.tailscale({ tag: "provider", endpoint: tail });
    const named = networkNamespace.default({ tag: "named", path: "/run/netns/network" });
    const ns = networkNamespace.unshare({ tag: "ns", pid_file: "netns.pid" });
    const egress = outbound.direct({ tag: "egress" }).dial({ netns: ns });
    const local = dnsServer.tailscale({ tag: "tdns", endpoint: tail, accept_search_domain: true });
    const classic = udp();
    const tcp = dnsServer.tcp({ tag: "tcp", server: "192.0.2.55", server_port: 5353 });
    const tls = dnsServer
      .tls({ tag: "dot", server: "resolver.example" })
      .dial({ domain_resolver: classic });
    const https = doh()
      .dial({ domain_resolver: { server: classic, timeout: "2s" } })
      .tls(clientTls);
    const select = outbound.selector({
      tag: "select",
      outbounds: [wireguard, egress],
      default: egress,
    });
    const test = outbound.urltest({ tag: "test", outbounds: [egress, wireguard], interval: "3m" });
    const receiving = inbound.mixed({ tag: "receiving" });
    const listener = inbound
      .mixed({ tag: "listener" })
      .listen(address, { port: 1080, netns: named, detour: receiving });
    const client = httpClient({ tag: "client" }).dial({ netns: "/run/netns/os" });
    const admin = service
      .api()
      .listen(address, { port: 9090, netns: "os" })
      .tls({ side: "server", certificate_provider: provider });

    expect(
      compile({
        inbounds: [receiving, listener],
        outbounds: [egress, select, test],
        endpoints: [wireguard, tail],
        certificate_providers: [provider],
        network_namespaces: [named, ns],
        services: [admin],
        http_clients: [client],
        dns: { servers: [classic, tcp, tls, https, local], final: local },
        route: {
          final: select,
          default_domain_resolver: { server: classic, rewrite_ttl: 0 },
          default_http_client: client,
        },
      }),
    ).toEqual({
      inbounds: [
        { type: "mixed", tag: "receiving" },
        {
          type: "mixed",
          tag: "listener",
          listen: address,
          listen_port: 1080,
          netns: "named",
          detour: "receiving",
        },
      ],
      outbounds: [
        { type: "direct", tag: "egress", netns: "ns" },
        { type: "selector", tag: "select", outbounds: ["wg", "egress"], default: "egress" },
        { type: "urltest", tag: "test", outbounds: ["egress", "wg"], interval: "3m" },
      ],
      endpoints: [
        { type: "wireguard", tag: "wg", address: ["192.0.2.3/32"], private_key: "test" },
        { type: "tailscale", tag: "tail", accept_routes: true, listen_port: 41641 },
      ],
      certificate_providers: [{ type: "tailscale", tag: "provider", endpoint: "tail" }],
      network_namespaces: [
        { type: "default", tag: "named", path: "/run/netns/network" },
        { type: "unshare", tag: "ns", pid_file: "netns.pid" },
      ],
      services: [
        {
          type: "api",
          listen: address,
          listen_port: 9090,
          netns: "os",
          tls: { enabled: true, certificate_provider: "provider" },
        },
      ],
      http_clients: [{ tag: "client", netns: "/run/netns/os" }],
      dns: {
        servers: [
          { type: "udp", tag: "resolver", server: "192.0.2.53" },
          { type: "tcp", tag: "tcp", server: "192.0.2.55", server_port: 5353 },
          { type: "tls", tag: "dot", server: "resolver.example", domain_resolver: "resolver" },
          {
            type: "https",
            tag: "https",
            server: "192.0.2.54",
            path: "/dns-query",
            domain_resolver: { server: "resolver", timeout: "2s" },
            tls: { enabled: true, certificate_path: "ca.pem" },
          },
          { type: "tailscale", tag: "tdns", endpoint: "tail", accept_search_domain: true },
        ],
        final: "tdns",
      },
      route: {
        final: "select",
        default_domain_resolver: { server: "resolver", rewrite_ttl: 0 },
        default_http_client: "client",
      },
    });
    expect(
      compile({ route: { default_domain_resolver: classic }, dns: { servers: [classic] } }).route,
    ).toEqual({ default_domain_resolver: "resolver" });
    expect(() =>
      compile({ route: { default_http_client: httpClient() } } as unknown as CompileInput),
    ).toThrow("route.default_http_client");
    expect(() => compile({ endpoints: [tail], services: [admin] })).toThrow(
      "services[0].tls.certificate_provider",
    );
    const bothTls = { ...serverTls, certificate_provider: provider };
    expect(() => service.api().tls(bothTls as unknown as typeof serverTls)).toThrow(
      "certificate_path",
    );
  });

  test("treats endpoint ingress and egress capabilities independently", () => {
    const tail = endpoint.tailscale({ tag: "shared" });
    const wireguard = endpoint.wireguard({
      tag: "wg",
      address: "192.0.2.1/32",
      private_key: "test",
    });
    const mixed = inbound.mixed({ tag: "shared" });
    const egress = proxy().dial({ detour: tail });
    const second = httpClient({ tag: "wg-client" }).dial({ detour: wireguard });
    const listener = inbound.mixed({ tag: "from" }).listen(address, { port: 1080, detour: mixed });
    expect(
      compile({
        inbounds: [mixed, listener],
        endpoints: [tail, wireguard],
        outbounds: [egress],
        http_clients: [second],
        route: {
          final: tail,
          rules: [route.rule(Rule.match({ inbound: wireguard }), { action: "reject" })],
        },
      }),
    ).toMatchObject({
      inbounds: [{ tag: "shared" }, { detour: "shared" }],
      outbounds: [{ detour: "shared" }],
      http_clients: [{ detour: "wg" }],
      route: { final: "shared", rules: [{ inbound: "wg" }] },
    });
    for (const detour of [tail, wireguard]) {
      const bad = inbound
        .mixed({ tag: "from" })
        .listen(address, { port: 1080, detour } as unknown as InboundListener);
      expect(() => compile({ inbounds: [bad, mixed], endpoints: [tail, wireguard] })).toThrow(
        "inbounds[0].detour",
      );
    }
    for (const inbound of [mixed, tail]) {
      const rule = route.rule(Rule.match({ inbound }), { action: "reject" });
      expect(() =>
        compile({ inbounds: [mixed], endpoints: [tail], route: { rules: [rule] } }),
      ).toThrow(/route\.rules\[0\]\.inbound.*ambiguous/);
    }
    expect(() => compile({ outbounds: [direct("shared")], endpoints: [tail] })).toThrow(
      "endpoints[0].tag",
    );
    const wrong = certificateProvider.tailscale({
      tag: "provider",
      endpoint: wireguard as unknown as typeof tail,
    });
    expect(() => compile({ certificate_providers: [wrong], endpoints: [wireguard] })).toThrow(
      "tailscale-endpoint",
    );
  });

  test("checks each registration scope, including all tags of a multitag rule-set", () => {
    const tail = endpoint.tailscale({ tag: "same" });
    const namespace = networkNamespace.unshare({ tag: "same" });
    const client = httpClient({ tag: "same" });
    const provider = certificateProvider.tailscale({ tag: "same", endpoint: tail });
    const mixed = inbound.mixed({ tag: "same" });
    const resolver = udp("same");
    const rule = ruleSet.local({ tag: ["first", "same"], path: "{tag}.json" });
    expect(() =>
      compile({
        inbounds: [mixed],
        endpoints: [tail],
        services: [service.api({ tag: "same" })],
        dns: { servers: [resolver] },
        route: { rule_set: [rule] },
        http_clients: [client],
        network_namespaces: [namespace],
        certificate_providers: [provider],
      }),
    ).not.toThrow();
    const cases: [CompileInput, string][] = [
      [{ inbounds: [mixed, mixed] }, "inbounds[1].tag"],
      [{ outbounds: [direct(), direct()] }, "outbounds[1].tag"],
      [{ endpoints: [tail, tail] }, "endpoints[1].tag"],
      [{ http_clients: [client, client] }, "http_clients[1].tag"],
      [{ network_namespaces: [namespace, namespace] }, "network_namespaces[1].tag"],
      [{ certificate_providers: [provider, provider] }, "certificate_providers[1].tag"],
      [{ dns: { servers: [resolver, resolver] } }, "dns.servers[1].tag"],
      [
        { route: { rule_set: [ruleSet.local({ tag: "same", path: "first.json" }), rule] } },
        "route.rule_set[1].tag[1]",
      ],
    ];
    for (const [input, path] of cases) expect(() => compile(input)).toThrow(path);
  });

  test("checks group candidates and remote DNS resolver requirements", () => {
    const egress = direct();
    const resolver = udp();
    expect(() => outbound.selector({ tag: "empty", outbounds: [] })).toThrow("outbounds");
    expect(() => outbound.urltest({ tag: "empty", outbounds: [] })).toThrow("outbounds");
    expect(() => outbound.selector({ tag: "duplicate", outbounds: [egress, direct()] })).toThrow(
      "outbounds[1]",
    );
    expect(() => outbound.urltest({ tag: "duplicate", outbounds: [egress, egress] })).toThrow(
      "outbounds[1]",
    );
    expect(() =>
      outbound.selector({ tag: "outside", outbounds: [egress], default: direct() }),
    ).toThrow("default");
    const invalid = doh("host", "dns.example");
    expect(() =>
      compile({
        dns: { servers: [invalid, resolver] },
        route: { default_domain_resolver: resolver },
      }),
    ).toThrow("dns.servers[0].domain_resolver");
    for (const dial of [
      { domain_resolver: resolver },
      { detour: egress },
      { domain_resolver: resolver, detour: egress },
    ]) {
      expect(() =>
        compile({ outbounds: [egress], dns: { servers: [invalid.dial(dial), resolver] } }),
      ).not.toThrow();
    }
    for (const value of [doh(), dnsServer.tls({ tag: "dot", server: "2001:db8::53" })]) {
      const without = compile({ dns: { servers: [value] } }).dns?.servers?.[0];
      expect(without).not.toHaveProperty("tls");
      expect(
        compile({ dns: { servers: [value.tls(clientTls)] } }).dns?.servers?.[0],
      ).toHaveProperty("tls", { certificate_path: "ca.pem", enabled: true });
    }
  });

  test("applies Dial Fields rules wherever a detour opens the connection", () => {
    const ns = networkNamespace.unshare({ tag: "ns" });
    const egress = outbound.direct({ tag: "egress" }).dial({ netns: ns });
    const detached = endpoint.wireguard({
      tag: "wg",
      address: "192.0.2.1/32",
      private_key: "test",
      listen_port: 5,
    });
    expect(() => detached.dial({ detour: egress })).toThrow("listen_port");
    for (const netns of [ns, "named"]) {
      expect(() => proxy().dial({ netns, detour: egress })).toThrow("netns");
      expect(() =>
        ruleSet.remote({
          tag: "remote",
          url: "https://example.test/a.json",
          http_client: { netns, detour: egress },
        }),
      ).toThrow("http_client.netns");
    }
    expect(() =>
      service.api({ dashboard: { http_client: { detour: egress, connect_timeout: "1s" } } }),
    ).toThrow("http_client.connect_timeout");
    expect(() =>
      compile({ outbounds: [egress, proxy().dial({ detour: egress, netns: "" })] }),
    ).toThrow("outbounds[0].netns");
    expect(
      compile({ outbounds: [egress, proxy().dial({ detour: egress })], network_namespaces: [ns] })
        .outbounds,
    ).toMatchObject([{ netns: "ns" }, { detour: "egress" }]);
  });

  test("shares namespace and resolver conversion between inline HTTP builders and objects", () => {
    const ns = networkNamespace.default({ tag: "ns", path: "/run/netns/test" });
    const server = udp();
    const settings = { netns: ns, domain_resolver: { server, rewrite_ttl: 0 } };
    for (const http_client of [httpClient().dial(settings), settings]) {
      const admin = service.api({ dashboard: { http_client } });
      expect(
        compile({ services: [admin], network_namespaces: [ns], dns: { servers: [server] } })
          .services,
      ).toEqual([
        {
          type: "api",
          dashboard: {
            http_client: { netns: "ns", domain_resolver: { server: "resolver", rewrite_ttl: 0 } },
          },
        },
      ]);
      expect(() => compile({ services: [admin], dns: { servers: [server] } })).toThrow(
        "services[0].dashboard.http_client.netns",
      );
    }
  });

  test("infers and preserves rule-set formats and expands each remote HTTP form", () => {
    const egress = direct();
    const registered = httpClient({ tag: "client" });
    const local = ruleSet.local({ tag: ["a", "b"], path: "/sets/{tag}.srs" });
    const remote = (tag: string, http_client: HttpClientInput) =>
      ruleSet.remote({ tag, url: "https://example.test/file.json?x=.srs#fragment", http_client });
    const tagged = remote("tagged", registered);
    const inline = remote("inline", httpClient().dial({ detour: egress }));
    const raw = remote("raw", { detour: egress, version: 3, tls: { enabled: true } });
    const multi = ruleSet.remote({
      tag: ["c", "d"],
      url: "https://example.test/{tag}",
      initial_path: "/sets/{tag}",
      format: "binary",
    });
    const headless = ruleSet.inline({ tag: "rules", rules: [{ domain: "example.test" }] });
    expect(
      compile({
        route: { rule_set: [local, tagged, inline, raw, multi, headless] },
        http_clients: [registered],
        outbounds: [egress],
      }).route?.rule_set,
    ).toEqual([
      { type: "local", tag: ["a", "b"], path: "/sets/{tag}.srs", format: "binary" },
      {
        type: "remote",
        tag: "tagged",
        url: "https://example.test/file.json?x=.srs#fragment",
        format: "source",
        http_client: "client",
      },
      {
        type: "remote",
        tag: "inline",
        url: "https://example.test/file.json?x=.srs#fragment",
        format: "source",
        http_client: { detour: "egress" },
      },
      {
        type: "remote",
        tag: "raw",
        url: "https://example.test/file.json?x=.srs#fragment",
        format: "source",
        http_client: { detour: "egress", version: 3, tls: { enabled: true } },
      },
      {
        type: "remote",
        tag: ["c", "d"],
        url: "https://example.test/{tag}",
        initial_path: "/sets/{tag}",
        format: "binary",
      },
      { type: "inline", tag: "rules", rules: [{ domain: "example.test" }] },
    ]);
    expect(() => compile({ route: { rule_set: [raw] } })).toThrow(
      "route.rule_set[0].http_client.detour",
    );
    expect(() => ruleSet.inline({ tag: "empty", rules: [] })).toThrow("rules");
    expect(() => ruleSet.local({ tag: "unknown", path: "/sets/file" })).toThrow("format");
    expect(() => ruleSet.local({ tag: ["a", "a"], path: "/sets/{tag}.srs" })).toThrow("tag[1]");
    expect(() => ruleSet.local({ tag: ["a", "b"], path: "file.json" })).toThrow("path");
    expect(() =>
      ruleSet.remote({ tag: ["a", "b"], url: "https://example.test/file.json" }),
    ).toThrow("url");
    expect(() =>
      ruleSet.remote({
        tag: ["a", "b"],
        url: "https://example.test/{tag}.json",
        initial_path: "initial",
      }),
    ).toThrow("initial_path");
  });

  test("validates Shadowsocks modes and SSM server capabilities and map keys", () => {
    const single = inbound.shadowsocks({ tag: "single", method: "none", users: [] });
    const multi = inbound.shadowsocks({
      tag: "multi",
      method: "aes-128-gcm",
      users: [{ name: "alice", password: "alice-pw" }],
    });
    const managed = inbound.shadowsocks({
      tag: "managed",
      method: "2022-blake3-aes-128-gcm",
      managed: true,
      password: "managed-pw",
    });
    const ssm = service
      .ssmApi({ servers: { "/": managed, "/ss": multi }, cache_path: "ssm.json" })
      .tls(serverTls);
    expect(compile({ inbounds: [single, multi, managed], services: [ssm] })).toEqual({
      inbounds: [
        { type: "shadowsocks", tag: "single", method: "none", users: [] },
        {
          type: "shadowsocks",
          tag: "multi",
          method: "aes-128-gcm",
          users: [{ name: "alice", password: "alice-pw" }],
        },
        {
          type: "shadowsocks",
          tag: "managed",
          method: "2022-blake3-aes-128-gcm",
          managed: true,
          password: "managed-pw",
        },
      ],
      services: [
        {
          type: "ssm-api",
          servers: { "/": "managed", "/ss": "multi" },
          cache_path: "ssm.json",
          tls: { enabled: true, certificate_path: "server.pem", key_path: "key.pem" },
        },
      ],
    });
    const unchecked = inbound.shadowsocks as unknown as (options: Fields) => typeof single;
    expect(() => unchecked({ tag: "x", method: "none", users: [{ name: "alice" }] })).toThrow(
      "method",
    );
    expect(() => unchecked({ tag: "x", method: "none", managed: true })).toThrow("method");
    expect(() =>
      unchecked({ tag: "x", method: "aes-128-gcm", managed: true, users: [{}] }),
    ).toThrow("users");
    expect(() => service.ssmApi({ servers: {} })).toThrow("servers");
    expect(() => service.ssmApi({ servers: { ss: managed } })).toThrow('servers["ss"]');
    const invalid = service.ssmApi({ servers: { "/": single as unknown as typeof managed } });
    expect(() => compile({ inbounds: [single], services: [invalid] })).toThrow(
      /servers\["\/"\].*ssm/,
    );
  });

  test("reports the reference that closes an internal dependency cycle", () => {
    function fixture<R extends Resource>(seed: R): [R, Fields] {
      const data = resourceData(seed)!;
      const fields = { ...data.fields };
      return [createResource<R>({ ...data, fields }), fields];
    }
    const [a, aFields] = fixture(outbound.selector({ tag: "a", outbounds: [direct()] }));
    const [b, bFields] = fixture(proxy("b").dial({ detour: direct() }));
    aFields.outbounds = [b];
    bFields.detour = a;
    expect(() => compile({ outbounds: [a, b] })).toThrow(/outbounds\[1\]\.detour.*cyclic/);

    const [first, firstFields] = fixture(udp("first").dial({ domain_resolver: udp() }));
    const [second, secondFields] = fixture(
      doh("second").dial({ domain_resolver: { server: udp() } }),
    );
    firstFields.domain_resolver = second;
    secondFields.domain_resolver = { server: first };
    expect(() => compile({ dns: { servers: [first, second] } })).toThrow(
      /dns\.servers\[1\]\.domain_resolver\.server.*cyclic/,
    );
  });
});

describe("Phase 2 logical rules", () => {
  test("preserves leaf semantics, grouping, ordering, and the top-level action and invert", () => {
    const out = direct();
    const resolver = udp();
    const a = Rule.match({ domain: "one.example", domain_suffix: "two.example" });
    const b = Rule.match({ port: 53 });
    const c = Rule.match({ domain_suffix: "three.example" });
    const grouped = a.or(b.not()).and(c).not();
    const leaf = { domain: "one.example", domain_suffix: "two.example" };
    const logical = {
      type: "logical" as const,
      mode: "and" as const,
      invert: true,
      rules: [
        {
          type: "logical" as const,
          mode: "or" as const,
          rules: [leaf, { port: 53, invert: true }],
        },
        { domain_suffix: "three.example" },
      ],
    };
    expect(
      compile({
        outbounds: [out],
        route: {
          rules: [
            route.rule(a, { action: "route", outbound: out }),
            route.rule(grouped, { action: "route", outbound: out }),
            route.rule(b.not().not(), { action: "hijack-dns" }),
            route.rule({ action: "reject" }),
          ],
        },
        dns: {
          servers: [resolver],
          rules: [
            dns.rule({ action: "route-options", disable_cache: true }),
            dns.rule(grouped, { action: "route", server: resolver }),
          ],
        },
      }),
    ).toEqual({
      outbounds: [{ type: "direct", tag: "egress", connect_timeout: "5s" }],
      route: {
        rules: [
          { ...leaf, action: "route", outbound: "egress" },
          { ...logical, action: "route", outbound: "egress" },
          { port: 53, action: "hijack-dns" },
          { action: "reject" },
        ],
      },
      dns: {
        servers: [{ type: "udp", tag: "resolver", server: "192.0.2.53" }],
        rules: [
          { action: "route-options", disable_cache: true },
          { ...logical, action: "route", server: "resolver" },
        ],
      },
    });
  });

  test("resolves single and array matches and identifies bad nested reference positions", () => {
    const mixed = inbound.mixed({ tag: "mixed" });
    const tail = endpoint.tailscale({ tag: "tail" });
    const preferred = dnsServer.tailscale({ tag: "local", endpoint: tail });
    const rawUdp = udp();
    const rawHttps = doh();
    const set = ruleSet.inline({ tag: "domains", rules: [{ domain_suffix: "example.test" }] });
    const routeCond = Rule.match({
      inbound: [mixed, tail],
      preferred_by: [tail],
      rule_set: set,
      client: "chrome",
    });
    const dnsCond = Rule.match({
      inbound: mixed,
      preferred_by: preferred,
      rule_set: [set],
      query_type: "A",
    });
    expect(
      compile({
        inbounds: [mixed],
        endpoints: [tail],
        route: { rule_set: [set], rules: [route.rule(routeCond, { action: "reject" })] },
        dns: {
          servers: [preferred],
          rules: [dns.rule(dnsCond, { action: "route", server: preferred })],
        },
      }),
    ).toMatchObject({
      route: {
        rules: [
          {
            inbound: ["mixed", "tail"],
            preferred_by: ["tail"],
            rule_set: "domains",
            client: "chrome",
          },
        ],
      },
      dns: {
        rules: [
          { inbound: "mixed", preferred_by: "local", rule_set: ["domains"], query_type: "A" },
        ],
      },
    });
    const nested = Rule.match({ port: 53 }).or(Rule.match({ preferred_by: tail }));
    expect(() => compile({ route: { rules: [route.rule(nested, { action: "reject" })] } })).toThrow(
      "route.rules[0].rules[1].preferred_by",
    );
    expect(() =>
      compile({
        inbounds: [mixed],
        route: { rule_set: [set], rules: [route.rule(routeCond, { action: "reject" })] },
      }),
    ).toThrow("route.rules[0].inbound[1]");
    for (const ordinary of [rawUdp, rawHttps]) {
      const invalid = Rule.match({ preferred_by: ordinary } as unknown as {
        preferred_by: typeof preferred;
      });
      expect(() =>
        compile({ dns: { servers: [ordinary], rules: [dns.rule(invalid, { action: "reject" })] } }),
      ).toThrow(/dns\.rules\[0\]\.preferred_by.*capability/);
    }
    expect(() => Rule.match({ preferred_by: [tail, preferred] } as unknown as MatchFields)).toThrow(
      "preferred_by",
    );
  });

  test("checks condition and action input keys and scopes at assembly", () => {
    const shared = Rule.match({ port: 53 });
    const routeOnly = Rule.match({ client: "chrome" });
    const dnsOnly = Rule.match({ query_type: "A" });
    const extraRoute = { action: "reject", domain_suffix: "example.test" } as const;
    const extraDns = { action: "reject", inbound: inbound.mixed({ tag: "mixed" }) } as const;
    const actionInMatch = { action: "reject", domain_suffix: "example.test" } as const;
    expect(() => route.rule(extraRoute)).toThrow("route.rule.domain_suffix");
    expect(() => dns.rule(shared, extraDns)).toThrow("dns.rule.inbound");
    expect(() => Rule.match(actionInMatch as MatchFields)).toThrow("match.action");
    expect(() => Rule.match({})).toThrow("condition has no active fields");
    expect(() => Rule.match({ domain: [], port: [] })).toThrow("condition has no active fields");
    expect(() => Rule.match({ match_response: false })).toThrow("condition has no active fields");
    expect(() => Rule.match({ match_response: "" })).toThrow("match_response");
    expect(() => Rule.match({ response_rcode: 0 } as unknown as MatchFields)).toThrow(
      "match_response",
    );
    expect(() => routeOnly.and(dnsOnly as unknown as typeof routeOnly)).toThrow("common scope");
    expect(() => route.rule(dnsOnly as unknown as typeof routeOnly, { action: "reject" })).toThrow(
      "scope",
    );
    expect(() => route.rule({ action: "evaluate" } as unknown as RouteRuleAction)).toThrow(
      "action",
    );
    expect(() => route.rule({ action: "route" } as RouteRuleAction)).toThrow("outbound");
    expect(() => dns.rule({ action: "evaluate" } as DnsRuleAction)).toThrow("server");
    expect(() =>
      dns.rule({ action: "reject", method: "reply" } as unknown as DnsRuleAction),
    ).toThrow("method");
    const target = direct();
    expect(() =>
      compile({ route: { rules: [route.rule({ action: "route", outbound: target })] } }),
    ).toThrow("route.rules[0].outbound");
  });

  test("emits bypass, reject, hijack-dns, route and predefined actions", () => {
    const egress = direct();
    const resolver = udp();
    expect(
      compile({
        outbounds: [egress],
        dns: {
          servers: [resolver],
          rules: [
            dns.rule({ action: "route", server: resolver, disable_optimistic_cache: true }),
            dns.rule({ action: "reject", method: "default", no_drop: true }),
            dns.rule({
              action: "predefined",
              rcode: "NOERROR",
              answer: "example.test. 60 IN A 192.0.2.10",
            }),
            dns.rule({ action: "predefined" }),
          ],
        },
        route: {
          rules: [
            route.rule({ action: "bypass" }),
            route.rule({ action: "bypass", outbound: egress }),
            route.rule({ action: "reject", method: "drop" }),
            route.rule({ action: "hijack-dns" }),
          ],
        },
      }),
    ).toMatchObject({
      route: {
        rules: [
          { action: "bypass" },
          { action: "bypass", outbound: "egress" },
          { action: "reject", method: "drop" },
          { action: "hijack-dns" },
        ],
      },
      dns: {
        rules: [
          { action: "route", server: "resolver", disable_optimistic_cache: true },
          { action: "reject", method: "default", no_drop: true },
          { action: "predefined", rcode: "NOERROR", answer: "example.test. 60 IN A 192.0.2.10" },
          { action: "predefined" },
        ],
      },
    });
    expect(() => route.rule({ action: "reject", method: "drop", no_drop: true })).toThrow(
      "no_drop",
    );
    expect(() => dns.rule({ action: "reject", method: "drop", no_drop: true })).toThrow("no_drop");
  });

  test("validates effective DNS options and preserves an explicit zero TTL", () => {
    for (const options of [
      {},
      { timeout: "0s" },
      { timeout: "-1s" },
      { disable_cache: false, disable_optimistic_cache: false, remove_client_subnet: false },
    ]) {
      expect(() => dns.rule({ action: "route-options", ...options })).toThrow(
        "effective DNS option",
      );
    }
    expect(() => dns.rule({ action: "route-options", client_subnet: "not-a-subnet" })).toThrow(
      "client_subnet",
    );
    expect(() =>
      dns.rule({
        action: "route-options",
        client_subnet: "192.0.2.0/24",
        remove_client_subnet: true,
      }),
    ).toThrow("client_subnet");
    expect(
      compile({
        dns: {
          rules: [
            dns.rule({ action: "route-options", rewrite_ttl: 0 }),
            dns.rule({ action: "route-options", timeout: "5s" }),
            dns.rule({ action: "route-options", client_subnet: "2001:db8::/32" }),
            dns.rule({ action: "route-options", remove_client_subnet: true }),
          ],
        },
      }).dns?.rules,
    ).toEqual([
      { action: "route-options", rewrite_ttl: 0 },
      { action: "route-options", timeout: "5s" },
      { action: "route-options", client_subnet: "2001:db8::/32" },
      { action: "route-options", remove_client_subnet: true },
    ]);
  });

  test("binds DNS responses to earlier named and untagged evaluations", () => {
    const server = udp();
    const domain = Rule.match({ domain_suffix: "example.test" });
    const evaluate = dns.rule(domain, { action: "evaluate", server, tag: "named" });
    const unnamed = dns.rule({ action: "evaluate", server, speculative: true });
    const matchNamed = Rule.match({ match_response: "named", response_rcode: 0 });
    const respond = dns.rule(matchNamed, { action: "respond", race: true });
    const logical = dns.rule(
      domain.and(Rule.match({ match_response: true, ip_accept_any: true })),
      { action: "respond" },
    );
    const withoutCondition = dns.rule({ action: "respond" });
    expect(
      compile({
        dns: { servers: [server], rules: [evaluate, respond, unnamed, logical, withoutCondition] },
      }).dns?.rules,
    ).toEqual([
      { domain_suffix: "example.test", action: "evaluate", server: "resolver", tag: "named" },
      { match_response: "named", response_rcode: 0, action: "respond", race: true },
      { action: "evaluate", server: "resolver", speculative: true },
      {
        type: "logical",
        mode: "and",
        rules: [{ domain_suffix: "example.test" }, { match_response: true, ip_accept_any: true }],
        action: "respond",
      },
      { action: "respond" },
    ]);
    expect(() => compile({ dns: { servers: [server], rules: [evaluate, evaluate] } })).toThrow(
      "dns.rules[1].tag",
    );
    expect(() => compile({ dns: { servers: [server], rules: [respond, evaluate] } })).toThrow(
      "dns.rules[0].match_response",
    );
    expect(() => compile({ dns: { rules: [respond] } })).toThrow("earlier named evaluate");
    expect(() => compile({ dns: { rules: [withoutCondition] } })).toThrow(
      "earlier untagged evaluate",
    );
    expect(() => compile({ dns: { servers: [server], rules: [evaluate, logical] } })).toThrow(
      "dns.rules[1].rules[1].match_response",
    );
    const invalid = dns.rule(domain.and(matchNamed), { action: "respond" });
    expect(() =>
      compile({ dns: { servers: [server], rules: [evaluate, unnamed, invalid] } }),
    ).toThrow("logical respond");
    expect(() => dns.rule({ action: "respond", race: true })).toThrow(
      "race requires active response matching",
    );
    expect(() =>
      dns.rule(matchNamed, { action: "route", server, race: true, speculative: true }),
    ).toThrow("race with speculative");
    const fake = createResource<DnsServer>({
      target: "dns.servers",
      kind: "fakeip",
      fields: { type: "fakeip", tag: "fake" },
      roles: ["dns-server"],
    });
    expect(() =>
      compile({
        dns: { servers: [fake], rules: [dns.rule({ action: "evaluate", server: fake })] },
      }),
    ).toThrow(/dns\.rules\[0\]\.server.*FakeIP/);
  });
});

describe("Phase 3 authenticated inbounds and REALITY", () => {
  test("matches one User across VLESS, Shadowsocks, SOCKS, and Mixed with separate credentials", () => {
    const alice = user({
      name: "alice",
      credentials: {
        vless: { uuid, flow: "xtls-rprx-vision" },
        shadowsocks: { password: "ss-pass" },
        socks: { password: "socks-pass" },
        mixed: { password: "mixed-pass" },
      },
    });
    const bob = user({ name: "bob", credentials: { socks: { password: "bob-pass" } } });
    const vless = inbound.vless({
      tag: "vless",
      users: [alice],
    });
    const shadow = inbound.shadowsocks({
      tag: "shadow",
      method: "aes-128-gcm",
      users: [alice, { name: "bob", password: "raw-ss" }],
    });
    const socks = inbound.socks({
      tag: "socks",
      users: [alice, bob],
    });
    const mixed = inbound.mixed({
      tag: "mixed",
      users: [{ username: "bob", password: "raw-mixed" }, alice],
    });
    const managed = inbound.shadowsocks({ tag: "managed", method: "aes-128-gcm", managed: true });
    const resolver = udp();
    const egress = direct();
    const ab = vless.authUser(alice).or(mixed.authUser(alice));
    const cd = socks.authUser(alice).or(shadow.authUser(alice));
    const condition = Rule.match({ domain_suffix: "example.test" }).and(ab.or(cd)).not();
    const result = compile({
      inbounds: [vless, shadow, socks, mixed, managed],
      outbounds: [egress],
      route: {
        rules: [
          route.rule(condition, { action: "route", outbound: egress }),
          route.rule(socks.authUser(alice).or(socks.authUser(bob)), { action: "reject" }),
          route.rule(Rule.match({ inbound: managed, auth_user: "alice" }), { action: "bypass" }),
          route.rule(Rule.match({ auth_user: ["alice", "bob"] }), { action: "reject" }),
          route.rule(Rule.match({ auth_user: "" }), { action: "reject" }),
        ],
      },
      dns: {
        servers: [resolver],
        rules: [dns.rule(condition, { action: "route", server: resolver })],
      },
    });
    expect(result.inbounds).toMatchObject([
      { tag: "vless", users: [{ name: "alice", uuid, flow: "xtls-rprx-vision" }] },
      {
        tag: "shadow",
        users: [
          { name: "alice", password: "ss-pass" },
          { name: "bob", password: "raw-ss" },
        ],
      },
      {
        tag: "socks",
        users: [
          { username: "alice", password: "socks-pass" },
          { username: "bob", password: "bob-pass" },
        ],
      },
      {
        tag: "mixed",
        users: [
          { username: "bob", password: "raw-mixed" },
          { username: "alice", password: "mixed-pass" },
        ],
      },
      { tag: "managed", managed: true },
    ]);
    const tree = {
      type: "logical" as const,
      mode: "and" as const,
      invert: true,
      rules: [
        { domain_suffix: "example.test" },
        {
          type: "logical" as const,
          mode: "or" as const,
          rules: [
            {
              type: "logical" as const,
              mode: "or" as const,
              rules: [
                { inbound: "vless", auth_user: "alice" },
                { inbound: "mixed", auth_user: "alice" },
              ],
            },
            {
              type: "logical" as const,
              mode: "or" as const,
              rules: [
                { inbound: "socks", auth_user: "alice" },
                { inbound: "shadow", auth_user: "alice" },
              ],
            },
          ],
        },
      ],
    };
    expect(result.route?.rules).toEqual([
      { ...tree, action: "route", outbound: "egress" },
      {
        type: "logical" as const,
        mode: "or" as const,
        rules: [
          { inbound: "socks", auth_user: "alice" },
          { inbound: "socks", auth_user: "bob" },
        ],
        action: "reject",
      },
      { inbound: "managed", auth_user: "alice", action: "bypass" },
      { auth_user: ["alice", "bob"], action: "reject" },
      { auth_user: "", action: "reject" },
    ]);
    expect(result.dns?.rules).toEqual([{ ...tree, action: "route", server: "resolver" }]);
  });

  test("preserves User identity and accepts raw entries in VMess inbounds", () => {
    const alice = user({ name: "alice", credentials: { vmess: { uuid, alter_id: 1 } } });
    const typed = inbound.vmess({ tag: "typed", users: [alice] });
    const raw = inbound.vmess({ tag: "raw", users: [{ name: "legacy", uuid }] });
    expect(
      compile({
        inbounds: [typed, raw],
        route: { rules: [route.rule(typed.authUser(alice), { action: "reject" })] },
      }),
    ).toMatchObject({
      inbounds: [
        { users: [{ name: "alice", uuid, alterId: 1 }] },
        { users: [{ name: "legacy", uuid }] },
      ],
      route: { rules: [{ inbound: "typed", auth_user: "alice" }] },
    });
  });

  test("rejects invalid protocol credentials when creating a User", () => {
    expect(() =>
      Reflect.apply(user, undefined, [{ name: "alice", credentials: { vless: { uuid: 1 } } }]),
    ).toThrow("user.credentials.vless.uuid");
  });

  test("checks User identity, name uniqueness, final registration, and mixed formats", () => {
    const alice = user({ name: "alice", credentials: { mixed: { password: "pw" } } });
    const empty = user({ name: "", credentials: { socks: { password: "empty" } } });
    const legacyEntry = { user: alice, password: "pw" };
    const mixed = inbound.mixed({ tag: "mixed", users: [alice] });
    expect(Object.isFrozen(alice)).toBe(true);
    expect(() => mixed.authUser(user({ name: "alice" }))).toThrow("authUser");
    expect(() => mixed.authUser(user({ name: "bob" }))).toThrow("authUser");
    expect(() => inbound.socks({ tag: "socks" }).authUser(alice)).toThrow("authUser");
    expect(() => inbound.socks({ tag: "socks", users: [empty] }).authUser(empty)).toThrow(
      "non-empty name",
    );
    expect(() =>
      inbound.mixed({ tag: "mixed", users: [alice, { username: "alice" }] }).authUser(alice),
    ).toThrow("unique non-empty name");
    expect(() => inbound.mixed({ tag: "mixed", users: [alice, alice] }).authUser(alice)).toThrow(
      "authUser",
    );
    for (const [factory, options, message] of [
      [inbound.mixed, { users: [legacyEntry] }, "users[0].user"],
      [inbound.shadowsocks, { method: "aes-128-gcm", users: [legacyEntry] }, "users[0].user"],
      [inbound.socks, { users: [legacyEntry] }, "expected a User"],
      [inbound.vless, { users: [{ user: alice, uuid }] }, "expected a User"],
    ] as const) {
      expect(() => Reflect.apply(factory, undefined, [{ tag: "legacy", ...options }])).toThrow(
        message,
      );
    }
    expect(() => inbound.socks({ tag: "missing", users: [alice] })).toThrow(
      "missing socks credentials",
    );
    const condition = mixed.authUser(alice);
    expect(() =>
      compile({
        inbounds: [mixed.listen(address, { port: 1080 })],
        route: { rules: [route.rule(condition, { action: "reject" })] },
      }),
    ).toThrow("route.rules[0].inbound");
  });

  test("snapshots nested arguments and preserves identities for referenced final values", () => {
    const egress = direct("first");
    const alternate = direct("second");
    const headers = { accept: ["application/json"] };
    const dial = { detour: egress };
    const http_client = { enabled: true, http_client: { headers, ...dial } };
    const admin = service.api({ dashboard: http_client });
    const client = httpClient({ tag: "client", headers }).dial(dial);
    const candidates = [egress];
    const select = outbound.selector({ tag: "select", outbounds: candidates });
    const domains = ["one.example"];
    const conditions = Rule.match({ domain: domains });
    const credentials = { mixed: { password: "original" } };
    const alice = user({ name: "alice", credentials });
    const members = [alice];
    const mixed = inbound.mixed({ tag: "mixed", users: members });
    const rule = route.rule(mixed.authUser(alice).and(conditions), {
      action: "route",
      outbound: select,
    });

    headers.accept[0] = "changed";
    dial.detour = alternate;
    http_client.http_client.detour = alternate;
    candidates[0] = alternate;
    domains[0] = "changed.example";
    credentials.mixed.password = "changed";
    members.length = 0;
    const input = {
      outbounds: [egress, select],
      inbounds: [mixed],
      http_clients: [client],
      services: [admin],
      route: { rules: [rule, route.rule(mixed.authUser(alice), { action: "reject" })] },
    };
    const output = compile(input);
    expect(output).toMatchObject({
      http_clients: [{ detour: "first", headers: { accept: ["application/json"] } }],
      services: [
        {
          dashboard: {
            http_client: { detour: "first", headers: { accept: ["application/json"] } },
          },
        },
      ],
      outbounds: [{ tag: "first" }, { outbounds: ["first"] }],
      inbounds: [{ users: [{ username: "alice", password: "original" }] }],
      route: {
        rules: [
          { rules: [{ inbound: "mixed", auth_user: "alice" }, { domain: ["one.example"] }] },
          { inbound: "mixed", auth_user: "alice" },
        ],
      },
    });
    output.http_clients![0]!.headers!.accept = "changed again";
    expect(compile(input).http_clients?.[0]?.headers?.accept).toEqual(["application/json"]);
  });

  test("emits REALITY server and client profiles and resolves handshake references", () => {
    const private_key = Buffer.alloc(32, 1).toString("base64url");
    const public_key = Buffer.alloc(32, 2).toString("base64url");
    const short_id = ["", "0A1234567890bCDE"];
    const egress = direct();
    const resolver = udp();
    const ns = networkNamespace.unshare({ tag: "ns" });
    const handshake = {
      server: "handshake.example",
      server_port: 9443,
      detour: egress,
      domain_resolver: { server: resolver, timeout: "1s" },
    };
    const vless = inbound.vless({ tag: "in", users: [] });
    const server = vless.tls({
      side: "server",
      server_name: "verify.example",
      reality: { private_key, short_id, handshake },
    });
    const client = proxy().tls({
      side: "client",
      server_name: "verify.example",
      reality: { public_key, short_id: "" },
    });
    short_id[0] = "99";
    handshake.server = "changed.example";
    const output = compile({
      inbounds: [server],
      outbounds: [client, egress],
      dns: { servers: [resolver] },
    });
    expect(output.inbounds).toEqual([
      {
        type: "vless",
        tag: "in",
        users: [],
        tls: {
          enabled: true,
          server_name: "verify.example",
          reality: {
            enabled: true,
            private_key,
            short_id: ["", "0A1234567890bCDE"],
            handshake: {
              server: "handshake.example",
              server_port: 9443,
              detour: "egress",
              domain_resolver: { server: "resolver", timeout: "1s" },
            },
          },
        },
      },
    ]);
    expect(output.outbounds?.[0]).toEqual({
      type: "vless",
      tag: "proxy",
      server: "proxy.example",
      server_port: 443,
      uuid,
      tls: {
        enabled: true,
        server_name: "verify.example",
        utls: { enabled: true },
        reality: {
          enabled: true,
          public_key,
          short_id: "",
        },
      },
    });
    expect(JSON.stringify(output.outbounds)).not.toContain(private_key);
    expect(() => compile({ inbounds: [server], dns: { servers: [resolver] } })).toThrow(
      "inbounds[0].tls.reality.handshake.detour",
    );
    expect(() => compile({ inbounds: [server], outbounds: [egress] })).toThrow(
      "inbounds[0].tls.reality.handshake.domain_resolver.server",
    );
    function withHandshake(dial: Dial) {
      return vless.tls({
        side: "server",
        server_name: "verify.example",
        reality: {
          private_key,
          short_id: "",
          handshake: { server: "192.0.2.99", server_port: 443, ...dial },
        },
      });
    }
    const withNs = withHandshake({ netns: ns, connect_timeout: "5s" });
    expect(compile({ inbounds: [withNs], network_namespaces: [ns] }).inbounds?.[0]).toMatchObject({
      tls: { reality: { short_id: "", handshake: { netns: "ns", connect_timeout: "5s" } } },
    });
    expect(() => withHandshake({ detour: egress, netns: ns })).toThrow("handshake.netns");
    expect(() => withHandshake({ detour: egress, connect_timeout: "5s" })).toThrow(
      "handshake.connect_timeout",
    );
  });

  test("validates REALITY encoding, TLS mode and conflicting fields without leaking credentials", () => {
    const valid = Buffer.alloc(32).toString("base64url");
    const vless = inbound.vless({ tag: "in", users: [] });
    const reality = {
      private_key: valid,
      short_id: "",
      handshake: { server: "192.0.2.99", server_port: 443 },
    };
    for (const private_key of [
      valid.slice(1),
      valid + "=",
      "+" + valid.slice(1),
      "secret-invalid-private",
    ]) {
      const call = () =>
        vless.tls({
          side: "server",
          server_name: "cover.example",
          reality: { ...reality, private_key },
        });
      expect(call).toThrow("private_key");
      try {
        call();
      } catch (error) {
        expect(String(error)).not.toContain(private_key);
      }
    }
    for (const short_id of ["A", "not-hex", "001122334455667788"]) {
      expect(() =>
        vless.tls({
          side: "server",
          server_name: "cover.example",
          reality: { ...reality, short_id },
        }),
      ).toThrow("short_id");
    }
    expect(() =>
      proxy().tls({
        side: "client",
        server_name: "cover.example",
        reality: { public_key: valid, short_id: "fF" },
      }),
    ).not.toThrow();
    expect(() =>
      proxy().tls({
        side: "client",
        server_name: "cover.example",
        reality: { public_key: "bad-key", short_id: "" },
      }),
    ).toThrow("public_key");
    const profile = { side: "server", server_name: "cover.example", reality } as const;
    expect(() =>
      inbound.mixed({ tag: "mixed" }).tls(profile as unknown as typeof serverTls),
    ).toThrow("unsupported TLS");
    const conflicting = { ...profile, certificate_path: "/secret/file", key_path: "/secret/key" };
    expect(() => vless.tls(conflicting as unknown as RealityServerTls)).toThrow("certificate_path");
    const provider = certificateProvider.tailscale({
      tag: "p",
      endpoint: endpoint.tailscale({ tag: "tail" }),
    });
    expect(() =>
      vless.tls({ ...profile, certificate_provider: provider } as unknown as RealityServerTls),
    ).toThrow("certificate_provider");
  });
});
