import { describe, expect, test } from "bun:test";
import { rejects } from "node:assert/strict";
import { compile, inbound, outbound, proxyProfile, route, service, user } from "../index";

const connect = { host: "edge.example", port: 443 };
const server = { tag: "in", listen: { address: "127.0.0.1", port: 8443 } };
const client = { tag: "out" };
const uuid = "00000000-0000-4000-8000-000000000001";
const secondUuid = "00000000-0000-4000-8000-000000000002";

describe("proxy profiles", () => {
  test("rejects explicit Naive ALPN in factories and profiles", () => {
    const alice = user({ name: "alice", credentials: { naive: { password: "fixture" } } });
    const settings = { connect, users: [alice], tls: { mode: "tls" } } as const;
    const profile = proxyProfile.naive(settings);
    const alpn = ["h2"];

    expect(() => inbound.naive({ tag: "in" }).tls({ alpn } as never)).toThrow(
      "inbounds.naive.tls.alpn",
    );
    expect(() => outbound.naive({ tag: "out" }).tls({ alpn: [] } as never)).toThrow(
      "outbounds.naive.tls.alpn",
    );
    expect(() => proxyProfile.naive({ ...settings, tls: { mode: "tls", alpn } } as never)).toThrow(
      "proxyProfile.naive.tls.alpn",
    );
    expect(() =>
      profile.server({
        ...server,
        tls: { alpn, certificate_path: "cert.pem", key_path: "key.pem" },
      } as never),
    ).toThrow("proxyProfile.naive.server.tls.alpn");
    expect(() => profile.client(alice, { ...client, tls: { alpn } } as never)).toThrow(
      "proxyProfile.naive.client.tls.alpn",
    );
    expect(compile({ outbounds: [outbound.http({ tag: "http" }).tls({ alpn })] })).toMatchObject({
      outbounds: [{ tls: { alpn } }],
    });
  });

  test("shares transport and TLS name, keeps side settings independent and emits one user's credentials", () => {
    const credentials = { vless: { uuid } };
    const alice = user({ name: "alice", credentials });
    const bob = user({ name: "bob", credentials: { vless: { uuid: secondUuid } } });
    credentials.vless.uuid = secondUuid;
    const profile = proxyProfile.vless({
      users: [alice, bob],
      connect,
      tls: { mode: "tls", alpn: ["h2"] },
      transport: { type: "grpc", service_name: "proxy" },
    });
    const incoming = profile
      .server({
        tag: server.tag,
        tls: { certificate_path: "cert.pem", key_path: "key.pem" },
        transport: { idle_timeout: "2s" },
      })
      .listen(server.listen.address, { port: server.listen.port });
    const outgoing = profile.client(alice, {
      ...client,
      transport: { permit_without_stream: true },
    });
    const serverConfig = compile({
      inbounds: [incoming],
      route: { rules: [route.rule(incoming.authUser(bob), { action: "reject" })] },
    });
    expect(serverConfig).toMatchObject({
      inbounds: [
        {
          listen_port: 8443,
          users: [
            { name: "alice", uuid },
            { name: "bob", uuid: secondUuid },
          ],
          transport: { type: "grpc", service_name: "proxy", idle_timeout: "2s" },
          tls: { enabled: true, certificate_path: "cert.pem", key_path: "key.pem", alpn: ["h2"] },
        },
      ],
      route: { rules: [{ inbound: "in", auth_user: "bob", action: "reject" }] },
    });
    expect(compile({ outbounds: [outgoing] })).toEqual({
      outbounds: [
        {
          type: "vless",
          tag: "out",
          server: connect.host,
          server_port: 443,
          uuid,
          transport: { type: "grpc", service_name: "proxy", permit_without_stream: true },
          tls: { enabled: true, server_name: connect.host, alpn: ["h2"] },
        },
      ],
    });
    expect(JSON.stringify(alice)).toBe('{"name":"alice"}');
    expect(() => profile.client(user({ name: "alice" }), client)).toThrow("client.user");
  });

  test("selects a REALITY short ID and only emits the key for the requested side", async () => {
    const alice = user({ name: "alice", credentials: { vless: { uuid } } });
    const privateKey = "ERERERERERERERERERERERERERERERERERERERERERE";
    const publicKey = "e06Qm75__kTEZaIgA31gjuNYl9Me-XLwf3SJLLD3PxM";
    const tls = {
      mode: "reality",
      serverName: "cover.example",
      keyPair: { privateKey, publicKey },
      handshake: { host: "target.example", port: 443 },
      shortIds: ["0011", "aabb"],
    } as const;
    const profile = await proxyProfile.vless({ users: [alice], connect, tls });
    const serverConfig = compile({ inbounds: [profile.server(server)] });
    expect(serverConfig).toMatchObject({
      inbounds: [
        {
          tls: {
            server_name: "cover.example",
            reality: {
              enabled: true,
              private_key: privateKey,
              short_id: ["0011", "aabb"],
              handshake: { server: "target.example", server_port: 443 },
            },
          },
        },
      ],
    });
    const clientConfig = compile({
      outbounds: [profile.client(alice, { ...client, shortId: "aabb" })],
    });
    expect(clientConfig).toMatchObject({
      outbounds: [
        {
          tls: {
            server_name: "cover.example",
            utls: { enabled: true },
            reality: { enabled: true, public_key: publicKey, short_id: "aabb" },
          },
        },
      ],
    });
    expect(JSON.stringify(serverConfig)).not.toContain(publicKey);
    expect(JSON.stringify(clientConfig)).not.toContain(privateKey);
    expect(() => profile.client(alice, client)).toThrow("shortId");
    expect(() => profile.client(alice, { ...client, shortId: "ccdd" })).toThrow("shortId");
    await rejects(
      proxyProfile.vless({
        users: [alice],
        connect,
        tls: { ...tls, keyPair: { privateKey, publicKey: privateKey } },
      }),
      { message: "proxyProfile.vless.tls.keyPair.publicKey: does not match private key" },
    );
    await rejects(
      proxyProfile.vless({
        users: [alice],
        connect,
        tls: { ...tls, keyPair: { privateKey: `${privateKey}=`, publicKey } },
      }),
      {
        message:
          "proxyProfile.vless.tls.keyPair.privateKey: expected an unpadded 32-byte Base64url key",
      },
    );
    await rejects(
      proxyProfile.vless({
        users: [alice],
        connect,
        tls: { ...tls, keyPair: { privateKey, publicKey: `${publicKey.slice(0, -1)}N` } },
      }),
      {
        message:
          "proxyProfile.vless.tls.keyPair.publicKey: expected an unpadded 32-byte Base64url key",
      },
    );
    const single = await proxyProfile.vless({
      users: [alice],
      connect,
      tls: {
        mode: "reality",
        serverName: tls.serverName,
        keyPair: tls.keyPair,
        handshake: tls.handshake,
        shortId: "",
      },
    });
    expect(compile({ outbounds: [single.client(alice, client)] })).toMatchObject({
      outbounds: [{ tls: { reality: { short_id: "" } } }],
    });
  });

  test("maps protocol versions and preserves SOCKS4 username-only authentication", () => {
    const alice = user({ name: "alice", credentials: { socks: { password: "" } } });
    const socks = proxyProfile.socks({ connect, users: [alice], version: "4a" });
    expect(
      compile({
        inbounds: [socks.server(server)],
        outbounds: [socks.client(alice, client)],
      }),
    ).toEqual({
      inbounds: [
        {
          type: "socks",
          tag: "in",
          listen: "127.0.0.1",
          listen_port: 8443,
          users: [{ username: "alice", password: "" }],
        },
      ],
      outbounds: [
        {
          type: "socks",
          tag: "out",
          server: connect.host,
          server_port: 443,
          version: "4a",
          username: "alice",
        },
      ],
    });
    const snell = proxyProfile.snell({
      connect,
      version: 5,
      psk: "test-shared-key",
      obfs_mode: "http",
    });
    expect(
      compile({
        inbounds: [snell.server(server)],
        outbounds: [snell.client({ ...client, options: { obfs_host: "cover.example" } })],
      }),
    ).toMatchObject({
      inbounds: [{ version: 5, obfs_mode: "http" }],
      outbounds: [{ version: 4, obfs_mode: "http", obfs_host: "cover.example" }],
    });
    const snellV6 = proxyProfile.snell({ connect, psk: "test-shared-key" });
    expect(() =>
      Reflect.apply(snellV6.client, undefined, [
        { ...client, options: { obfs_host: "cover.example" } },
      ]),
    ).toThrow("obfs_host");
    expect(() =>
      Reflect.apply(proxyProfile.snell, undefined, [{ connect, psk: "secret", version: 4 }]),
    ).toThrow("version");
    expect(() => Reflect.apply(snell.client, undefined, [{ tag: "out", version: 6 }])).toThrow(
      "version",
    );
  });

  test("builds managed Shadowsocks and Realm without copying side-specific secrets", () => {
    const key = Buffer.alloc(16, 1).toString("base64");
    const password = Buffer.alloc(16, 2).toString("base64");
    const alice = user({
      name: "alice",
      credentials: { shadowsocks: { password }, hysteria2: { password: "user-key" } },
    });
    const ss = proxyProfile.shadowsocks({
      connect,
      method: "2022-blake3-aes-128-gcm",
      managed: true,
      serverKey: key,
    });
    const managed = ss.server({ tag: server.tag }).listen({ port: server.listen.port });
    expect(
      compile({ inbounds: [managed], services: [service.ssmApi({ servers: { "/": managed } })] }),
    ).toMatchObject({
      inbounds: [{ managed: true, password: key, listen_port: server.listen.port }],
      services: [{ type: "ssm-api", servers: { "/": "in" } }],
    });
    const outgoing = ss.client(alice, client).dial({ connect_timeout: "5s" });
    expect(compile({ outbounds: [outgoing] })).toMatchObject({
      outbounds: [{ password: `${key}:${password}`, connect_timeout: "5s" }],
    });
    const hy = proxyProfile.hysteria2({
      users: [alice],
      tls: { mode: "tls", serverName: "edge.example" },
      realm: {
        server_url: "https://realm.example",
        realm_id: "edge",
        stun_servers: ["192.0.2.1"],
        token: "default",
      },
    });
    const result = compile({
      inbounds: [
        hy.server({
          ...server,
          tls: { certificate_path: "cert.pem", key_path: "key.pem" },
          realm: { token: "server-token" },
        }),
      ],
      outbounds: [hy.client(alice, client)],
    });
    expect(result).toMatchObject({
      inbounds: [{ realm: { realm_id: "edge", token: "server-token" } }],
      outbounds: [
        {
          password: "user-key",
          realm: { realm_id: "edge", token: "default" },
          tls: { server_name: "edge.example" },
        },
      ],
    });
    expect(result.outbounds?.[0]).not.toHaveProperty("server");
    expect(result.outbounds?.[0]).not.toHaveProperty("server_port");
  });

  test("rejects invalid shared options and missing credentials without including secrets", () => {
    const alice = user({ name: "alice", credentials: { vless: { uuid } } });
    expect(() => proxyProfile.vless({ users: [alice, user({ name: "alice" })], connect })).toThrow(
      "duplicate",
    );
    expect(() => proxyProfile.vless({ users: [user({ name: "alice" })], connect })).toThrow(
      "missing vless credentials",
    );
    expect(() =>
      Reflect.apply(proxyProfile.vless, undefined, [
        { users: [alice], connect, transport: { type: "quic" } },
      ]),
    ).toThrow("requires regular TLS");
    const profile = proxyProfile.vless({
      users: [alice],
      connect,
      transport: { type: "grpc", service_name: "proxy" },
    });
    expect(() =>
      Reflect.apply(profile.client, undefined, [alice, { ...client, options: { uuid } }]),
    ).toThrow("controlled by the profile");
    expect(() =>
      Reflect.apply(profile.client, undefined, [
        alice,
        { ...client, transport: { service_name: "other" } },
      ]),
    ).toThrow("service_name");
    const headers = { headers: { "x-proxy": "one" } };
    expect(() =>
      Reflect.apply(profile.server, undefined, [{ ...server, transport: headers }]),
    ).toThrow("transport.headers");
    expect(() =>
      Reflect.apply(profile.client, undefined, [alice, { ...client, transport: headers }]),
    ).toThrow("transport.headers");
  });
});
