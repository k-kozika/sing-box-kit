import { createPrivateKey, createPublicKey } from "node:crypto";
import { inbound, outbound } from "./factories";
import type {
  Hysteria2InboundRealm,
  InboundTLSOptions,
  OutboundTLSOptions,
  SBKitInputs,
  ShadowTLSHandshakeOptions,
  V2RayTransport,
} from "./generated/sbkit-inputs";
import { fieldsFrom, record, snapshot } from "./resource";
import type { Resource, SsmInbound } from "./resource";
import { fail, keyPath } from "./schema";
import { checkTlsAlpn } from "./settings";
import type { Dial, ProtocolTlsOptions } from "./settings";
import type { Fields, ReadonlyJson, StrictUnion } from "./type-utils";
import { isUser, requireUserCredentials } from "./user";
import type { User, UserCredentials } from "./user";

type Protocol = Exclude<keyof UserCredentials, "mixed">;
type TransportProtocol = "vmess" | "vless" | "trojan";
type TlsRequired = "anytls" | "hysteria" | "hysteria2" | "naive" | "tuic";
type TlsUnsupported = "shadowsocks" | "snell" | "socks";
type Catalog = SBKitInputs["factories"];
type Options<T extends "inbounds" | "outbounds", K extends Protocol> = ReadonlyJson<
  Catalog[T][K]["options"]
>;
type Inbound<K extends Protocol> = ReturnType<(typeof inbound)[K]>;
type Outbound<K extends Protocol> = ReturnType<(typeof outbound)[K]>;
type Users = readonly [User, ...User[]];
type Port = { readonly host: string; readonly port: number };
type Direct = { readonly connect: Port; readonly realm?: never };
type Hopping = { readonly host: string; readonly ports: string | readonly string[] };
type HysteriaDirect = { readonly connect: StrictUnion<Port | Hopping>; readonly realm?: never };

type Transport = StrictUnion<
  | { readonly type: "tcp" | "quic" }
  | ReadonlyJson<
      Pick<Extract<V2RayTransport, { type: "http" }>, "type" | "host" | "path" | "method">
    >
  | ReadonlyJson<
      Pick<
        Extract<V2RayTransport, { type: "ws" }>,
        "type" | "path" | "max_early_data" | "early_data_header_name"
      >
    >
  | ReadonlyJson<Pick<Extract<V2RayTransport, { type: "grpc" }>, "type" | "service_name">>
  | ReadonlyJson<Pick<Extract<V2RayTransport, { type: "httpupgrade" }>, "type" | "host" | "path">>
> & { readonly [Key in AllTransportSideFields]?: never };
type NormalTls = {
  readonly mode: "tls";
  readonly serverName?: string;
  readonly alpn?: string | readonly string[];
};
type RealityTls = {
  readonly mode: "reality";
  readonly serverName: string;
  readonly handshake: Port & Dial;
  readonly keyPair: { readonly privateKey: string; readonly publicKey: string };
} & StrictUnion<
  { readonly shortId: string } | { readonly shortIds: readonly [string, ...string[]] }
>;
type NoTls = { readonly mode: "none" };
type TransportTls<K extends TransportProtocol> = StrictUnion<
  | { readonly transport: Transport; readonly tls: NormalTls }
  | {
      readonly transport?: Exclude<Transport, { type: "tcp" | "quic" }> | { readonly type: "tcp" };
      readonly tls?: NormalTls | NoTls | (K extends "vless" ? RealityTls : never);
    }
>;

const sharedOption = {
  hysteria: "obfs",
  hysteria2: "obfs",
  shadowsocks: "method",
} as const;

const ownedServer = [
  "tag",
  "users",
  "password",
  "version",
  "transport",
  "managed",
  "destinations",
  "psk",
  "mode",
  "obfs_mode",
  "realm",
  "handshake",
] as const;
const ownedClient = [
  "tag",
  "server",
  "server_port",
  "server_ports",
  "username",
  "password",
  "uuid",
  "flow",
  "alter_id",
  "auth",
  "auth_str",
  "userkey",
  "psk",
  "version",
  "transport",
  "mode",
  "obfs_mode",
  "realm",
] as const;
type SharedOption<K extends Protocol> = K extends keyof typeof sharedOption
  ? (typeof sharedOption)[K]
  : never;
type SideOptions<O, Keys extends PropertyKey> = O extends unknown
  ? Omit<O, Keys> & { readonly [K in Extract<Keys, keyof O | "version" | "transport">]?: never }
  : never;
type ProfileOutboundOptions<K extends Protocol, Input> = K extends "snell"
  ? Extract<
      StrictUnion<Options<"outbounds", "snell">>,
      { version: [Input] extends [{ readonly version: 5 }] ? 4 : 6 }
    >
  : Options<"outbounds", K>;

type Realm = ReadonlyJson<
  Required<Pick<Hysteria2InboundRealm, "server_url" | "realm_id" | "stun_servers">>
> &
  ReadonlyJson<Pick<Hysteria2InboundRealm, "token">>;
type RealmLocal = ReadonlyJson<
  Omit<Hysteria2InboundRealm, "server_url" | "realm_id" | "stun_servers">
>;

type ServerSettings<K extends Protocol, Input> = {
  readonly tag: string;
  readonly listen?: ReadonlyJson<Catalog["inbounds"][K]["listen"]> & {
    readonly address?: string;
  };
  readonly options?: SideOptions<
    Options<"inbounds", K>,
    (typeof ownedServer)[number] | SharedOption<K>
  >;
  readonly tls?: K extends TlsUnsupported | "shadowtls"
    ? never
    : ProtocolTlsOptions<K, ReadonlyJson<Omit<InboundTLSOptions, "enabled" | "reality">>>;
  readonly transport?: K extends TransportProtocol
    ? TransportSideOptions<ProfileTransport<Input>, false>
    : never;
  readonly realm?: K extends "hysteria2" ? RealmLocal : never;
};
type ClientTls = ReadonlyJson<Omit<OutboundTLSOptions, "enabled" | "server_name" | "reality">>;
type ClientSettings<K extends Protocol, Input> = {
  readonly tag: string;
  readonly dial?: ReadonlyJson<Catalog["outbounds"][K]["dial"]>;
  readonly options?: SideOptions<
    ProfileOutboundOptions<K, Input>,
    (typeof ownedClient)[number] | SharedOption<K>
  >;
  readonly tls?: K extends TlsUnsupported ? never : ProtocolTlsOptions<K, ClientTls>;
  readonly transport?: K extends TransportProtocol
    ? TransportSideOptions<ProfileTransport<Input>, true>
    : never;
  readonly realm?: K extends "hysteria2" ? Omit<RealmLocal, "stun_domain_resolver"> : never;
  readonly shortId?: K extends "vless" ? string : never;
};
interface Profile<
  K extends Protocol,
  Authenticated extends boolean,
  ExtraInbound = unknown,
  Input = unknown,
> {
  server(this: void, options: ServerSettings<K, Input>): Inbound<K> & ExtraInbound;
  client(
    this: void,
    ...args: Authenticated extends true
      ? [user: User, options: ClientSettings<K, Input>]
      : [options: ClientSettings<K, Input>]
  ): Outbound<K>;
}

type TransportInput<K extends TransportProtocol> = Direct & {
  readonly users: Users;
} & TransportTls<K>;
type PlainInput = Direct & { readonly tls?: NormalTls | NoTls };
type RequiredTlsInput<K extends Protocol = Protocol> = Direct & {
  readonly users: Users;
  readonly tls: ProtocolTlsOptions<K, NormalTls>;
};
type HysteriaInput = HysteriaDirect &
  Pick<RequiredTlsInput, "users" | "tls"> &
  Pick<Options<"inbounds", "hysteria">, "obfs">;
type Hysteria2Input = { readonly users: Users } & Pick<Options<"inbounds", "hysteria2">, "obfs"> &
  (
    | (HysteriaDirect & { readonly tls: NormalTls })
    | {
        readonly connect?: never;
        readonly realm: Realm;
        readonly tls: NormalTls & { readonly serverName: string };
      }
  );
type SocksInput = Direct & { readonly version?: "4" | "4a" | "5" };
type SnellInput = Direct & { readonly psk: string } & StrictUnion<
    | { readonly version: 5; readonly obfs_mode?: "none" | "http" | "tls" }
    | { readonly version?: 6; readonly mode?: "default" | "unshaped" | "unsafe-raw" }
  >;
type ShadowTlsInput = Direct & {
  readonly handshake: ReadonlyJson<ShadowTLSHandshakeOptions> & {
    readonly server: string;
    readonly server_port: number;
  };
  readonly serverName: string;
};
type ShadowsocksInput = Direct;
type ShadowsocksMethod = Options<"inbounds", "shadowsocks">["method"];
type MultiMethod = Exclude<ShadowsocksMethod, "none" | "2022-blake3-chacha20-poly1305">;
type SharedPassword = StrictUnion<
  | { readonly method: "none" }
  | { readonly method: Exclude<ShadowsocksMethod, "none">; readonly password: string }
>;
type MultiPassword = StrictUnion<
  | { readonly method: Extract<MultiMethod, `2022-${string}`>; readonly serverKey: string }
  | { readonly method: Exclude<MultiMethod, `2022-${string}`> }
>;

const transportFields = {
  tcp: [],
  quic: [],
  http: ["host", "path", "method"],
  ws: ["path", "max_early_data", "early_data_header_name"],
  grpc: ["service_name"],
  httpupgrade: ["host", "path"],
} as const;
const localTransportFields = {
  tcp: [],
  quic: [],
  http: ["headers", "idle_timeout", "ping_timeout"],
  ws: ["headers"],
  grpc: ["idle_timeout", "ping_timeout"],
  httpupgrade: ["headers"],
} as const;
const grpcClientFields = ["permit_without_stream"] as const;
type TransportKind = keyof typeof localTransportFields;
type TransportSelection<K extends TransportKind> = { readonly transport: { readonly type: K } };
type ProfileTransport<Input> = Input extends TransportSelection<infer K> ? K : "tcp";
type TransportSideField<K extends TransportKind, Client extends boolean> =
  | (typeof localTransportFields)[K][number]
  | (Client extends true ? (K extends "grpc" ? (typeof grpcClientFields)[number] : never) : never);
type AllTransportSideFields = TransportSideField<TransportKind, true>;
// A setting must work for every possible transport when the input type is a union.
type CommonTransportSideFields<
  K extends TransportKind,
  Client extends boolean,
> = keyof (K extends TransportKind ? Record<TransportSideField<K, Client>, true> : never) &
  AllTransportSideFields;
type TransportSideOptions<
  K extends TransportKind,
  Client extends boolean,
  Allowed extends AllTransportSideFields = CommonTransportSideFields<K, Client>,
> = [Allowed] extends [never]
  ? never
  : ReadonlyJson<Pick<StrictUnion<V2RayTransport>, Allowed>> & {
      readonly [Key in Exclude<AllTransportSideFields, Allowed>]?: never;
    };

const tlsRequired = new Set<Protocol>([
  "anytls",
  "hysteria",
  "hysteria2",
  "naive",
  "tuic",
] satisfies TlsRequired[]);
const versioned: readonly Protocol[] = ["socks", "shadowtls", "snell"];
const transportProtocols: readonly Protocol[] = ["vmess", "vless", "trojan"];
const namedClients: readonly Protocol[] = ["socks", "http", "naive"];
const optionalUsers: readonly Protocol[] = ["http", "socks", "snell", "shadowsocks", "shadowtls"];
const specialFields: Partial<Record<Protocol, readonly string[]>> = {
  hysteria2: ["realm"],
  shadowsocks: ["password", "serverKey", "managed"],
  shadowtls: ["password", "serverName", "handshake"],
  snell: ["psk", "obfs_mode", "mode"],
};

type NativeBuilder = Resource & {
  listen(address: unknown, options: Fields): NativeBuilder;
  dial(options: unknown): NativeBuilder;
  tls(options: unknown): NativeBuilder;
};

// Native factories validate the assembled options and return the public resource types.
function native(factory: (options: never) => Resource, options: Fields): NativeBuilder {
  return factory(options as never) as NativeBuilder;
}

function connection(value: unknown, path: string): Fields {
  const { host, port } = fieldsFrom(value, path, ["host", "port"], ["host", "port"]);
  if (typeof host !== "string" || host === "") fail(`${path}.host`, "expected a host");
  if (typeof port !== "number" || !Number.isInteger(port) || port < 1 || port > 65535)
    fail(`${path}.port`, "expected a port from 1 to 65535");
  return { server: host, server_port: port };
}

function profileConnection(kind: Protocol, value: unknown, path: string): Fields {
  if (kind !== "hysteria" && kind !== "hysteria2") return connection(value, path);
  const fields = record(value, path);
  if (!Object.hasOwn(fields, "ports")) return connection(fields, path);
  const { host, ports } = fieldsFrom(fields, path, ["host", "ports"], ["host", "ports"]);
  return { server: requiredString(host, `${path}.host`), server_ports: ports };
}

function usersFor(input: unknown, path: string): readonly User[] {
  if (!Array.isArray(input) || input.length === 0)
    fail(path, "expected a non-empty array of Users");
  const names = new Set<string>();
  return Array.from(input, (value, index) => {
    const entry = `${path}[${index}]`;
    if (!isUser(value) || !value.name) fail(entry, "expected a User with a non-empty name");
    if (names.has(value.name)) fail(entry, "duplicate user name");
    names.add(value.name);
    return value;
  });
}

function realityKeys(input: unknown, path: string): Fields {
  const keys = fieldsFrom(input, path, ["privateKey", "publicKey"], ["privateKey", "publicKey"]);
  const { privateKey, publicKey } = keys;
  for (const [key, value] of Object.entries(keys)) {
    if (
      typeof value !== "string" ||
      !/^[A-Za-z0-9_-]{43}$/.test(value) ||
      Buffer.from(value, "base64url").toString("base64url") !== value
    )
      fail(`${path}.${key}`, "expected an unpadded 32-byte Base64url key");
  }
  // The PKCS #8 prefix identifies a raw X25519 private key.
  const der = Buffer.concat([
    Buffer.from("302e020100300506032b656e04220420", "hex"),
    Buffer.from(privateKey as string, "base64url"),
  ]);
  const derived = createPublicKey(createPrivateKey({ key: der, format: "der", type: "pkcs8" }));
  if (derived.export({ format: "jwk" }).x !== publicKey)
    fail(`${path}.publicKey`, "does not match private key");
  return keys;
}

function tlsFor(kind: Protocol, input: unknown, needsTls: boolean, path: string) {
  const { mode } = record(input ?? { mode: "none" }, path);
  if (mode === "tls") {
    if (kind === "shadowsocks" || kind === "snell" || kind === "socks" || kind === "shadowtls")
      fail(path, "TLS is unavailable for this profile");
    const fields = fieldsFrom(input, path, ["mode", "serverName", "alpn"]);
    checkTlsAlpn(kind, fields, path);
    if (
      fields.serverName !== undefined &&
      (typeof fields.serverName !== "string" || !fields.serverName)
    )
      fail(`${path}.serverName`, "expected a server name");
    return { mode, fields } as const;
  }
  if (needsTls) fail(path, "requires regular TLS");
  if (mode === "none") {
    if (input !== undefined) fieldsFrom(input, path, ["mode"]);
    return { mode } as const;
  }
  if (mode !== "reality" || kind !== "vless") fail(`${path}.mode`, "unsupported TLS mode");
  const fields = fieldsFrom(
    input,
    path,
    ["mode", "serverName", "handshake", "keyPair", "shortId", "shortIds"],
    ["serverName", "handshake", "keyPair"],
  );
  if (typeof fields.serverName !== "string" || !fields.serverName)
    fail(`${path}.serverName`, "expected a server name");
  if ((fields.shortId === undefined) === (fields.shortIds === undefined))
    fail(path, "specify either shortId or shortIds");
  const ids = fields.shortIds ?? [fields.shortId];
  if (
    !Array.isArray(ids) ||
    !ids.length ||
    Array.from(ids).some((id) => typeof id !== "string" || !/^(?:[\da-f]{2}){0,8}$/i.test(id)) ||
    new Set(ids.map((id: string) => id.toLowerCase())).size !== ids.length
  )
    fail(`${path}.shortIds`, "expected unique hexadecimal short IDs");
  const { host, port, ...dial } = record(fields.handshake, `${path}.handshake`);
  if (Object.hasOwn(dial, "server") || Object.hasOwn(dial, "server_port"))
    fail(`${path}.handshake`, "use host and port for the handshake address");
  return {
    mode,
    serverName: fields.serverName,
    keys: realityKeys(fields.keyPair, `${path}.keyPair`),
    ids: ids as string[],
    handshake: { ...dial, ...connection({ host, port }, `${path}.handshake`) },
  } as const;
}

function checkedOptions(value: unknown, owned: readonly string[], path: string): Fields {
  const fields = record(value ?? {}, path);
  for (const key of Object.keys(fields))
    if (owned.includes(key)) fail(keyPath(path, key), "field is controlled by the profile");
  return fields;
}

function protocolOptions(
  kind: Protocol,
  config: Fields,
  hasUsers: boolean,
  sharedKey: string | undefined,
  path: string,
) {
  const serverFields: Fields = {};
  const clientFields: Fields = {};
  if (sharedKey && config[sharedKey] !== undefined) {
    serverFields[sharedKey] = config[sharedKey];
    clientFields[sharedKey] = config[sharedKey];
  }

  switch (kind) {
    case "socks": {
      const version = config.version ?? "5";
      if (version !== "4" && version !== "4a" && version !== "5")
        fail(`${path}.version`, "unsupported SOCKS version");
      clientFields.version = version;
      break;
    }
    case "snell": {
      const version = config.version ?? 6;
      if (version !== 5 && version !== 6) fail(`${path}.version`, "unsupported Snell version");
      const forbidden = version === 5 ? "mode" : "obfs_mode";
      if (config[forbidden] !== undefined)
        fail(`${path}.${forbidden}`, "unavailable for this Snell version");
      serverFields.version = version;
      clientFields.version = version === 5 ? 4 : 6;
      const flag = version === 5 ? "obfs_mode" : "mode";
      if (config[flag] !== undefined) serverFields[flag] = clientFields[flag] = config[flag];
      serverFields.psk = clientFields.psk = requiredString(config.psk, `${path}.psk`);
      break;
    }
    case "shadowtls": {
      const version = config.version ?? 3;
      if (version !== 1 && version !== 2 && version !== 3)
        fail(`${path}.version`, "unsupported ShadowTLS version");
      if (version === 3 ? !hasUsers : hasUsers)
        fail(
          `${path}.users`,
          "users are required for ShadowTLS v3 and unavailable in other versions",
        );
      if (version === 2)
        serverFields.password = clientFields.password = requiredString(
          config.password,
          `${path}.password`,
        );
      else if (config.password !== undefined)
        fail(`${path}.password`, "shared password is available only in ShadowTLS v2");
      const handshake = record(config.handshake, `${path}.handshake`);
      connection({ host: handshake.server, port: handshake.server_port }, `${path}.handshake`);
      serverFields.handshake = handshake;
      requiredString(config.serverName, `${path}.serverName`);
      serverFields.version = clientFields.version = version;
      break;
    }
    case "shadowsocks": {
      if (config.managed !== undefined && typeof config.managed !== "boolean")
        fail(`${path}.managed`, "expected a boolean");
      if (config.managed && hasUsers)
        fail(`${path}.users`, "managed Shadowsocks uses SSM accounts");
      const method = requiredString(config.method, `${path}.method`);
      if (config.managed || hasUsers) {
        if (method === "none" || method === "2022-blake3-chacha20-poly1305")
          fail(`${path}.method`, "unavailable with multiple Shadowsocks users");
        if (config.password !== undefined)
          fail(`${path}.password`, "use User credentials for multiple users");
        if (method.startsWith("2022-"))
          serverFields.password = requiredString(config.serverKey, `${path}.serverKey`);
        else if (config.serverKey !== undefined)
          fail(`${path}.serverKey`, "requires a Shadowsocks 2022 AES method");
        if (config.managed) serverFields.managed = true;
      } else {
        if (config.serverKey !== undefined) fail(`${path}.serverKey`, "requires multiple users");
        if (method !== "none")
          serverFields.password = clientFields.password = requiredString(
            config.password,
            `${path}.password`,
          );
        else if (config.password !== undefined)
          fail(`${path}.password`, "unavailable with method none");
      }
      break;
    }
  }
  return { serverFields, clientFields };
}

function makeProfile<
  K extends Protocol,
  Authenticated extends boolean,
  ExtraInbound = unknown,
  Input = unknown,
>(kind: K, input: unknown): Profile<K, Authenticated, ExtraInbound, Input> {
  const path = `proxyProfile.${kind}`;
  const sharedKey = Object.hasOwn(sharedOption, kind)
    ? sharedOption[kind as keyof typeof sharedOption]
    : undefined;
  const config = snapshot(
    fieldsFrom(input, path, [
      "connect",
      "users",
      ...(kind === "shadowtls" || kind === "shadowsocks" || kind === "snell" || kind === "socks"
        ? []
        : ["tls"]),
      ...(transportProtocols.includes(kind) ? ["transport"] : []),
      ...(versioned.includes(kind) ? ["version"] : []),
      ...(sharedKey ? [sharedKey] : []),
      ...(specialFields[kind] ?? []),
    ]),
    path,
  );
  const realm =
    config.realm === undefined
      ? undefined
      : fieldsFrom(
          config.realm,
          `${path}.realm`,
          ["server_url", "realm_id", "stun_servers", "token"],
          ["server_url", "realm_id", "stun_servers"],
        );
  if (realm && config.connect !== undefined) fail(`${path}.connect`, "conflicts with Realm");
  const connect = realm ? {} : profileConnection(kind, config.connect, `${path}.connect`);
  const users = config.users === undefined ? [] : usersFor(config.users, `${path}.users`);
  if (!optionalUsers.includes(kind) && !users.length)
    fail(`${path}.users`, "expected at least one User");

  let transport: Fields = {};
  let transportType: keyof typeof transportFields = "tcp";
  if (config.transport !== undefined) {
    const { type } = record(config.transport, `${path}.transport`);
    if (typeof type !== "string" || !Object.hasOwn(transportFields, type))
      fail(`${path}.transport.type`, "unsupported transport");
    transportType = type as keyof typeof transportFields;
    transport = fieldsFrom(config.transport, `${path}.transport`, [
      "type",
      ...transportFields[transportType],
    ]);
  }
  const tls = tlsFor(
    kind,
    config.tls,
    tlsRequired.has(kind) || transportType === "quic",
    `${path}.tls`,
  );
  if (realm && (tls.mode !== "tls" || !tls.fields.serverName))
    fail(`${path}.tls.serverName`, "required for Realm connections");

  const { serverFields, clientFields } = protocolOptions(
    kind,
    config,
    users.length > 0,
    sharedKey,
    path,
  );

  function credentials(user: User, location: string): Fields {
    if (kind === "socks" && clientFields.version !== "5") {
      if (requireUserCredentials(user, "socks", location).password !== "")
        fail(location, "SOCKS4 and SOCKS4a use username-only authentication");
      return {};
    }
    return { ...requireUserCredentials(user, kind, location) };
  }

  users.forEach((user, index) => credentials(user, `${path}.users[${index}]`));
  if (users.length) serverFields.users = users;

  function sideOptions(input: unknown, client: boolean) {
    const part = client ? "client" : "server";
    const location = `${path}.${part}`;
    const local = fieldsFrom(
      input,
      location,
      [
        "tag",
        "options",
        "tls",
        "transport",
        "realm",
        ...(client ? ["dial", "shortId"] : ["listen"]),
      ],
      ["tag"],
    );
    const extra = checkedOptions(
      local.options,
      [...(client ? ownedClient : ownedServer), ...(sharedKey ? [sharedKey] : [])],
      `${location}.options`,
    );
    let transportOptions: Fields = {};
    if (local.transport !== undefined) {
      if (transportType === "tcp" || transportType === "quic")
        fail(`${location}.transport`, "this transport has no side-specific fields");
      transportOptions = fieldsFrom(local.transport, `${location}.transport`, [
        ...localTransportFields[transportType],
        ...(client && transportType === "grpc" ? grpcClientFields : []),
      ]);
    }
    let realmOptions: Fields = {};
    if (local.realm !== undefined) {
      if (!realm) fail(`${location}.realm`, "requires a Realm profile");
      realmOptions = fieldsFrom(local.realm, `${location}.realm`, [
        "token",
        "ip_version",
        "port_mapping",
        "http_client",
        ...(client ? [] : ["stun_domain_resolver"]),
      ]);
    }
    const fields = {
      ...extra,
      tag: local.tag,
      ...(transportType === "tcp" ? {} : { transport: { ...transport, ...transportOptions } }),
      ...(realm ? { realm: { ...realm, ...realmOptions } } : {}),
    };
    return { location, local, fields };
  }

  function applyTls(builder: NativeBuilder, local: Fields, location: string, client: boolean) {
    if (local.shortId !== undefined && tls.mode !== "reality")
      fail(`${location}.shortId`, "requires REALITY");
    if (tls.mode === "reality") {
      if (local.tls !== undefined)
        fail(`${location}.tls`, "REALITY settings belong to the profile");
      if (!client)
        return builder.tls({
          side: "server",
          server_name: tls.serverName,
          reality: {
            private_key: tls.keys.privateKey,
            short_id: tls.ids,
            handshake: tls.handshake,
          },
        });
      const selected = local.shortId ?? (tls.ids.length === 1 ? tls.ids[0] : undefined);
      if (typeof selected !== "string" || !tls.ids.includes(selected))
        fail(`${location}.shortId`, "select a short ID from the profile");
      return builder.tls({
        side: "client",
        server_name: tls.serverName,
        reality: { public_key: tls.keys.publicKey, short_id: selected },
      });
    }
    if (tls.mode === "tls" || (kind === "shadowtls" && client)) {
      const settings = checkedOptions(
        local.tls,
        [
          "enabled",
          "reality",
          "side",
          ...(client ? ["server_name"] : []),
          ...(tls.mode === "tls" && tls.fields.alpn !== undefined ? ["alpn"] : []),
        ],
        `${location}.tls`,
      );
      checkTlsAlpn(kind, settings, `${location}.tls`);
      if (
        !client &&
        !settings.certificate_provider &&
        (!(settings.certificate || settings.certificate_path) ||
          !(settings.key || settings.key_path))
      )
        fail(`${location}.tls`, "expected a certificate and key or certificate provider");
      return builder.tls({
        ...settings,
        enabled: true,
        ...(tls.mode === "tls" && tls.fields.alpn !== undefined ? { alpn: tls.fields.alpn } : {}),
        ...(client
          ? {
              server_name:
                tls.mode === "tls" ? (tls.fields.serverName ?? connect.server) : config.serverName,
            }
          : {}),
      });
    }
    if (local.tls !== undefined) fail(`${location}.tls`, "TLS must be enabled in the profile");
    return builder;
  }

  const profile = {
    server(input: unknown) {
      const { local, fields, location } = sideOptions(input, false);
      let builder = native(inbound[kind], { ...fields, ...serverFields });
      if (local.listen !== undefined) {
        const { address, ...listen } = record(local.listen, `${location}.listen`);
        builder = builder.listen(address, listen);
      }
      return applyTls(builder, local, location, false);
    },
    client(userOrOptions: unknown, options?: unknown) {
      const authenticated = users.length > 0 || config.managed === true;
      if (
        authenticated &&
        (!isUser(userOrOptions) ||
          !userOrOptions.name ||
          (config.managed !== true && !users.includes(userOrOptions)))
      )
        fail(`${path}.client.user`, "expected a User for this profile");
      if (!authenticated && options !== undefined)
        fail(`${path}.client.user`, "profile has no user selection");
      const { local, fields, location } = sideOptions(
        authenticated ? options : userOrOptions,
        true,
      );
      const selected = isUser(userOrOptions) ? userOrOptions : undefined;
      const auth: Fields = selected
        ? {
            ...credentials(selected, `${location}.user`),
            ...(namedClients.includes(kind) ? { username: selected.name } : {}),
          }
        : {};
      if (
        kind === "shadowsocks" &&
        typeof auth.password === "string" &&
        typeof serverFields.password === "string"
      )
        auth.password = `${serverFields.password}:${auth.password}`;
      let builder = native(outbound[kind], { ...fields, ...clientFields, ...connect, ...auth });
      if (local.dial !== undefined) builder = builder.dial(local.dial);
      return applyTls(builder, local, location, true);
    },
  };
  return Object.freeze(profile) as unknown as Profile<K, Authenticated, ExtraInbound, Input>;
}

function requiredString(input: unknown, path: string): string {
  if (typeof input !== "string" || !input) fail(path, "expected a non-empty string");
  return input;
}

function http(input: PlainInput & { readonly users: Users }): Profile<"http", true>;
function http(input: PlainInput & { readonly users?: never }): Profile<"http", false>;
function http(input: PlainInput & { readonly users?: Users }) {
  return makeProfile<"http", boolean>("http", input);
}

function socks(input: SocksInput & { readonly users: Users }): Profile<"socks", true>;
function socks(input: SocksInput & { readonly users?: never }): Profile<"socks", false>;
function socks(input: SocksInput & { readonly users?: Users }) {
  return makeProfile<"socks", boolean>("socks", input);
}

function snell<const Version extends 5 | 6 = 6>(
  input: SnellInput & { readonly version?: Version; readonly users: Users },
): Profile<"snell", true, unknown, { readonly version: Version }>;
function snell<const Version extends 5 | 6 = 6>(
  input: SnellInput & { readonly version?: Version; readonly users?: never },
): Profile<"snell", false, unknown, { readonly version: Version }>;
function snell(input: SnellInput & { readonly users?: Users }) {
  return makeProfile<"snell", boolean>("snell", input);
}

function shadowtls(
  input: ShadowTlsInput & {
    readonly version?: 3;
    readonly users: Users;
    readonly password?: never;
  },
): Profile<"shadowtls", true>;
function shadowtls(
  input: ShadowTlsInput & {
    readonly version: 1;
    readonly users?: never;
    readonly password?: never;
  },
): Profile<"shadowtls", false>;
function shadowtls(
  input: ShadowTlsInput & {
    readonly version: 2;
    readonly users?: never;
    readonly password: string;
  },
): Profile<"shadowtls", false>;
function shadowtls(input: ShadowTlsInput) {
  return makeProfile<"shadowtls", boolean>("shadowtls", input);
}

function shadowsocks(
  input: ShadowsocksInput &
    MultiPassword & { readonly managed: true; readonly users?: never; readonly password?: never },
): Profile<"shadowsocks", true, SsmInbound>;
function shadowsocks(
  input: ShadowsocksInput &
    MultiPassword & { readonly managed?: false; readonly users: Users; readonly password?: never },
): Profile<"shadowsocks", true, SsmInbound>;
function shadowsocks(
  input: ShadowsocksInput &
    SharedPassword & {
      readonly managed?: false;
      readonly users?: never;
      readonly serverKey?: never;
    },
): Profile<"shadowsocks", false>;
function shadowsocks(input: ShadowsocksInput) {
  return makeProfile<"shadowsocks", boolean>("shadowsocks", input);
}

function transportProfile<K extends TransportProtocol>(kind: K) {
  function create<const Transport extends TransportKind>(
    input: TransportInput<K> & TransportSelection<Transport>,
  ): Profile<K, true, unknown, TransportSelection<Transport>>;
  function create(input: TransportInput<K>): Profile<K, true>;
  function create(input: TransportInput<K>) {
    return makeProfile<K, true>(kind, input);
  }
  return create;
}

export const proxyProfile = Object.freeze({
  anytls: (input: RequiredTlsInput) => makeProfile<"anytls", true>("anytls", input),
  http,
  hysteria: (input: HysteriaInput) => makeProfile<"hysteria", true>("hysteria", input),
  hysteria2: (input: Hysteria2Input) => makeProfile<"hysteria2", true>("hysteria2", input),
  naive: (input: RequiredTlsInput<"naive">) => makeProfile<"naive", true>("naive", input),
  shadowsocks,
  shadowtls,
  snell,
  socks,
  trojan: transportProfile("trojan"),
  tuic: (input: RequiredTlsInput) => makeProfile<"tuic", true>("tuic", input),
  vless: transportProfile("vless"),
  vmess: transportProfile("vmess"),
});
