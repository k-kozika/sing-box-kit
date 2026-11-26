import type { SBKitInputs } from "./generated/sbkit-inputs";
import type { ShadowsocksUser } from "./generated/sing-box";
import { factoryCatalog, factoryName } from "./input-schema";
import type { FactoryBranch } from "./input-schema";
import {
  createResource,
  fieldsFrom,
  preferredDnsKinds,
  preferredRouteEndpoints,
  record,
  resourceData,
  snapshot,
} from "./resource";
import type { Resource, Role, SsmInbound, Target } from "./resource";
import { Rule } from "./rules";
import type { Condition } from "./rules";
import { checkSchema, compileSchema, definitionName, fail, keyPath } from "./schema";
import {
  checkSsmServers,
  expandInput,
  listenFields,
  matchesDiscriminators,
  previewReference,
  tlsFields,
} from "./settings";
import type { ClientTls, RealityClientTls, RealityServerTls, ServerTls, TlsMode } from "./settings";
import type { CamelCase, Fields, ReadonlyJson, StrictUnion } from "./type-utils";
import { isUser, requireUserCredentials } from "./user";
import type { User } from "./user";

interface ListenMethod<T> {
  listen(options?: T): this;
  listen(address?: "port" extends keyof T ? string : undefined, options?: T): this;
}
interface DialMethod<T> {
  dial(options: T): this;
}
interface TlsMethod<T> {
  tls(profile: T): this;
}
interface AuthMethod {
  authUser(user: User): Condition;
}

const targetRoles = {
  inbounds: ["inbound", "listen-detour"],
  outbounds: ["egress"],
  endpoints: ["egress", "inbound"],
  services: [],
  http_clients: ["http-client"],
  "dns.servers": ["dns-server"],
  "route.rule_set": ["rule-set"],
  certificate_providers: ["certificate-provider"],
  network_namespaces: ["netns"],
} as const satisfies Record<Target, readonly Role[]>;

const endpointRoles = {
  tailscale: "tailscale-endpoint",
  openconnect: "openconnect-endpoint",
  "openvpn-client": "openvpn-client-endpoint",
} as const satisfies Record<string, Role>;

const namedAuth = { name: "name", allowRaw: true } as const;
const usernameAuth = { name: "username", allowRaw: true } as const;
const authOptions = {
  anytls: namedAuth,
  http: usernameAuth,
  hysteria: namedAuth,
  hysteria2: namedAuth,
  mixed: usernameAuth,
  naive: usernameAuth,
  shadowsocks: namedAuth,
  shadowtls: namedAuth,
  snell: namedAuth,
  socks: { name: "username", allowRaw: false },
  trojan: namedAuth,
  tuic: namedAuth,
  vless: { name: "name", allowRaw: false },
  vmess: namedAuth,
} as const;
type AuthKind = keyof typeof authOptions;
type ShadowsocksEntry = User | (Readonly<ShadowsocksUser> & { user?: never });

type Catalog = SBKitInputs["factories"];
type Kind<T extends Target> = keyof Catalog[T] & string;
type Groups<T extends Target, K extends Kind<T>> = ReadonlyJson<Catalog[T][K]>;
type Options<T extends Target, K extends Kind<T>> =
  Groups<T, K> extends { options: infer O } ? StrictUnion<O> : never;
type Tag = string | readonly string[] | undefined;
type ExtraRoles<T extends Target, K> = T extends "endpoints"
  ? | (K extends keyof typeof endpointRoles ? (typeof endpointRoles)[K] : never)
    | (K extends (typeof preferredRouteEndpoints)[number] ? "preferred-routes" : never)
  : T extends "outbounds"
    ? K extends "bridge"
      ? "preferred-routes"
      : never
    : T extends "services"
      ? K extends "resolved"
        ? "resolved-service"
        : never
      : T extends "dns.servers"
        ? K extends (typeof preferredDnsKinds)[number]
          ? "preferred-domain"
          : never
        : never;
type Profile<T extends Target, K, F> = "enabled" extends keyof F
  ? T extends "inbounds" | "services"
    ? ServerTls | (K extends "vless" ? RealityServerTls : never)
    : ClientTls | (K extends "vless" ? RealityClientTls : never)
  : never;
type Built<
  T extends Target,
  K extends Kind<T>,
  V extends Tag = string,
  G = Groups<T, K>,
> = Resource<T, K, V, (typeof targetRoles)[T][number] | ExtraRoles<T, K>> &
  (G extends { listen: infer L } ? ListenMethod<L> : unknown) &
  (G extends { dial: infer D } ? DialMethod<D> : unknown) &
  (G extends { tls: infer F } ? TlsMethod<(F & { side?: never }) | Profile<T, K, F>> : unknown) &
  (T extends "inbounds" ? (K extends keyof typeof authOptions ? AuthMethod : unknown) : unknown);

type Factory<T extends Target, K extends Kind<T>> = T extends "services" | "http_clients"
  ? {
      (options: Options<T, K> & { tag: string }): Built<T, K>;
      (
        ...args: {} extends Options<T, K> ? [options?: Options<T, K>] : [options: Options<T, K>]
      ): Built<T, K, string | undefined>;
    }
  : (options: Options<T, K>) => Built<T, K>;

type Factories<T extends Target> = { [K in Kind<T> as CamelCase<K>]: Factory<T, K> };

interface Membership {
  readonly user?: User;
  readonly name: unknown;
}
function prepareUsers(fields: Fields, kind: AuthKind, path: string): readonly Membership[] {
  if (fields.users === undefined) return [];
  const users = fields.users;
  if (!Array.isArray(users)) fail(`${path}.users`, "expected an array");
  const auth = authOptions[kind];
  const members: Membership[] = [];
  fields.users = Array.from(users, (value, index) => {
    const entryPath = `${path}.users[${index}]`;
    if (isUser(value)) {
      members.push({ user: value, name: value.name });
      if (kind === "vmess") {
        const { alter_id, ...credentials } = requireUserCredentials(value, kind, entryPath);
        return { name: value.name, ...credentials, alterId: alter_id };
      }
      return { [auth.name]: value.name, ...requireUserCredentials(value, kind, entryPath) };
    }
    if (!auth.allowRaw) fail(entryPath, "expected a User from user()");
    const raw = record(value, entryPath);
    if (Object.hasOwn(raw, "user"))
      fail(`${entryPath}.user`, "pass the User directly and configure credentials in user()");
    members.push({ name: raw[auth.name] });
    return raw;
  });
  return members;
}

function validateTag(tag: unknown, path: string): void {
  if (tag === undefined) return;
  if (Array.isArray(tag)) {
    if (tag.length === 0) fail(path, "expected at least one tag");
    const seen = new Set<string>();
    Array.from(tag).forEach((value, index) => {
      const field = `${path}[${index}]`;
      if (typeof value !== "string" || value === "") fail(field, "expected a non-empty tag");
      if (seen.has(value)) fail(field, "duplicate tag", value);
      seen.add(value);
    });
  } else if (typeof tag !== "string" || tag === "") {
    fail(path, "expected a non-empty tag");
  }
}

function checkGroup(fields: Fields, path: string): void {
  const candidates = fields.outbounds;
  if (!Array.isArray(candidates) || candidates.length === 0)
    fail(`${path}.outbounds`, "expected at least one candidate");
  const seen = new Set<string>();
  Array.from(candidates).forEach((candidate, index) => {
    const candidatePath = `${path}.outbounds[${index}]`;
    previewReference(candidate, "egress", candidatePath);
    const tag = resourceData(candidate)?.fields.tag;
    if (typeof tag !== "string") return;
    if (seen.has(tag)) fail(candidatePath, "duplicate candidate tag", tag);
    seen.add(tag);
  });
  if (fields.default !== undefined && !candidates.includes(fields.default)) {
    fail(`${path}.default`, "default must be a candidate");
  }
}
function ruleSetFormat(fields: Fields, path: string, location: "path" | "url"): void {
  const input = fields[location];
  if (typeof input !== "string") fail(keyPath(path, location), "expected a string");
  if (Array.isArray(fields.tag) && fields.tag.length > 1) {
    const paths = location === "url" ? ["url", "initial_path"] : ["path"];
    for (const key of paths) {
      const value = fields[key];
      if (value !== undefined && (typeof value !== "string" || !value.includes("{tag}"))) {
        fail(keyPath(path, key), "multiple tags require a {tag} placeholder");
      }
    }
  }
  if (fields.format !== undefined) return;
  const extension = location === "url" ? URL.parse(input)?.pathname : input;
  if (extension?.endsWith(".json")) fields.format = "source";
  else if (extension?.endsWith(".srs")) fields.format = "binary";
  else fail(`${path}.format`, "cannot infer rule-set format");
}

type SettingsGroup = "listen" | "dial" | "tls";
const settingsGroups = ["listen", "dial", "tls"] as const;

function prepareOptions(
  target: Target,
  kind: string,
  options: Fields,
  path: string,
  roles: Role[],
): void {
  if (target === "inbounds" && kind === "shadowsocks") {
    const hasUsers = Array.isArray(options.users) && options.users.length > 0;
    if (hasUsers && options.managed === true)
      fail(`${path}.users`, "managed mode cannot have static users");
    if (hasUsers || options.managed === true) {
      if (options.method === "none")
        fail(`${path}.method`, "method none is unavailable in multi-user modes");
      roles.push("ssm");
    }
  }
  if (target === "outbounds" && (kind === "selector" || kind === "urltest"))
    checkGroup(options, path);
  if (target === "services" && kind === "ssm-api")
    checkSsmServers(options.servers, `${path}.servers`);
  if (target === "route.rule_set") {
    if (kind === "inline") {
      if (typeof options.tag !== "string") fail(`${path}.tag`, "expected a single tag");
      if (!Array.isArray(options.rules) || !options.rules.length)
        fail(`${path}.rules`, "expected at least one rule");
    } else {
      ruleSetFormat(options, path, kind === "local" ? "path" : "url");
    }
  }
}

function getRoles(target: Target, kind: string): Role[] {
  const roles: Role[] = [...targetRoles[target]];
  if (target === "endpoints") {
    if (Object.hasOwn(endpointRoles, kind))
      roles.push(endpointRoles[kind as keyof typeof endpointRoles]);
    if (preferredRouteEndpoints.some((preferred) => preferred === kind))
      roles.push("preferred-routes");
  }
  if (target === "outbounds" && kind === "bridge") roles.push("preferred-routes");
  if (target === "dns.servers" && preferredDnsKinds.some((preferred) => preferred === kind))
    roles.push("preferred-domain");
  if (target === "services" && kind === "resolved") roles.push("resolved-service");
  return roles;
}

function makeFactory(target: Target, kind: string, branches: FactoryBranch[]) {
  const path = `${target}.${kind}`;
  const validators = new Map<FactoryBranch, ReturnType<typeof compileSchema>>();
  const auth =
    target === "inbounds" && Object.hasOwn(authOptions, kind) ? (kind as AuthKind) : undefined;
  return (input: unknown = {}): Resource => {
    const raw = record(input, path);
    const branch =
      branches.length === 1
        ? branches[0]!
        : branches.find((item) => matchesDiscriminators(item.options, raw));
    if (!branch) {
      const discriminator = branches[0]?.options.properties?.version ? "version" : "provider";
      fail(keyPath(path, discriminator), "invalid or missing branch discriminator");
    }
    const options = fieldsFrom(
      raw,
      path,
      Object.keys(branch.options.properties!),
      branch.options.required,
    );
    validateTag(options.tag, `${path}.tag`);
    const users = auth ? prepareUsers(options, auth, path) : [];
    const members = kind === "shadowtls" && options.version !== 3 ? [] : users;
    const roles = getRoles(target, kind);
    prepareOptions(target, kind, options, path, roles);
    const base = snapshot(target === "http_clients" ? options : { type: kind, ...options }, path);
    const expand = (value: unknown, path: string, resolve: Parameters<typeof expandInput>[3]) =>
      expandInput(branch.output, value, path, resolve);

    const validate = validators.get(branch) ?? compileSchema(branch.output);
    validators.set(branch, validate);
    const { listen, dial, tls } = branch;

    function create(groups: Partial<Record<SettingsGroup, Fields>>): Resource {
      const fields = { ...base };
      for (const group of settingsGroups) {
        for (const [key, value] of Object.entries(groups[group] ?? {})) {
          if (Object.hasOwn(fields, key)) fail(keyPath(path, key), "conflicting output field");
          fields[key] = value;
        }
      }
      checkSchema(validate, expand(fields, path, previewReference), path);

      const apply = (group: SettingsGroup, getFields: () => Fields) => {
        if (groups[group]) fail(keyPath(path, group), "settings group already applied");
        return create({ ...groups, [group]: snapshot(getFields(), path) });
      };
      const methods: Fields = {};
      if (listen) {
        methods.listen = (address?: unknown, input: unknown = {}) =>
          apply("listen", () =>
            address !== null && typeof address === "object"
              ? listenFields(undefined, address, path, listen)
              : listenFields(address, input, path, listen),
          );
      }
      if (dial) {
        methods.dial = (input: unknown) =>
          apply("dial", () => {
            const settings = fieldsFrom(input, path, Object.keys(dial.properties!));
            if (
              kind === "wireguard" &&
              settings.detour !== undefined &&
              fields.listen_port !== undefined &&
              fields.listen_port !== 0
            ) {
              fail(`${path}.listen_port`, "non-zero WireGuard listen port with detour");
            }
            return settings;
          });
      }
      if (tls) {
        const name = definitionName(tls);
        let mode: TlsMode | undefined;
        if (name === "InboundTLSOptions") mode = kind === "vless" ? "server-reality" : "server";
        if (name === "OutboundTLSOptions") mode = kind === "vless" ? "client-reality" : "client";
        methods.tls = (input: unknown) =>
          apply("tls", () => tlsFields(input, `${path}.tls`, tls, mode));
      }
      if (auth) {
        methods.authUser = (user: User) => {
          if (
            !isUser(user) ||
            members.filter((entry) => entry.user === user).length !== 1 ||
            !user.name ||
            members.filter((entry) => entry.name === user.name).length !== 1
          ) {
            fail(`${path}.authUser`, "expected one User entry with a unique non-empty name");
          }
          return Rule.match({
            inbound: resource as Resource<"inbounds", string, string>,
            auth_user: user.name,
          });
        };
      }
      const resource = createResource(
        Object.freeze({
          target,
          kind,
          fields: Object.freeze(fields),
          expand,
          roles: Object.freeze(roles),
          remoteDns: target === "dns.servers" && Object.hasOwn(base, "server"),
          startupDetour:
            (target === "outbounds" && kind === "vless") ||
            (target === "endpoints" && kind === "wireguard"),
        }),
        methods,
      );
      return resource;
    }
    return create({});
  };
}

function factoriesFor<T extends Target>(target: T): Factories<T> {
  return Object.fromEntries(
    Array.from(factoryCatalog(target), ([kind, branches]) => [
      factoryName(kind),
      makeFactory(target, kind, branches),
    ]),
  ) as Factories<T>;
}

type ShadowsocksBase = Omit<Options<"inbounds", "shadowsocks">, "method" | "users" | "managed">;
type Method = Options<"inbounds", "shadowsocks">["method"];
type MultiMethod = Exclude<Method, "none">;
type ManagedShadowsocks = ShadowsocksBase & {
  method: MultiMethod;
  managed: true;
  users?: readonly [];
};
type StaticShadowsocks = ShadowsocksBase & {
  method: MultiMethod;
  managed?: false;
  users: readonly [ShadowsocksEntry, ...ShadowsocksEntry[]];
};
type ShadowsocksOptions = ShadowsocksBase &
  (
    | { method: Method; managed?: false; users?: readonly [] }
    | { method: MultiMethod; managed?: boolean; users?: readonly [] }
    | { method: MultiMethod; managed?: false; users?: readonly ShadowsocksEntry[] }
  );

type InboundUsers<O, K extends AuthKind> = O extends { users?: readonly (infer Entry)[] }
  ? Omit<O, "users"> &
      (O extends { users: unknown }
        ? { readonly users: readonly User[] }
        : {
            readonly users?: readonly (
              | User
              | ((typeof authOptions)[K]["allowRaw"] extends true
                  ? Entry & { user?: never }
                  : never)
            )[];
          })
  : O;
type InboundFactories = Omit<Factories<"inbounds">, AuthKind> & {
  [K in Exclude<AuthKind, "shadowsocks">]: (
    options: StrictUnion<InboundUsers<Options<"inbounds", K>, K>>,
  ) => Built<"inbounds", K>;
} & {
  shadowsocks: {
    (
      options: ManagedShadowsocks | StaticShadowsocks,
    ): Built<"inbounds", "shadowsocks"> & SsmInbound;
    (options: ShadowsocksOptions): Built<"inbounds", "shadowsocks">;
  };
};

type RuleSetFactory<K extends "local" | "remote"> = <const T extends string | readonly string[]>(
  options: Omit<Options<"route.rule_set", K>, "tag"> & { readonly tag: T },
) => Built<"route.rule_set", K, T>;

export const inbound = Object.freeze(factoriesFor("inbounds") as unknown as InboundFactories);
export const outbound = Object.freeze(factoriesFor("outbounds"));
export const endpoint = Object.freeze(factoriesFor("endpoints"));
export const service = Object.freeze(factoriesFor("services"));
export const dnsServer = Object.freeze(factoriesFor("dns.servers"));
export const certificateProvider = Object.freeze(factoriesFor("certificate_providers"));
export const networkNamespace = Object.freeze(factoriesFor("network_namespaces"));
export const httpClient: Factory<"http_clients", "http-client"> =
  factoriesFor("http_clients").httpClient;
export const ruleSet = Object.freeze(
  factoriesFor("route.rule_set") as {
    inline(
      options: Omit<Options<"route.rule_set", "inline">, "tag"> & { tag: string },
    ): Built<"route.rule_set", "inline">;
    local: RuleSetFactory<"local">;
    remote: RuleSetFactory<"remote">;
  },
);
