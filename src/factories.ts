import type {
  CertificateProvider as RawProvider,
  DNSServer as RawDnsServer,
  Endpoint as RawEndpoint,
  HeadlessRule,
  HTTPClient,
  Inbound as RawInbound,
  NetworkNamespace as RawNamespace,
  Outbound as RawOutbound,
  RuleSet as RawRuleSet,
  Service as RawService,
  ShadowsocksUser,
  User as RawUser,
  VLESSUser,
} from "./generated/sing-box";
import {
  arrayOrOne,
  createResource,
  expandFields,
  fieldsFrom,
  record,
  ref,
  resourceData,
  snapshot,
} from "./resource";
import type {
  Egress,
  Expansions,
  Fields,
  ReadonlyJson,
  Resource,
  Role,
  SsmInbound,
  TailscaleEndpoint,
  Target,
} from "./resource";
import { Rule } from "./rules";
import type { Condition } from "./rules";
import { checkSchema, compileSchema, definition, fail, keyPath, variant } from "./schema";
import {
  dialFields,
  dialReferences,
  expandDashboard,
  expandHttpClient,
  expandSsmServers,
  expandTls,
  listenFields,
  listenReferences,
  previewReference,
  tlsFields,
} from "./settings";
import type {
  ClientTls,
  Dial,
  DirectDial,
  HttpClientInput,
  InboundListener,
  Listener,
  RealityClientTls,
  RealityServerTls,
  ServerTls,
  TlsMode,
} from "./settings";
import { isUser } from "./user";
import type { User } from "./user";

interface ListenMethod<T> {
  listen(address: string, options: T): this;
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

const targetSchema = {
  inbounds: "Inbound",
  outbounds: "Outbound",
  endpoints: "Endpoint",
  services: "Service",
  http_clients: "HTTPClient",
  "dns.servers": "DNSServer",
  "route.rule_set": "RuleSet",
  certificate_providers: "CertificateProvider",
  network_namespaces: "NetworkNamespace",
} as const satisfies Record<Target, string>;
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

type PasswordEntry<Name extends "username" | "name"> = {
  readonly user: User;
  readonly password: string;
} & { readonly [K in Name]?: never };
type MixedEntry = PasswordEntry<"username"> | (Readonly<RawUser> & { user?: never });
type ShadowsocksEntry = PasswordEntry<"name"> | (Readonly<ShadowsocksUser> & { user?: never });
type VlessEntry = Required<Pick<VLESSUser, "uuid">> &
  Pick<VLESSUser, "flow"> & { user: User; name?: never };

interface AuthOptions {
  readonly name: "name" | "username";
  readonly credentials: readonly string[];
  readonly required: readonly string[];
  readonly allowRaw?: boolean;
}

interface Definition {
  readonly target: Target;
  readonly kind: string;
  readonly required: readonly string[];
  readonly optional?: readonly string[];
  readonly listen?: "listener" | "forwarding";
  readonly dial?: "direct" | "detour";
  readonly tls?: TlsMode;
  readonly auth?: AuthOptions;
  readonly roles?: readonly Role[];
  readonly references?: Expansions;
  readonly remoteDns?: boolean;
  readonly startupDetour?: boolean;
  readonly prepare?: (fields: Fields, path: string) => readonly Role[] | void;
  readonly checkDial?: (fields: Fields, dial: Fields, path: string) => void;
}

type RawByTarget = {
  inbounds: RawInbound;
  outbounds: RawOutbound;
  endpoints: RawEndpoint;
  services: RawService;
  http_clients: HTTPClient;
  "dns.servers": RawDnsServer;
  "route.rule_set": RawRuleSet;
  certificate_providers: RawProvider;
  network_namespaces: RawNamespace;
};
type Variant<Raw, Kind> = Raw extends { type?: infer Type }
  ? Kind extends Type
    ? Raw
    : never
  : never;
type Raw<D extends Definition> = D["target"] extends "http_clients"
  ? HTTPClient
  : Variant<RawByTarget[D["target"]], D["kind"]>;
type Options<D extends Definition> = ReadonlyJson<
  Required<Pick<Raw<D>, Extract<D["required"][number], keyof Raw<D>>>> &
    Pick<Raw<D>, Extract<NonNullable<D["optional"]>[number], keyof Raw<D>>>
>;
type Override<T, U> = Omit<T, keyof U> & U;

type TlsProfile = {
  server: ServerTls;
  client: ClientTls;
  "server-reality": ServerTls | RealityServerTls;
  "client-reality": ClientTls | RealityClientTls;
};
type Tag = string | readonly string[] | undefined;
type ExtraRoles<D> = D extends { roles: readonly (infer R extends Role)[] } ? R : never;
type Built<D extends Definition, T extends Tag = string> = Resource<
  D["target"],
  D["kind"],
  T,
  (typeof targetRoles)[D["target"]][number] | ExtraRoles<D>
> &
  (D extends { listen: infer L }
    ? ListenMethod<L extends "forwarding" ? InboundListener : Listener>
    : unknown) &
  (D extends { dial: infer F } ? DialMethod<F extends "direct" ? DirectDial : Dial> : unknown) &
  (D extends { tls: infer P extends TlsMode } ? TlsMethod<TlsProfile[P]> : unknown) &
  (D extends { auth: AuthOptions } ? AuthMethod : unknown);

type SettingsGroup = "listen" | "dial" | "tls";
const settingsGroups = ["listen", "dial", "tls"] as const;
const validators = new WeakMap<Definition, ReturnType<typeof compileSchema>>();

function validateFactoryOutput(def: Definition, fields: Fields, path: string): void {
  let validate = validators.get(def);
  if (!validate) {
    const name = targetSchema[def.target];
    validate = compileSchema(
      def.target === "http_clients" ? definition(name) : variant(name, def.kind),
    );
    validators.set(def, validate);
  }
  checkSchema(validate, fields, path);
}

interface Membership {
  readonly user?: User;
  readonly name: unknown;
}

function prepareUsers(fields: Fields, auth: AuthOptions, path: string): readonly Membership[] {
  if (fields.users === undefined) return [];
  const users = fields.users;
  if (!Array.isArray(users)) fail(`${path}.users`, "expected an array");
  const members: Membership[] = [];
  fields.users = Array.from(users, (value, index) => {
    const entryPath = `${path}.users[${index}]`;
    const entry = record(value, entryPath);
    if (!Object.hasOwn(entry, "user") && auth.allowRaw) {
      const raw = fieldsFrom(entry, entryPath, [auth.name, ...auth.credentials]);
      members.push({ name: raw[auth.name] });
      return raw;
    }
    if (Object.hasOwn(entry, auth.name))
      fail(keyPath(entryPath, auth.name), "explicit name with User");
    const { user, ...credentials } = fieldsFrom(
      entry,
      entryPath,
      ["user", ...auth.credentials],
      ["user", ...auth.required],
    );
    if (!isUser(user)) fail(`${entryPath}.user`, "expected a User");
    members.push({ user, name: user.name });
    return { [auth.name]: user.name, ...credentials };
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

function build<D extends Definition, T extends Tag>(def: D, input: unknown): Built<D, T> {
  const path = `${def.target}.${def.kind}`;
  const options = fieldsFrom(input, path, [...def.required, ...(def.optional ?? [])], def.required);
  validateTag(options.tag, `${path}.tag`);
  const members = def.auth ? prepareUsers(options, def.auth, path) : [];
  const extraRoles = def.prepare?.(options, path) ?? [];
  const roles = Object.freeze([...targetRoles[def.target], ...(def.roles ?? []), ...extraRoles]);
  const base = snapshot(
    def.target === "http_clients" ? options : { type: def.kind, ...options },
    path,
  );
  const references = Object.freeze({
    ...def.references,
    ...(def.listen ? listenReferences : {}),
    ...(def.dial ? dialReferences : {}),
    ...(def.tls ? { tls: expandTls } : {}),
  });

  function create(groups: Partial<Record<SettingsGroup, Fields>>): Built<D, T> {
    const fields = { ...base };
    for (const group of settingsGroups) {
      for (const [key, value] of Object.entries(groups[group] ?? {})) {
        if (Object.hasOwn(fields, key)) fail(keyPath(path, key), "conflicting output field");
        fields[key] = value;
      }
    }
    validateFactoryOutput(def, expandFields(fields, references, path, previewReference), path);

    const apply = (group: SettingsGroup, getFields: () => Fields) => {
      if (groups[group]) fail(keyPath(path, group), "settings group already applied");
      return create({ ...groups, [group]: snapshot(getFields(), path) });
    };
    const methods: Fields = {};
    if (def.listen)
      methods.listen = (address: string, input: unknown) =>
        apply("listen", () => listenFields(address, input, path, def.listen === "forwarding"));
    if (def.dial)
      methods.dial = (input: unknown) =>
        apply("dial", () => {
          const dial = dialFields(input, path, def.dial === "detour");
          def.checkDial?.(fields, dial, path);
          return dial;
        });
    const tlsMode = def.tls;
    if (tlsMode)
      methods.tls = (input: unknown) =>
        apply("tls", () => tlsFields(input, `${path}.tls`, tlsMode));
    if (def.auth)
      methods.authUser = (user: User) => {
        const matching = members.filter((entry) => entry.user === user);
        if (
          !isUser(user) ||
          matching.length !== 1 ||
          !user.name ||
          members.filter((entry) => entry.name === user.name).length !== 1
        ) {
          fail(`${path}.authUser`, "expected one User entry with a unique non-empty name");
        }
        return Rule.match({
          inbound: resource as unknown as Resource<"inbounds", string, string>,
          auth_user: user.name,
        });
      };
    const resource = createResource<Built<D, T>>(
      Object.freeze({
        target: def.target,
        kind: def.kind,
        fields: Object.freeze(fields),
        references,
        roles,
        remoteDns: def.remoteDns,
        startupDetour: def.startupDetour,
      }),
      methods,
    );
    return resource;
  }
  return create({});
}

function factory<const D extends Definition>(def: D) {
  return (options: Options<D>): Built<D> => build(def, options);
}

const passwordAuth = {
  name: "username",
  credentials: ["password"],
  required: ["password"],
} as const;
const mixed = {
  target: "inbounds",
  kind: "mixed",
  required: ["tag"],
  optional: ["users", "set_system_proxy"],
  listen: "forwarding",
  tls: "server",
  auth: { ...passwordAuth, allowRaw: true },
} as const satisfies Definition;
const socks = {
  target: "inbounds",
  kind: "socks",
  required: ["tag"],
  optional: ["users"],
  listen: "forwarding",
  auth: passwordAuth,
} as const satisfies Definition;
const inboundVless = {
  target: "inbounds",
  kind: "vless",
  required: ["tag", "users"],
  listen: "forwarding",
  tls: "server-reality",
  auth: { name: "name", credentials: ["uuid", "flow"], required: ["uuid"] },
} as const satisfies Definition;

const shadowsocks = {
  target: "inbounds",
  kind: "shadowsocks",
  required: ["tag", "method"],
  optional: ["network", "password", "users", "managed"],
  listen: "forwarding",
  auth: { ...passwordAuth, name: "name", allowRaw: true },
  prepare(fields, path) {
    const hasUsers = Array.isArray(fields.users) && fields.users.length > 0;
    if (hasUsers && fields.managed === true)
      fail(`${path}.users`, "managed mode cannot have static users");
    if (hasUsers || fields.managed === true) {
      if (fields.method === "none")
        fail(`${path}.method`, "method none is unavailable in multi-user modes");
      return ["ssm"];
    }
  },
} as const satisfies Definition;
type ShadowsocksBase = Omit<Options<typeof shadowsocks>, "method" | "users" | "managed">;
type Method = NonNullable<Extract<RawInbound, { type: "shadowsocks" }>["method"]>;
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
function makeShadowsocks(
  options: ManagedShadowsocks | StaticShadowsocks,
): Built<typeof shadowsocks> & SsmInbound;
function makeShadowsocks(options: ShadowsocksOptions): Built<typeof shadowsocks>;
function makeShadowsocks(options: ShadowsocksOptions): Built<typeof shadowsocks> {
  return build(shadowsocks, options);
}

export const inbound = Object.freeze({
  mixed: (options: Override<Options<typeof mixed>, { users?: readonly MixedEntry[] }>) =>
    build<typeof mixed, string>(mixed, options),
  socks: (
    options: Override<Options<typeof socks>, { users?: readonly PasswordEntry<"username">[] }>,
  ) => build<typeof socks, string>(socks, options),
  vless: (options: Override<Options<typeof inboundVless>, { users: readonly VlessEntry[] }>) =>
    build<typeof inboundVless, string>(inboundVless, options),
  shadowsocks: makeShadowsocks,
});

const api = {
  target: "services",
  kind: "api",
  required: [],
  optional: [
    "tag",
    "secret",
    "dashboard",
    "access_control_allow_origin",
    "access_control_allow_private_network",
  ],
  listen: "listener",
  tls: "server",
  references: { dashboard: expandDashboard },
} as const satisfies Definition;
type RawDashboard = NonNullable<Extract<RawService, { type: "api" }>["dashboard"]>;
type Dashboard =
  | boolean
  | string
  | Override<ReadonlyJson<Extract<RawDashboard, object>>, { http_client?: HttpClientInput }>;
const ssmApi = {
  target: "services",
  kind: "ssm-api",
  required: ["servers"],
  optional: ["tag", "cache_path"],
  listen: "listener",
  tls: "server",
  references: { servers: expandSsmServers },
} as const satisfies Definition;

export const service = Object.freeze({
  /**
   * sing-box defaults to loopback (127.0.0.1). An omitted or empty secret allows
   * unauthenticated connections. Omitting server TLS uses plaintext TCP.
   */
  api: (options: Override<Options<typeof api>, { dashboard?: Dashboard }> = {}) =>
    build<typeof api, string | undefined>(api, options),
  ssmApi: (
    options: Override<Options<typeof ssmApi>, { servers: Readonly<Record<string, SsmInbound>> }>,
  ) => build<typeof ssmApi, string | undefined>(ssmApi, options),
});

const http = {
  target: "http_clients",
  kind: "http-client",
  required: [],
  optional: ["version", "headers", "tag"],
  dial: "detour",
  tls: "client",
} as const satisfies Definition;
export function httpClient(
  options: Options<typeof http> & { tag: string },
): Built<typeof http, string>;
export function httpClient(options?: Options<typeof http>): Built<typeof http, string | undefined>;
export function httpClient(
  options: Options<typeof http> = {},
): Built<typeof http, string | undefined> {
  return build(http, options);
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
const selector = {
  target: "outbounds",
  kind: "selector",
  required: ["tag", "outbounds"],
  optional: ["default", "interrupt_exist_connections"],
  prepare: checkGroup,
  references: { outbounds: arrayOrOne(ref("egress")), default: ref("egress") },
} as const satisfies Definition;
const urltest = {
  target: "outbounds",
  kind: "urltest",
  required: ["tag", "outbounds"],
  optional: ["url", "interval", "tolerance", "idle_timeout", "interrupt_exist_connections"],
  prepare: checkGroup,
  references: { outbounds: arrayOrOne(ref("egress")) },
} as const satisfies Definition;
export const outbound = Object.freeze({
  direct: factory({ target: "outbounds", kind: "direct", required: ["tag"], dial: "direct" }),
  vless: factory({
    target: "outbounds",
    kind: "vless",
    required: ["tag", "server", "server_port", "uuid"],
    optional: ["flow"],
    dial: "detour",
    tls: "client-reality",
    startupDetour: true,
  }),
  selector: (
    options: Override<Options<typeof selector>, { outbounds: readonly Egress[]; default?: Egress }>,
  ) => build<typeof selector, string>(selector, options),
  urltest: (options: Override<Options<typeof urltest>, { outbounds: readonly Egress[] }>) =>
    build<typeof urltest, string>(urltest, options),
});

export const endpoint = Object.freeze({
  tailscale: factory({
    target: "endpoints",
    kind: "tailscale",
    required: ["tag"],
    optional: [
      "state_directory",
      "auth_key",
      "hostname",
      "accept_routes",
      "exit_node",
      "listen_port",
    ],
    dial: "detour",
    roles: ["preferred-routes", "tailscale-endpoint"],
  }),
  wireguard: factory({
    target: "endpoints",
    kind: "wireguard",
    required: ["tag", "address", "private_key"],
    optional: ["peers", "listen_port", "system"],
    dial: "detour",
    startupDetour: true,
    roles: ["preferred-routes"],
    checkDial(fields, dial, path) {
      if (
        dial.detour !== undefined &&
        fields.listen_port !== undefined &&
        fields.listen_port !== 0
      ) {
        fail(`${path}.listen_port`, "non-zero WireGuard listen port with detour");
      }
    },
  }),
});

const remoteDns = {
  target: "dns.servers",
  required: ["tag", "server"],
  optional: ["server_port"],
  dial: "detour",
  remoteDns: true,
} as const;
const tailscaleDns = {
  target: "dns.servers",
  kind: "tailscale",
  required: ["tag", "endpoint"],
  optional: ["accept_default_resolvers", "accept_search_domain"],
  roles: ["preferred-domain"],
  references: { endpoint: ref("tailscale-endpoint") },
} as const satisfies Definition;
export const dnsServer = Object.freeze({
  tcp: factory({ ...remoteDns, kind: "tcp" }),
  udp: factory({ ...remoteDns, kind: "udp" }),
  tls: factory({ ...remoteDns, kind: "tls", tls: "client" }),
  https: factory({
    ...remoteDns,
    kind: "https",
    tls: "client",
    optional: ["server_port", "path", "headers"],
  }),
  tailscale: (options: Override<Options<typeof tailscaleDns>, { endpoint: TailscaleEndpoint }>) =>
    build<typeof tailscaleDns, string>(tailscaleDns, options),
});

const tailscaleProvider = {
  target: "certificate_providers",
  kind: "tailscale",
  required: ["tag", "endpoint"],
  references: { endpoint: ref("tailscale-endpoint") },
} as const satisfies Definition;
export const certificateProvider = Object.freeze({
  tailscale: (
    options: Override<Options<typeof tailscaleProvider>, { endpoint: TailscaleEndpoint }>,
  ) => build<typeof tailscaleProvider, string>(tailscaleProvider, options),
});

export const networkNamespace = Object.freeze({
  default: factory({ target: "network_namespaces", kind: "default", required: ["tag", "path"] }),
  unshare: factory({
    target: "network_namespaces",
    kind: "unshare",
    required: ["tag"],
    optional: ["pid_file"],
  }),
});

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

const inlineRuleSet = {
  target: "route.rule_set",
  kind: "inline",
  required: ["tag", "rules"],
  prepare(fields, path) {
    if (!Array.isArray(fields.rules) || !fields.rules.length)
      fail(`${path}.rules`, "expected at least one rule");
  },
} as const satisfies Definition;
const localRuleSet = {
  target: "route.rule_set",
  kind: "local",
  required: ["tag", "path"],
  optional: ["format"],
  prepare: (fields, path) => ruleSetFormat(fields, path, "path"),
} as const satisfies Definition;
const remoteRuleSet = {
  target: "route.rule_set",
  kind: "remote",
  required: ["tag", "url"],
  optional: ["format", "initial_path", "update_interval", "http_client"],
  references: { http_client: expandHttpClient },
  prepare: (fields, path) => ruleSetFormat(fields, path, "url"),
} as const satisfies Definition;
function requireSingleTag(fields: Fields, path: string): void {
  if (typeof fields.tag !== "string") fail(`${path}.tag`, "expected a single tag");
}

export const ruleSet = Object.freeze({
  inline(options: {
    tag: string;
    rules: readonly ReadonlyJson<HeadlessRule>[];
  }): Built<typeof inlineRuleSet> {
    requireSingleTag(record(options, "ruleSet.inline"), "ruleSet.inline");
    return build(inlineRuleSet, options);
  },
  local<const T extends string | readonly string[]>(
    options: Override<Options<typeof localRuleSet>, { tag: T }>,
  ) {
    return build<typeof localRuleSet, T>(localRuleSet, options);
  },
  remote<const T extends string | readonly string[]>(
    options: Override<Options<typeof remoteRuleSet>, { tag: T; http_client?: HttpClientInput }>,
  ) {
    return build<typeof remoteRuleSet, T>(remoteRuleSet, options);
  },
});
