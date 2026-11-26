import { fail, keyPath } from "./schema";
import type { Fields } from "./type-utils";

export type Target =
  | "inbounds"
  | "outbounds"
  | "endpoints"
  | "services"
  | "http_clients"
  | "dns.servers"
  | "route.rule_set"
  | "certificate_providers"
  | "network_namespaces";
export type Role =
  | "inbound"
  | "listen-detour"
  | "dial-detour"
  | "egress"
  | "preferred-routes"
  | "dns-server"
  | "preferred-domain"
  | "ssm"
  | "certificate-provider"
  | "http-client"
  | "netns"
  | "rule-set"
  | "tailscale-endpoint"
  | "openconnect-endpoint"
  | "openvpn-client-endpoint"
  | "resolved-service";

declare const resourceBrand: unique symbol;
export interface Resource<
  T extends Target = Target,
  K extends string = string,
  Tag extends string | readonly string[] | undefined = string | readonly string[] | undefined,
  R extends Role = Role,
> {
  readonly [resourceBrand]: { target: T; kind: K; tag: Tag; roles: R };
}

export type InboundRef = Resource<"inbounds" | "endpoints", string, string>;
export type ListenDetour = Resource<
  "inbounds",
  string,
  string,
  "listen-detour" | "inbound" | "ssm"
>;
export type Egress = Resource<"outbounds" | "endpoints", string, string>;
export const preferredRouteEndpoints = [
  "tailscale",
  "wireguard",
  "openconnect",
  "openvpn-client",
] as const;
export type PreferredRoutes =
  | Resource<"endpoints", (typeof preferredRouteEndpoints)[number], string>
  | Resource<"outbounds", "bridge", string>;
export type DnsServer = Resource<"dns.servers", string, string>;
export const preferredDnsKinds = [
  "hosts",
  "local",
  "mdns",
  "tailscale",
  "openconnect",
  "openvpn",
  "resolved",
] as const;
export type PreferredDomain = Resource<"dns.servers", (typeof preferredDnsKinds)[number], string>;
export type Namespace = Resource<"network_namespaces", string, string>;
export type CertificateProvider = Resource<"certificate_providers", string, string>;
export type TaggedHttpClient = Resource<"http_clients", "http-client", string>;
export type HttpClientValue = Resource<"http_clients", "http-client", string | undefined>;
export type RuleSetRef = Resource<"route.rule_set", string, string | readonly [string]>;
export type SsmInbound = Resource<
  "inbounds",
  "shadowsocks",
  string,
  "inbound" | "listen-detour" | "ssm"
> & { readonly [ssmBrand]: true };
declare const ssmBrand: unique symbol;
export type TailscaleEndpoint = Resource<"endpoints", "tailscale", string>;
export type OpenConnectEndpoint = Resource<"endpoints", "openconnect", string>;
export type OpenVpnClientEndpoint = Resource<"endpoints", "openvpn-client", string>;
export type ResolvedService = Resource<"services", "resolved", string>;

export type Resolve = (value: unknown, role: Role, path: string) => string;
export type Expand = (value: unknown, path: string, resolve: Resolve) => unknown;
export interface ResourceData {
  readonly target: Target;
  readonly kind: string;
  readonly fields: Fields;
  readonly roles: readonly Role[];
  readonly expand?: Expand;
  readonly startupDetour?: boolean;
  readonly remoteDns?: boolean;
}

const resources = new WeakMap<object, ResourceData>();
const identities = new WeakSet<object>();

/** Internal constructor. Factory methods supply immutable data. */
export function createResource<T extends Resource>(data: ResourceData, methods: object = {}): T {
  const value = Object.freeze(methods);
  resources.set(value, data);
  identities.add(value);
  return value as T;
}

export function resourceData(value: unknown): ResourceData | undefined {
  return value !== null && typeof value === "object" ? resources.get(value) : undefined;
}

export function preserveIdentity<T extends object>(value: T): T {
  identities.add(value);
  return Object.freeze(value);
}

export function record(value: unknown, path: string): Fields {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    identities.has(value)
  ) {
    fail(path, "expected an options object");
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) fail(path, "expected a plain object");
  return value as Fields;
}

export function fieldsFrom(
  input: unknown,
  path: string,
  allowed: readonly string[],
  required: readonly string[] = [],
): Fields {
  const value = record(input, path);
  for (const key of Object.keys(value)) {
    if (!allowed.includes(key)) fail(keyPath(path, key), "unexpected field");
  }
  for (const key of required) {
    if (!Object.hasOwn(value, key) || value[key] === undefined)
      fail(keyPath(path, key), "required field");
  }
  return Object.fromEntries(Object.entries(value).filter(([, field]) => field !== undefined));
}

function copy(value: unknown, path: string, immutable: boolean, ancestors: Set<object>): unknown {
  if (value === null || typeof value !== "object") return value;
  if (identities.has(value)) {
    if (immutable) return value;
    fail(path, "unexpected Kit value in JSON fields");
  }
  if (ancestors.has(value)) fail(path, "cyclic configuration object");
  ancestors.add(value);
  const result = Array.isArray(value)
    ? Array.from(value, (child, index) => copy(child, `${path}[${index}]`, immutable, ancestors))
    : Object.fromEntries(
        Object.entries(record(value, path)).map(([key, child]) => [
          key,
          copy(child, keyPath(path, key), immutable, ancestors),
        ]),
      );
  ancestors.delete(value);
  return immutable ? Object.freeze(result) : result;
}

export function snapshot<T>(value: T, path: string): T {
  return copy(value, path, true, new Set()) as T;
}

export function copyJson<T>(value: T, path: string): T {
  return copy(value, path, false, new Set()) as T;
}
