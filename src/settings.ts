import type {
  DomainResolver as RawDomainResolver, HTTPClient, HTTPClientReference, InboundRealityHandshakeOptions,
  InboundTLSOptions, OutboundTLSOptions,
} from "./generated/sing-box";
import {
  expandFields, fieldsFrom, record, ref, resourceData,
} from "./resource";
import type {
  CertificateProvider, DnsServer, Egress, Expand, Expansions, Fields, ListenDetour, Namespace,
  ReadonlyJson, Resolve, Resource,
} from "./resource";
import {
  checkSchema, compileSchema, definition, durationNanoseconds, fail, tlsProfileValidators,
} from "./schema";

export type DomainResolver = DnsServer
  | ReadonlyJson<Omit<Extract<RawDomainResolver, object>, "server">> & { readonly server: DnsServer };

export interface DirectDial {
  /**
   * Go Duration string. An explicit detour disallows a non-zero timeout on
   * the resource using it. Configure the timeout on the detour target.
   * On a direct detour target, an effective zero is equivalent to omission.
   */
  readonly connect_timeout?: HTTPClient["connect_timeout"];
  readonly domain_resolver?: DomainResolver;
  readonly netns?: Namespace | string;
}

export interface Dial extends DirectDial {
  readonly detour?: Egress;
}

export interface Listener {
  readonly port: number;
  readonly netns?: Namespace | string;
}

export interface InboundListener extends Listener {
  readonly detour?: ListenDetour;
}

export type ServerTls = { side: "server"; reality?: never } & (
  | Required<Pick<InboundTLSOptions, "certificate_path" | "key_path">> & { certificate_provider?: never }
  | { certificate_provider: CertificateProvider; certificate_path?: never; key_path?: never }
);
export type ClientTls = { side: "client"; reality?: never }
  & ReadonlyJson<Pick<OutboundTLSOptions, "server_name" | "certificate_path">>;
export type RealityServerTls = {
  side: "server";
  server_name: string;
  certificate_path?: never;
  key_path?: never;
  certificate_provider?: never;
  reality: {
    private_key: string;
    short_id: string | readonly string[];
    handshake: Required<Pick<InboundRealityHandshakeOptions, "server" | "server_port">> & Dial;
  };
};
export type RealityClientTls = {
  side: "client";
  server_name: string;
  certificate_path?: never;
  reality: { public_key: string; short_id: string };
};

export type HttpClientValue = Resource<"http_clients", "http-client", string | undefined>;
export type InlineHttpClient = ReadonlyJson<Omit<Extract<HTTPClientReference, object>, keyof Dial>>
  & Dial & { readonly tag?: never };
export type HttpClientInput = HttpClientValue | InlineHttpClient;

export const previewReference: Resolve = (value, role, path) => {
  if (!resourceData(value)) fail(path, `expected a typed ${role} reference`);
  return "reference";
};

export const expandResolver: Expand = (value, path, resolve) => {
  if (resourceData(value) || typeof value !== "object" || value === null) {
    return resolve(value, "dns-server", path);
  }
  const options = record(value, path);
  if (options.server === undefined) fail(`${path}.server`, "required field");
  return expandFields(options, { server: ref("dns-server") }, path, resolve);
};

const expandNamespace: Expand = (value, path, resolve) =>
  typeof value === "string" ? value : resolve(value, "netns", path);
export const listenReferences = { netns: expandNamespace, detour: ref("listen-detour") };
export const dialReferences = {
  netns: expandNamespace, detour: ref("dial-detour"), domain_resolver: expandResolver,
};

export function checkDial(fields: Fields, path: string): void {
  const timeout = durationNanoseconds(fields.connect_timeout, `${path}.connect_timeout`);
  if (fields.detour === undefined) return;
  if (timeout !== 0) fail(`${path}.connect_timeout`, "non-zero timeout with detour");
  if (fields.netns !== undefined && fields.netns !== "") fail(`${path}.netns`, "namespace with detour");
}

const commonDialKeys = ["connect_timeout", "domain_resolver", "netns"] as const satisfies readonly (keyof DirectDial)[];
export function dialFields(input: unknown, path: string, detour: boolean): Fields {
  const fields = fieldsFrom(input, path, detour ? [...commonDialKeys, "detour"] : commonDialKeys);
  checkDial(fields, path);
  return fields;
}

export function listenFields(address: string, input: unknown, path: string, detour: boolean): Fields {
  const { port, ...options } = fieldsFrom(input, path,
    detour ? ["port", "netns", "detour"] : ["port", "netns"], ["port"]);
  if (typeof address !== "string") fail(`${path}.listen`, "expected a string");
  return { listen: address, listen_port: port, ...options };
}

const expandReality: Expand = (value, path, resolve) =>
  expandFields(record(value, path), {
    handshake: (handshake, path, resolve) => expandFields(record(handshake, path), dialReferences, path, resolve),
  }, path, resolve);

export const expandTls: Expand = (value, path, resolve) =>
  expandFields(record(value, path), {
    certificate_provider: ref("certificate-provider"),
    reality: expandReality,
  }, path, resolve);

export type TlsMode = "server" | "client" | "server-reality" | "client-reality";

export function tlsFields(input: unknown, path: string, mode: TlsMode): Fields {
  const profile = record(input, path);
  const server = mode === "server" || mode === "server-reality";
  const isReality = profile.reality !== undefined;
  if (isReality && !mode.endsWith("-reality")) fail(`${path}.reality`, "unsupported TLS profile");
  const validate = server
    ? isReality ? tlsProfileValidators.server.reality
      : profile.certificate_provider === undefined ? tlsProfileValidators.server.files : tlsProfileValidators.server.provider
    : isReality ? tlsProfileValidators.client.reality : tlsProfileValidators.client.regular;

  checkSchema(validate, expandTls(profile, path, previewReference), path);
  const { side, ...fields } = profile;
  if (isReality) {
    const reality = record(profile.reality, `${path}.reality`);
    if (server) checkDial(record(reality.handshake, `${path}.reality.handshake`), `${path}.reality.handshake`);
    fields.reality = { ...reality, enabled: true };
    if (!server) fields.utls = { enabled: true };
  }
  return { tls: { ...fields, enabled: true } };
}

const httpClientObject = compileSchema(definition("HTTPClientReference").anyOf![1]!);
export const expandHttpClient: Expand = (value, path, resolve) => {
  const data = resourceData(value);
  if (data) {
    if (data.target === "http_clients" && data.fields.tag === undefined) {
      return expandFields(data.fields, data.references ?? {}, path, resolve);
    }
    return resolve(value, "http-client", path);
  }
  const fields = record(value, path);
  if (Object.hasOwn(fields, "tag")) fail(`${path}.tag`, "unexpected field");
  checkDial(fields, path);
  const output = expandFields(fields, dialReferences, path, resolve);
  return checkSchema(httpClientObject, output, path);
};

export const expandDashboard: Expand = (value, path, resolve) =>
  typeof value === "string" || typeof value === "boolean" ? value
    : expandFields(record(value, path), { http_client: expandHttpClient }, path, resolve);

export const expandSsmServers: Expand = (value, path, resolve) => {
  const servers = Object.entries(record(value, path));
  if (servers.length === 0) fail(path, "expected at least one SSM server");
  return Object.fromEntries(servers.map(([pattern, inbound]) => {
    const fieldPath = `${path}[${JSON.stringify(pattern)}]`;
    if (!pattern.startsWith("/")) fail(fieldPath, "expected a route pattern starting with /");
    return [pattern, resolve(inbound, "ssm", fieldPath)];
  }));
};

export function isEmptyDirect(fields: Fields): boolean {
  return durationNanoseconds(fields.connect_timeout, "connect_timeout") === 0
    && (fields.netns === undefined || fields.netns === "") && fields.domain_resolver === undefined;
}
