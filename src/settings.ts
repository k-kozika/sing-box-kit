import type {
  DomainResolver as SBKitDomainResolver,
  HTTPClientReference,
  InboundTLSOptions,
  OutboundTLSOptions,
  SBKitInputs,
} from "./generated/sbkit-inputs";
import { inputProperty, schemaShape, tagReference } from "./input-schema";
import { copyJson, fieldsFrom, record, resourceData } from "./resource";
import type { CertificateProvider, HttpClientValue, Resolve } from "./resource";
import {
  checkSchema,
  definition,
  definitionName,
  durationNanoseconds,
  fail,
  keyPath,
  tlsProfileValidators,
} from "./schema";
import type { SchemaNode } from "./schema";
import type { Fields, ReadonlyJson } from "./type-utils";

export type DomainResolver = ReadonlyJson<SBKitDomainResolver>;
export type DirectDial = ReadonlyJson<SBKitInputs["factories"]["outbounds"]["direct"]["dial"]>;
export type Dial = ReadonlyJson<SBKitInputs["factories"]["outbounds"]["vless"]["dial"]>;
export type InboundListener = ReadonlyJson<SBKitInputs["factories"]["inbounds"]["mixed"]["listen"]>;
export type Listener = Omit<InboundListener, "detour">;

export type ServerTls = { side: "server"; reality?: never } & (
  | (Required<Pick<InboundTLSOptions, "certificate_path" | "key_path">> & {
      certificate_provider?: never;
    })
  | { certificate_provider: CertificateProvider; certificate_path?: never; key_path?: never }
);
export type ClientTls = { side: "client"; reality?: never } & ReadonlyJson<
  Pick<OutboundTLSOptions, "server_name" | "certificate_path">
>;
export type RealityServerTls = {
  side: "server";
  server_name: string;
  certificate_path?: never;
  key_path?: never;
  certificate_provider?: never;
  reality: {
    private_key: string;
    short_id: string | readonly string[];
    handshake: { server: string; server_port: number } & Dial;
  };
};
export type RealityClientTls = {
  side: "client";
  server_name: string;
  certificate_path?: never;
  reality: { public_key: string; short_id: string };
};

export type InlineHttpClient = ReadonlyJson<Exclude<HTTPClientReference, HttpClientValue>> & {
  readonly tag?: never;
};
export type HttpClientInput = ReadonlyJson<HTTPClientReference>;

export const previewReference: Resolve = (value, role, path) => {
  if (!resourceData(value)) fail(path, `expected a typed ${role} reference`);
  return "reference";
};

export function checkDial(fields: Fields, path: string): void {
  const timeout = durationNanoseconds(fields.connect_timeout, `${path}.connect_timeout`);
  if (fields.detour === undefined) return;
  if (timeout !== 0) fail(`${path}.connect_timeout`, "non-zero timeout with detour");
  if (fields.netns !== undefined && fields.netns !== "")
    fail(`${path}.netns`, "namespace with detour");
}

const discriminators = ["type", "version", "provider"] as const;

export function matchesDiscriminators(schema: SchemaNode, fields: Fields): boolean {
  return discriminators.every((key) => {
    const property = schema.properties?.[key];
    if (property?.const === undefined && !property?.enum) return true;
    const value = fields[key];
    if (value === undefined) return !schema.required?.includes(key);
    return property.const === value || property.enum?.includes(value) === true;
  });
}

function matchesShape(input: SchemaNode, value: unknown): boolean {
  const schema = schemaShape(input);
  const alternatives = schema.oneOf ?? schema.anyOf;
  if (alternatives) return alternatives.some((option) => matchesShape(option, value));
  if (schema.const !== undefined) return value === schema.const;
  if (schema.enum) return schema.enum.includes(value);
  if (resourceData(value)) return schema["x-tag-reference"] !== undefined;
  if (schema.type === "array") return Array.isArray(value);
  if (schema.type === "object") {
    return (
      value !== null &&
      typeof value === "object" &&
      !Array.isArray(value) &&
      matchesDiscriminators(schema, value as Fields)
    );
  }
  if (schema.type === "integer") return typeof value === "number";
  return schema.type === undefined || typeof value === schema.type;
}

/** Expand annotated tags anywhere in a schema-shaped input. Ajv checks the resulting JSON. */
export function expandInput(
  input: SchemaNode,
  value: unknown,
  path: string,
  resolve: Resolve,
): unknown {
  const name = definitionName(input);
  if (name === "HTTPClientReference") {
    const client = resourceData(value);
    if (client?.target === "http_clients" && client.fields.tag === undefined) {
      return expandInput(definition("HTTPClient"), client.fields, path, resolve);
    }
  }

  const schema = schemaShape(input);
  const annotation = schema["x-tag-reference"];
  if (annotation !== undefined) {
    const reference = tagReference(annotation);
    if ("allowString" in reference && typeof value === "string") return value;
    return resolve(value, reference.role, path);
  }

  const alternatives = schema.oneOf ?? schema.anyOf;
  if (alternatives) {
    const option = alternatives.find((branch) => matchesShape(branch, value));
    return option ? expandInput(option, value, path, resolve) : copyJson(value, path);
  }
  if (schema.items && Array.isArray(value)) {
    const items = schema.items;
    return Array.from(value, (item, index) =>
      expandInput(items, item, `${path}[${index}]`, resolve),
    );
  }
  if (
    schema.type === "object" &&
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value)
  ) {
    const fields = record(value, path);
    const detour = schema.properties?.detour?.["x-tag-reference"];
    if (detour === "dial_detour" || detour === "outbound") checkDial(fields, path);
    const additional =
      typeof schema.additionalProperties === "object" ? schema.additionalProperties : {};
    return Object.fromEntries(
      Object.entries(fields)
        .filter(([, item]) => item !== undefined)
        .map(([key, item]) => {
          const property =
            schema.properties && Object.hasOwn(schema.properties, key)
              ? schema.properties[key]!
              : additional;
          return [
            key,
            expandInput(inputProperty(key, property), item, keyPath(path, key), resolve),
          ];
        }),
    );
  }
  return copyJson(value, path);
}

export function listenFields(
  address: unknown,
  input: unknown,
  path: string,
  schema: SchemaNode,
): Fields {
  const { port, ...options } = fieldsFrom(input, path, Object.keys(schema.properties!));
  if (address !== undefined) {
    if (!Object.hasOwn(schema.properties!, "port")) fail(`${path}.listen`, "unexpected field");
    if (typeof address !== "string") fail(`${path}.listen`, "expected a string");
    options.listen = address;
  }
  if (port !== undefined) options.listen_port = port;
  return options;
}

export type TlsMode = "server" | "client" | "server-reality" | "client-reality";

export function tlsFields(
  input: unknown,
  path: string,
  schema: SchemaNode,
  mode?: TlsMode,
): Fields {
  const profile = record(input, path);
  const enabled = Object.hasOwn(schemaShape(schema).properties ?? {}, "enabled");
  if (!Object.hasOwn(profile, "side")) {
    return {
      tls: enabled && profile.enabled === undefined ? { ...profile, enabled: true } : profile,
    };
  }
  if (!mode) fail(`${path}.side`, "unsupported TLS profile");
  const server = mode === "server" || mode === "server-reality";
  const isReality = profile.reality !== undefined;
  if (isReality && !mode.endsWith("-reality")) fail(`${path}.reality`, "unsupported TLS profile");
  const validate = server
    ? isReality
      ? tlsProfileValidators.server.reality
      : profile.certificate_provider === undefined
        ? tlsProfileValidators.server.files
        : tlsProfileValidators.server.provider
    : isReality
      ? tlsProfileValidators.client.reality
      : tlsProfileValidators.client.regular;

  checkSchema(validate, expandInput(schema, profile, path, previewReference), path);
  const { side: _side, ...fields } = profile;
  if (isReality) {
    fields.reality = { ...record(profile.reality, `${path}.reality`), enabled: true };
    if (!server) fields.utls = { enabled: true };
  }
  return { tls: { ...fields, enabled: true } };
}

export function checkSsmServers(value: unknown, path: string): void {
  const servers = Object.keys(record(value, path));
  if (servers.length === 0) fail(path, "expected at least one SSM server");
  for (const pattern of servers) {
    if (!pattern.startsWith("/")) {
      fail(`${path}[${JSON.stringify(pattern)}]`, "expected a route pattern starting with /");
    }
  }
}

const directDialProperties = definition("DialerOptions").properties!;

export function isEmptyDirect(fields: Fields): boolean {
  return Object.entries(fields).every(([key, value]) => {
    if (value === undefined || !Object.hasOwn(directDialProperties, key)) return true;
    if (definitionName(directDialProperties[key]!) === "Duration") {
      return durationNanoseconds(value, key) === 0;
    }
    if (key === "udp_fragment") return false; // This setting distinguishes false from omission.
    if (key === "routing_mark") return Number(value) === 0;
    return value === "" || value === 0 || value === false;
  });
}
