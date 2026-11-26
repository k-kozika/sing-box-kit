import Ajv2020 from "ajv/dist/2020.js";
import type { AnySchema, ErrorObject, ValidateFunction } from "ajv";
import official from "../schema/sing-box.json";
import type { SingBoxConfig } from "./generated/sing-box";

export function fail(path: string, category: string, tag?: string): never {
  throw new Error(
    `${path}: ${category}${tag === undefined ? "" : ` (tag ${JSON.stringify(tag)})`}`,
  );
}

export function keyPath(path: string, key: string): string {
  if (/^[A-Za-z_$][\w$]*$/.test(key)) return path ? `${path}.${key}` : key;
  return `${path}[${JSON.stringify(key)}]`;
}

const ajv = new Ajv2020({
  strict: true,
  allErrors: true,
  coerceTypes: false,
  useDefaults: false,
  removeAdditional: false,
  ownProperties: true,
});
ajv.addKeyword({ keyword: "x-tag-reference", schemaType: "string", valid: true });
const validateOfficial = ajv.compile<SingBoxConfig>(official);

function errorPath(error: ErrorObject, value: unknown, root: string): string {
  let path = root;
  let current = value;
  for (const encoded of error.instancePath.split("/").slice(1)) {
    const key = encoded.replaceAll("~1", "/").replaceAll("~0", "~");
    path = Array.isArray(current) ? `${path}[${key}]` : keyPath(path, key);
    current =
      current && typeof current === "object"
        ? (current as Record<string, unknown>)[key]
        : undefined;
  }
  const key = error.params.additionalProperty ?? error.params.missingProperty;
  return typeof key === "string" ? keyPath(path, key) : path;
}

export function checkSchema<T>(validate: ValidateFunction<T>, value: unknown, path: string): T {
  if (validate(value)) return value;
  const errors = (validate.errors ?? []).filter(
    (error) => !["anyOf", "oneOf", "if"].includes(error.keyword),
  );
  const paths = [...new Set(errors.map((error) => errorPath(error, value, path) || "config"))];
  fail(paths.join(", ") || path || "config", "schema validation failed");
}

export function validateConfig(value: unknown): SingBoxConfig {
  return checkSchema(validateOfficial, value, "");
}

// Resolve references in projected schemas against the same, untouched snapshot.
export type SchemaFields = Record<string, SchemaNode>;
export interface SchemaNode {
  type?: string;
  $ref?: string;
  const?: unknown;
  enum?: readonly unknown[];
  properties?: SchemaFields;
  oneOf?: readonly SchemaNode[];
  anyOf?: readonly SchemaNode[];
}

const definitions = official.$defs as unknown as Record<string, SchemaNode>;
export function definition(name: string): SchemaNode {
  return definitions[name] ?? fail(name, "unknown schema definition");
}

export function variant(name: string, type: string): SchemaNode {
  const schema = definition(name);
  return (
    (schema.oneOf ?? schema.anyOf)?.find(
      (option) =>
        option.properties?.type?.const === type || option.properties?.type?.enum?.includes(type),
    ) ?? fail(name, "unknown schema variant")
  );
}

export function compileSchema(schema: AnySchema): ValidateFunction {
  const rewriteReferences = (key: string, value: unknown) =>
    key === "$ref" && typeof value === "string" && value.startsWith("#/")
      ? official.$id + value
      : value;
  return ajv.compile(JSON.parse(JSON.stringify(schema, rewriteReferences)));
}

export function objectValidator(
  properties: SchemaFields,
  required: readonly string[] = [],
): ValidateFunction {
  return compileSchema({ type: "object", properties, required, additionalProperties: false });
}

export function pickSchema(properties: SchemaFields, keys: readonly string[]): SchemaFields {
  return Object.fromEntries(
    keys.map((key) => [key, properties[key] ?? fail(key, "field missing from official schema")]),
  );
}

const duration = compileSchema(definition("Duration"));
const durationUnits: Record<string, number> = {
  ns: 1,
  us: 1e3,
  µs: 1e3,
  μs: 1e3,
  ms: 1e6,
  s: 1e9,
  m: 60e9,
  h: 3600e9,
  d: 86400e9,
};

export function durationNanoseconds(value: unknown, path: string): number {
  if (value === undefined) return 0;
  const input = checkSchema(duration, value, path) as string;
  let nanoseconds = 0;
  for (const match of input.matchAll(/(\d+(?:\.\d*)?|\.\d+)(ns|us|µs|μs|ms|s|m|h|d)/g)) {
    nanoseconds += Math.trunc(Number(match[1]) * durationUnits[match[2]!]!);
  }
  return input.startsWith("-") ? -nanoseconds : nanoseconds;
}

const nonempty = { type: "string", minLength: 1 };
const shortId = { type: "string", pattern: "^(?:[0-9a-fA-F]{2}){0,8}$" };
// Unpadded Base64url needs 43 characters for a 32-byte key.
const realityKey = { type: "string", pattern: "^[A-Za-z0-9_-]{43}$" };

export const tlsProfileValidators = {
  server: {
    files: compileSchema({
      type: "object",
      additionalProperties: false,
      properties: { side: { const: "server" }, certificate_path: nonempty, key_path: nonempty },
      required: ["side", "certificate_path", "key_path"],
    }),
    provider: compileSchema({
      type: "object",
      additionalProperties: false,
      properties: { side: { const: "server" }, certificate_provider: nonempty },
      required: ["side", "certificate_provider"],
    }),
    reality: compileSchema({
      type: "object",
      additionalProperties: false,
      properties: {
        side: { const: "server" },
        server_name: nonempty,
        reality: {
          type: "object",
          additionalProperties: false,
          properties: {
            private_key: realityKey,
            short_id: { anyOf: [shortId, { type: "array", items: shortId }] },
            handshake: {
              type: "object",
              additionalProperties: false,
              properties: pickSchema(definition("InboundRealityHandshakeOptions").properties!, [
                "server",
                "server_port",
                "connect_timeout",
                "detour",
                "domain_resolver",
                "netns",
              ]),
              required: ["server", "server_port"],
            },
          },
          required: ["private_key", "short_id", "handshake"],
        },
      },
      required: ["side", "server_name", "reality"],
    }),
  },
  client: {
    regular: compileSchema({
      type: "object",
      additionalProperties: false,
      properties: {
        side: { const: "client" },
        ...pickSchema(definition("OutboundTLSOptions").properties!, [
          "server_name",
          "certificate_path",
        ]),
      },
      required: ["side"],
    }),
    reality: compileSchema({
      type: "object",
      additionalProperties: false,
      properties: {
        side: { const: "client" },
        server_name: nonempty,
        reality: {
          type: "object",
          additionalProperties: false,
          properties: { public_key: realityKey, short_id: shortId },
          required: ["public_key", "short_id"],
        },
      },
      required: ["side", "server_name", "reality"],
    }),
  },
};
