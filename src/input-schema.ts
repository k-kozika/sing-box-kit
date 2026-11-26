import { definition, definitionName, fail, rootProperties, schemaBranches } from "./schema";
import type { SchemaFields, SchemaNode } from "./schema";
import type { Role, Target } from "./resource";

export const targetSchema = {
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

export const tagReferences = {
  inbound: { role: "inbound", type: "InboundRef" },
  listen_detour: { role: "listen-detour", type: "ListenDetour" },
  outbound: { role: "egress", type: "Egress" },
  dial_detour: { role: "dial-detour", type: "Egress" },
  network_namespace: { role: "netns", type: "Namespace", allowString: true },
  dns_server: { role: "dns-server", type: "DnsServer" },
  rule_set: { role: "rule-set", type: "RuleSetRef" },
  certificate_provider: { role: "certificate-provider", type: "CertificateProvider" },
  http_client: { role: "http-client", type: "HttpClientValue" },
  tagged_http_client: { role: "http-client", type: "TaggedHttpClient" },
  tailscale_endpoint: { role: "tailscale-endpoint", type: "TailscaleEndpoint" },
  openconnect_endpoint: { role: "openconnect-endpoint", type: "OpenConnectEndpoint" },
  openvpn_client_endpoint: { role: "openvpn-client-endpoint", type: "OpenVpnClientEndpoint" },
  resolved_service: { role: "resolved-service", type: "ResolvedService" },
  ssm: { role: "ssm", type: "SsmInbound" },
  preferred_routes: { role: "preferred-routes", type: "PreferredRoutes" },
  preferred_domain: { role: "preferred-domain", type: "PreferredDomain" },
} as const satisfies Record<string, { role: Role; type: string; allowString?: boolean }>;

export function tagReference(name: string) {
  if (!Object.hasOwn(tagReferences, name)) fail(name, "unknown tag reference");
  return tagReferences[name as keyof typeof tagReferences];
}

function tagged(schema: SchemaNode, reference: keyof typeof tagReferences): SchemaNode {
  return { ...schema, "x-tag-reference": reference };
}

export function inputProperty(key: string, schema: SchemaNode): SchemaNode {
  if (key !== "detour") return schema;
  const reference = schema["x-tag-reference"];
  if (reference === "outbound") return tagged(schema, "dial_detour");
  if (reference === "inbound") return tagged(schema, "listen_detour");
  return schema;
}

function oneOrManyReference(schema: SchemaNode, reference: keyof typeof tagReferences) {
  return {
    ...schema,
    anyOf: schema.anyOf!.map((option) =>
      option.items
        ? { ...option, items: tagged(option.items, reference) }
        : tagged(option, reference),
    ),
  };
}

function projectObject(properties: SchemaFields, required: readonly string[] = []): SchemaNode {
  return { type: "object", properties, required, additionalProperties: false };
}

function supplementFactory(target: Target, kind: string, properties: SchemaFields): void {
  if (target === "dns.servers" && properties.endpoint) {
    const references = {
      tailscale: "tailscale_endpoint",
      openconnect: "openconnect_endpoint",
      openvpn: "openvpn_client_endpoint",
    } as const;
    if (Object.hasOwn(references, kind)) {
      properties.endpoint = tagged(
        properties.endpoint,
        references[kind as keyof typeof references],
      );
    }
  }
  if (target === "dns.servers" && kind === "resolved") {
    properties.service = tagged(properties.service!, "resolved_service");
  }
  if (target === "certificate_providers" && kind === "tailscale") {
    properties.endpoint = tagged(properties.endpoint!, "tailscale_endpoint");
  }
  if (target === "services" && kind === "derp") {
    properties.verify_client_endpoint = oneOrManyReference(
      properties.verify_client_endpoint!,
      "tailscale_endpoint",
    );
  }
  if (target === "services" && kind === "ssm-api") {
    const servers = properties.servers!;
    properties.servers = { ...servers, additionalProperties: tagged({ type: "string" }, "ssm") };
  }
}

const definitions = new Map<string, SchemaNode>();
export function inputDefinition(name: string): SchemaNode {
  const cached = definitions.get(name);
  if (cached) return cached;

  let schema = definition(name);
  if (name === "RouteOptions") {
    schema = {
      ...schema,
      properties: {
        ...schema.properties,
        default_http_client: tagged(schema.properties!.default_http_client!, "tagged_http_client"),
      },
    };
  }
  if (name === "CertificateProviderReference") {
    const [tag, inline] = schema.anyOf!;
    schema = {
      ...schema,
      anyOf: [
        tag!,
        {
          ...inline,
          oneOf: inline!.oneOf!.map((branch) => {
            if (branch.properties?.type?.const !== "tailscale") return branch;
            const properties = { ...branch.properties };
            supplementFactory("certificate_providers", "tailscale", properties);
            return { ...branch, properties };
          }),
        },
      ],
    };
  }
  definitions.set(name, schema);
  return schema;
}

export const rootSettings = Object.fromEntries(
  Object.entries(rootProperties).filter(
    ([key]) => !Object.hasOwn(targetSchema, key) && key !== "route" && key !== "dns",
  ),
);
export const sectionSettings = {
  route: projectObject(
    Object.fromEntries(
      Object.entries(inputDefinition("RouteOptions").properties!).filter(
        ([key]) => key !== "rules" && key !== "rule_set",
      ),
    ),
  ),
  dns: projectObject(
    Object.fromEntries(
      Object.entries(definition("DNS").properties!).filter(
        ([key]) => key !== "rules" && key !== "servers",
      ),
    ),
  ),
};

const dialKeys = new Set(Object.keys(definition("DialerOptions").properties!));
const listenKeys = new Set([
  "listen",
  "listen_port",
  "udp_timeout",
  "domain_resolver",
  "bind_interface",
  "routing_mark",
  "reuse_addr",
  "netns",
  "disable_tcp_keep_alive",
  "tcp_keep_alive",
  "tcp_keep_alive_interval",
  "tcp_fast_open",
  "tcp_multi_path",
  "udp_fragment",
  "detour",
]);

// Kit requirements supplement the schema's structural requirements.
const requiredOptions: Partial<Record<Target, Record<string, readonly string[]>>> = {
  inbounds: { shadowsocks: ["method"], vless: ["users"] },
  outbounds: {
    vless: ["server", "server_port", "uuid"],
    selector: ["outbounds"],
    urltest: ["outbounds"],
  },
  endpoints: { wireguard: ["address", "private_key"] },
  services: { "ssm-api": ["servers"] },
  "dns.servers": {
    tcp: ["server"],
    udp: ["server"],
    tls: ["server"],
    https: ["server"],
    tailscale: ["endpoint"],
    openconnect: ["endpoint"],
    openvpn: ["endpoint"],
    resolved: ["service"],
  },
  "route.rule_set": { inline: ["rules"], local: ["path"], remote: ["url"] },
  certificate_providers: { tailscale: ["endpoint"] },
  network_namespaces: { default: ["path"] },
};

export interface FactoryBranch {
  output: SchemaNode;
  options: SchemaNode;
  listen?: SchemaNode;
  dial?: SchemaNode;
  tls?: SchemaNode;
}

export function factoryCatalog(target: Target): Map<string, FactoryBranch[]> {
  const kinds = new Map<string, FactoryBranch[]>();
  for (const schema of schemaBranches(definition(targetSchema[target]))) {
    const type = schema.properties?.type;
    const kind = type?.const ?? type?.enum?.[0] ?? "http-client";
    if (typeof kind !== "string") fail(target, "expected a resource kind in the schema");
    const properties = Object.fromEntries(
      Object.entries(schema.properties ?? {}).map(([key, value]) => [
        key,
        inputProperty(key, value),
      ]),
    );
    supplementFactory(target, kind, properties);
    const listens = properties.listen !== undefined || (target === "inbounds" && kind === "tun");
    const options: SchemaFields = {};
    const listen: SchemaFields = {};
    const dial: SchemaFields = {};
    for (const [key, value] of Object.entries(properties)) {
      if (key === "type" || key === "tls") continue;
      if (listens && listenKeys.has(key)) {
        if (key === "listen") continue;
        listen[key === "listen_port" ? "port" : key] = value;
      } else if (!listens && dialKeys.has(key)) {
        // sing-box disallows detouring through a direct outbound's own Dial Fields.
        if (key === "detour" && target === "outbounds" && kind === "direct") continue;
        dial[key] = value;
      } else {
        options[key] = value;
      }
    }
    const required = [...(schema.required ?? []), ...(requiredOptions[target]?.[kind] ?? [])];
    if (target !== "services" && target !== "http_clients") required.push("tag");
    const branch: FactoryBranch = {
      output: { ...schema, properties },
      options: projectObject(
        options,
        [...new Set(required)].filter((key) => Object.hasOwn(options, key)),
      ),
      listen: listens ? projectObject(listen) : undefined,
      dial: Object.keys(dial).length ? projectObject(dial) : undefined,
      tls: properties.tls,
    };
    const entries = kinds.get(kind) ?? [];
    entries.push(branch);
    kinds.set(kind, entries);
  }
  return kinds;
}

export function factoryName(kind: string): string {
  return kind.replace(/-([a-z])/g, (_match, letter: string) => letter.toUpperCase());
}

export function schemaShape(schema: SchemaNode): SchemaNode {
  const name = definitionName(schema);
  return name ? inputDefinition(name) : schema;
}

export const ruleMatchSchema = {
  route: matchSchema("NestedRule", "preferred_routes"),
  dns: matchSchema("NestedDNSRule", "preferred_domain"),
};

function matchSchema(
  name: "NestedRule" | "NestedDNSRule",
  preferred: "preferred_routes" | "preferred_domain",
): SchemaNode {
  const { type: _type, ...properties } = definition(name).oneOf![0]!.properties!;
  properties.preferred_by = oneOrManyReference(properties.preferred_by!, preferred);
  return projectObject(properties);
}

export function ruleActionSchemas(scope: "route" | "dns"): Map<string, SchemaNode> {
  const actions = schemaBranches(definition(scope === "route" ? "RuleAction" : "DNSRuleAction"));
  return new Map(
    actions.map((branch) => {
      const properties = { ...branch.properties };
      const action = properties.action!.const as string;
      const required = new Set(["action", ...(branch.required ?? [])]);
      if (action === "route" && scope === "route") required.add("outbound");
      if (scope === "dns" && (action === "route" || action === "evaluate")) required.add("server");
      if (action === "reject" && scope === "dns") {
        properties.method = { type: "string", enum: ["default", "drop"] };
      }
      return [action, projectObject(properties, [...required])];
    }),
  );
}
