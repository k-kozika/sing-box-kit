import { isIP } from "node:net";
import type { SBKitInputs } from "./generated/sbkit-inputs";
import { rootSettings, sectionSettings } from "./input-schema";
import type { SingBoxConfig } from "./generated/sing-box";
import { copyJson, fieldsFrom, resourceData } from "./resource";
import type {
  DnsServer,
  Resolve,
  Resource,
  ResourceData,
  TaggedHttpClient,
  Target,
} from "./resource";
import { checkDnsRules, expandRule } from "./rules";
import type { RuleValue } from "./rules";
import { fail, validateConfig } from "./schema";
import { expandInput, isEmptyDirect } from "./settings";
import type { Fields, ReadonlyJson } from "./type-utils";

export interface CompileInput extends Partial<ReadonlyJson<SBKitInputs["root"]>> {
  readonly inbounds?: readonly Resource<"inbounds">[];
  readonly outbounds?: readonly Resource<"outbounds">[];
  readonly endpoints?: readonly Resource<"endpoints">[];
  readonly services?: readonly Resource<"services">[];
  readonly http_clients?: readonly TaggedHttpClient[];
  readonly certificate_providers?: readonly Resource<"certificate_providers">[];
  readonly network_namespaces?: readonly Resource<"network_namespaces">[];
  readonly route?: {
    readonly rules?: readonly RuleValue<"route">[];
    readonly rule_set?: readonly Resource<"route.rule_set">[];
  } & ReadonlyJson<SBKitInputs["sections"]["route"]>;
  readonly dns?: {
    readonly rules?: readonly RuleValue<"dns">[];
    readonly servers?: readonly DnsServer[];
  } & ReadonlyJson<SBKitInputs["sections"]["dns"]>;
}

type TopLevelTarget = Exclude<Target, "dns.servers" | "route.rule_set">;
const topLevelLists = [
  "inbounds",
  "outbounds",
  "endpoints",
  "services",
  "http_clients",
  "certificate_providers",
  "network_namespaces",
] as const satisfies readonly TopLevelTarget[];
const routeKeys = ["rules", "rule_set", ...Object.keys(sectionSettings.route.properties!)];
const dnsKeys = ["rules", "servers", ...Object.keys(sectionSettings.dns.properties!)];

interface Registered {
  readonly value: Resource;
  readonly data: ResourceData;
  readonly path: string;
  readonly tags: readonly string[];
  readonly dependencies: Dependency[];
}

interface Dependency {
  readonly target: Registered;
  readonly path: string;
  readonly tag: string;
}

function array(value: unknown, path: string): unknown[] {
  if (!Array.isArray(value)) fail(path, "expected an array");
  return Array.from(value);
}

function fieldTags(data: ResourceData): readonly unknown[] {
  const tag = data.fields.tag;
  return Array.isArray(tag) ? tag : tag === undefined ? [] : [tag];
}

function checkCycles(resources: Iterable<Registered>): void {
  const active = new Set<Registered>();
  const visited = new Set<Registered>();
  for (const root of resources) visit(root);

  function visit(node: Registered): void {
    if (visited.has(node)) return;
    active.add(node);
    for (const edge of node.dependencies) {
      if (active.has(edge.target)) fail(edge.path, "cyclic dependency", edge.tag);
      visit(edge.target);
    }
    active.delete(node);
    visited.add(node);
  }
}

/**
 * Compile using registered final values. If you recreate a resource with the
 * same tag, rebuild its references so they refer to the new value.
 */
export function compile(input: CompileInput): SingBoxConfig {
  const fields = fieldsFrom(input, "config", [
    ...Object.keys(rootSettings),
    ...topLevelLists,
    "route",
    "dns",
  ]);
  const route =
    fields.route === undefined ? undefined : fieldsFrom(fields.route, "route", routeKeys);
  const dns = fields.dns === undefined ? undefined : fieldsFrom(fields.dns, "dns", dnsKeys);
  const scopes = new Map<Target, Map<string, Registered>>();
  const registrations = new Map<Resource, Registered>();

  function tagScope(target: Target): Map<string, Registered> {
    const scope = target === "endpoints" ? "outbounds" : target;
    let tags = scopes.get(scope);
    if (!tags) {
      tags = new Map();
      scopes.set(scope, tags);
    }
    return tags;
  }

  function registerList(input: unknown, target: Target): Registered[] | undefined {
    if (input === undefined) return undefined;
    const tags = tagScope(target);
    return array(input, target).map((item, index) => {
      const path = `${target}[${index}]`;
      const data = resourceData(item);
      if (!data || data.target !== target) fail(path, `expected a ${target} resource`);
      const explicit = fieldTags(data);
      if (!explicit.length && target !== "services")
        fail(`${path}.tag`, "tagged resource required");
      const entry: Registered = {
        value: item as Resource,
        data,
        path,
        tags: explicit.length
          ? explicit.map((value, i) => {
              const tagPath = Array.isArray(data.fields.tag) ? `${path}.tag[${i}]` : `${path}.tag`;
              if (typeof value !== "string" || !value) fail(tagPath, "expected a non-empty tag");
              return value;
            })
          : [String(index)],
        dependencies: [],
      };

      entry.tags.forEach((tag, i) => {
        const tagPath = Array.isArray(data.fields.tag) ? `${path}.tag[${i}]` : `${path}.tag`;
        if (tags.has(tag)) fail(tagPath, "duplicate tag", tag);
        tags.set(tag, entry);
      });
      registrations.set(entry.value, entry);
      return entry;
    });
  }

  const lists = new Map<Target, Registered[] | undefined>(
    topLevelLists.map((target) => [target, registerList(fields[target], target)]),
  );
  lists.set("route.rule_set", registerList(route?.rule_set, "route.rule_set"));
  lists.set("dns.servers", registerList(dns?.servers, "dns.servers"));

  function resolveFrom(origin?: Registered): Resolve {
    return (value, role, path) => {
      const data = resourceData(value);
      if (!data) fail(path, `expected a typed ${role} reference`);
      const tags = fieldTags(data);
      const tag = tags.length === 1 && typeof tags[0] === "string" && tags[0] ? tags[0] : undefined;
      const capability = role === "dial-detour" ? "egress" : role;
      if (!data.roles.includes(capability))
        fail(path, `target lacks ${capability} capability`, tag);
      if (!tag) fail(path, "reference requires a single explicit tag");
      const target = registrations.get(value as Resource);
      if (!target) fail(path, "referenced final value is unregistered", tag);
      if (role === "inbound" || role === "listen-detour") {
        const inbound = tagScope("inbounds").get(tag);
        const egress = tagScope("outbounds").get(tag);
        const endpoint = egress?.data.target === "endpoints" ? egress : undefined;
        if (role === "inbound" && inbound && endpoint) fail(path, "ambiguous inbound tag", tag);
        if ((inbound ?? endpoint) !== target)
          fail(path, "inbound tag resolves to another resource", tag);
      }
      if (role === "dial-detour" && data.kind === "direct" && isEmptyDirect(data.fields)) {
        fail(path, "empty direct outbound cannot be an explicit detour", tag);
      }
      if (origin) {
        const edge = path.slice(origin.path.length);
        const group = role === "egress" && edge.startsWith(".outbounds[");
        const detour = role === "dial-detour" && edge === ".detour" && origin.data.startupDetour;
        const resolver =
          role === "dns-server" &&
          origin.data.target === "dns.servers" &&
          (edge === ".domain_resolver" || edge === ".domain_resolver.server");
        if (group || detour || resolver) origin.dependencies.push({ target, path, tag });
      }
      return tag;
    };
  }

  function emitList(target: Target): Fields[] | undefined {
    return lists.get(target)?.map((entry) => {
      const { data, path } = entry;
      const { server, detour, domain_resolver } = data.fields;
      if (
        data.remoteDns &&
        typeof server === "string" &&
        !isIP(server) &&
        detour === undefined &&
        domain_resolver === undefined
      ) {
        fail(`${path}.domain_resolver`, "hostname requires a per-server resolver or detour");
      }
      const expand = data.expand ?? copyJson;
      return expand(data.fields, path, resolveFrom(entry)) as Fields;
    });
  }

  const resolve = resolveFrom();
  const output: Fields = {};
  for (const [key, schema] of Object.entries(rootSettings)) {
    if (fields[key] !== undefined) output[key] = expandInput(schema, fields[key], key, resolve);
  }
  for (const target of topLevelLists) {
    const values = emitList(target);
    if (values !== undefined) output[target] = values;
  }
  if (route) {
    const { rules, rule_set, ...settings } = route;
    const result = expandInput(sectionSettings.route, settings, "route", resolve) as Fields;
    if (rule_set !== undefined) result.rule_set = emitList("route.rule_set");
    if (rules !== undefined) {
      result.rules = array(rules, "route.rules").map((value, index) =>
        expandRule(value, "route", `route.rules[${index}]`, resolve),
      );
    }
    output.route = result;
  }
  if (dns) {
    const { rules, servers, ...settings } = dns;
    const result = expandInput(sectionSettings.dns, settings, "dns", resolve) as Fields;
    if (servers !== undefined) result.servers = emitList("dns.servers");
    if (rules !== undefined) {
      const compiled = array(rules, "dns.rules").map((value, index) =>
        expandRule(value, "dns", `dns.rules[${index}]`, resolve),
      );
      checkDnsRules(compiled, "dns.rules");
      result.rules = compiled;
    }
    output.dns = result;
  }
  checkCycles(registrations.values());
  return validateConfig(output);
}
