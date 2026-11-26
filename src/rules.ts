import { isIP } from "node:net";
import type {
  DNSRuleAction as RawDnsAction, NestedDNSRule, NestedRule, RuleAction as RawRouteAction,
} from "./generated/sing-box";
import {
  arrayOrOne, expandFields, fieldsFrom, preserveIdentity, ref, record, resourceData, snapshot,
} from "./resource";
import type {
  DnsServer, Egress, Expansions, Fields, InboundRef, PreferredDomain, PreferredRoutes,
  ReadonlyJson, Resolve, RuleSetRef,
} from "./resource";
import { checkSchema, definition, durationNanoseconds, fail, keyPath, objectValidator, pickSchema } from "./schema";
import { previewReference } from "./settings";

export type Scope = "route" | "dns";
type OneOrMany<T> = T | readonly T[];
type RouteLeaf = Exclude<NestedRule, { type: "logical" }>;
type DnsLeaf = Exclude<NestedDNSRule, { type: "logical" }>;

const commonMatches = ["domain", "domain_suffix", "port", "auth_user"] as const;
const routeMatches = ["client"] as const;
const responseMatches = [
  "response_rcode", "response_answer", "response_ns", "response_extra",
  "ip_cidr", "ip_is_private", "ip_accept_any",
] as const;
const dnsMatches = ["query_type", "match_response", ...responseMatches] as const;
const referenceMatches = ["inbound", "rule_set", "preferred_by"] as const;

type CommonMatches = ReadonlyJson<Pick<RouteLeaf, Exclude<typeof commonMatches[number], "auth_user">>> & {
  /** An empty string can match traffic with no authenticated name. */
  readonly auth_user?: OneOrMany<string>;
  readonly inbound?: OneOrMany<InboundRef>;
  readonly rule_set?: OneOrMany<RuleSetRef>;
};
type RouteMatches = ReadonlyJson<Pick<RouteLeaf, typeof routeMatches[number]>> & {
  readonly preferred_by?: OneOrMany<PreferredRoutes>;
};
type DnsMatches = ReadonlyJson<Pick<DnsLeaf, typeof dnsMatches[number]>> & {
  readonly preferred_by?: OneOrMany<PreferredDomain>;
};
type RouteMatchInput = CommonMatches & RouteMatches & { readonly [K in typeof dnsMatches[number]]?: never };
type DnsMatchInput = CommonMatches & DnsMatches & { readonly [K in typeof routeMatches[number]]?: never };
export type MatchFields = RouteMatchInput | DnsMatchInput;

type MatchScope<M> =
  | ([M] extends [RouteMatchInput] ? "route" : never)
  | ([M] extends [DnsMatchInput] ? "dns" : never);

declare const conditionBrand: unique symbol;
export interface Condition<S extends Scope = Scope> {
  readonly [conditionBrand]: S;
  and<O extends Scope>(other: Condition<O> & ([S & O] extends [never] ? never : unknown)): Condition<S & O>;
  or<O extends Scope>(other: Condition<O> & ([S & O] extends [never] ? never : unknown)): Condition<S & O>;
  not(): Condition<S>;
}

interface ConditionData {
  readonly scopes: readonly Scope[];
  readonly invert: boolean;
  readonly node: { fields: Fields } | { mode: "and" | "or"; rules: readonly Condition[] };
}
const conditions = new WeakMap<Condition, ConditionData>();
const allScopes: readonly Scope[] = ["route", "dns"];
function conditionData(value: unknown, path: string): ConditionData {
  return conditions.get(value as Condition) ?? fail(path, "expected a rule condition");
}

function makeCondition<S extends Scope>(data: ConditionData): Condition<S> {
  const combine = (mode: "and" | "or", other: Condition) => {
    const otherData = conditionData(other, "condition");
    const scopes = data.scopes.filter(scope => otherData.scopes.includes(scope));
    if (scopes.length === 0) fail("condition", "operands have no common scope");
    return makeCondition({ scopes, invert: false, node: { mode, rules: [value, other] } });
  };
  const value = preserveIdentity({
    and: (other: Condition) => combine("and", other),
    or: (other: Condition) => combine("or", other),
    not: () => makeCondition({ ...data, invert: !data.invert }),
  }) as unknown as Condition<S>;
  conditions.set(value, data);
  return value;
}

const scopeMatches = { route: routeMatches, dns: dnsMatches };
const allMatches = [...commonMatches, ...referenceMatches, ...routeMatches, ...dnsMatches];
const leafValidators = {
  route: objectValidator(pickSchema(definition("NestedRule").oneOf![0]!.properties!,
    [...commonMatches, ...referenceMatches, ...routeMatches])),
  dns: objectValidator(pickSchema(definition("NestedDNSRule").oneOf![0]!.properties!,
    [...commonMatches, ...referenceMatches, ...dnsMatches])),
};
const leafReferences: Record<Scope, Expansions> = {
  route: { inbound: arrayOrOne(ref("inbound")), rule_set: arrayOrOne(ref("rule-set")),
    preferred_by: arrayOrOne(ref("preferred-routes")) },
  dns: { inbound: arrayOrOne(ref("inbound")), rule_set: arrayOrOne(ref("rule-set")),
    preferred_by: arrayOrOne(ref("preferred-domain")) },
};

function active(value: unknown): boolean {
  return value !== undefined && value !== false && (!Array.isArray(value) || value.length !== 0);
}

function checkLeaf(fields: Fields, path: string): void {
  if (fields.match_response === "") fail(`${path}.match_response`, "empty response tag");
  if (responseMatches.some(key => active(fields[key])) && !active(fields.match_response)) {
    fail(`${path}.match_response`, "response fields require active response matching");
  }
  if (!Object.values(fields).some(active)) fail(path, "condition has no active fields");
}

function match<M extends MatchFields>(input: M & Record<Exclude<keyof M, keyof MatchFields>, never>): Condition<MatchScope<M>> {
  const fields = fieldsFrom(input, "match", allMatches);
  checkLeaf(fields, "match");
  const preferred = Array.isArray(fields.preferred_by) ? fields.preferred_by : [fields.preferred_by];
  const hasDnsTransport = preferred.some(value => resourceData(value)?.target === "dns.servers");
  const hasOtherResource = preferred.some(value => {
    const data = resourceData(value);
    return data && data.target !== "dns.servers";
  });
  if (hasDnsTransport && hasOtherResource) fail("match.preferred_by", "mixed route and DNS targets");
  const scopes = allScopes.filter(scope => {
    const opposite = scope === "route" ? "dns" : "route";
    return !scopeMatches[opposite].some(key => fields[key] !== undefined)
      && !(scope === "route" ? hasDnsTransport : hasOtherResource);
  });
  if (!scopes.length) fail("match", "fields have no common scope");
  for (const scope of scopes) {
    checkSchema(leafValidators[scope], expandFields(fields, leafReferences[scope], "match", previewReference), "match");
  }
  return makeCondition({ scopes, invert: false, node: { fields: snapshot(fields, "match") } });
}

export const Rule = Object.freeze({ match });

type SharedDnsOptions = ReadonlyJson<Pick<Extract<RawDnsAction, { action: "route-options" }>,
  "timeout" | "disable_cache" | "disable_optimistic_cache" | "rewrite_ttl" | "client_subnet" | "remove_client_subnet">>;
type RejectOptions = Omit<Extract<RawRouteAction, { action: "reject" }>, "action" | "method"> & {
  method?: "default" | "drop";
};
export type RouteRuleAction =
  | { action: "route"; outbound: Egress }
  | { action: "bypass"; outbound?: Egress }
  | { action: "reject" } & RejectOptions
  | { action: "hijack-dns" };
export type DnsRuleAction =
  | { action: "route"; server: DnsServer; speculative?: boolean; race?: boolean } & SharedDnsOptions
  | { action: "evaluate"; server: DnsServer; tag?: string; speculative?: boolean } & SharedDnsOptions
  | Extract<RawDnsAction, { action: "respond" }>
  | { action: "route-options" } & SharedDnsOptions
  | { action: "reject"; race?: boolean } & RejectOptions
  | ReadonlyJson<Extract<RawDnsAction, { action: "predefined" }>>;

export type RuleAction<S extends Scope> = { route: RouteRuleAction; dns: DnsRuleAction }[S];

function actionVariant(scope: Scope, action: string, keys: readonly string[], required: readonly string[] = []) {
  const schema = definition(scope === "route" ? "RuleAction" : "DNSRuleAction");
  const raw = schema.oneOf!.find(item => item.properties?.action?.const === action)!.properties!;
  const properties = pickSchema(raw, ["action", ...keys]);
  if (action === "reject") properties.method = { type: "string", enum: ["default", "drop"] };
  return { keys: ["action", ...keys], required: ["action", ...required], validate: objectValidator(properties, ["action", ...required]) };
}

const sharedDnsOptions = [
  "timeout", "disable_cache", "disable_optimistic_cache", "rewrite_ttl", "client_subnet", "remove_client_subnet",
] as const satisfies readonly (keyof SharedDnsOptions)[];
const actions = {
  route: {
    route: actionVariant("route", "route", ["outbound"], ["outbound"]),
    bypass: actionVariant("route", "bypass", ["outbound"]),
    reject: actionVariant("route", "reject", ["method", "no_drop"]),
    "hijack-dns": actionVariant("route", "hijack-dns", []),
  },
  dns: {
    route: actionVariant("dns", "route", ["server", "speculative", "race", ...sharedDnsOptions], ["server"]),
    evaluate: actionVariant("dns", "evaluate", ["server", "tag", "speculative", ...sharedDnsOptions], ["server"]),
    respond: actionVariant("dns", "respond", ["race"]),
    "route-options": actionVariant("dns", "route-options", sharedDnsOptions),
    reject: actionVariant("dns", "reject", ["method", "no_drop", "race"]),
    predefined: actionVariant("dns", "predefined", ["rcode", "answer", "ns", "extra", "race"]),
  },
};

function validSubnet(input: string): boolean {
  const [address = "", prefix, ...extra] = input.split("/");
  const version = isIP(address);
  return version !== 0 && !address.includes("%") && extra.length === 0
    && (prefix === undefined || /^\d+$/.test(prefix) && Number(prefix) <= (version === 4 ? 32 : 128));
}

function checkAction(fields: Fields, path: string): void {
  if (fields.method === "drop" && fields.no_drop === true) fail(`${path}.no_drop`, "no_drop with drop");
  if (fields.client_subnet !== undefined) {
    if (fields.remove_client_subnet === true) fail(`${path}.client_subnet`, "client_subnet with remove_client_subnet");
    if (!validSubnet(fields.client_subnet as string)) fail(`${path}.client_subnet`, "invalid subnet");
  }
  if (fields.action === "route-options" && fields.rewrite_ttl === undefined
    && fields.client_subnet === undefined && fields.disable_cache !== true
    && fields.disable_optimistic_cache !== true && fields.remove_client_subnet !== true
    && durationNanoseconds(fields.timeout, `${path}.timeout`) <= 0) {
    fail(path, "route-options requires an effective DNS option");
  }
  if (fields.race === true && fields.speculative === true) fail(`${path}.race`, "race with speculative");
}

const actionReferences = { route: { outbound: ref("egress") }, dns: { server: ref("dns-server") } };

declare const ruleBrand: unique symbol;
export interface RuleValue<S extends Scope> {
  readonly [ruleBrand]: S;
}

interface RuleData {
  readonly scope: Scope;
  readonly condition?: Condition;
  readonly action: Fields;
}
const rules = new WeakMap<object, RuleData>();

function makeRule<S extends Scope>(scope: S, condition: unknown, actionInput: unknown): RuleValue<S> {
  const path = `${scope}.rule`;
  const variants = actions[scope] as Record<string, ReturnType<typeof actionVariant>>;
  const name = record(actionInput, path).action;
  if (typeof name !== "string" || !Object.hasOwn(variants, name)) fail(`${path}.action`, "unsupported action");
  const variant = variants[name]!;
  const action = fieldsFrom(actionInput, path, variant.keys, variant.required);
  checkSchema(variant.validate, expandFields(action, actionReferences[scope], path, previewReference), path);
  checkAction(action, path);
  if (condition !== undefined && !conditionData(condition, path).scopes.includes(scope)) {
    fail(path, "condition is incompatible with rule scope");
  }
  if (action.race === true && !hasResponseCondition(condition as Condition | undefined)) {
    fail(`${path}.race`, "race requires active response matching");
  }
  const value = preserveIdentity({}) as RuleValue<S>;
  rules.set(value, { scope, condition: condition as Condition | undefined, action: snapshot(action, path) });
  return value;
}

function hasResponseCondition(condition: Condition | undefined): boolean {
  if (!condition) return false;
  const { node } = conditionData(condition, "condition");
  return "fields" in node ? active(node.fields.match_response) : node.rules.some(hasResponseCondition);
}

interface RuleFactory<S extends Scope> {
  (action: RuleAction<S>): RuleValue<S>;
  <C extends Scope>(condition: Condition<C> & (S extends C ? unknown : never), action: RuleAction<S>): RuleValue<S>;
}

function ruleFactory<S extends Scope>(scope: S): RuleFactory<S> {
  return function(first: unknown, second?: unknown) {
    return arguments.length === 1 ? makeRule(scope, undefined, first) : makeRule(scope, first, second);
  };
}
export const route = Object.freeze({ rule: ruleFactory("route") });
export const dns = Object.freeze({ rule: ruleFactory("dns") });

function expandCondition(value: Condition, scope: Scope, path: string, resolve: Resolve): Fields {
  const { node, invert } = conditionData(value, path);
  const inversion = invert ? { invert: true } : {};
  if ("fields" in node) {
    checkLeaf(node.fields, path);
    return { ...expandFields(node.fields, leafReferences[scope], path, resolve), ...inversion };
  }
  if (!node.rules.length) fail(`${path}.rules`, "empty logical group");
  return {
    type: "logical", mode: node.mode, ...inversion,
    rules: node.rules.map((child, index) => expandCondition(child, scope, `${path}.rules[${index}]`, resolve)),
  };
}

export function expandRule(value: unknown, scope: Scope, path: string, resolve: Resolve): Fields {
  const data = rules.get(value as object);
  if (!data || data.scope !== scope) fail(path, `expected a ${scope} rule`);
  if (data.action.action === "evaluate" && resourceData(data.action.server)?.kind === "fakeip") {
    // Resolve first to preserve the registration and capability diagnostics.
    const tag = resolve(data.action.server, "dns-server", `${path}.server`);
    fail(`${path}.server`, "evaluate cannot use FakeIP", tag);
  }
  return {
    ...(data.condition ? expandCondition(data.condition, scope, path, resolve) : {}),
    ...expandFields(data.action, actionReferences[scope], path, resolve),
  };
}

export function checkDnsRules(rules: readonly Fields[], path: string): void {
  const named = new Set<string>();
  let anonymous = false;

  function inspect(node: Fields, nodePath: string, logicalRespond: boolean): void {
    if (node.type === "logical") {
      (node.rules as Fields[]).forEach((child, index) => inspect(child, `${nodePath}.rules[${index}]`, logicalRespond));
      return;
    }
    const match = node.match_response;
    if (typeof match === "string") {
      if (logicalRespond) fail(`${nodePath}.match_response`, "logical respond cannot bind a named result", match);
      if (!named.has(match)) fail(`${nodePath}.match_response`, "requires an earlier named evaluate", match);
    }
    if (match === true && !anonymous) fail(`${nodePath}.match_response`, "requires an earlier untagged evaluate");
  }

  rules.forEach((rule, index) => {
    const rulePath = `${path}[${index}]`;
    inspect(rule, rulePath, rule.type === "logical" && rule.action === "respond");
    if (rule.action === "respond" && typeof rule.match_response !== "string" && !anonymous) {
      fail(keyPath(rulePath, "action"), "respond requires an earlier untagged evaluate");
    }
    if (rule.action === "evaluate") {
      if (typeof rule.tag === "string" && rule.tag !== "") {
        if (named.has(rule.tag)) fail(`${rulePath}.tag`, "duplicate evaluate tag", rule.tag);
        named.add(rule.tag);
      } else {
        anonymous = true;
      }
    }
  });
}
