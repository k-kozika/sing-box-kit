import { isIP } from "node:net";
import type { KitInputs } from "./generated/kit-inputs";
import { ruleActionSchemas, ruleMatchSchema } from "./input-schema";
import { fieldsFrom, preserveIdentity, record, resourceData, snapshot } from "./resource";
import type { Resolve } from "./resource";
import { checkSchema, compileSchema, durationNanoseconds, fail, keyPath } from "./schema";
import type { SchemaNode } from "./schema";
import { expandInput, previewReference } from "./settings";
import type { Fields, ReadonlyJson, StrictUnion } from "./type-utils";

export type Scope = "route" | "dns";
type RouteMatch = ReadonlyJson<KitInputs["matches"]["route"]>;
type DnsMatch = ReadonlyJson<KitInputs["matches"]["dns"]>;

const responseMatches = [
  "response_rcode",
  "response_answer",
  "response_ns",
  "response_extra",
  "ip_cidr",
  "ip_is_private",
  "ip_accept_any",
] as const;
type ResponseKey = (typeof responseMatches)[number];
type DnsMatchInput = Omit<DnsMatch, ResponseKey | "match_response"> &
  (
    | (Pick<DnsMatch, ResponseKey> & { readonly match_response: true | string })
    | {
        readonly match_response?: false;
        readonly ip_is_private?: false;
        readonly ip_accept_any?: false;
      }
  );
type AllMatchKeys = keyof RouteMatch | keyof DnsMatch;
type RouteMatchInput = RouteMatch & {
  readonly [K in Exclude<AllMatchKeys, keyof RouteMatch>]?: never;
};
type ScopedDnsMatch = DnsMatchInput & {
  readonly [K in Exclude<AllMatchKeys, keyof DnsMatch>]?: never;
};
export type MatchFields = RouteMatchInput | ScopedDnsMatch;

type MatchScope<M> =
  | ([M] extends [RouteMatchInput] ? "route" : never)
  | ([M] extends [ScopedDnsMatch] ? "dns" : never);

declare const conditionBrand: unique symbol;
export interface Condition<S extends Scope = Scope> {
  readonly [conditionBrand]: S;
  and<O extends Scope>(
    other: Condition<O> & ([S & O] extends [never] ? never : unknown),
  ): Condition<S & O>;
  or<O extends Scope>(
    other: Condition<O> & ([S & O] extends [never] ? never : unknown),
  ): Condition<S & O>;
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
    const scopes = data.scopes.filter((scope) => otherData.scopes.includes(scope));
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

const routeKeys = new Set(Object.keys(ruleMatchSchema.route.properties!));
const dnsKeys = new Set(Object.keys(ruleMatchSchema.dns.properties!));
const allMatches = [...new Set([...routeKeys, ...dnsKeys])];
const leafValidators = {
  route: compileSchema(ruleMatchSchema.route),
  dns: compileSchema(ruleMatchSchema.dns),
};

function active(value: unknown): boolean {
  return value !== undefined && value !== false && (!Array.isArray(value) || value.length !== 0);
}

function checkLeaf(fields: Fields, path: string, scope: Scope): void {
  if (fields.match_response === "") fail(`${path}.match_response`, "empty response tag");
  if (
    scope === "dns" &&
    responseMatches.some((key) => active(fields[key])) &&
    !active(fields.match_response)
  ) {
    fail(`${path}.match_response`, "response fields require active response matching");
  }
  if (!Object.entries(fields).some(([key, value]) => key !== "invert" && active(value))) {
    fail(path, "condition has no active fields");
  }
}

function match<const M extends MatchFields>(
  input: M & Record<Exclude<keyof M, AllMatchKeys>, never>,
): Condition<MatchScope<M>> {
  const fields = fieldsFrom(input, "match", allMatches);
  const preferred = Array.isArray(fields.preferred_by)
    ? fields.preferred_by
    : [fields.preferred_by];
  const hasDnsTransport = preferred.some((value) => resourceData(value)?.target === "dns.servers");
  const hasOtherResource = preferred.some((value) => {
    const data = resourceData(value);
    return data && data.target !== "dns.servers";
  });
  if (hasDnsTransport && hasOtherResource)
    fail("match.preferred_by", "mixed route and DNS targets");

  const keys = Object.keys(fields);
  const dnsOnly = hasDnsTransport || keys.some((key) => !routeKeys.has(key));
  const icmp =
    fields.network === "icmp" || (Array.isArray(fields.network) && fields.network.includes("icmp"));
  const addressMatch = fields.ip_cidr !== undefined || fields.ip_is_private === true;
  const routeOnly =
    hasOtherResource || icmp || keys.some((key) => !dnsKeys.has(key)) || (addressMatch && !dnsOnly);
  const scopes = allScopes.filter((scope) => (scope === "route" ? !dnsOnly : !routeOnly));
  if (!scopes.length) fail("match", "fields have no common scope");

  for (const scope of scopes) {
    checkLeaf(fields, "match", scope);
    checkSchema(
      leafValidators[scope],
      expandInput(ruleMatchSchema[scope], fields, "match", previewReference),
      "match",
    );
  }
  return makeCondition({ scopes, invert: false, node: { fields: snapshot(fields, "match") } });
}

export const Rule = Object.freeze({ match });

export type RouteRuleAction = StrictUnion<ReadonlyJson<KitInputs["actions"]["route"]>>;
export type DnsRuleAction = StrictUnion<ReadonlyJson<KitInputs["actions"]["dns"]>>;
export type RuleAction<S extends Scope> = { route: RouteRuleAction; dns: DnsRuleAction }[S];

function actionsFor(scope: Scope) {
  return new Map(
    Array.from(ruleActionSchemas(scope), ([action, schema]) => [
      action,
      { schema, validate: compileSchema(schema) },
    ]),
  );
}

const actions = { route: actionsFor("route"), dns: actionsFor("dns") };

function validSubnet(input: string): boolean {
  const [address = "", prefix, ...extra] = input.split("/");
  const version = isIP(address);
  return (
    version !== 0 &&
    !address.includes("%") &&
    extra.length === 0 &&
    (prefix === undefined || (/^\d+$/.test(prefix) && Number(prefix) <= (version === 4 ? 32 : 128)))
  );
}

function checkAction(fields: Fields, path: string, scope: Scope): void {
  if (fields.method === "drop" && fields.no_drop === true)
    fail(`${path}.no_drop`, "no_drop with drop");
  if (fields.client_subnet !== undefined) {
    if (fields.remove_client_subnet === true)
      fail(`${path}.client_subnet`, "client_subnet with remove_client_subnet");
    if (!validSubnet(fields.client_subnet as string))
      fail(`${path}.client_subnet`, "invalid subnet");
  }
  if (
    scope === "dns" &&
    fields.action === "route-options" &&
    fields.rewrite_ttl === undefined &&
    fields.client_subnet === undefined &&
    fields.disable_cache !== true &&
    fields.disable_optimistic_cache !== true &&
    fields.remove_client_subnet !== true &&
    durationNanoseconds(fields.timeout, `${path}.timeout`) <= 0
  ) {
    fail(path, "route-options requires an effective DNS option");
  }
  if (fields.race === true && fields.speculative === true)
    fail(`${path}.race`, "race with speculative");
}

declare const ruleBrand: unique symbol;
export interface RuleValue<S extends Scope> {
  readonly [ruleBrand]: S;
}

interface RuleData {
  readonly scope: Scope;
  readonly condition?: Condition;
  readonly action: Fields;
  readonly schema: SchemaNode;
}
const rules = new WeakMap<object, RuleData>();

function makeRule<S extends Scope>(
  scope: S,
  condition: unknown,
  actionInput: unknown,
): RuleValue<S> {
  const path = `${scope}.rule`;
  const name = record(actionInput, path).action;
  const variant = typeof name === "string" ? actions[scope].get(name) : undefined;
  if (!variant) fail(`${path}.action`, "unsupported action");
  const action = fieldsFrom(
    actionInput,
    path,
    Object.keys(variant.schema.properties!),
    variant.schema.required,
  );
  checkSchema(variant.validate, expandInput(variant.schema, action, path, previewReference), path);
  checkAction(action, path, scope);
  if (condition !== undefined && !conditionData(condition, path).scopes.includes(scope)) {
    fail(path, "condition is incompatible with rule scope");
  }
  if (action.race === true && !hasResponseCondition(condition as Condition | undefined)) {
    fail(`${path}.race`, "race requires active response matching");
  }
  const value = preserveIdentity({}) as RuleValue<S>;
  rules.set(value, {
    scope,
    condition: condition as Condition | undefined,
    action: snapshot(action, path),
    schema: variant.schema,
  });
  return value;
}

function hasResponseCondition(condition: Condition | undefined): boolean {
  if (!condition) return false;
  const { node } = conditionData(condition, "condition");
  return "fields" in node
    ? active(node.fields.match_response)
    : node.rules.some(hasResponseCondition);
}

interface RuleFactory<S extends Scope> {
  (action: RuleAction<S>): RuleValue<S>;
  <C extends Scope>(
    condition: Condition<C> & (S extends C ? unknown : never),
    action: RuleAction<S>,
  ): RuleValue<S>;
}

function ruleFactory<S extends Scope>(scope: S): RuleFactory<S> {
  return function (first: unknown, second?: unknown) {
    return arguments.length === 1
      ? makeRule(scope, undefined, first)
      : makeRule(scope, first, second);
  };
}
export const route = Object.freeze({ rule: ruleFactory("route") });
export const dns = Object.freeze({ rule: ruleFactory("dns") });

function expandCondition(value: Condition, scope: Scope, path: string, resolve: Resolve): Fields {
  const { node, invert } = conditionData(value, path);
  const inversion = invert ? { invert: true } : {};
  if ("fields" in node) {
    checkLeaf(node.fields, path, scope);
    const fields = expandInput(ruleMatchSchema[scope], node.fields, path, resolve) as Fields;
    if (invert) fields.invert = node.fields.invert !== true;
    return fields;
  }
  if (!node.rules.length) fail(`${path}.rules`, "empty logical group");
  return {
    type: "logical",
    mode: node.mode,
    ...inversion,
    rules: node.rules.map((child, index) =>
      expandCondition(child, scope, `${path}.rules[${index}]`, resolve),
    ),
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
    ...(expandInput(data.schema, data.action, path, resolve) as Fields),
  };
}

export function checkDnsRules(rules: readonly Fields[], path: string): void {
  const named = new Set<string>();
  let anonymous = false;

  function inspect(node: Fields, nodePath: string, logicalRespond: boolean): void {
    if (node.type === "logical") {
      (node.rules as Fields[]).forEach((child, index) =>
        inspect(child, `${nodePath}.rules[${index}]`, logicalRespond),
      );
      return;
    }
    const match = node.match_response;
    if (typeof match === "string") {
      if (logicalRespond)
        fail(`${nodePath}.match_response`, "logical respond cannot bind a named result", match);
      if (!named.has(match))
        fail(`${nodePath}.match_response`, "requires an earlier named evaluate", match);
    }
    if (match === true && !anonymous)
      fail(`${nodePath}.match_response`, "requires an earlier untagged evaluate");
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
