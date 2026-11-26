# Route and DNS rules

Use `Rule.match(fields)` to create a condition. Attach an action with `route.rule(condition, action)` or `dns.rule(condition, action)` and add the result to the matching list in `compile()`. The one-argument form, such as `route.rule({ action: "reject" })`, matches all traffic that reaches the rule.

## Match conditions

Both rule scopes accept `domain`, `domain_suffix`, `port`, `inbound`, `rule_set`, and `auth_user`. Route rules also accept `client` and can use Tailscale or WireGuard endpoints in `preferred_by`. DNS rules also accept `query_type` and can use Tailscale DNS servers in `preferred_by`. The `inbound`, `rule_set`, and `preferred_by` fields accept one typed resource or an array of typed resources.

Use `.and()`, `.or()`, and `.not()` to build a condition tree. Each group retains its operand order, so `a.or(b).and(c)` means `(a OR b) AND c`. The action appears at the top level. Combining conditions requires at least one rule scope common to both operands.

## Match authenticated users

A `User` represents a name shared across inbounds. Supply credentials on each inbound entry. SOCKS, Mixed, and Shadowsocks use `password`. VLESS uses `uuid` with optional `flow`. Mixed and Shadowsocks also accept their sing-box entry formats. In an entry that uses `user`, omit the explicit `username` or `name`.

Call `inboundValue.authUser(user)` on the final inbound to match that inbound and authenticated name together. The exact `User` object must appear once, and its name must be non-empty and unique on that inbound. To match a name added through the SSM API, use `Rule.match({ inbound: managedInbound, auth_user: "alice" })`. A plain `auth_user` condition can also match a name across inbounds. An empty string can match traffic with no authenticated name.

```ts
import { compile, inbound, outbound, route, Rule, user } from "./index";

const alice = user({ name: "alice" });
const proxy = inbound
  .socks({
    tag: "proxy",
    users: [{ user: alice, password: "example-password" }],
  })
  .listen("127.0.0.1", { port: 1080 });
const egress = outbound.direct({ tag: "egress" });
const allowed = proxy.authUser(alice).and(Rule.match({ domain_suffix: "example.test" }));

compile({
  inbounds: [proxy],
  outbounds: [egress],
  route: {
    rules: [
      route.rule(allowed, { action: "route", outbound: egress }),
      route.rule({ action: "reject" }),
    ],
  },
});
```

## Actions

| Rule scope | Action          | Options                                                                                |
| ---------- | --------------- | -------------------------------------------------------------------------------------- |
| Route      | `route`         | Requires an egress `outbound`                                                          |
| Route      | `bypass`        | Optional egress `outbound`                                                             |
| Route      | `hijack-dns`    | None                                                                                   |
| DNS        | `route`         | Requires a DNS `server`. Accepts shared DNS options, `race`, and `speculative`         |
| DNS        | `evaluate`      | Requires a DNS `server`. Accepts a result `tag`, shared DNS options, and `speculative` |
| DNS        | `respond`       | Optional `race`                                                                        |
| DNS        | `route-options` | Requires at least one effective shared DNS option                                      |
| DNS        | `predefined`    | Optional `rcode`, `answer`, `ns`, `extra`, and `race`                                  |
| Both       | `reject`        | Optional `method` of `default` or `drop`, plus `no_drop`. DNS also accepts `race`      |

Shared DNS options include `timeout`, `disable_cache`, `disable_optimistic_cache`, `rewrite_ttl`, `client_subnet`, and `remove_client_subnet`. For `route-options`, a positive timeout, a true flag, a valid subnet, or an explicit TTL counts as effective. A TTL of zero counts.

## DNS response evaluation

Place an `evaluate` rule before rules that depend on its response. Match a named response with `match_response: "tag"`, or an untagged response with `match_response: true`. With response matching active, a leaf can also test `response_rcode`, `response_answer`, `response_ns`, `response_extra`, `ip_cidr`, `ip_is_private`, or `ip_accept_any`.

A `respond` rule can return a named response when its own default condition matches that tag. For a logical `respond` rule, use an untagged evaluation. Enable `race` only on a rule with active response matching and omit `speculative` on that rule.

```ts
import { compile, dns, dnsServer, Rule } from "./index";

const resolver = dnsServer.udp({ tag: "resolver", server: "192.0.2.53" });
const evaluate = dns.rule(Rule.match({ domain_suffix: "example.test" }), {
  action: "evaluate",
  server: resolver,
  tag: "example-answer",
});
const respond = dns.rule(
  Rule.match({ match_response: "example-answer", response_rcode: "NOERROR" }),
  { action: "respond" },
);

compile({ dns: { servers: [resolver], rules: [evaluate, respond] } });
```

See the [configuration reference](configuration.md) for resource registration and TLS.
