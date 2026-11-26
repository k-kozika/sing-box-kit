# DNS rules and response evaluation

Create a DNS rule with `dns.rule(condition, action)` and add it to `dns.rules` in `compile()`. Use `dns.rule(action)` for a rule that matches every query that reaches it. Register each referenced DNS server in `dns.servers`. See [Resource factories and registration](resources.md#dns-servers) for the available server types.

## Match conditions

Use `Rule.match(fields)` and the same condition methods as [routing rules](rules.md#match-conditions). DNS conditions include `query_type`, `query_client_subnet`, `query_dnssec`, and the response fields described below. DNS `preferred_by` accepts one or more Hosts, Local, mDNS, Tailscale, OpenConnect, OpenVPN, or Resolved DNS servers.

## DNS actions

| Action          | Options                                                                                 |
| --------------- | --------------------------------------------------------------------------------------- |
| `route`         | Requires a DNS `server`. Accepts shared DNS options, `race`, and `speculative`.         |
| `evaluate`      | Requires a DNS `server`. Accepts a result `tag`, shared DNS options, and `speculative`. |
| `respond`       | Optional `race`                                                                         |
| `route-options` | Requires at least one effective shared DNS option                                       |
| `predefined`    | Optional `rcode`, `answer`, `ns`, `extra`, and `race`                                   |
| `reject`        | Optional `method` of `default` or `drop`, plus `no_drop` and `race`                     |

Shared DNS options include `timeout`, `disable_cache`, `disable_optimistic_cache`, `rewrite_ttl`, `client_subnet`, and `remove_client_subnet`. For `route-options`, a positive timeout, a true flag, a valid subnet, or an explicit TTL counts as effective. A TTL of zero counts.

## DNS response evaluation

Place an `evaluate` rule before rules that depend on its response. Match a named response with `match_response: "tag"`, or an untagged response with `match_response: true`. With response matching active, a leaf can also test `response_rcode`, `response_answer`, `response_ns`, `response_extra`, `ip_cidr`, `ip_is_private`, or `ip_accept_any`.

A `respond` rule can return a named response when its own default condition matches that tag. For a logical `respond` rule, use an untagged evaluation. Enable `race` only on a rule with active response matching and omit `speculative` on that rule.

```ts
import { compile, dns, dnsServer, Rule } from "sing-box-kit";

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
