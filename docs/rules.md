# Routing rules and shared conditions

Use `Rule.match(fields)` to create a condition. Attach an action with `route.rule(condition, action)` and put the result in `route.rules`. The one-argument form, such as `route.rule({ action: "reject" })`, matches all traffic that reaches the rule.

```ts
import { compile, outbound, route, Rule } from "sing-box-kit";

const direct = outbound.direct({ tag: "direct" });
compile({
  outbounds: [direct],
  route: {
    rules: [
      route.rule(Rule.match({ domain_suffix: "example.test" }), {
        action: "route",
        outbound: direct,
      }),
      route.rule({ action: "reject" }),
    ],
  },
});
```

## Match conditions

Use the condition fields from the pinned schema. Route and DNS rules share fields such as `domain`, `domain_suffix`, `network`, `port`, `inbound`, `rule_set`, and `auth_user`. Routing rules also support `client`, `network: "icmp"`, and `ip_cidr` for the destination address.

The `inbound`, `rule_set`, and `preferred_by` fields accept one typed resource or an array of typed resources. Route `preferred_by` accepts Tailscale, WireGuard, OpenConnect, and OpenVPN client endpoints and Bridge outbounds. See [DNS match conditions](dns-rules.md#match-conditions) for DNS-specific fields and server types.

Use `.and()`, `.or()`, and `.not()` to build a condition tree. Each group retains its operand order, so `a.or(b).and(c)` means `(a OR b) AND c`. The action appears at the top level. Combining conditions requires at least one rule scope common to both operands.

## Route actions

| Action          | Options                                                                                |
| --------------- | -------------------------------------------------------------------------------------- |
| `route`         | Requires an egress `outbound`. Accepts route options.                                  |
| `bypass`        | Optional egress `outbound`. Accepts route options.                                     |
| `hijack-dns`    | None                                                                                   |
| `route-options` | Route options such as `override_address` and `override_port`                           |
| `sniff`         | Optional `sniffer` and `timeout`                                                       |
| `resolve`       | Optional typed DNS `server`, strategy, timeout, cache settings, TTL, and client subnet |
| `reject`        | Optional `method` of `default`, `drop`, or `reply` for ICMP echo, plus `no_drop`       |

Route options include `override_address`, `override_port`, and the other fields defined by the pinned schema. Use these options with `route`, `bypass`, or `route-options`.

## Match authenticated users

A `User` represents a name shared across inbounds. Supply credentials on each inbound entry. SOCKS, Mixed, and Shadowsocks use `password`. VLESS uses `uuid` with optional `flow`. Mixed and Shadowsocks also accept their sing-box entry formats. In an entry that uses `user`, omit the explicit `username` or `name`.

Call `inboundValue.authUser(user)` on the final inbound to match that inbound and authenticated name together. The exact `User` object must appear once, and its name must be non-empty and unique on that inbound. To match a name added through the SSM API, use `Rule.match({ inbound: managedInbound, auth_user: "alice" })`. A plain `auth_user` condition can also match a name across inbounds. An empty string can match traffic with no authenticated name.

```ts
import { compile, inbound, outbound, route, Rule, user } from "sing-box-kit";

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
