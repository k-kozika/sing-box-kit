# Build and validate a configuration

Create resources with the package factories, apply any shared settings, then pass the finished resources to `compile()`. Use those same resource values wherever the configuration references them.

```ts
import { compile, dnsServer, outbound } from "sing-box-kit";

const resolver = dnsServer.local({ tag: "local" });
const direct = outbound.direct({ tag: "direct" }).dial({ domain_resolver: resolver });

const config = compile({
  outbounds: [direct],
  dns: { servers: [resolver], final: resolver, strategy: "prefer_ipv4" },
  route: { final: direct },
});
```

## Register and reference resources

Each builder method returns a new resource. In the example, register the result of `.dial()` in `outbounds` and pass that same value to `route.final`. If you recreate a resource with the same tag, rebuild any references to use the new value. Apply each settings method at most once per chain.

`compile()` checks that each reference points to a registered resource that supports the requested role. It resolves references to tags even inside objects, maps, and arrays. Outbounds and endpoints share a tag scope. Services without explicit tags use their zero-based list position for collision checks.

See [Resource factories and registration](resources.md) for the lists where each resource belongs and [Shared settings](settings.md) for available builder methods.

## Set top-level, route, and DNS options

Pass `$schema`, `log`, `ntp`, `certificate`, and `experimental` at the root of the input to `compile()`. Set route and DNS options directly under `route` and `dns`. See [Routing rules](rules.md) and [DNS rules](dns-rules.md) for their respective rule lists.

The returned `SingBoxConfig` is ready for `JSON.stringify()`. The compiler preserves list order, sing-box field names, and explicit values such as `false`, `0`, and empty arrays.

## Validate existing JSON

Pass a parsed JSON configuration to `validateConfig(value)` to check it against the pinned sing-box schema. The function accepts raw tag strings and returns the validated `SingBoxConfig`. Use `compile()` when building a config with SBKit resources to also check registration, reference capabilities, and dependencies.
