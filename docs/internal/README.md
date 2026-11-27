# SBKit internals

The [package entry point](../../index.ts) exports resource builders, rule builders, `compile()`, `validateConfig()`, and their public types. Users build a configuration from SBKit values, then call `compile()` to turn those values into sing-box JSON. The [configuration guide](../configuration.md) shows this flow through the public API.

## Resource builders and rules

- [`src/input-schema.ts`](../../src/input-schema.ts) projects the pinned schema into factory branches, configuration sections, and rule match and action schemas. A factory branch describes its options, output, and which shared settings methods it supports. The projection also maps `x-tag-reference` annotations to SBKit reference types and runtime roles.
- [`src/factories.ts`](../../src/factories.ts) builds the factory collections from that catalog. Each factory selects a schema branch, checks its options, and creates a resource. Calling `.listen()`, `.dial()`, or `.tls()` builds a new resource from the original options and the accumulated settings.
- [`src/resource.ts`](../../src/resource.ts) keeps resource metadata in a `WeakMap` keyed by the frozen builder value. The metadata includes its target list, kind, fields, and reference roles. Snapshots copy and freeze ordinary options while retaining the identity of SBKit values that may be referenced later.
- [`src/settings.ts`](../../src/settings.ts) normalizes listener and TLS settings and expands references in schema-shaped inputs. During builder validation, it uses placeholder strings for resource references so Ajv can validate the JSON shape before the full configuration is available.
- [`src/rules.ts`](../../src/rules.ts) stores condition trees and rule actions. Each condition carries the scopes it supports. Combining conditions intersects those scopes, while expansion turns groups into sing-box logical rules and places the action at the top level. [`src/user.ts`](../../src/user.ts) supplies the identity-bearing `User` values that inbound builders use to implement `.authUser()`.

## Configuration compilation

[`src/compile.ts`](../../src/compile.ts) assembles the configuration in this order.

1. **Register resources.** Read the root and nested resource lists and index each resource by its object identity. Index tags separately to catch collisions. Outbounds and endpoints share a tag scope.
2. **Expand settings and rules.** Walk the projected schemas and resolve each typed reference to a tag. The resolver checks the requested role, a single explicit tag, and registration of the exact builder value. During expansion it records dependency edges for group membership and for the detours and DNS resolver references that need cycle checks.
3. **Check relationships and validate JSON.** Check DNS response dependencies in rule order and reject cycles in the recorded dependency graph. Pass the assembled configuration to `validateConfig()`.

[`src/schema.ts`](../../src/schema.ts) owns the Ajv validators and formats validation errors with configuration paths. A direct call to `validateConfig()` starts at the final schema check and accepts raw sing-box JSON.

## Schema and generated types

[`schema/sing-box.json`](../../schema/sing-box.json) is the upstream snapshot used for final JSON validation. [`scripts/generate-schema.ts`](../../scripts/generate-schema.ts) generates [`sing-box.ts`](../../src/generated/sing-box.ts) from that snapshot for the raw `SingBoxConfig` shape. It generates [`sbkit-inputs.ts`](../../src/generated/sbkit-inputs.ts) from the projections in `input-schema.ts` for builder options, config sections, and rule inputs. Reusing those projections keeps the generated TypeScript inputs and runtime checks aligned. Follow the [schema generation guide](../../schema/README.md) when updating the pin or regenerating the types.

## Where to check a change

- [`tests/types.ts`](../../tests/types.ts) covers accepted and rejected TypeScript calls through the public API. Run `vp check` to check those cases.
- [`tests/compile.test.ts`](../../tests/compile.test.ts) and [`tests/schema-coverage.test.ts`](../../tests/schema-coverage.test.ts) cover emitted JSON, reference resolution, rules, and validation errors. [`tests/factories.test.ts`](../../tests/factories.test.ts) compares public factories and branches with the pinned schema. Run the suite with `vp test` on Node.js or `bun run --bun vp test --pool=threads` on Bun.
- [`tests/sing-box-check.ts`](../../tests/sing-box-check.ts) runs the pinned sing-box binary against representative compiled configurations. The [CI workflow](../../.github/workflows/ci.yml) also checks generated files and runs the test suite on both runtimes.
