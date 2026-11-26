# Schema and type generation

The [pinned schema](sing-box.json) is the verbatim output of `sing-box schema`. The Kit uses it for both Ajv validation and TypeScript generation.

[`version.json`](version.json) records the output of `sing-box version --name` and the `Revision` reported by `sing-box version` for the same binary.

The upstream sing-box project is Copyright (C) 2022 by nekohasekai and publishes under GPL-3.0-or-later with additional naming terms. See the [sing-box v1.14.4 license notice](https://github.com/SagerNet/sing-box/blob/v1.14.4/README.md#license) and [release](https://github.com/SagerNet/sing-box/releases/tag/v1.14.4).

## Regenerate the types

```sh
vp install --frozen-lockfile
bun run schema:generate
git diff --exit-code -- src/generated
vp check
bun test
```

Type generation reads the local snapshot and works offline after dependency installation. CI checks both generated type files and independently compares the public factory names and branches to the pinned schema. The Kit input types use the same schema projections as the runtime builders. Run `bun tests/sing-box-check.ts` with the pinned binary on `PATH`, or set `SING_BOX` to its path, to check the representative configurations. When updating the supported sing-box version, update the schema snapshot, `version.json`, generated types, and affected test expectations together.
