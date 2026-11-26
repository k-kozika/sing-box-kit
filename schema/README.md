# Schema and type generation

The [pinned schema](sing-box.json) is the verbatim output of `sing-box schema`. The Kit uses it for both Ajv validation and TypeScript generation.

[`version.json`](version.json) records the output of `sing-box version --name` and the `Revision` reported by `sing-box version` for the same binary.

The upstream sing-box project is Copyright (C) 2022 by nekohasekai and publishes under GPL-3.0-or-later with additional naming terms. See the [sing-box v1.14.4 license notice](https://github.com/SagerNet/sing-box/blob/v1.14.4/README.md#license) and [release](https://github.com/SagerNet/sing-box/releases/tag/v1.14.4).

## Regenerate the types

```sh
vp install --frozen-lockfile
bun run schema:generate
git diff --exit-code -- src/generated/sing-box.ts
vp check
bun test
```

Type generation reads the local snapshot and works offline after dependency installation. CI checks that the generated file matches the checked-in types. When updating the supported sing-box version, update the schema snapshot, `version.json`, generated types, and affected test expectations together.
