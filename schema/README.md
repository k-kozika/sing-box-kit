# Schema and type generation

The [pinned schema](sing-box.json) is the verbatim output of `sing-box schema`. The Kit uses it for both Ajv validation and TypeScript generation.

## Provenance

- Version: 1.14.4
- Revision: `c005f35300ce76427dc285481ec5695f5b179cd2`
- Source: `sing-box schema` from the installed Linux amd64 binary, built with Go 1.26.10 and CGO enabled
- Build tags: `with_gvisor,with_quic,with_dhcp,with_wireguard,with_utls,with_acme,with_clash_api,with_tailscale,with_ccm,with_ocm,with_cloudflared,with_naive_outbound,with_usbip,with_openvpn,with_openconnect,badlinkname,tfogo_checklinkname0,with_musl`
- SHA-256: `32f7598b8428276c5d358fd385942fa54dbe099055974120912b93626accbfd9`

The upstream sing-box project is Copyright (C) 2022 by nekohasekai and publishes under GPL-3.0-or-later with additional naming terms. See the [sing-box v1.14.4 license notice](https://github.com/SagerNet/sing-box/blob/v1.14.4/README.md#license) and [release](https://github.com/SagerNet/sing-box/releases/tag/v1.14.4).

## Regenerate the types

```sh
bun install --frozen-lockfile
bun run schema:generate
git diff --exit-code -- src/generated/sing-box.ts
bun run typecheck
bun test
```

Type generation reads the local snapshot and works offline after dependency installation. CI checks that the generated file matches the checked-in types. When updating the supported sing-box version, update the snapshot, provenance, generated types, and affected test expectations together.
