# Repository Guidelines

## Project Structure

SBKit builds and validates sing-box configurations in TypeScript. The public API is exported from `index.ts`. In `src/`, `factories.ts` exposes resource builders, `compile.ts` assembles configurations, `rules.ts` handles route and DNS rules, and `schema.ts` validates raw configs with Ajv. User-facing examples and API behavior live in `README.md` and `docs/`.

The upstream schema snapshot and its version and revision live in `schema/`. Follow [the schema generation guide](schema/README.md) when changing schema inputs or updating the pin. Regenerate and commit the corresponding files in `src/generated/`.

## Build, Test, and Development Commands

- `vp install --frozen-lockfile` installs dependencies from the Bun lockfile.
- `vp check` checks formatting, lint, and types. Apply formatting with `vp fmt`.
- `bun test` runs the test suite. Run a focused suite with `bun test tests/compile.test.ts`.
- `bun run build` uses Vite+ to emit the ESM bundle and type declarations in `dist/`.
- To try the README example locally, import from `./index` in `config.ts` and run `bun config.ts`.

## Coding Style

Use strict TypeScript with two-space indentation, double quotes, semicolons, and explicit `import type` for type-only imports. Use camelCase for TypeScript functions and factory names, PascalCase for types, and kebab-case for multiword file names. Keep upstream field names such as `listen_port` in configuration objects. Keep the public API compatible with Bun and Node.js.

## Testing

Use `bun:test` in `tests/*.test.ts` with names that describe the behavior under test. Exercise public behavior through `index.ts` and add compile-time API cases to `tests/types.ts`. For schema or compilation changes, run `bun tests/sing-box-check.ts` with the binary pinned in `schema/version.json` on `PATH` or via `SING_BOX`. CI also verifies generated files and smoke-tests the packed library on Node.js.

## Commits and Pull Requests

Use short imperative commit subjects, such as “Support all pinned sing-box configuration kinds.” In pull requests, summarize user-visible changes, link related issues when available, and list the checks you ran. Include an example configuration when it helps explain a public API change.
