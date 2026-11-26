# sing-box Kit

Build and validate sing-box v1.14.4 configurations in TypeScript.

## Quick start

Install the package with `bun add sing-box-kit`, then create `config.ts`.

```ts
import { compile, outbound } from "sing-box-kit";

const config = compile({ outbounds: [outbound.direct({ tag: "direct" })] });
console.log(JSON.stringify(config, null, 2));
```

Generate JSON with `bun config.ts > config.json`.

To run the example from a source checkout, run `bun install --frozen-lockfile` and use `./index` as the import path.

## Documentation

- [Configuration reference](docs/configuration.md)
- [Route and DNS rules](docs/rules.md)
- [Schema and type generation](schema/README.md)
