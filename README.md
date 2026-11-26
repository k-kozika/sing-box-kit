# sing-box-kit

Build and validate sing-box v1.14.4 configurations in TypeScript.

## Quick start

Install the package with `bun add sing-box-kit`, then save this local proxy configuration as `config.ts`.

```ts
import { compile, inbound, outbound } from "sing-box-kit";

const proxy = inbound.mixed({ tag: "proxy" }).listen("127.0.0.1", { port: 1080 });
const direct = outbound.direct({ tag: "direct" });
const config = compile({
  inbounds: [proxy],
  outbounds: [direct],
  route: { final: direct },
});
console.log(JSON.stringify(config, null, 2));
```

Generate and check the config with sing-box.

```sh
bun config.ts > config.json
sing-box check -c config.json
```

On Node.js 22.1 or later, install with `npm install sing-box-kit`, save the same example as `config.mjs`, and generate JSON with `node config.mjs > config.json`.

To run the example from a source checkout, run `vp install --frozen-lockfile` and use `./index` as the import path.

## Documentation

- [Build and validate a configuration](docs/configuration.md)
- [Resource factories and registration](docs/resources.md)
- [Listen, dial, resolver, and TLS settings](docs/settings.md)
- [Routing rules and shared conditions](docs/rules.md)
- [DNS rules and response evaluation](docs/dns-rules.md)

## Contributing

- [SBKit internals](docs/internal/README.md)
- [Schema and type generation](schema/README.md)
