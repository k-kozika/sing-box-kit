import { compile } from "json-schema-to-typescript";

const schema = await Bun.file(new URL("../schema/sing-box.json", import.meta.url)).json();
const types = await compile({ ...schema, title: "SingBoxConfig" }, "SingBoxConfig", {
  additionalProperties: false,
});
await Bun.write(new URL("../src/generated/sing-box.ts", import.meta.url), types);
