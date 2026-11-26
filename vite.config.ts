import { defineConfig } from "vite-plus";

export default defineConfig({
  pack: {
    entry: ["./index.ts"],
    format: "esm",
    dts: true,
  },
  fmt: {
    ignorePatterns: ["dist/**", "schema/sing-box.json", "src/generated/sing-box.ts"],
  },
  lint: {
    ignorePatterns: ["dist/**", "src/generated/sing-box.ts"],
    options: { typeAware: true, typeCheck: true },
  },
});
