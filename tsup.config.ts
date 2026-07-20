import { defineConfig } from "tsup";

export default defineConfig({
  entry: {
    cli: "src/cli.ts",
    "vulnerable-server": "examples/vulnerable-server/server.ts",
  },
  format: ["esm"],
  target: "node20",
  platform: "node",
  clean: true,
  splitting: false,
  sourcemap: false,
  dts: false,
  // @anthropic-ai/sdk is an optionalDependency, lazily imported; never bundle it.
  external: ["@anthropic-ai/sdk"],
  banner: {
    js: "#!/usr/bin/env node",
  },
});
