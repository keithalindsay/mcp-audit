import { describe, it, expect } from "vitest";
import { fileURLToPath } from "node:url";
import { loadMcpConfig, scanSecrets, matchSecret } from "../src/config-scan.js";
import { MCP005 } from "../src/rules/config.js";
import { BUILTIN_SECRET_PATTERNS } from "../src/config-scan.js";
import type { RuleContext } from "../src/rules/types.js";

const mcpJsonPath = fileURLToPath(
  new URL("../examples/vulnerable-server/mcp.json", import.meta.url),
);

describe("matchSecret", () => {
  it("matches an sk- style key by name, never returns the value", () => {
    const name = matchSecret("sk-abcd1234abcd1234abcd1234abcd1234");
    expect(name).toBe("openai-anthropic-style-key");
  });
  it("does not match a benign value", () => {
    expect(matchSecret("true")).toBeNull();
    expect(matchSecret("node")).toBeNull();
  });
  it("matches an AWS access key id", () => {
    expect(matchSecret("AKIAIOSFODNN7EXAMPLE")).toBe("aws-access-key-id");
  });
});

describe("loadMcpConfig + scanSecrets on the bundled mcp.json", () => {
  it("parses the vulnerable-demo server", () => {
    const cfg = loadMcpConfig(mcpJsonPath);
    expect(cfg.servers.length).toBeGreaterThanOrEqual(1);
    const srv = cfg.servers.find((s) => s.name === "vulnerable-demo");
    expect(srv).toBeDefined();
    expect(srv!.env.API_TOKEN).toBeDefined();
  });

  it("finds the planted secret (location + pattern only)", () => {
    const cfg = loadMcpConfig(mcpJsonPath);
    const matches = scanSecrets(cfg.servers);
    const tokenMatch = matches.find((m) => m.location === "config:env.API_TOKEN");
    expect(tokenMatch).toBeDefined();
    // must not leak the value anywhere in the match object
    expect(JSON.stringify(tokenMatch)).not.toContain("sk-");
  });

  it("MCP005 rule emits a critical secret finding", () => {
    const cfg = loadMcpConfig(mcpJsonPath);
    const srv = cfg.servers.find((s) => s.name === "vulnerable-demo")!;
    const ctx: RuleContext = {
      model: null,
      classified: new Map(),
      configServer: srv,
      configPath: cfg.path,
      secretPatterns: BUILTIN_SECRET_PATTERNS,
    };
    const findings = MCP005.check(ctx);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0]!.severity).toBe("critical");
    expect(findings[0]!.detail).not.toContain("sk-");
  });
});
