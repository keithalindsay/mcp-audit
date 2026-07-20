import { describe, it, expect } from "vitest";
import { MCP004, MCP011 } from "../src/rules/combinations.js";
import type { RuleContext } from "../src/rules/types.js";
import { classifyTools } from "../src/classify.js";
import { BUILTIN_SECRET_PATTERNS } from "../src/config-scan.js";
import { tool, param, resource, model } from "./helpers.js";
import type { Tool, Resource } from "../src/schemas.js";

function ctxFor(tools: Tool[], resources: Resource[] = []): RuleContext {
  return {
    model: model(tools, resources),
    classified: classifyTools(tools),
    configServer: null,
    configPath: null,
    secretPatterns: BUILTIN_SECRET_PATTERNS,
  };
}

describe("MCP004 exfiltration combination", () => {
  it("does NOT fire for a source-only server", () => {
    const f = MCP004.check(ctxFor([tool("read_file", "Read a file.", [param("path")])]));
    expect(f).toHaveLength(0);
  });

  it("fires when a source + an external sink coexist", () => {
    const f = MCP004.check(
      ctxFor([
        tool("read_file", "Read a file.", [param("path")]),
        tool("http_fetch", "Fetch a URL.", [param("url")]),
      ]),
    );
    expect(f).toHaveLength(1);
    expect(f[0]!.severity).toBe("critical");
    expect(f[0]!.location).toContain("read_file");
    expect(f[0]!.location).toContain("http_fetch");
  });

  it("fires from a sensitive resource source + a sink tool", () => {
    const f = MCP004.check(
      ctxFor(
        [tool("http_post", "Send data to a webhook.", [param("url")])],
        [resource("env://all", { description: "process environment" })],
      ),
    );
    expect(f).toHaveLength(1);
  });

  it("does NOT fire for a sink-only server with no source", () => {
    const f = MCP004.check(ctxFor([tool("send_email", "Send an email.", [param("to")])]));
    expect(f).toHaveLength(0);
  });
});

describe("MCP011 posture", () => {
  it("does not fire with only 2 high-capability tools", () => {
    const f = MCP011.check(
      ctxFor([tool("run_shell", "Run.", [param("command")]), tool("http_fetch", "Fetch.", [param("url")])]),
    );
    expect(f).toHaveLength(0);
  });

  it("fires at 3+ executor/sink tools", () => {
    const f = MCP011.check(
      ctxFor([
        tool("run_shell", "Run.", [param("command")]),
        tool("http_fetch", "Fetch.", [param("url")]),
        tool("send_email", "Send an email webhook.", [param("to")]),
      ]),
    );
    expect(f).toHaveLength(1);
    expect(f[0]!.severity).toBe("info");
  });
});
