import { describe, it, expect } from "vitest";
import { MCP001, MCP002, MCP003, MCP006, MCP007, MCP009 } from "../src/rules/tools.js";
import type { RuleContext } from "../src/rules/types.js";
import { classifyTools } from "../src/classify.js";
import { BUILTIN_SECRET_PATTERNS } from "../src/config-scan.js";
import { tool, param, model } from "./helpers.js";
import type { Tool } from "../src/schemas.js";

function ctxFor(tools: Tool[]): RuleContext {
  const m = model(tools);
  return {
    model: m,
    classified: classifyTools(tools),
    configServer: null,
    configPath: null,
    secretPatterns: BUILTIN_SECRET_PATTERNS,
  };
}

describe("MCP001 exec", () => {
  it("flags run_shell", () => {
    const f = MCP001.check(ctxFor([tool("run_shell", "Execute a shell command.", [param("command")])]));
    expect(f).toHaveLength(1);
    expect(f[0]!.severity).toBe("critical");
    expect(f[0]!.location).toBe("run_shell.command");
  });
  it("does not flag a benign echo", () => {
    expect(MCP001.check(ctxFor([tool("echo", "Echo text.", [param("text")])]))).toHaveLength(0);
  });
});

describe("MCP002 filesystem", () => {
  it("flags an unconstrained path param", () => {
    const f = MCP002.check(ctxFor([tool("read_file", "Read a file.", [param("path")])]));
    expect(f).toHaveLength(1);
    expect(f[0]!.location).toBe("read_file.path");
  });
  it("does not flag a constrained path", () => {
    const f = MCP002.check(ctxFor([tool("read_file", "Read a file.", [param("path", { constrained: true })])]));
    expect(f).toHaveLength(0);
  });
  it("does not flag a tool with no path param", () => {
    expect(MCP002.check(ctxFor([tool("ping", "Ping.", [param("host")])]))).toHaveLength(0);
  });
});

describe("MCP003 network", () => {
  it("flags an unconstrained url param", () => {
    const f = MCP003.check(ctxFor([tool("http_fetch", "Fetch a URL.", [param("url")])]));
    expect(f).toHaveLength(1);
    expect(f[0]!.location).toBe("http_fetch.url");
  });
  it("does not flag a constrained url", () => {
    expect(
      MCP003.check(ctxFor([tool("http_fetch", "Fetch a URL.", [param("url", { constrained: true })])])),
    ).toHaveLength(0);
  });
});

describe("MCP006 validation", () => {
  it("flags an unconstrained command string", () => {
    const f = MCP006.check(ctxFor([tool("run_shell", "Run.", [param("command")])]));
    expect(f).toHaveLength(1);
    expect(f[0]!.severity).toBe("medium");
  });
  it("does not double-flag a path param (that is MCP002's job)", () => {
    expect(MCP006.check(ctxFor([tool("read_file", "Read.", [param("path")])]))).toHaveLength(0);
  });
});

describe("MCP007 destructive", () => {
  it("flags a delete tool with no confirmation", () => {
    const f = MCP007.check(ctxFor([tool("delete_record", "Delete a record permanently.", [param("id")])]));
    expect(f).toHaveLength(1);
    expect(f[0]!.severity).toBe("high");
  });
  it("does not flag when a confirm affordance exists", () => {
    const f = MCP007.check(
      ctxFor([tool("delete_record", "Delete a record.", [param("id"), param("confirm", { type: "boolean" })])]),
    );
    expect(f).toHaveLength(0);
  });
  it("does not flag a read-only tool", () => {
    expect(MCP007.check(ctxFor([tool("get_status", "Get status.", [])]))).toHaveLength(0);
  });
});

describe("MCP009 description", () => {
  it("flags an over-broad description", () => {
    const f = MCP009.check(ctxFor([tool("helper", "This tool can do anything you ask.", [])]));
    expect(f).toHaveLength(1);
    expect(f[0]!.severity).toBe("low");
  });
  it("does not flag a narrow description", () => {
    expect(MCP009.check(ctxFor([tool("read_file", "Read a file from disk.", [param("path")])]))).toHaveLength(0);
  });
});
