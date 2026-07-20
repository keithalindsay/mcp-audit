import { describe, it, expect } from "vitest";
import { runRules, ruleCatalog, ALL_RULES } from "../src/rules/index.js";
import type { RuleContext } from "../src/rules/types.js";
import { classifyTools } from "../src/classify.js";
import { BUILTIN_SECRET_PATTERNS } from "../src/config-scan.js";
import { tool, param, model } from "./helpers.js";

function fullCtx(): RuleContext {
  const tools = [
    tool("run_shell", "Execute a shell command.", [param("command")]),
    tool("read_file", "Read a file from disk.", [param("path")]),
    tool("http_fetch", "Fetch a URL over HTTP.", [param("url")]),
  ];
  return {
    model: model(tools),
    classified: classifyTools(tools),
    configServer: null,
    configPath: null,
    secretPatterns: BUILTIN_SECRET_PATTERNS,
  };
}

describe("catalog", () => {
  it("has all 11 rules MCP001..MCP011 in order", () => {
    const ids = ruleCatalog().map((r) => r.id);
    expect(ids).toEqual([
      "MCP001", "MCP002", "MCP003", "MCP004", "MCP005", "MCP006",
      "MCP007", "MCP008", "MCP009", "MCP010", "MCP011",
    ]);
    expect(ALL_RULES).toHaveLength(11);
  });
});

describe("runRules", () => {
  it("sorts findings by severity desc then ruleId asc", () => {
    const findings = runRules(fullCtx());
    for (let i = 1; i < findings.length; i++) {
      const order = { critical: 5, high: 4, medium: 3, low: 2, info: 1 } as const;
      const prev = findings[i - 1]!;
      const cur = findings[i]!;
      expect(order[prev.severity]).toBeGreaterThanOrEqual(order[cur.severity]);
    }
    // MCP001 (critical) and MCP004 (critical) present
    const ids = findings.map((f) => f.ruleId);
    expect(ids).toContain("MCP001");
    expect(ids).toContain("MCP004");
  });

  it("respects disabledRules", () => {
    const findings = runRules(fullCtx(), { disabledRules: ["MCP004"] });
    expect(findings.map((f) => f.ruleId)).not.toContain("MCP004");
    // others still present
    expect(findings.map((f) => f.ruleId)).toContain("MCP001");
  });

  it("respects minSeverity", () => {
    const findings = runRules(fullCtx(), { minSeverity: "high" });
    // no medium/low/info findings survive
    expect(findings.every((f) => ["critical", "high"].includes(f.severity))).toBe(true);
    // MCP006 (medium) filtered out
    expect(findings.map((f) => f.ruleId)).not.toContain("MCP006");
  });
});
