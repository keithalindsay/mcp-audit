import { describe, it, expect } from "vitest";
import {
  ConfigSchema,
  DEFAULT_CONFIG,
  FindingSchema,
  SEVERITY_ORDER,
  compareSeverityDesc,
  severityAtLeast,
  type Severity,
} from "../src/schemas.js";

describe("severity ordering", () => {
  it("orders critical > high > medium > low > info", () => {
    expect(SEVERITY_ORDER.critical).toBeGreaterThan(SEVERITY_ORDER.high);
    expect(SEVERITY_ORDER.high).toBeGreaterThan(SEVERITY_ORDER.medium);
    expect(SEVERITY_ORDER.medium).toBeGreaterThan(SEVERITY_ORDER.low);
    expect(SEVERITY_ORDER.low).toBeGreaterThan(SEVERITY_ORDER.info);
  });

  it("sorts descending (most severe first)", () => {
    const arr: Severity[] = ["low", "critical", "medium", "info", "high"];
    arr.sort(compareSeverityDesc);
    expect(arr).toEqual(["critical", "high", "medium", "low", "info"]);
  });

  it("severityAtLeast respects the threshold", () => {
    expect(severityAtLeast("critical", "high")).toBe(true);
    expect(severityAtLeast("high", "high")).toBe(true);
    expect(severityAtLeast("medium", "high")).toBe(false);
    expect(severityAtLeast("info", "low")).toBe(false);
  });
});

describe("Config schema defaults", () => {
  it("applies defaults per §7.4", () => {
    expect(DEFAULT_CONFIG).toEqual({
      failOn: "high",
      minSeverity: "low",
      disabledRules: [],
      secretPatterns: [],
      timeoutMs: 10000,
    });
  });

  it("accepts overrides", () => {
    const c = ConfigSchema.parse({ failOn: "critical", disabledRules: ["MCP009"] });
    expect(c.failOn).toBe("critical");
    expect(c.disabledRules).toEqual(["MCP009"]);
  });
});

describe("Finding schema", () => {
  it("parses a well-formed finding", () => {
    const f = FindingSchema.parse({
      ruleId: "MCP001",
      severity: "critical",
      category: "exec",
      title: "t",
      detail: "d",
      location: "run_shell",
      remediation: "r",
      confidence: "high",
    });
    expect(f.ruleId).toBe("MCP001");
  });

  it("rejects an invalid severity", () => {
    expect(() =>
      FindingSchema.parse({
        ruleId: "MCP001",
        severity: "nope",
        category: "exec",
        title: "t",
        detail: "d",
        location: "x",
        remediation: "r",
        confidence: "high",
      }),
    ).toThrow();
  });
});
