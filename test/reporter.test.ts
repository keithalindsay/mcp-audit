import { describe, it, expect } from "vitest";
import { renderReport, toJson } from "../src/reporter.js";
import type { AuditReport } from "../src/schemas.js";

const REPORT: AuditReport = {
  schemaVersion: 1,
  target: "vulnerable-demo",
  startedAt: "2026-01-01T00:00:00.000Z",
  finishedAt: "2026-01-01T00:00:01.000Z",
  serverSummary: { name: "vulnerable-demo", tools: 3, resources: 1, prompts: 0 },
  findings: [
    {
      ruleId: "MCP001",
      severity: "critical",
      category: "exec",
      title: "run_shell executes arbitrary shell/code",
      detail: "d",
      location: "run_shell.command",
      remediation: "r",
      confidence: "high",
    },
    {
      ruleId: "MCP002",
      severity: "high",
      category: "filesystem",
      title: "read_file accepts an unrestricted path",
      detail: "d",
      location: "read_file.path",
      remediation: "r",
      confidence: "high",
    },
  ],
  totals: { critical: 1, high: 1, medium: 0, low: 0, info: 0, total: 2 },
  failOn: "high",
  exitCode: 1,
};

describe("renderReport (no-color)", () => {
  const out = renderReport(REPORT, { color: false });

  it("includes the target + server summary with singular/plural", () => {
    expect(out).toContain("target=vulnerable-demo");
    expect(out).toContain("3 tools, 1 resource, 0 prompts");
  });

  it("lists rule ids and severities", () => {
    expect(out).toContain("MCP001");
    expect(out).toContain("CRITICAL");
    expect(out).toContain("MCP002");
    expect(out).toContain("HIGH");
  });

  it("prints the summary + exit line", () => {
    expect(out).toContain("Summary: 2 findings — 1 critical · 1 high");
    expect(out).toContain("Fail threshold: high");
    expect(out).toContain("Exit: 1");
  });

  it("contains no ANSI escape codes when color is off", () => {
    const ESC = String.fromCharCode(27);
    expect(out.includes(ESC)).toBe(false);
  });
});

describe("toJson", () => {
  it("round-trips the report", () => {
    const parsed = JSON.parse(toJson(REPORT));
    expect(parsed.schemaVersion).toBe(1);
    expect(parsed.findings).toHaveLength(2);
    expect(parsed.exitCode).toBe(1);
  });
});
