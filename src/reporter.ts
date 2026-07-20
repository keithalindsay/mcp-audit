import pc from "picocolors";
import type { AuditReport, Finding, Severity } from "./schemas.js";

/**
 * reporter.ts — the terminal report (DESIGN.md §9) + JSON output.
 * Findings arrive pre-sorted (severity desc, ruleId asc) from the rule engine.
 */

const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "CRITICAL",
  high: "HIGH",
  medium: "MEDIUM",
  low: "LOW",
  info: "INFO",
};

function colorSeverity(sev: Severity, color: boolean): string {
  const label = SEVERITY_LABEL[sev].padEnd(8);
  if (!color) return label;
  switch (sev) {
    case "critical":
      return pc.bgRed(pc.white(pc.bold(` ${SEVERITY_LABEL[sev]} `))) + " ".repeat(Math.max(0, 8 - SEVERITY_LABEL[sev].length - 2));
    case "high":
      return pc.red(pc.bold(label));
    case "medium":
      return pc.yellow(label);
    case "low":
      return pc.cyan(label);
    case "info":
      return pc.dim(label);
  }
}

function dim(s: string, color: boolean): string {
  return color ? pc.dim(s) : s;
}

function bold(s: string, color: boolean): string {
  return color ? pc.bold(s) : s;
}

function wrapDetail(text: string, indent: string, width = 92): string[] {
  const words = text.split(/\s+/);
  const lines: string[] = [];
  let cur = indent;
  for (const w of words) {
    if (cur.length + w.length + 1 > width && cur.trim().length > 0) {
      lines.push(cur);
      cur = indent + w;
    } else {
      cur = cur.trim().length ? `${cur} ${w}` : indent + w;
    }
  }
  if (cur.trim().length) lines.push(cur);
  return lines;
}

function renderFinding(f: Finding, color: boolean): string {
  const sev = colorSeverity(f.severity, color);
  const id = bold(f.ruleId, color);
  const cat = dim(f.category.padEnd(12), color);
  const head = `  ${sev} ${id}  ${cat} ${f.title}`;
  const body = wrapDetail(
    `→ ${f.detail} [confidence: ${f.confidence}] Fix: ${f.remediation}`,
    "      ",
  )
    .map((l) => dim(l, color))
    .join("\n");
  const loc = dim(`      location: ${f.location}`, color);
  return `${head}\n${loc}\n${body}`;
}

export function renderReport(report: AuditReport, opts: { color?: boolean } = {}): string {
  const color = opts.color ?? true;
  const lines: string[] = [];

  const s = report.serverSummary;
  const plural = (n: number, word: string) => `${n} ${word}${n === 1 ? "" : "s"}`;
  const summarySuffix = s
    ? `  (${plural(s.tools, "tool")}, ${plural(s.resources, "resource")}, ${plural(s.prompts, "prompt")})`
    : "  (no live server introspected)";
  lines.push("");
  lines.push(`${bold("mcp-audit", color)} · target=${report.target}${summarySuffix}`);
  lines.push("");

  if (report.findings.length === 0) {
    lines.push(dim("  No findings at or above the configured minimum severity.", color));
  } else {
    for (const f of report.findings) {
      lines.push(renderFinding(f, color));
      lines.push("");
    }
  }

  const t = report.totals;
  const summary =
    `Summary: ${t.total} finding${t.total === 1 ? "" : "s"} — ` +
    `${t.critical} critical · ${t.high} high · ${t.medium} medium · ${t.low} low · ${t.info} info`;
  lines.push(color ? bold(summary, color) : summary);
  lines.push(`Fail threshold: ${report.failOn} → Exit: ${report.exitCode}`);
  return lines.join("\n");
}

export function toJson(report: AuditReport): string {
  return JSON.stringify(report, null, 2);
}
