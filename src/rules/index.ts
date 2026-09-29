import type { Finding, Severity } from "../schemas.js";
import { compareSeverityDesc, severityAtLeast } from "../schemas.js";
import type { Rule, RuleContext } from "./types.js";
import { MCP001, MCP002, MCP003, MCP006, MCP007, MCP009 } from "./tools.js";
import { MCP004, MCP011 } from "./combinations.js";
import { MCP005, MCP010 } from "./config.js";
import { stripUrls } from "../classify.js";

export type { Rule, RuleContext } from "./types.js";

/**
 * MCP008 (injection) spans the whole toolset, so it lives here: any tool that pulls
 * external/web content and returns it to the model is an indirect-prompt-injection
 * surface.
 */
export const MCP008: Rule = {
  id: "MCP008",
  title: "Tool returns untrusted external content to the model",
  severity: "medium",
  category: "injection",
  check(ctx: RuleContext): Finding[] {
    if (!ctx.model) return [];
    const out: Finding[] = [];
    for (const t of ctx.model.tools) {
      const tags = ctx.classified.get(t.name);
      // Word-start anchored: `maxRequestPayloadBytes` does not contain the word
      // "request" (field regression on mongodb-mcp-server insert-many/update-many).
      // Doc links are stripped first — a URL in prose is not a fetch capability.
      const text = stripUrls(`${t.name} ${t.description}`).toLowerCase();
      const external = /\b(?:https?|url|web|fetch|request|download|scrape|brows)/.test(text);
      if (tags?.source && external) {
        out.push({
          ruleId: "MCP008",
          severity: "medium",
          category: "injection",
          title: `${t.name} returns untrusted external content`,
          detail: `tool "${t.name}" fetches external/web content that is returned to the model. Attacker-controlled pages can carry prompt-injection payloads that hijack the agent (indirect prompt injection).`,
          location: t.name,
          remediation:
            "Treat fetched content as untrusted data, not instructions: sanitize/segment it, and never let it drive tool calls without a human in the loop.",
          confidence: "medium",
        });
      }
    }
    return out;
  },
};

/** The ordered check catalog (DESIGN.md §7.3), MCP001 → MCP011. */
export const ALL_RULES: Rule[] = [
  MCP001,
  MCP002,
  MCP003,
  MCP004,
  MCP005,
  MCP006,
  MCP007,
  MCP008,
  MCP009,
  MCP010,
  MCP011,
];

export type RunRulesOptions = {
  disabledRules?: string[];
  minSeverity?: Severity;
};

/**
 * Run the catalog against a context and return severity-ranked findings.
 * Sorted by severity (desc) then ruleId (asc) for deterministic output.
 */
export function runRules(ctx: RuleContext, opts: RunRulesOptions = {}): Finding[] {
  const disabled = new Set(opts.disabledRules ?? []);
  const minSeverity = opts.minSeverity ?? "low";

  const findings: Finding[] = [];
  for (const rule of ALL_RULES) {
    if (disabled.has(rule.id)) continue;
    for (const f of rule.check(ctx)) {
      if (severityAtLeast(f.severity, minSeverity)) findings.push(f);
    }
  }

  findings.sort((a, b) => {
    const bySeverity = compareSeverityDesc(a.severity, b.severity);
    if (bySeverity !== 0) return bySeverity;
    return a.ruleId.localeCompare(b.ruleId);
  });
  return findings;
}

/** Catalog metadata for `mcp-audit rules`. */
export function ruleCatalog(): {
  id: string;
  severity: Severity;
  category: string;
  title: string;
}[] {
  return ALL_RULES.map((r) => ({
    id: r.id,
    severity: r.severity,
    category: r.category,
    title: r.title,
  }));
}
