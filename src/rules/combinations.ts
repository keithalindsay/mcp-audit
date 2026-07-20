import type { Finding } from "../schemas.js";
import type { Rule, RuleContext } from "./types.js";

/**
 * rules/combinations.ts — taint / lethal-trifecta combination analysis.
 *
 * MCP004 is the differentiator: two individually-fine tools (a data SOURCE + an
 * external SINK) together form a data-exfiltration path. MCP011 is an aggregate
 * posture note when a server piles up many high-capability tools.
 */

// MCP004 — combination: a data source + an external sink = exfiltration path.
export const MCP004: Rule = {
  id: "MCP004",
  title: "Source + sink combination forms a data-exfiltration path",
  severity: "critical",
  category: "exfiltration",
  check(ctx) {
    if (!ctx.model) return [];
    const tools = ctx.model.tools;

    const sources = tools.filter((t) => ctx.classified.get(t.name)?.source);
    const sinks = tools.filter((t) => ctx.classified.get(t.name)?.sink);

    // A sensitive resource (env://, credentials, .env, ~/.ssh …) is also a private
    // data source that a sink can exfiltrate.
    const sensitiveResources = ctx.model.resources.filter((r) =>
      SENSITIVE_RESOURCE_RE.test(`${r.uri} ${r.name ?? ""} ${r.description ?? ""}`),
    );

    const hasSource = sources.length > 0 || sensitiveResources.length > 0;
    const hasSink = sinks.length > 0;
    if (!hasSource || !hasSink) return [];

    // Pick the clearest pairing: prefer a pure source (not also a sink) as the
    // "reads private data" leg, and any sink as the "sends out" leg.
    const pureSource = sources.find((t) => !ctx.classified.get(t.name)?.sink);
    const sourceTool = pureSource ?? sources[0];
    const sinkTool = sinks.find((t) => t.name !== sourceTool?.name) ?? sinks[0]!;

    const sourceLabel =
      sourceTool?.name ??
      (sensitiveResources[0] ? `resource ${sensitiveResources[0].uri}` : "a data source");
    const sinkLabel = sinkTool.name;

    const location = `tools[${sourceTool ? sourceTool.name : sourceLabel}+${sinkLabel}]`;

    const finding: Finding = {
      ruleId: "MCP004",
      severity: "critical",
      category: "exfiltration",
      title: `${sourceLabel} + ${sinkLabel} form a data-exfiltration path`,
      detail:
        `"${sourceLabel}" reads local/private (or untrusted) data and "${sinkLabel}" sends data to an external destination. ` +
        `Together they are a lethal-trifecta exfiltration path: an injected instruction can read a secret with the first tool and POST it out with the second — neither tool is dangerous alone.`,
      location,
      remediation:
        "Break the chain: constrain what the source can read AND restrict where the sink can send (host allowlist), or don't expose both capabilities to the same agent.",
      confidence: "high",
    };
    return [finding];
  },
};

export const SENSITIVE_RESOURCE_RE =
  /\benv\b|environment|\.env|id_rsa|\.ssh|credential|secret|password|passwd|\btoken\b|home dir|\/home\/|~\/|\.aws|\.npmrc|private[_-]?key/i;

// MCP011 — aggregate: many high-capability tools with no scoping.
export const MCP011: Rule = {
  id: "MCP011",
  title: "Server exposes many high-capability tools",
  severity: "info",
  category: "posture",
  check(ctx) {
    if (!ctx.model) return [];
    const dangerous = ctx.model.tools.filter((t) => {
      const tags = ctx.classified.get(t.name);
      return tags?.executor || tags?.sink;
    });
    if (dangerous.length < 3) return [];
    return [
      {
        ruleId: "MCP011",
        severity: "info",
        category: "posture",
        title: `Server exposes ${dangerous.length} high-capability tools`,
        detail: `${dangerous.length} tools are executors or external sinks (${dangerous
          .map((t) => t.name)
          .join(", ")}). Aggregating this much capability behind one agent connection multiplies blast radius.`,
        location: "server",
        remediation:
          "Split high-capability tools across separately-scoped servers, or expose only the minimum an agent needs.",
        confidence: "low",
      } satisfies Finding,
    ];
  },
};

export const COMBINATION_RULES: Rule[] = [MCP004, MCP011];
