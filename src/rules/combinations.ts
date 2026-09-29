import type { Finding } from "../schemas.js";
import type { Tool } from "../schemas.js";
import type { Rule, RuleContext } from "./types.js";
import { hasAnyToken, normalize, paramIntent } from "./util.js";

// "local"/"env"/"secret" name data on the operator's own machine; "file"/"key" are
// weaker because remote project files and API keys-as-arguments use them too.
const STRONG_PRIVATE_TOKENS = ["local", "env", "secret", "secrets", "credential", "credentials", "home", "ssh"];
const WEAK_PRIVATE_TOKENS = ["file", "files", "key"];

/**
 * How strongly a source tool reads PRIVATE data. A free-form path parameter is the
 * strongest signal (it reaches anything the process can read); private-data words
 * come next. Used to name the leg that actually makes the chain dangerous — the
 * first-found source was a field regression (`check_domino_job_run_status` was named
 * instead of `sync_local_file_to_domino`, which reads any local path).
 */
function privateDataStrength(t: Tool): number {
  const pathParams = t.params.filter((p) => paramIntent(p.name) === "path");
  // A path param that is itself named for private data (`local_file_path`, `ssh_key_path`)
  // is the strongest signal of all: it is the parameter that reaches the operator's disk.
  const privatePath = pathParams.some((p) => hasAnyToken(normalize(p.name), STRONG_PRIVATE_TOKENS));
  const pathParam = privatePath ? 4 : pathParams.length > 0 ? 2 : 0;
  const text = normalize(`${t.name} ${t.description}`);
  const strong = hasAnyToken(text, STRONG_PRIVATE_TOKENS) ? 2 : 0;
  const weak = hasAnyToken(text, WEAK_PRIVATE_TOKENS) ? 1 : 0;
  return pathParam + strong + weak;
}

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
    // Strength decides first; a "pure" source (not also a sink) only breaks ties, then
    // discovery order. Preferring pure sources FIRST was the field regression: the real
    // local-file reader also uploads, so a weaker remote-listing tool was named instead.
    const isPure = (t: Tool) => (ctx.classified.get(t.name)?.sink ? 0 : 1);
    const ranked = [...sources].sort(
      (a, b) => privateDataStrength(b) - privateDataStrength(a) || isPure(b) - isPure(a),
    );
    const sourceTool = ranked[0];
    // Prefer a sink that reaches an ARBITRARY destination (a free-form URL/host param)
    // over one that writes to the platform's own storage: the open URL is the leg an
    // attacker controls. Discovery order breaks ties.
    const reachesArbitraryHost = (t: Tool) =>
      t.params.some((p) => paramIntent(p.name) === "url") ? 1 : 0;
    const otherSinks = sinks.filter((t) => t.name !== sourceTool?.name);
    const sinkTool =
      [...otherSinks].sort((a, b) => reachesArbitraryHost(b) - reachesArbitraryHost(a))[0] ?? sinks[0]!;

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
