import type {
  AuditReport,
  Config,
  ConfigServer,
  Finding,
  ServerModel,
  ServerSpec,
  Severity,
  Totals,
} from "./schemas.js";
import { SEVERITIES, severityAtLeast } from "./schemas.js";
import { introspect } from "./connector.js";
import { classifyTools } from "./classify.js";
import { runRules } from "./rules/index.js";
import type { RuleContext } from "./rules/types.js";
import { BUILTIN_SECRET_PATTERNS, type SecretPattern } from "./config-scan.js";
import { loadLlmFindings } from "./llm.js";

export type AuditOptions = {
  /** A live server to introspect. */
  serverSpec?: ServerSpec;
  /** A config-file server entry for secret scanning (its env/args). */
  configServer?: ConfigServer;
  /** Path of the config file (for finding locations / target label). */
  configPath?: string;
  /** Parsed mcp-audit.config.yaml (thresholds, disabled rules, extra patterns). */
  config: Config;
  /** Run the optional Anthropic LLM pass. */
  llm?: boolean;
};

function buildSecretPatterns(config: Config): SecretPattern[] {
  const extra: SecretPattern[] = config.secretPatterns.map((src, i) => ({
    name: `custom-pattern-${i + 1}`,
    regex: new RegExp(src),
  }));
  return [...BUILTIN_SECRET_PATTERNS, ...extra];
}

function computeTotals(findings: Finding[]): Totals {
  const totals: Totals = { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 };
  for (const f of findings) {
    totals[f.severity] += 1;
    totals.total += 1;
  }
  return totals;
}

/** Run a full audit of one target and produce a ranked AuditReport. */
export async function runAudit(opts: AuditOptions): Promise<AuditReport> {
  const { config } = opts;
  const startedAt = new Date().toISOString();

  let model: ServerModel | null = null;
  if (opts.serverSpec) {
    model = await introspect(opts.serverSpec, { timeoutMs: config.timeoutMs });
  }

  const classified = model ? classifyTools(model.tools) : new Map();

  const ctx: RuleContext = {
    model,
    classified,
    configServer: opts.configServer ?? null,
    configPath: opts.configPath ?? null,
    secretPatterns: buildSecretPatterns(config),
  };

  const findings = runRules(ctx, {
    disabledRules: config.disabledRules,
    minSeverity: config.minSeverity,
  });

  if (opts.llm && model) {
    const llmFindings = await loadLlmFindings(model, config).catch((err: unknown) => {
      // Never let the optional pass break the deterministic audit.
      process.stderr.write(
        `warning: --llm pass failed: ${err instanceof Error ? err.message : String(err)}\n`,
      );
      return [] as Finding[];
    });
    for (const f of llmFindings) {
      if (severityAtLeast(f.severity, config.minSeverity)) findings.push(f);
    }
    // Re-sort with the LLM findings merged in.
    findings.sort((a, b) => {
      const order: Record<Severity, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
      return order[b.severity] - order[a.severity] || a.ruleId.localeCompare(b.ruleId);
    });
  }

  const finishedAt = new Date().toISOString();
  const totals = computeTotals(findings);

  const failOn = config.failOn;
  const exitCode: 0 | 1 = findings.some((f) => severityAtLeast(f.severity, failOn)) ? 1 : 0;

  const target =
    opts.serverSpec?.label ?? opts.configServer?.name ?? opts.configPath ?? "unknown";

  const report: AuditReport = {
    schemaVersion: 1,
    target,
    startedAt,
    finishedAt,
    serverSummary: model
      ? {
          name: model.server.name,
          tools: model.tools.length,
          resources: model.resources.length,
          prompts: model.prompts.length,
        }
      : null,
    findings,
    totals,
    failOn,
    exitCode,
  };
  return report;
}

/** Ensure every severity key exists (used by consumers of totals). */
export const ALL_SEVERITIES: readonly Severity[] = SEVERITIES;
