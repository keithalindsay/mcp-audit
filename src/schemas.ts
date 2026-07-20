import { z } from "zod";

/**
 * schemas.ts — zod schemas + inferred types for the data models in DESIGN.md §8.
 *
 * These are the shared contracts between the connector, config scanner, classifier,
 * rule engine, and reporter. Severity ordering + comparators live here too.
 */

// ---------------------------------------------------------------------------
// Severity
// ---------------------------------------------------------------------------

export const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;
export const SeveritySchema = z.enum(SEVERITIES);
export type Severity = (typeof SEVERITIES)[number];

/** Higher number = more severe. Used for ranking + threshold comparisons. */
export const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
};

/** Comparator for descending severity sort (most severe first). */
export function compareSeverityDesc(a: Severity, b: Severity): number {
  return SEVERITY_ORDER[b] - SEVERITY_ORDER[a];
}

/** True when `sev` is at least as severe as `threshold`. */
export function severityAtLeast(sev: Severity, threshold: Severity): boolean {
  return SEVERITY_ORDER[sev] >= SEVERITY_ORDER[threshold];
}

export const ConfidenceSchema = z.enum(["high", "medium", "low"]);
export type Confidence = z.infer<typeof ConfidenceSchema>;

// ---------------------------------------------------------------------------
// ServerModel (from the connector) — §8.1
// ---------------------------------------------------------------------------

export const ToolParamSchema = z.object({
  name: z.string(),
  type: z.string(),
  required: z.boolean(),
  /** has enum/pattern/format/min/max/const — i.e. some constraint beyond the bare type */
  constrained: z.boolean(),
  raw: z.unknown(),
});
export type ToolParam = z.infer<typeof ToolParamSchema>;

export const ToolSchema = z.object({
  name: z.string(),
  description: z.string(),
  params: z.array(ToolParamSchema),
  rawInputSchema: z.unknown(),
});
export type Tool = z.infer<typeof ToolSchema>;

export const ResourceSchema = z.object({
  uri: z.string(),
  name: z.string().optional(),
  description: z.string().optional(),
  mimeType: z.string().optional(),
});
export type Resource = z.infer<typeof ResourceSchema>;

export const PromptSchema = z.object({
  name: z.string(),
  description: z.string().optional(),
});
export type Prompt = z.infer<typeof PromptSchema>;

export const ServerSpecSchema = z.object({
  command: z.string(),
  args: z.array(z.string()),
  env: z.record(z.string(), z.string()).optional(),
  cwd: z.string().optional(),
  label: z.string(),
});
export type ServerSpec = z.infer<typeof ServerSpecSchema>;

export const ServerModelSchema = z.object({
  server: z.object({ name: z.string(), version: z.string().optional() }),
  spec: ServerSpecSchema,
  tools: z.array(ToolSchema),
  resources: z.array(ResourceSchema),
  prompts: z.array(PromptSchema),
});
export type ServerModel = z.infer<typeof ServerModelSchema>;

// ---------------------------------------------------------------------------
// ConfigModel (from a claude_desktop_config.json / mcp.json) — §8.2
// ---------------------------------------------------------------------------

export const ConfigServerSchema = z.object({
  name: z.string(),
  command: z.string(),
  args: z.array(z.string()),
  env: z.record(z.string(), z.string()),
});
export type ConfigServer = z.infer<typeof ConfigServerSchema>;

export const ConfigModelSchema = z.object({
  path: z.string(),
  servers: z.array(ConfigServerSchema),
});
export type ConfigModel = z.infer<typeof ConfigModelSchema>;

// ---------------------------------------------------------------------------
// Finding + AuditReport — §8.5
// ---------------------------------------------------------------------------

export const FindingSchema = z.object({
  ruleId: z.string(),
  severity: SeveritySchema,
  category: z.string(),
  title: z.string(),
  detail: z.string(),
  /** e.g. tool name, "config:env.API_KEY", "tools[read_file+http_fetch]" */
  location: z.string(),
  remediation: z.string(),
  confidence: ConfidenceSchema,
});
export type Finding = z.infer<typeof FindingSchema>;

export const TotalsSchema = z.object({
  critical: z.number(),
  high: z.number(),
  medium: z.number(),
  low: z.number(),
  info: z.number(),
  total: z.number(),
});
export type Totals = z.infer<typeof TotalsSchema>;

export const AuditReportSchema = z.object({
  schemaVersion: z.literal(1),
  target: z.string(),
  startedAt: z.string(),
  finishedAt: z.string(),
  serverSummary: z
    .object({
      name: z.string(),
      tools: z.number(),
      resources: z.number(),
      prompts: z.number(),
    })
    .nullable(),
  findings: z.array(FindingSchema),
  totals: TotalsSchema,
  failOn: SeveritySchema,
  exitCode: z.union([z.literal(0), z.literal(1)]),
});
export type AuditReport = z.infer<typeof AuditReportSchema>;

// ---------------------------------------------------------------------------
// Config file (mcp-audit.config.yaml) — §7.4
// ---------------------------------------------------------------------------

export const ConfigSchema = z.object({
  failOn: SeveritySchema.default("high"),
  minSeverity: SeveritySchema.default("low"),
  disabledRules: z.array(z.string()).default([]),
  secretPatterns: z.array(z.string()).default([]),
  timeoutMs: z.number().int().positive().default(10000),
});
/** Parsed + defaulted config. */
export type Config = z.infer<typeof ConfigSchema>;

/** Default config used when no mcp-audit.config.yaml is present. */
export const DEFAULT_CONFIG: Config = ConfigSchema.parse({});
