import type { ServerModel, ConfigServer, Finding, Severity } from "../schemas.js";
import type { ToolTags } from "../classify.js";
import type { SecretPattern } from "../config-scan.js";

/**
 * The context every rule receives. Assembled by the audit orchestrator (audit.ts)
 * from the connector's ServerModel, the classifier output, and the parsed config.
 */
export type RuleContext = {
  /** The live server model (null when only a config is being scanned). */
  model: ServerModel | null;
  /** Tool name → classification tags. Empty when there's no model. */
  classified: Map<string, ToolTags>;
  /** The matching config-file server entry, for secret scanning (null if none). */
  configServer: ConfigServer | null;
  /** Path of the config file the configServer came from (for finding locations). */
  configPath: string | null;
  /** Built-in + user secret patterns (MCP005). */
  secretPatterns: SecretPattern[];
};

export type Rule = {
  id: string;
  title: string;
  severity: Severity;
  category: string;
  /** Produce zero or more findings from the context. Must be pure + deterministic. */
  check(ctx: RuleContext): Finding[];
};
