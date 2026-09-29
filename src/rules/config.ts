import type { Finding } from "../schemas.js";
import type { Rule, RuleContext } from "./types.js";
import { scanSecrets } from "../config-scan.js";
import { SENSITIVE_RESOURCE_RE } from "./combinations.js";

/**
 * rules/config.ts — config + resource exposure checks:
 * MCP005 (secret in config env/args) and MCP010 (a resource exposing sensitive data).
 *
 * SECURITY: MCP005 reports the location + matched pattern name only, never the value.
 */

// MCP005 — secret present in config env/args.
export const MCP005: Rule = {
  id: "MCP005",
  title: "Secret present in config env/args",
  severity: "critical",
  category: "secrets",
  check(ctx) {
    if (!ctx.configServer) return [];
    const matches = scanSecrets([ctx.configServer], ctx.secretPatterns);
    return matches.map(
      (m): Finding => ({
        ruleId: "MCP005",
        severity: "critical",
        category: "secrets",
        title: `Secret in ${m.location}`,
        detail: `${m.location} matches secret pattern "${m.patternName}". Secrets committed to an MCP config leak to anyone with the file and are handed to the server process. (Value withheld.)`,
        location: m.location,
        remediation:
          "Move the secret to a secret manager or an untracked local env and reference it indirectly; rotate the exposed credential.",
        confidence: "high",
      }),
    );
  },
};

// MCP010 — a resource exposes sensitive data (env, .env, home dir, credentials, id_rsa).
export const MCP010: Rule = {
  id: "MCP010",
  title: "Resource exposes sensitive data",
  severity: "high",
  category: "secrets",
  check(ctx) {
    if (!ctx.model) return [];
    const out: Finding[] = [];
    for (const r of ctx.model.resources) {
      const hay = `${r.uri} ${r.name ?? ""} ${r.description ?? ""}`;
      if (!SENSITIVE_RESOURCE_RE.test(hay)) continue;
      out.push({
        ruleId: "MCP010",
        severity: "high",
        category: "secrets",
        title: `resource ${r.uri} exposes sensitive data`,
        detail: `resource "${r.uri}"${r.name ? ` (${r.name})` : ""} appears to expose sensitive data (environment, credentials, keys, or home-directory files) directly to the agent — a ready-made source for exfiltration. This is inferred from the resource's URI, name and description; its contents were not read, and a server that redacts secrets before returning them will not leak them (mongodb-mcp-server's config://config does).`,
        location: r.uri,
        remediation:
          "Do not expose environment/credential/home-directory contents as a resource. Scope resources to non-sensitive, explicitly-allowlisted data.",
        confidence: "medium",
      });
    }
    return out;
  },
};

export const CONFIG_RULES: Rule[] = [MCP005, MCP010];
