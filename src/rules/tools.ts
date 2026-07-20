import type { Finding, Tool } from "../schemas.js";
import type { Rule, RuleContext } from "./types.js";
import {
  isUnconstrainedString,
  paramIntent,
  toolText,
  hasAnyToken,
} from "./util.js";

/**
 * rules/tools.ts — per-tool checks (DESIGN.md §7.3):
 * MCP001 exec, MCP002 filesystem, MCP003 network, MCP006 validation,
 * MCP007 destructive, MCP009 over-broad description.
 */

function tools(ctx: RuleContext): Tool[] {
  return ctx.model?.tools ?? [];
}

// MCP001 — arbitrary command / shell / code execution.
export const MCP001: Rule = {
  id: "MCP001",
  title: "Tool exposes arbitrary command/shell/code execution",
  severity: "critical",
  category: "exec",
  check(ctx) {
    const out: Finding[] = [];
    for (const t of tools(ctx)) {
      const tags = ctx.classified.get(t.name);
      if (!tags?.executor) continue;
      // Prefer to name the parameter that gets executed.
      const execParam =
        t.params.find((p) => ["command", "cmd", "script", "code", "query", "sql", "eval", "expression"].includes(p.name.toLowerCase())) ??
        t.params[0];
      const loc = execParam ? `${t.name}.${execParam.name}` : t.name;
      out.push({
        ruleId: "MCP001",
        severity: "critical",
        category: "exec",
        title: `${t.name} executes arbitrary shell/code`,
        detail: `tool "${t.name}"${execParam ? ` param "${execParam.name}"` : ""} is passed to a shell/interpreter (${tags.reasons[0] ?? "matches an execution keyword"}). An injected instruction to the agent becomes code execution on the host.`,
        location: loc,
        remediation:
          "Remove arbitrary execution, or replace the free-form input with a fixed allowlist of specific, non-shell operations.",
        confidence: "high",
      });
    }
    return out;
  },
};

// MCP002 — free-form filesystem path with no root/allowlist restriction.
export const MCP002: Rule = {
  id: "MCP002",
  title: "Tool accepts an unrestricted filesystem path",
  severity: "high",
  category: "filesystem",
  check(ctx) {
    const out: Finding[] = [];
    for (const t of tools(ctx)) {
      for (const p of t.params) {
        if (paramIntent(p.name) !== "path") continue;
        if (!isUnconstrainedString(p)) continue;
        out.push({
          ruleId: "MCP002",
          severity: "high",
          category: "filesystem",
          title: `${t.name} accepts an unrestricted path`,
          detail: `tool "${t.name}" param "${p.name}" is a free-form string path with no root/allowlist restriction, so it can reach any file the server process can read (e.g. ../../.env, ~/.ssh/id_rsa).`,
          location: `${t.name}.${p.name}`,
          remediation:
            "Confine paths to an explicit root directory (jail/allowlist) and reject absolute paths and .. traversal.",
          confidence: "high",
        });
      }
    }
    return out;
  },
};

// MCP003 — arbitrary URL/host fetch (SSRF / exfil sink).
export const MCP003: Rule = {
  id: "MCP003",
  title: "Tool fetches an arbitrary URL/host",
  severity: "high",
  category: "network",
  check(ctx) {
    const out: Finding[] = [];
    for (const t of tools(ctx)) {
      for (const p of t.params) {
        if (paramIntent(p.name) !== "url") continue;
        if (!isUnconstrainedString(p)) continue;
        out.push({
          ruleId: "MCP003",
          severity: "high",
          category: "network",
          title: `${t.name} reaches arbitrary URLs`,
          detail: `tool "${t.name}" param "${p.name}" accepts an arbitrary URL/host with no allowlist, enabling SSRF (reach internal services / cloud metadata) and acting as an outbound exfiltration sink.`,
          location: `${t.name}.${p.name}`,
          remediation:
            "Restrict destinations to an explicit host allowlist; block private/link-local ranges and cloud metadata endpoints.",
          confidence: "high",
        });
      }
    }
    return out;
  },
};

// MCP006 — unconstrained string where the name implies path/command/url.
// path→MCP002 and url→MCP003 already own those; MCP006 covers command-like inputs.
export const MCP006: Rule = {
  id: "MCP006",
  title: "Unconstrained string input where the name implies a command/query",
  severity: "medium",
  category: "validation",
  check(ctx) {
    const out: Finding[] = [];
    for (const t of tools(ctx)) {
      for (const p of t.params) {
        if (paramIntent(p.name) !== "command") continue;
        if (!isUnconstrainedString(p)) continue;
        out.push({
          ruleId: "MCP006",
          severity: "medium",
          category: "validation",
          title: `${t.name}.${p.name} is an unconstrained string`,
          detail: `param "${p.name}" of "${t.name}" is a bare string with no enum/pattern/format constraint, yet its name implies a command/query. Unvalidated free-form input widens the injection surface.`,
          location: `${t.name}.${p.name}`,
          remediation:
            "Constrain the input with an enum, pattern, or format, or split it into typed, validated fields.",
          confidence: "medium",
        });
      }
    }
    return out;
  },
};

const DESTRUCTIVE_TOKENS = ["delete", "drop", "remove", "rm", "overwrite", "truncate", "destroy", "wipe", "erase", "purge", "unlink"];
const WRITE_TOKENS = ["write", "update", "put", "set", "modify", "patch"];
const CONFIRM_PARAMS = ["confirm", "confirmation", "dry_run", "dryrun", "force", "yes", "acknowledge"];

// MCP007 — destructive tool with no dry-run / confirmation affordance.
export const MCP007: Rule = {
  id: "MCP007",
  title: "Destructive tool with no dry-run/confirmation",
  severity: "high",
  category: "destructive",
  check(ctx) {
    const out: Finding[] = [];
    for (const t of tools(ctx)) {
      const text = toolText(t);
      const isDestructive =
        hasAnyToken(text, DESTRUCTIVE_TOKENS) || hasAnyToken(text, WRITE_TOKENS);
      if (!isDestructive) continue;
      const strongDestructive = hasAnyToken(text, DESTRUCTIVE_TOKENS);
      const hasAffordance = t.params.some((p) =>
        CONFIRM_PARAMS.includes(p.name.toLowerCase()),
      );
      if (hasAffordance) continue;
      out.push({
        ruleId: "MCP007",
        severity: "high",
        category: "destructive",
        title: `${t.name} performs a destructive action with no confirmation`,
        detail: `tool "${t.name}" ${strongDestructive ? "deletes/overwrites data" : "mutates state"} but exposes no dry-run or confirmation parameter, so an agent can trigger irreversible changes without a guard.`,
        location: t.name,
        remediation:
          "Add a required confirmation/dry-run parameter, make the operation idempotent, or gate destructive actions behind human approval.",
        confidence: strongDestructive ? "high" : "low",
      });
    }
    return out;
  },
};

const OVERBROAD_PHRASES = [
  "do anything",
  "anything you want",
  "any command",
  "any shell",
  "arbitrary",
  "run any",
  "execute any",
  "full access",
  "unrestricted",
  "no restrictions",
  "no limits",
  "whatever you",
  "any file",
  "any url",
  "any request",
];

// MCP009 — over-broad tool description inviting unconstrained action.
export const MCP009: Rule = {
  id: "MCP009",
  title: "Over-broad tool description invites unconstrained action",
  severity: "low",
  category: "description",
  check(ctx) {
    const out: Finding[] = [];
    for (const t of tools(ctx)) {
      const desc = t.description.toLowerCase();
      const phrase = OVERBROAD_PHRASES.find((p) => desc.includes(p));
      if (!phrase) continue;
      out.push({
        ruleId: "MCP009",
        severity: "low",
        category: "description",
        title: `${t.name} has an over-broad description`,
        detail: `the description of "${t.name}" contains "${phrase}", inviting the model to use it for unconstrained action. Tool descriptions are attacker-controllable prompt surface.`,
        location: t.name,
        remediation:
          "Describe the tool's narrow, specific capability. Avoid language that implies unlimited scope.",
        confidence: "low",
      });
    }
    return out;
  },
};

export const TOOL_RULES: Rule[] = [MCP001, MCP002, MCP003, MCP006, MCP007, MCP009];
