import type { Tool } from "./schemas.js";

/**
 * classify.ts — heuristic, deterministic tool classification (DESIGN.md §8.3).
 *
 * Tags each tool as `source` (reads private/local data OR pulls untrusted external
 * content), `sink` (sends/writes externally), and/or `executor` (runs shell/code/
 * queries). A tool can carry several tags at once — `http_fetch` is both a source of
 * untrusted content AND an external sink. Every tag records a human-readable reason.
 */

export type ToolTags = {
  source: boolean;
  sink: boolean;
  executor: boolean;
  reasons: string[];
};

// Token sets per §8.3. Matched against a normalized "search text" built from the
// tool name, description, and parameter names (non-alphanumerics collapsed to spaces
// so `run_shell` tokenizes to `run shell`).
const EXECUTOR_TOKENS = [
  "exec",
  "execute",
  "run",
  "shell",
  "command",
  "cmd",
  "eval",
  "spawn",
  "sql",
  "query",
  "script",
  "bash",
  "process",
];

const SOURCE_TOKENS = [
  "read",
  "get",
  "list",
  "load",
  "file",
  "fs",
  "cat",
  "fetch",
  "download",
  "db",
  "query",
  "search",
  "env",
  "secret",
  "credential",
  "http",
  "url",
  "content",
];

const SINK_TOKENS = [
  "http",
  "https",
  "fetch",
  "request",
  "post",
  "put",
  "url",
  "webhook",
  "upload",
  "send",
  "email",
  "mail",
  "publish",
  "dns",
  "curl",
];

/** Collapse to a lowercase, space-separated token stream. */
function normalize(text: string): string {
  return ` ${text.toLowerCase().replace(/[^a-z0-9]+/g, " ").trim()} `;
}

/** Which of the given tokens appear as whole words in `haystack`. */
function matchedTokens(haystack: string, tokens: string[]): string[] {
  const hits: string[] = [];
  for (const t of tokens) {
    if (haystack.includes(` ${t} `)) hits.push(t);
  }
  return hits;
}

export function classifyTool(tool: Tool): ToolTags {
  const paramNames = tool.params.map((p) => p.name).join(" ");
  const nameText = normalize(tool.name);
  const bodyText = normalize(`${tool.name} ${tool.description} ${paramNames}`);

  const reasons: string[] = [];

  const execHits = matchedTokens(bodyText, EXECUTOR_TOKENS);
  const sourceHits = matchedTokens(bodyText, SOURCE_TOKENS);
  const sinkHits = matchedTokens(bodyText, SINK_TOKENS);

  // An executor is the strongest / most dangerous tag. Prefer to explain it from the
  // tool name where possible.
  const executor = execHits.length > 0;
  const source = sourceHits.length > 0;
  const sink = sinkHits.length > 0;

  if (executor) {
    const fromName = matchedTokens(nameText, EXECUTOR_TOKENS);
    const shown = (fromName.length ? fromName : execHits).slice(0, 3);
    reasons.push(`executor: matches ${shown.map((t) => `"${t}"`).join(", ")}`);
  }
  if (source) {
    reasons.push(
      `source: reads local/private or untrusted external data (matches ${sourceHits
        .slice(0, 3)
        .map((t) => `"${t}"`)
        .join(", ")})`,
    );
  }
  if (sink) {
    reasons.push(
      `sink: can send/write data externally (matches ${sinkHits
        .slice(0, 3)
        .map((t) => `"${t}"`)
        .join(", ")})`,
    );
  }

  return { source, sink, executor, reasons };
}

/** Classify every tool in a model, keyed by tool name. */
export function classifyTools(tools: Tool[]): Map<string, ToolTags> {
  const map = new Map<string, ToolTags>();
  for (const t of tools) map.set(t.name, classifyTool(t));
  return map;
}
