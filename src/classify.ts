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
  "shell",
  "command",
  "cmd",
  "eval",
  "spawn",
  "sql",
  "script",
  "bash",
];
// NOTE: "query" and "process" are deliberately NOT executor tokens — a
// search/memory `query` param is a data SOURCE (below), not code execution, and
// "process" (process_data) is usually benign. Real SQL/code executors carry
// stronger signals ("sql", "execute", "exec", "shell", "eval", "spawn", …).

// An identifier-shaped parameter names a HANDLE, not code or a path: `run_id`,
// `execution_id`, `workflow_uuid`, `script_arn`. Such a name must not by itself make a
// tool an executor — the value selects an existing thing, it is not the thing that runs.
// This matters because `run_id` is near-universal in workflow orchestration (Temporal,
// Airflow, GitHub Actions, MLflow, Dagster, Prefect), where it tokenizes to "run id" and
// hits the "run" executor token. Suppression applies ONLY to parameter names, and ONLY to
// the executor decision — the tool's own name and description still count, so
// `execute(script_id)` remains an executor and the rule cannot be used as a bypass.
const IDENTIFIER_SUFFIX = /_(id|ids|uuid|guid|arn|handle|ref)$/;

function isIdentifierParam(name: string): boolean {
  return IDENTIFIER_SUFFIX.test(name.toLowerCase());
}

// "run" is a WEAK executor signal: "Run an aggregation", "Run a find query" and "a job
// run" are query verbs and nouns, not code execution (field regression: every
// mongodb-mcp-server read tool and every domino_mcp_server status tool was a false
// CRITICAL MCP001). It only counts when a parameter actually carries a command/code
// payload — `run_shell(command)`, `run_domino_job(run_command)`, `run_python(code)`.
const WEAK_EXECUTOR_TOKENS = ["run"];
const COMMAND_PARAM_TOKENS = ["command", "cmd", "script", "code", "sql", "eval", "expression"];

/** A parameter whose name says it carries a command/code payload (not a handle). */
export function isCommandParam(name: string): boolean {
  if (isIdentifierParam(name)) return false;
  const n = normalize(name);
  return COMMAND_PARAM_TOKENS.some((t) => n.includes(` ${t} `));
}

/** URLs in prose are documentation links, not capabilities — drop them before tokenizing. */
export function stripUrls(text: string): string {
  return text.replace(/\b(?:https?|ftp):\/\/\S+/gi, " ");
}

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
  const execParamNames = tool.params
    .filter((p) => !isIdentifierParam(p.name))
    .map((p) => p.name)
    .join(" ");
  const description = stripUrls(tool.description);
  const nameText = normalize(tool.name);
  const bodyText = normalize(`${tool.name} ${description} ${paramNames}`);
  const execText = normalize(`${tool.name} ${description} ${execParamNames}`);
  const hasCommandParam = tool.params.some((p) => isCommandParam(p.name));

  const reasons: string[] = [];

  const execHits = [
    ...matchedTokens(execText, EXECUTOR_TOKENS),
    ...(hasCommandParam ? matchedTokens(execText, WEAK_EXECUTOR_TOKENS) : []),
  ];
  const sourceHits = matchedTokens(bodyText, SOURCE_TOKENS);
  const sinkHits = matchedTokens(bodyText, SINK_TOKENS);

  // An executor is the strongest / most dangerous tag. Prefer to explain it from the
  // tool name where possible.
  const executor = execHits.length > 0;
  const source = sourceHits.length > 0;
  const sink = sinkHits.length > 0;

  if (executor) {
    const fromName = matchedTokens(nameText, [...EXECUTOR_TOKENS, ...WEAK_EXECUTOR_TOKENS]).filter(
      (t) => execHits.includes(t),
    );
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
