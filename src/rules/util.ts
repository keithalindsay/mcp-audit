import type { Tool, ToolParam } from "../schemas.js";

/** Lowercased token stream (non-alphanumerics → single spaces, padded). */
export function normalize(text: string): string {
  return ` ${text.toLowerCase().replace(/[^a-z0-9]+/g, " ").trim()} `;
}

export function hasToken(haystack: string, token: string): boolean {
  return haystack.includes(` ${token} `);
}

export function hasAnyToken(haystack: string, tokens: string[]): boolean {
  return tokens.some((t) => hasToken(haystack, t));
}

export type ParamIntent = "path" | "url" | "command" | null;

const PATH_TOKENS = ["path", "file", "filename", "filepath", "dir", "directory", "location", "folder"];
const URL_TOKENS = ["url", "uri", "endpoint", "host", "hostname", "address", "link", "target"];
const COMMAND_TOKENS = ["command", "cmd", "script", "code", "query", "sql", "arg", "args", "input", "eval", "expression"];

/**
 * Classify a parameter by what its NAME implies. Used to route unconstrained-string
 * findings: path→MCP002, url→MCP003, command→MCP006.
 */
export function paramIntent(name: string): ParamIntent {
  const n = normalize(name);
  if (hasAnyToken(n, PATH_TOKENS)) return "path";
  if (hasAnyToken(n, URL_TOKENS)) return "url";
  if (hasAnyToken(n, COMMAND_TOKENS)) return "command";
  return null;
}

/** A string parameter with no enum/pattern/format/min/max/const constraint. */
export function isUnconstrainedString(p: ToolParam): boolean {
  return p.type === "string" && !p.constrained;
}

/** Tool name + description as a single normalized token stream. */
export function toolText(t: Tool): string {
  const paramNames = t.params.map((p) => p.name).join(" ");
  return normalize(`${t.name} ${t.description} ${paramNames}`);
}
