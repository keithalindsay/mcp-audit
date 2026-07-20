import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import type { ConfigModel, ConfigServer } from "./schemas.js";

/**
 * config-scan.ts — parse claude_desktop_config.json / mcp.json into a ConfigModel,
 * and scan env values + args for secrets (DESIGN.md §8.4).
 *
 * SECURITY: scanSecrets reports matches by LOCATION and PATTERN NAME only. The secret
 * value is never included in a SecretMatch, printed, or transmitted.
 */

export type SecretPattern = {
  name: string;
  regex: RegExp;
};

// Built-in secret patterns (§8.4). Ordered most-specific first.
export const BUILTIN_SECRET_PATTERNS: SecretPattern[] = [
  { name: "openai-anthropic-style-key", regex: /sk-[A-Za-z0-9]{20,}/ },
  { name: "github-token", regex: /gh[pousr]_[A-Za-z0-9]{36,}/ },
  { name: "aws-access-key-id", regex: /AKIA[0-9A-Z]{16}/ },
  { name: "slack-token", regex: /xox[baprs]-[A-Za-z0-9-]{10,}/ },
  { name: "google-api-key", regex: /AIza[0-9A-Za-z\-_]{35}/ },
  { name: "private-key-block", regex: /-----BEGIN [A-Z ]*PRIVATE KEY-----/ },
  {
    name: "generic-credential-assignment",
    regex: /(?:api[_-]?key|token|secret|password|passwd|pwd)["']?\s*[:=]\s*["']?[A-Za-z0-9_\-]{16,}/i,
  },
];

export type SecretMatch = {
  /** e.g. "config:env.API_TOKEN" or "config:args[2]" */
  location: string;
  patternName: string;
  /** which server the match came from */
  server: string;
};

/** Shannon entropy (bits/char) of a string. */
function shannonEntropy(s: string): number {
  if (!s.length) return 0;
  const freq = new Map<string, number>();
  for (const ch of s) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  let bits = 0;
  for (const c of freq.values()) {
    const p = c / s.length;
    bits -= p * Math.log2(p);
  }
  return bits;
}

/** High-entropy fallback: long, random-looking values that dodge the named patterns. */
function looksHighEntropy(value: string): boolean {
  const v = value.trim();
  if (v.length < 32) return false;
  if (/\s/.test(v)) return false; // real secrets don't contain whitespace
  if (!/[A-Za-z]/.test(v) || !/[0-9]/.test(v)) return false; // needs mixed classes
  return shannonEntropy(v) >= 3.6;
}

/**
 * Test a single value against the pattern set (+ entropy fallback).
 * Returns the matched pattern name, or null. Never returns the value.
 */
export function matchSecret(
  value: string,
  patterns: SecretPattern[] = BUILTIN_SECRET_PATTERNS,
): string | null {
  for (const p of patterns) {
    if (p.regex.test(value)) return p.name;
  }
  if (looksHighEntropy(value)) return "high-entropy-value";
  return null;
}

/** Scan every server's env values + args for secrets. Location + pattern only. */
export function scanSecrets(
  servers: ConfigServer[],
  patterns: SecretPattern[] = BUILTIN_SECRET_PATTERNS,
): SecretMatch[] {
  const matches: SecretMatch[] = [];
  for (const srv of servers) {
    for (const [key, value] of Object.entries(srv.env)) {
      const name = matchSecret(value, patterns);
      if (name) {
        matches.push({ location: `config:env.${key}`, patternName: name, server: srv.name });
      }
    }
    srv.args.forEach((arg, i) => {
      const name = matchSecret(arg, patterns);
      if (name) {
        matches.push({ location: `config:args[${i}]`, patternName: name, server: srv.name });
      }
    });
  }
  return matches;
}

type RawServerEntry = {
  command?: unknown;
  args?: unknown;
  env?: unknown;
};

function coerceServer(name: string, raw: RawServerEntry): ConfigServer {
  const command = typeof raw.command === "string" ? raw.command : "";
  const args = Array.isArray(raw.args) ? raw.args.map((a) => String(a)) : [];
  const env: Record<string, string> = {};
  if (raw.env && typeof raw.env === "object") {
    for (const [k, v] of Object.entries(raw.env as Record<string, unknown>)) {
      env[k] = String(v);
    }
  }
  return { name, command, args, env };
}

/** Parse a claude_desktop_config.json / mcp.json file into a ConfigModel. */
export function loadMcpConfig(path: string): ConfigModel {
  const abs = resolve(path);
  const text = readFileSync(abs, "utf8");
  const json = JSON.parse(text) as Record<string, unknown>;
  // Support both `mcpServers` (Claude Desktop) and a top-level `servers` object.
  const container =
    (json.mcpServers as Record<string, RawServerEntry> | undefined) ??
    (json.servers as Record<string, RawServerEntry> | undefined) ??
    {};
  const servers: ConfigServer[] = Object.entries(container).map(([name, raw]) =>
    coerceServer(name, raw ?? {}),
  );
  return { path: abs, servers };
}
