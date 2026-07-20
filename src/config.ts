import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { parse as parseYaml } from "yaml";
import { ConfigSchema, DEFAULT_CONFIG, type Config } from "./schemas.js";

/**
 * config.ts — load the optional mcp-audit.config.yaml (thresholds, disabled rules,
 * extra secret patterns). Missing file → defaults (§7.4).
 */

const DEFAULT_FILENAMES = ["mcp-audit.config.yaml", "mcp-audit.config.yml"];

/** Resolve the config path: explicit path, else the first default in `cwd`. */
export function findConfigPath(explicit?: string, cwd = process.cwd()): string | null {
  if (explicit) return resolve(cwd, explicit);
  for (const name of DEFAULT_FILENAMES) {
    const p = resolve(cwd, name);
    if (existsSync(p)) return p;
  }
  return null;
}

export function loadConfig(explicit?: string, cwd = process.cwd()): Config {
  const path = findConfigPath(explicit, cwd);
  if (!path || !existsSync(path)) return { ...DEFAULT_CONFIG };
  const raw = parseYaml(readFileSync(path, "utf8")) ?? {};
  return ConfigSchema.parse(raw);
}
