import { describe, it, expect, beforeAll } from "vitest";
import { spawnSync, execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { MCP006 } from "../src/rules/tools.js";
import { matchSecret } from "../src/config-scan.js";
import { classifyTools } from "../src/classify.js";
import { BUILTIN_SECRET_PATTERNS } from "../src/config-scan.js";
import type { RuleContext } from "../src/rules/types.js";
import type { Tool } from "../src/schemas.js";
import { tool, param } from "./helpers.js";

/**
 * Regression tests from a chaos-QA battery (chaos-dogfood + chaos-invariants +
 * chaos-inputs + chaos-faults). Each `it` encodes an invariant that is currently
 * VIOLATED, reproduced against real usage. They assert the user-observable contract,
 * not any particular fix site.
 */

const repoRoot = fileURLToPath(new URL("..", import.meta.url));
const cliJs = fileURLToPath(new URL("../dist/cli.js", import.meta.url));
const errlistServer = fileURLToPath(new URL("./fixtures/errlist-server.mjs", import.meta.url));
const okServer = fileURLToPath(new URL("./fixtures/ok-server.mjs", import.meta.url));
const crashServer = fileURLToPath(new URL("./fixtures/crash-server.mjs", import.meta.url));

function ctxFor(tools: Tool[]): RuleContext {
  return {
    model: { server: { name: "t" }, spec: { command: "node", args: [], label: "t" }, tools, resources: [], prompts: [] },
    classified: classifyTools(tools),
    configServer: null,
    configPath: null,
    secretPatterns: BUILTIN_SECRET_PATTERNS,
  };
}

// ---------------------------------------------------------------------------
// F3 (chaos-dogfood/invariants): false positive — a natural-language search
// `query` param is flagged by MCP006 as an unvalidated "command/query" that
// "widens the injection surface". This is the SAME class the project already
// fixed for MCP001 (classify.ts dropped "query" from the executor tokens because
// "a search/memory `query` param is a data SOURCE, not code execution"), but the
// fix never propagated to MCP006's paramIntent ("query" is still a COMMAND_TOKEN).
// Real repro: `audit --server agent-memory-mcp` flags recall.query and compare.query.
// ---------------------------------------------------------------------------
describe("MCP006 must not cry wolf on a natural-language search query (FP class)", () => {
  it("does NOT flag recall(query) — a plain-language memory/search input", () => {
    const t = tool("recall", "Answer a question from long-term memory. Ask in plain language.", [param("query")]);
    expect(MCP006.check(ctxFor([t]))).toHaveLength(0);
  });

  it("does NOT flag compare(query) — a benchmarking search input", () => {
    const t = tool("compare", "Answer the same question with both backends, side by side.", [param("query")]);
    expect(MCP006.check(ctxFor([t]))).toHaveLength(0);
  });

  it("still DOES flag a real free-form command param (no over-correction)", () => {
    const t = tool("run_shell", "Run a shell command.", [param("command")]);
    expect(MCP006.check(ctxFor([t]))).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// F4 (chaos-inputs/invariants): false positive — the high-entropy secret
// fallback flags ordinary filesystem paths that appear in real MCP config args
// (npx/pnpm cache paths, dir args with digits) as `high-entropy-value` secrets,
// producing spurious CRITICAL MCP005 findings that can fail a --ci build.
// ---------------------------------------------------------------------------
describe("high-entropy secret fallback must not flag ordinary config file paths", () => {
  it("does NOT flag an npx cache path", () => {
    expect(matchSecret("/home/alice/.npm/_npx/8f3a2b1c9d4e5f6a/node_modules/.bin/mcp-memory-server")).toBeNull();
  });

  it("does NOT flag a directory argument with digits", () => {
    expect(matchSecret("--allowed-dir=/var/data/2024/uploads/batch01")).toBeNull();
  });

  it("still DOES flag a real sk- style key (no over-correction)", () => {
    const key = "sk-" + "a1B2c3D4e5F6g7H8i9J0kL"; // assembled at runtime; not a real secret
    expect(matchSecret(key)).not.toBeNull();
  });
});

// ---------------------------------------------------------------------------
// The spawn-based tests exercise the CLI end-to-end. Build once.
// ---------------------------------------------------------------------------
describe("CLI-level chaos-QA regressions", () => {
  beforeAll(() => {
    if (!existsSync(cliJs)) {
      execFileSync("npm", ["run", "build"], { cwd: repoRoot, stdio: "ignore" });
    }
  });

  // F2 (chaos-faults/invariants): silent failure + wrong exit code. A server that
  // ERRORS on tools/list is reported as "0 tools, No findings, Exit: 0" — a clean
  // bill of health that hides an introspection failure. Per the exit-code contract
  // (2 = connection/introspection error) this must NOT be a clean success.
  it("F2: does not report a clean pass when tools/list introspection fails", () => {
    const res = spawnSync(process.execPath, [cliJs, "audit", "--server", `node ${errlistServer}`, "--no-color"], {
      cwd: repoRoot,
      encoding: "utf8",
      timeout: 30000,
    });
    // The audit could not enumerate the primary surface; a security auditor must not
    // exit 0 "all clear". (Contract: introspection/connection error → exit 2.)
    expect(res.status, `stdout:\n${res.stdout}\nstderr:\n${res.stderr}`).not.toBe(0);
  });

  // F1 (chaos-faults/dogfood): a multi-server --config aborts entirely if ANY one
  // server can't be launched — the remaining servers are never audited and the
  // static config secret scan (MCP005, which needs no live server) never runs.
  // DESIGN §7.1 promises `--config` audits *every* mcpServers entry.
  it("F1: --config still scans a launchable server's secret when another server can't launch", () => {
    const dir = mkdtempSync(join(tmpdir(), "mcp-audit-chaos-"));
    const secret = "sk-" + "a1B2c3D4e5F6g7H8i9J0kL"; // assembled at runtime; not a real secret
    const cfg = {
      mcpServers: {
        "aaa-broken": { command: "node", args: [crashServer], env: {} },
        "zzz-good": { command: "node", args: [okServer], env: { API_TOKEN: secret } },
      },
    };
    const cfgPath = join(dir, "multi.json");
    writeFileSync(cfgPath, JSON.stringify(cfg));

    const res = spawnSync(process.execPath, [cliJs, "audit", "--config", cfgPath, "--no-color"], {
      cwd: repoRoot,
      encoding: "utf8",
      timeout: 30000,
    });
    const out = `${res.stdout}\n${res.stderr}`;
    // The good server's planted secret must still be reported despite the broken one.
    expect(out, `output:\n${out}`).toContain("config:env.API_TOKEN");
    // And, per the secrets-never-leave invariant, the raw value must never appear.
    expect(out).not.toContain(secret);
  });
});
