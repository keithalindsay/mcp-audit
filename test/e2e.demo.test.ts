import { describe, it, expect, beforeAll } from "vitest";
import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { runAudit } from "../src/audit.js";
import { loadMcpConfig } from "../src/config-scan.js";
import { renderReport } from "../src/reporter.js";
import { DEFAULT_CONFIG, type ServerSpec } from "../src/schemas.js";

/**
 * The crux integration test (DESIGN.md §11 step 14): build the bundled vulnerable
 * server, spawn it over REAL stdio MCP, run the full audit in-process, and assert the
 * expected finding set + exit code. Offline, deterministic, no network, no key.
 */

const repoRoot = fileURLToPath(new URL("..", import.meta.url));
const serverJs = fileURLToPath(new URL("../dist/vulnerable-server.js", import.meta.url));
const mcpJson = fileURLToPath(new URL("../examples/vulnerable-server/mcp.json", import.meta.url));

describe("e2e: audit the bundled vulnerable server over real stdio MCP", () => {
  beforeAll(() => {
    // Ensure the vulnerable server is built to dist/ so it can be spawned via node.
    if (!existsSync(serverJs)) {
      execFileSync("npm", ["run", "build"], { cwd: repoRoot, stdio: "ignore" });
    }
  });

  it("finds MCP001, MCP002, MCP003, MCP004, MCP005, MCP010 and exits 1", async () => {
    const cfg = loadMcpConfig(mcpJson);
    const configServer = cfg.servers.find((s) => s.name === "vulnerable-demo")!;

    const spec: ServerSpec = {
      command: process.execPath,
      args: [serverJs],
      label: "vulnerable-demo",
    };

    const report = await runAudit({
      serverSpec: spec,
      configServer,
      configPath: cfg.path,
      config: DEFAULT_CONFIG,
    });

    // Server was really introspected over stdio.
    expect(report.serverSummary).not.toBeNull();
    expect(report.serverSummary!.tools).toBe(3);
    expect(report.serverSummary!.resources).toBe(1);

    const ids = new Set(report.findings.map((f) => f.ruleId));
    for (const required of ["MCP001", "MCP002", "MCP003", "MCP004", "MCP005", "MCP010"]) {
      expect(ids, `expected ${required} to be found`).toContain(required);
    }

    // The combination finding is the core value — assert its shape explicitly.
    const combo = report.findings.find((f) => f.ruleId === "MCP004")!;
    expect(combo.severity).toBe("critical");
    expect(combo.category).toBe("exfiltration");
    expect(combo.location).toContain("read_file");
    expect(combo.location).toContain("http_fetch");

    // Secret is reported by location/pattern only — never the value.
    const secret = report.findings.find((f) => f.ruleId === "MCP005")!;
    expect(secret.location).toBe("config:env.API_TOKEN");
    expect(JSON.stringify(report)).not.toContain("sk-abcd");

    expect(report.exitCode).toBe(1);

    // Report renders without throwing.
    const text = renderReport(report, { color: false });
    expect(text).toContain("MCP004");
  });
});
