import { Command } from "commander";
import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { runAudit, type AuditOptions } from "./audit.js";
import { loadConfig } from "./config.js";
import { loadMcpConfig } from "./config-scan.js";
import { renderReport, toJson } from "./reporter.js";
import { ruleCatalog } from "./rules/index.js";
import {
  SeveritySchema,
  type AuditReport,
  type Config,
  type ServerSpec,
  type Severity,
} from "./schemas.js";

/**
 * cli.ts — commander entrypoint wiring audit / demo / rules (§7.1) + exit codes.
 *   0 = no findings ≥ failOn · 1 = findings ≥ failOn · 2 = usage/connection/config error.
 */

const program = new Command();

program
  .name("mcp-audit")
  .description("A security linter for MCP servers (connect, introspect, flag risky tool designs).")
  .version("0.1.0")
  .option("--no-color", "disable colored output");

function useColor(): boolean {
  const opts = program.opts();
  return opts.color !== false && process.stdout.isTTY === true;
}

/** Parse `--server "node dist/server.js"` into a ServerSpec. */
function parseServerSpec(cmd: string, cwd?: string): ServerSpec {
  const parts = cmd.trim().split(/\s+/);
  const command = parts[0];
  if (!command) throw new Error("--server requires a command, e.g. --server \"node dist/server.js\"");
  return { command, args: parts.slice(1), cwd, label: cmd.trim() };
}

function emit(reports: AuditReport[], jsonPath: string | boolean | undefined): void {
  const wantJson = jsonPath !== undefined;
  if (wantJson) {
    const payload = reports.length === 1 ? reports[0]! : reports;
    const text = JSON.stringify(payload, null, 2);
    if (typeof jsonPath === "string") {
      writeFileSync(jsonPath, text);
      process.stderr.write(`wrote ${jsonPath}\n`);
    } else {
      process.stdout.write(text + "\n");
    }
    return;
  }
  const color = useColor();
  for (const r of reports) {
    process.stdout.write(renderReport(r, { color }) + "\n");
  }
}

function overallExit(reports: AuditReport[]): 0 | 1 {
  return reports.some((r) => r.exitCode === 1) ? 1 : 0;
}

function applyOverrides(
  config: Config,
  opts: { minSeverity?: string; timeout?: string },
): Config {
  const next = { ...config };
  if (opts.minSeverity) {
    next.minSeverity = SeveritySchema.parse(opts.minSeverity as Severity);
  }
  if (opts.timeout) {
    const n = Number(opts.timeout);
    if (Number.isFinite(n) && n > 0) next.timeoutMs = n;
  }
  return next;
}

// --------------------------------------------------------------------------- audit
program
  .command("audit")
  .description("Audit a stdio MCP server (--server) and/or every server in a config (--config).")
  .option("--server <cmd>", 'launch + introspect a stdio server, e.g. --server "node dist/server.js"')
  .option("--config <path>", "a claude_desktop_config.json / mcp.json; audit every mcpServers entry")
  .option("--cwd <dir>", "working directory for the launched server")
  .option("--ci", "non-interactive; exit non-zero if any finding at/above the fail threshold")
  .option("--json [path]", "emit the machine-readable AuditReport to stdout or <path>")
  .option("--min-severity <level>", "only report findings at/above this level (critical|high|medium|low|info)")
  .option("--llm", "run the optional Anthropic deep-analysis pass (needs ANTHROPIC_API_KEY)")
  .option("--timeout <ms>", "server startup/introspection timeout in ms")
  .action(async (opts) => {
    try {
      if (!opts.server && !opts.config) {
        process.stderr.write("error: provide --server and/or --config\n");
        process.exitCode = 2;
        return;
      }
      const baseConfig = applyOverrides(loadConfig(), opts);
      const reports: AuditReport[] = [];

      if (opts.server) {
        const spec = parseServerSpec(opts.server, opts.cwd);
        reports.push(await runAudit({ serverSpec: spec, config: baseConfig, llm: opts.llm }));
      }

      if (opts.config) {
        const cfgModel = loadMcpConfig(opts.config);
        for (const srv of cfgModel.servers) {
          const spec: ServerSpec = {
            command: srv.command,
            args: srv.args,
            env: srv.env,
            cwd: opts.cwd,
            label: srv.name,
          };
          const auditOpts: AuditOptions = {
            serverSpec: spec,
            configServer: srv,
            configPath: cfgModel.path,
            config: baseConfig,
            llm: opts.llm,
          };
          reports.push(await runAudit(auditOpts));
        }
      }

      emit(reports, opts.json);
      process.exitCode = overallExit(reports);
    } catch (err) {
      process.stderr.write(`error: ${err instanceof Error ? err.message : String(err)}\n`);
      process.exitCode = 2;
    }
  });

// ---------------------------------------------------------------------------- demo
program
  .command("demo")
  .description("Audit the bundled deliberately-vulnerable MCP server (offline, no key).")
  .option("--json [path]", "emit the machine-readable AuditReport")
  .action(async (opts) => {
    try {
      const serverPath = fileURLToPath(new URL("./vulnerable-server.js", import.meta.url));
      const mcpJsonPath = fileURLToPath(
        new URL("../examples/vulnerable-server/mcp.json", import.meta.url),
      );
      const cfgModel = loadMcpConfig(mcpJsonPath);
      const configServer = cfgModel.servers.find((s) => s.name === "vulnerable-demo") ?? cfgModel.servers[0];

      const spec: ServerSpec = {
        command: process.execPath, // node
        args: [serverPath],
        label: "vulnerable-demo",
      };
      const report = await runAudit({
        serverSpec: spec,
        configServer,
        configPath: cfgModel.path,
        config: loadConfig(),
      });
      emit([report], opts.json);
      process.exitCode = report.exitCode;
    } catch (err) {
      process.stderr.write(`error: ${err instanceof Error ? err.message : String(err)}\n`);
      process.exitCode = 2;
    }
  });

// --------------------------------------------------------------------------- rules
program
  .command("rules")
  .description("List the check catalog (id, severity, category, title).")
  .option("--json", "emit the catalog as JSON")
  .action((opts) => {
    const catalog = ruleCatalog();
    if (opts.json) {
      process.stdout.write(JSON.stringify(catalog, null, 2) + "\n");
      return;
    }
    const color = useColor();
    const lines = catalog.map((r) => {
      const id = color ? `\x1b[1m${r.id}\x1b[0m` : r.id;
      return `  ${id}  ${r.severity.padEnd(8)} ${r.category.padEnd(13)} ${r.title}`;
    });
    process.stdout.write(
      `\nmcp-audit check catalog (${catalog.length} rules)\n\n` + lines.join("\n") + "\n",
    );
  });

program.parseAsync(process.argv).catch((err) => {
  process.stderr.write(`error: ${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(2);
});
