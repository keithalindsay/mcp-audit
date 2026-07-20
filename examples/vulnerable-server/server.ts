/**
 * examples/vulnerable-server/server.ts
 *
 * A DELIBERATELY-INSECURE MCP server, shipped as an offline fixture for
 * `mcp-audit demo` and the e2e test. It is synthetic and for demonstration only —
 * DO NOT deploy it or copy its tool designs.
 *
 * It exposes, on purpose:
 *   - run_shell  : arbitrary shell execution                       (→ MCP001)
 *   - read_file  : free-form filesystem path, no jail              (→ MCP002)
 *   - http_fetch : arbitrary outbound URL                          (→ MCP003)
 *   - read_file + http_fetch : source + sink exfil combination     (→ MCP004)
 *   - resource env://all : exposes the whole process environment   (→ MCP010)
 *
 * The tool callbacks are inert stubs: mcp-audit only *lists* capabilities, it never
 * invokes them, so nothing here actually runs a command or reads a file.
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

const server = new McpServer({ name: "vulnerable-demo", version: "0.0.0" });

server.registerTool(
  "run_shell",
  {
    description: "Execute a shell command and return its stdout/stderr.",
    inputSchema: { command: z.string() },
  },
  async ({ command }) => ({
    content: [{ type: "text", text: `[demo stub] would run: ${command}` }],
  }),
);

server.registerTool(
  "read_file",
  {
    description: "Read a file from the local filesystem and return its contents.",
    inputSchema: { path: z.string() },
  },
  async ({ path }) => ({
    content: [{ type: "text", text: `[demo stub] would read: ${path}` }],
  }),
);

server.registerTool(
  "http_fetch",
  {
    description: "Fetch a URL over HTTP(S) and return the response body.",
    inputSchema: { url: z.string() },
  },
  async ({ url }) => ({
    content: [{ type: "text", text: `[demo stub] would fetch: ${url}` }],
  }),
);

server.registerResource(
  "environment",
  "env://all",
  {
    description: "All process environment variables (including secrets).",
    mimeType: "text/plain",
  },
  async (uri) => ({
    contents: [{ uri: uri.href, text: "[demo stub] environment withheld" }],
  }),
);

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((err) => {
  // eslint-disable-next-line no-console
  console.error("vulnerable-demo server failed:", err);
  process.exit(1);
});
