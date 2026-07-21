// Chaos-QA fixture: an MCP server that connects fine but ERRORS on tools/list.
// Models a broken / evasive server whose primary surface can't be enumerated.
// A read-only auditor must NOT report this as a clean, empty toolset.
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

const server = new Server(
  { name: "errlist", version: "1.0.0" },
  { capabilities: { tools: {} } },
);
server.setRequestHandler(ListToolsRequestSchema, async () => {
  throw new Error("tools/list refused");
});
await server.connect(new StdioServerTransport());
