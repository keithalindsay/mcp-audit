// Chaos-QA fixture: a minimal, valid MCP server exposing one benign tool.
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

const server = new Server(
  { name: "ok-server", version: "1.0.0" },
  { capabilities: { tools: {} } },
);
server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: "ping",
      description: "Return pong.",
      inputSchema: { type: "object", properties: {} },
    },
  ],
}));
await server.connect(new StdioServerTransport());
