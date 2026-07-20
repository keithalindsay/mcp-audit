import type { Tool, ToolParam, Resource, ServerModel, ServerSpec } from "../src/schemas.js";

export function param(
  name: string,
  opts: Partial<ToolParam> = {},
): ToolParam {
  return {
    name,
    type: opts.type ?? "string",
    required: opts.required ?? true,
    constrained: opts.constrained ?? false,
    raw: opts.raw ?? { type: opts.type ?? "string" },
  };
}

export function tool(
  name: string,
  description = "",
  params: ToolParam[] = [],
): Tool {
  return { name, description, params, rawInputSchema: { type: "object" } };
}

export function resource(uri: string, extra: Partial<Resource> = {}): Resource {
  return { uri, ...extra };
}

export const SPEC: ServerSpec = {
  command: "node",
  args: ["server.js"],
  label: "test",
};

export function model(
  tools: Tool[],
  resources: Resource[] = [],
  serverName = "test-server",
): ServerModel {
  return {
    server: { name: serverName },
    spec: SPEC,
    tools,
    resources,
    prompts: [],
  };
}
