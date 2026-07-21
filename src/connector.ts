import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import type {
  ServerModel,
  ServerSpec,
  Tool,
  ToolParam,
  Resource,
  Prompt,
} from "./schemas.js";

/**
 * connector.ts — the MCP client. Spawns a target stdio server, runs the handshake,
 * and lists tools/resources/prompts into a ServerModel.
 *
 * READ-ONLY: this only ever calls the list methods (tools/list, resources/list,
 * prompts/list). It never calls a tool, reads a resource, or sends a payload — auditing
 * a server cannot trigger its side effects.
 */

const CLIENT_INFO = { name: "mcp-audit", version: "0.1.0" };

function withTimeout<T>(p: Promise<T>, ms: number, label: string): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(
      () => reject(new Error(`${label} timed out after ${ms}ms`)),
      ms,
    );
    p.then(
      (v) => {
        clearTimeout(timer);
        resolve(v);
      },
      (e) => {
        clearTimeout(timer);
        reject(e);
      },
    );
  });
}

type RawSchema = {
  type?: unknown;
  properties?: Record<string, Record<string, unknown>>;
  required?: string[];
};

const CONSTRAINT_KEYS = [
  "enum",
  "pattern",
  "format",
  "const",
  "minLength",
  "maxLength",
  "minimum",
  "maximum",
  "exclusiveMinimum",
  "exclusiveMaximum",
  "multipleOf",
];

function normalizeParams(schema: unknown): ToolParam[] {
  const s = (schema ?? {}) as RawSchema;
  const props = s.properties ?? {};
  const required = new Set(s.required ?? []);
  const params: ToolParam[] = [];
  for (const [name, raw] of Object.entries(props)) {
    const propType =
      typeof raw.type === "string"
        ? raw.type
        : Array.isArray(raw.type)
          ? (raw.type[0] as string)
          : raw.enum
            ? "enum"
            : "unknown";
    const constrained = CONSTRAINT_KEYS.some((k) => k in raw);
    params.push({
      name,
      type: propType,
      required: required.has(name),
      constrained,
      raw,
    });
  }
  return params;
}

/** Introspect a stdio MCP server into a ServerModel. Always closes the transport. */
export async function introspect(
  spec: ServerSpec,
  opts: { timeoutMs?: number } = {},
): Promise<ServerModel> {
  const timeoutMs = opts.timeoutMs ?? 10000;

  const transport = new StdioClientTransport({
    command: spec.command,
    args: spec.args,
    env: { ...process.env, ...(spec.env ?? {}) } as Record<string, string>,
    cwd: spec.cwd,
    stderr: "ignore",
  });

  const client = new Client(CLIENT_INFO);

  try {
    await withTimeout(client.connect(transport), timeoutMs, "MCP connect");

    const version = client.getServerVersion();
    const caps = client.getServerCapabilities();

    // tools/list is the PRIMARY introspection surface. Distinguish "no tools
    // capability advertised" (a genuine empty toolset — fine) from "the server
    // advertises tools but the list call errors/times out" (a real introspection
    // failure). The latter must NOT be silently reported as "0 tools, all clear":
    // let it throw so the audit exits with the connection/introspection error code
    // (2), rather than handing out a false clean bill of health.
    let tools: Awaited<ReturnType<typeof client.listTools>>["tools"] = [];
    if (caps?.tools) {
      const result = await withTimeout(
        client.listTools(),
        timeoutMs,
        "MCP tools/list",
      );
      tools = result.tools;
    }

    // resources/prompts are secondary: an absent capability is safely an empty list.
    const resources = await safeList(
      () => client.listResources(),
      (r) => r.resources,
      timeoutMs,
    );
    const prompts = await safeList(
      () => client.listPrompts(),
      (r) => r.prompts,
      timeoutMs,
    );

    const model: ServerModel = {
      server: {
        name: version?.name ?? spec.label,
        version: version?.version,
      },
      spec,
      tools: (tools ?? []).map(
        (t): Tool => ({
          name: t.name,
          description: t.description ?? "",
          params: normalizeParams(t.inputSchema),
          rawInputSchema: t.inputSchema,
        }),
      ),
      resources: (resources ?? []).map(
        (r): Resource => ({
          uri: r.uri,
          name: r.name,
          description: r.description,
          mimeType: r.mimeType,
        }),
      ),
      prompts: (prompts ?? []).map(
        (p): Prompt => ({ name: p.name, description: p.description }),
      ),
    };
    return model;
  } finally {
    try {
      await client.close();
    } catch {
      /* ignore */
    }
    try {
      await transport.close();
    } catch {
      /* ignore */
    }
  }
}

async function safeList<R, T>(
  call: () => Promise<R>,
  pick: (r: R) => T[],
  timeoutMs: number,
): Promise<T[]> {
  try {
    const result = await withTimeout(call(), timeoutMs, "MCP list");
    return pick(result);
  } catch {
    return [];
  }
}
