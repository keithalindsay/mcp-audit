import type { Config, Finding, ServerModel, Severity } from "./schemas.js";
import { SeveritySchema } from "./schemas.js";

/**
 * llm.ts — the OPTIONAL Anthropic deep-analysis pass (--llm).
 *
 * - Off by default. Deterministic rules are the product; this is additive.
 * - @anthropic-ai/sdk is an optionalDependency, imported lazily so the tool runs with
 *   zero LLM deps installed.
 * - The model id is read ONLY from env (MCP_AUDIT_MODEL) or the fallback here — it is
 *   never hardcoded anywhere else.
 * - No secrets are sent: only tool names, descriptions, and param names/types.
 */

// The single place the default model id is defined.
const DEFAULT_MODEL = "claude-haiku-4-5";

export function resolveModel(): string {
  return process.env.MCP_AUDIT_MODEL?.trim() || DEFAULT_MODEL;
}

const SYSTEM_PROMPT = [
  "You are a security auditor for Model Context Protocol (MCP) servers.",
  "You are given the tools a server exposes (names, descriptions, parameter names/types).",
  "Identify SUBTLE risks a keyword linter would miss: prompt-injection framing in descriptions,",
  "dangerous capability combinations, over-permissive designs, confused-deputy patterns.",
  "Respond with ONLY a JSON array of findings. Each finding is an object:",
  '{ "title": string, "detail": string, "location": string, "severity": "critical"|"high"|"medium"|"low"|"info", "remediation": string, "confidence": "high"|"medium"|"low" }.',
  "Return [] if you find nothing beyond the obvious. Never include secret values.",
].join(" ");

function buildUserPrompt(model: ServerModel): string {
  const toolLines = model.tools.map((t) => {
    const params = t.params.map((p) => `${p.name}:${p.type}${p.required ? "" : "?"}`).join(", ");
    return `- ${t.name}(${params}) — ${t.description}`;
  });
  const resourceLines = model.resources.map((r) => `- ${r.uri} ${r.description ?? ""}`);
  return [
    `Server: ${model.server.name}`,
    "Tools:",
    ...toolLines,
    resourceLines.length ? "Resources:" : "",
    ...resourceLines,
  ]
    .filter(Boolean)
    .join("\n");
}

type RawLlmFinding = {
  title?: unknown;
  detail?: unknown;
  location?: unknown;
  severity?: unknown;
  remediation?: unknown;
  confidence?: unknown;
};

function coerceFindings(text: string): Finding[] {
  let parsed: unknown;
  try {
    // Tolerate the model wrapping JSON in prose/code fences.
    const match = text.match(/\[[\s\S]*\]/);
    parsed = JSON.parse(match ? match[0] : text);
  } catch {
    return [];
  }
  if (!Array.isArray(parsed)) return [];
  const out: Finding[] = [];
  for (const raw of parsed as RawLlmFinding[]) {
    const sev = SeveritySchema.safeParse(raw.severity);
    const severity: Severity = sev.success ? sev.data : "medium";
    const conf = raw.confidence === "high" || raw.confidence === "low" ? raw.confidence : "medium";
    out.push({
      ruleId: "MCP-LLM",
      severity,
      category: "llm",
      title: String(raw.title ?? "LLM-identified risk"),
      detail: String(raw.detail ?? ""),
      location: String(raw.location ?? "server"),
      remediation: String(raw.remediation ?? ""),
      confidence: conf,
    });
  }
  return out;
}

/**
 * Run the Anthropic pass. Throws if no API key or the SDK isn't installed. One bounded
 * retry on transient failure. Returns category-"llm" findings.
 */
export async function loadLlmFindings(model: ServerModel, _config: Config): Promise<Finding[]> {
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    throw new Error("ANTHROPIC_API_KEY is not set (required for --llm).");
  }

  let AnthropicMod: typeof import("@anthropic-ai/sdk");
  try {
    AnthropicMod = await import("@anthropic-ai/sdk");
  } catch {
    throw new Error(
      "@anthropic-ai/sdk is not installed. Install it to use --llm: npm i @anthropic-ai/sdk",
    );
  }
  const Anthropic = AnthropicMod.default;
  const client = new Anthropic({ apiKey });
  const modelId = resolveModel();
  const userPrompt = buildUserPrompt(model);

  const callOnce = async (): Promise<Finding[]> => {
    const resp = await client.messages.create({
      model: modelId,
      max_tokens: 1500,
      system: SYSTEM_PROMPT,
      messages: [{ role: "user", content: userPrompt }],
    });
    const text = resp.content
      .map((block: { type: string; text?: string }) =>
        block.type === "text" ? (block.text ?? "") : "",
      )
      .join("");
    return coerceFindings(text);
  };

  try {
    return await callOnce();
  } catch (err) {
    // Single bounded retry.
    try {
      return await callOnce();
    } catch {
      throw err instanceof Error ? err : new Error(String(err));
    }
  }
}
