import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { resolveModel, loadLlmFindings } from "../src/llm.js";
import { DEFAULT_CONFIG } from "../src/schemas.js";
import { model, tool, param } from "./helpers.js";

// Mock the optional Anthropic SDK so no real network call ever happens.
const createMock = vi.fn();
vi.mock("@anthropic-ai/sdk", () => {
  return {
    default: class MockAnthropic {
      messages = { create: createMock };
      constructor(_opts: unknown) {}
    },
  };
});

const M = model([
  tool("run_shell", "Execute a shell command.", [param("command")]),
  tool("http_fetch", "Fetch a URL.", [param("url")]),
]);

describe("resolveModel", () => {
  const orig = process.env.MCP_AUDIT_MODEL;
  afterEach(() => {
    if (orig === undefined) delete process.env.MCP_AUDIT_MODEL;
    else process.env.MCP_AUDIT_MODEL = orig;
  });

  it("defaults to claude-haiku-4-5", () => {
    delete process.env.MCP_AUDIT_MODEL;
    expect(resolveModel()).toBe("claude-haiku-4-5");
  });

  it("honors MCP_AUDIT_MODEL from env", () => {
    process.env.MCP_AUDIT_MODEL = "claude-sonnet-4-5";
    expect(resolveModel()).toBe("claude-sonnet-4-5");
  });
});

describe("loadLlmFindings (SDK mocked)", () => {
  const origKey = process.env.ANTHROPIC_API_KEY;
  beforeEach(() => {
    createMock.mockReset();
    process.env.ANTHROPIC_API_KEY = "sk-test-key-not-real";
  });
  afterEach(() => {
    if (origKey === undefined) delete process.env.ANTHROPIC_API_KEY;
    else process.env.ANTHROPIC_API_KEY = origKey;
  });

  it("throws without an API key", async () => {
    delete process.env.ANTHROPIC_API_KEY;
    await expect(loadLlmFindings(M, DEFAULT_CONFIG)).rejects.toThrow(/ANTHROPIC_API_KEY/);
  });

  it("parses a JSON array of findings from the model", async () => {
    createMock.mockResolvedValue({
      content: [
        {
          type: "text",
          text: JSON.stringify([
            {
              title: "Confused deputy",
              detail: "http_fetch can be steered to internal hosts.",
              location: "http_fetch",
              severity: "high",
              remediation: "Allowlist hosts.",
              confidence: "medium",
            },
          ]),
        },
      ],
    });
    const findings = await loadLlmFindings(M, DEFAULT_CONFIG);
    expect(createMock).toHaveBeenCalledOnce();
    expect(findings).toHaveLength(1);
    expect(findings[0]!.category).toBe("llm");
    expect(findings[0]!.severity).toBe("high");
    // model id passed through
    expect(createMock.mock.calls[0]![0].model).toBe("claude-haiku-4-5");
  });

  it("tolerates prose-wrapped JSON and retries once on failure", async () => {
    createMock
      .mockRejectedValueOnce(new Error("transient 529"))
      .mockResolvedValueOnce({
        content: [{ type: "text", text: "Here you go:\n[]\nThanks" }],
      });
    const findings = await loadLlmFindings(M, DEFAULT_CONFIG);
    expect(createMock).toHaveBeenCalledTimes(2);
    expect(findings).toEqual([]);
  });

  it("never transmits secret values (only names/descriptions/params)", async () => {
    createMock.mockResolvedValue({ content: [{ type: "text", text: "[]" }] });
    await loadLlmFindings(M, DEFAULT_CONFIG);
    const sent = JSON.stringify(createMock.mock.calls[0]![0]);
    expect(sent).not.toContain("ANTHROPIC_API_KEY");
    expect(sent).not.toContain("sk-test-key-not-real");
  });
});
