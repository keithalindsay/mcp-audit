import { describe, it, expect } from "vitest";
import { classifyTool } from "../src/classify.js";
import { tool, param } from "./helpers.js";

describe("classifyTool (§8.3)", () => {
  it("run_shell → executor only", () => {
    const t = classifyTool(
      tool("run_shell", "Execute a shell command and return its output.", [
        param("command"),
      ]),
    );
    expect(t.executor).toBe(true);
    expect(t.source).toBe(false);
    expect(t.sink).toBe(false);
    expect(t.reasons.join(" ")).toMatch(/executor/);
  });

  it("read_file → source only", () => {
    const t = classifyTool(
      tool("read_file", "Read a file from the local filesystem.", [param("path")]),
    );
    expect(t.source).toBe(true);
    expect(t.sink).toBe(false);
    expect(t.executor).toBe(false);
  });

  // Regression: a search/memory tool with a `query` param must NOT be flagged as
  // an executor (MCP001). Found by auditing a real memory MCP server whose
  // `recall`/`compare` tools were wrongly reported as "executes arbitrary code".
  it("recall(query) → source only, NOT executor", () => {
    const t = classifyTool(
      tool("recall", "Answer a question from memory by graph traversal.", [param("query")]),
    );
    expect(t.executor).toBe(false);
    expect(t.source).toBe(true);
  });

  it("run_sql → still executor (real SQL execution is not a false positive)", () => {
    const t = classifyTool(
      tool("run_sql", "Execute an arbitrary SQL statement.", [param("sql")]),
    );
    expect(t.executor).toBe(true);
  });

  it("http_fetch → source AND sink", () => {
    const t = classifyTool(
      tool("http_fetch", "Fetch a URL over HTTP and return the body.", [param("url")]),
    );
    expect(t.source).toBe(true);
    expect(t.sink).toBe(true);
    expect(t.executor).toBe(false);
  });

  it("a benign echo → no tags", () => {
    const t = classifyTool(tool("echo", "Return the text you were given.", [param("text")]));
    expect(t.source).toBe(false);
    expect(t.sink).toBe(false);
    expect(t.executor).toBe(false);
    expect(t.reasons).toEqual([]);
  });
});
