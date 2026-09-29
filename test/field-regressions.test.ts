import { describe, it, expect } from "vitest";
import { MCP001, MCP002, MCP007 } from "../src/rules/tools.js";
import { MCP004 } from "../src/rules/combinations.js";
import { MCP008 } from "../src/rules/index.js";
import { MCP010 } from "../src/rules/config.js";
import type { RuleContext } from "../src/rules/types.js";
import { classifyTool, classifyTools } from "../src/classify.js";
import { BUILTIN_SECRET_PATTERNS } from "../src/config-scan.js";
import { tool, param, model, resource } from "./helpers.js";
import type { Tool, Resource } from "../src/schemas.js";

/**
 * Field regressions — every case below is a real tool definition (name, description,
 * parameter names, annotations) captured on 2026-09-29 by auditing two published MCP
 * servers: mongodb-mcp-server 3.0.4 (npm) and dominodatalab/domino_mcp_server @ 8aa0be5.
 * Of 30 findings across the two, 11 of MongoDB's 13 were false positives, and a
 * manual code read found each misfire's cause. Each test pins one of those causes.
 */

function ctxFor(tools: Tool[], resources: Resource[] = []): RuleContext {
  return {
    model: model(tools, resources),
    classified: classifyTools(tools),
    configServer: null,
    configPath: null,
    secretPatterns: BUILTIN_SECRET_PATTERNS,
  };
}

// --- captured definitions -------------------------------------------------------

const mongoAggregate = tool("aggregate", "Run an aggregation against a MongoDB collection", [
  param("connectionId"),
  param("database"),
  param("collection"),
  param("pipeline", { type: "array" }),
  param("responseBytesLimit", { type: "number" }),
]);

const mongoFind = tool("find", "Run a find query against a MongoDB collection", [
  param("connectionId"),
  param("database"),
  param("collection"),
  param("filter", { type: "object" }),
]);

const mongoInsertMany = tool(
  "insert-many",
  "Insert an array of documents into a MongoDB collection. If the list of documents is above com.mongodb/maxRequestPayloadBytes, consider inserting them in batches.",
  [param("connectionId"), param("database"), param("collection"), param("documents", { type: "array" })],
);

const mongoLocalCreate = tool(
  "atlas-local-create-deployment",
  "Create a MongoDB Atlas local deployment. Default image is preview. When the user does not specify an image tag, inform them that preview is used by default and provide this link for more information: https://hub.docker.com/r/mongodb/mongodb-atlas-local",
  [param("deploymentName"), param("loadSampleData", { type: "boolean" }), param("imageTag")],
);

const dominoRunJob = tool(
  "run_domino_job",
  "The run_domino_job function runs a command as a job on the domino data science platform, typically a python script such a 'python my_script.py --arg1 arv1_val --arg2 arv2_val' on the Domino cloud platform.",
  [param("user_name"), param("project_name"), param("run_command"), param("title")],
);

const dominoCheckStatus = tool(
  "check_domino_job_run_status",
  "The check_domino_job_run_status function checks the status of a job run to determine if its finished or in-progress or had an error. A run can sometimes take 1 or more minutes, so it might be necessary to call this a few times until it's finished before using a different function to read the results.",
  [param("user_name"), param("project_name"), param("run_id")],
);

const dominoSyncLocal = tool(
  "sync_local_file_to_domino",
  "Reads a local file and uploads it to a Domino project. Works with DFS (non-git) projects. This is a convenience function that combines reading a local file and uploading it. Args: local_file_path (str): The absolute path to the local file to upload domino_file_path (str, optional): The path in Domino where the file should be saved. Returns: Dict containing upload result on success.",
  [param("user_name"), param("project_name"), param("local_file_path"), param("domino_file_path")],
);

const dominoListFiles = tool(
  "list_domino_project_files",
  "Lists files in a Domino project directory. Works with DFS (non-git) projects. Use this to see what files exist in a Domino project before uploading or downloading.",
  [param("user_name"), param("project_name"), param("path")],
);

const dominoUpload = tool(
  "upload_file_to_domino_project",
  "Uploads a file to a Domino project. Works with DFS (non-git) projects. Use this to sync local file changes to a Domino project.",
  [param("user_name"), param("project_name"), param("file_path"), param("file_content")],
);

const dominoOpenBrowser = tool("open_web_browser", "Opens the specified URL in the default web browser.", [
  param("url"),
]);

const dominoSmartSync = tool(
  "smart_sync_file",
  "Intelligently syncs a file to a Domino project with conflict detection. It automatically detects if someone else modified the file since you last downloaded it, and returns conflict information instead of blindly overwriting.",
  [
    param("user_name"),
    param("project_name"),
    param("file_path"),
    param("content"),
    param("force_overwrite", { type: "boolean", required: false }),
  ],
);

// --- MCP001: executor detection and attribution ----------------------------------

describe("MCP001 field regressions", () => {
  it("'Run an aggregation' is a query verb, not code execution (mongodb aggregate)", () => {
    expect(classifyTool(mongoAggregate).executor).toBe(false);
    expect(MCP001.check(ctxFor([mongoAggregate]))).toHaveLength(0);
  });

  it("'Run a find query' is not code execution (mongodb find)", () => {
    expect(MCP001.check(ctxFor([mongoFind]))).toHaveLength(0);
  });

  it("'job run' as a noun in a status tool is not execution (domino check status)", () => {
    expect(MCP001.check(ctxFor([dominoCheckStatus]))).toHaveLength(0);
  });

  it("a real command runner is still flagged, on the param that carries the command", () => {
    const f = MCP001.check(ctxFor([dominoRunJob]));
    expect(f).toHaveLength(1);
    // Was `run_domino_job.user_name` — the first param, not the executed one.
    expect(f[0]!.location).toBe("run_domino_job.run_command");
  });

  it("never blames an unrelated param: no command-like param means no param is named", () => {
    const t = tool("exec_task", "Execute the configured task.", [param("user_name"), param("project")]);
    const f = MCP001.check(ctxFor([t]));
    expect(f).toHaveLength(1);
    expect(f[0]!.location).toBe("exec_task");
    expect(f[0]!.detail).not.toContain("user_name");
  });
});

// --- MCP004 / classify: URLs in prose are documentation, not capability ----------

describe("MCP004 field regressions", () => {
  it("a documentation link in a description does not make a tool an external sink", () => {
    expect(classifyTool(mongoLocalCreate).sink).toBe(false);
  });

  it("no exfil path from a doc link: aggregate + local-deployment is not a pairing", () => {
    // `find` is a genuine data source ("query"); the only candidate sink is the doc link.
    expect(classifyTool(mongoFind).source).toBe(true);
    expect(MCP004.check(ctxFor([mongoFind, mongoLocalCreate]))).toHaveLength(0);
  });

  it("names the strongest private-data source in the chain, not the first source found", () => {
    const f = MCP004.check(ctxFor([dominoCheckStatus, dominoSyncLocal, dominoOpenBrowser]));
    expect(f).toHaveLength(1);
    // Was `check_domino_job_run_status + open_web_browser`. The tool that reads an
    // arbitrary local path is the leg that makes this an exfiltration path.
    expect(f[0]!.location).toBe("tools[sync_local_file_to_domino+open_web_browser]");
  });

  it("in the real server's tool order, names the tool whose PATH PARAM is local", () => {
    // upload_file_to_domino_project's prose says "sync local file changes", but its
    // file_path is the destination inside Domino. sync_local_file_to_domino takes
    // local_file_path — the parameter that actually reaches the operator's disk.
    const f = MCP004.check(
      ctxFor([dominoListFiles, dominoUpload, dominoOpenBrowser, dominoSyncLocal]),
    );
    expect(f[0]!.location).toBe("tools[sync_local_file_to_domino+open_web_browser]");
  });

  it("prefers a LOCAL-file reader over a remote-project lister when both take a path", () => {
    // Real server order: the remote lister is discovered first and ties on "path + file".
    const f = MCP004.check(ctxFor([dominoListFiles, dominoSyncLocal, dominoOpenBrowser]));
    expect(f[0]!.location).toBe("tools[sync_local_file_to_domino+open_web_browser]");
  });
});

// --- MCP002: a param named for file CONTENT is not a path --------------------------

describe("MCP002 field regressions", () => {
  it("file_content carries the file's bytes, not a path; file_path still counts", () => {
    const locs = MCP002.check(ctxFor([dominoUpload])).map((f) => f.location);
    expect(locs).toContain("upload_file_to_domino_project.file_path");
    expect(locs).not.toContain("upload_file_to_domino_project.file_content");
  });

  it("the content exclusion must not hide real paths like data_dir or data_path", () => {
    const t = tool("load", "Load a dataset.", [param("data_dir"), param("data_path"), param("text_file")]);
    const locs = MCP002.check(ctxFor([t])).map((f) => f.location);
    expect(locs).toEqual(["load.data_dir", "load.data_path", "load.text_file"]);
  });
});

// --- MCP007: confirmation affordances and declared read-only tools ---------------

describe("MCP007 field regressions", () => {
  it("a force_overwrite flag (default off) is a confirmation affordance", () => {
    expect(MCP007.check(ctxFor([dominoSmartSync]))).toHaveLength(0);
  });

  it("a tool that declares readOnlyHint is not flagged as mutating", () => {
    const t: Tool = {
      ...tool("preview_update", "Preview which documents an update would change, without applying it.", [
        param("collection"),
      ]),
      annotations: { readOnlyHint: true },
    };
    expect(MCP007.check(ctxFor([t]))).toHaveLength(0);
  });

  it("a declared destructiveHint makes a mutating tool high confidence", () => {
    // mongodb update-many: only "update" words, but the server declares it destructive.
    const t: Tool = {
      ...tool("update-many", "Updates all documents that match the specified filter for a collection.", [
        param("filter", { type: "object" }),
        param("update", { type: "object" }),
      ]),
      annotations: { readOnlyHint: false, destructiveHint: true },
    };
    const f = MCP007.check(ctxFor([t]));
    expect(f).toHaveLength(1);
    expect(f[0]!.confidence).toBe("high");
  });

  it("says that runtime confirmation (elicitation) is invisible to static introspection", () => {
    // mongodb-mcp-server gates drop-database behind elicitation via a runtime
    // confirmationRequiredTools list — nothing in the tool schema shows it.
    const drop = tool("drop-database", "Removes the specified database, deleting the associated data files", [
      param("connectionId"),
      param("database"),
    ]);
    const f = MCP007.check(ctxFor([drop]));
    expect(f).toHaveLength(1);
    expect(f[0]!.detail).toMatch(/runtime|elicitation/i);
  });
});

// --- MCP008: whole-word matching ---------------------------------------------------

describe("MCP008 field regressions", () => {
  it("'maxRequestPayloadBytes' does not contain the word 'request'", () => {
    expect(MCP008.check(ctxFor([mongoInsertMany]))).toHaveLength(0);
  });
});

// --- MCP010: description-only inference is not high confidence -------------------

describe("MCP010 field regressions", () => {
  it("a config resource flagged from its description alone is medium confidence, and says so", () => {
    const r = resource("config://config", {
      name: "config",
      description:
        "Server configuration, supplied by the user either as environment variables or as startup arguments",
    });
    const f = MCP010.check(ctxFor([], [r]));
    expect(f).toHaveLength(1);
    expect(f[0]!.confidence).toBe("medium");
    expect(f[0]!.detail).toMatch(/not read|contents/i);
  });
});
