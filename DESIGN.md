# DESIGN.md — mcp-audit

> Build-ready design package. An expert coding agent should be able to build the v1 MVP from this
> document alone. Read top-to-bottom before writing code.
>
> Author: Keith Lindsay (GitHub: [keithalindsay](https://github.com/keithalindsay)) · License: MIT © 2026 Keith Lindsay

---

## 1. What it is (one-liner) + the problem it solves

**mcp-audit** is a security linter for **Model Context Protocol (MCP) servers**. Point it at a server and
it connects as an MCP client, enumerates the tools/resources/prompts the server actually exposes, *and*
parses the server's config, then reports ranked security findings — the footguns that let an AI agent be
turned into an exfiltration or code-execution vector.

**The problem.** MCP lets agents call tools, but every tool a server exposes is attack surface, and the
risks are non-obvious because they're **emergent**: a `read_file` tool and an `http_get` tool are each
fine alone, but together they're a data-exfiltration path (the "lethal trifecta": access to private data
+ exposure to untrusted content + the ability to send data out). Teams wire up MCP servers with
free-form string arguments, unrestricted filesystem/network reach, secrets in config, and tool
descriptions an LLM can be socially-engineered through — and there's no `eslint` for any of it.
`mcp-audit` is that linter: **run it before you connect a server to your agent.**

---

## 2. Who it's for and why it's useful

- **Anyone wiring an MCP server into an agent** (Claude Desktop/Code, Cursor, custom) who wants to know
  what they're exposing before they trust it.
- **MCP server authors** who want a CI gate that flags insecure tool designs on every change.
- **AppSec / platform teams** evaluating third-party MCP servers they didn't write.

Why it's useful:

- **Protocol-level, language-agnostic.** It audits what a server *actually exposes over MCP*, not its
  source, so it works on any server (Python, TS, Go, a binary) with no access to the code.
- **Catches emergent risk.** It doesn't just flag individual dangerous tools; it does **combination
  (taint) analysis** — a data *source* plus an external *sink* is flagged as an exfiltration path even
  when neither tool is dangerous alone.
- **Config-aware.** It parses `claude_desktop_config.json` / `mcp.json` to find secrets in env/args and
  over-broad server definitions.
- **Runs in 60 seconds, zero setup.** Ships a deliberately-vulnerable demo MCP server; `mcp-audit demo`
  audits it and prints a rich report offline, no API key.
- **CI-ready.** Ranked findings, `--json`, and exit codes so it can gate a build.

---

## 3. Scope: v1 MVP vs out-of-scope

### v1 MVP (must-have)

1. **MCP client connector**: spawn a target server over **stdio**, run the MCP handshake, and call
   `tools/list`, `resources/list`, `prompts/list` to build a `ServerModel` (§8). Uses the official MCP
   TypeScript SDK.
2. **Config scanner**: parse `claude_desktop_config.json` / `mcp.json`; extract server definitions
   (command/args/env); scan env+args for secrets; feed discovered servers to the connector.
3. **Rule engine**: a catalog of deterministic checks (§7.3) over the `ServerModel` + parsed config,
   each producing zero or more `Finding`s with a severity, category, rationale, and remediation.
4. **Tool classification + taint/combination analysis**: classify each tool as `source` (reads private/
   local data), `sink` (writes/sends externally), and/or `executor` (runs shell/code/queries), then flag
   dangerous **combinations** (lethal-trifecta exfil paths) — not just individual tools.
5. **Reporter**: ranked terminal report (severity-sorted, colored) + `--json`; a summary line with
   per-severity counts; CI-friendly exit codes.
6. **`audit`, `demo`, `rules` commands** (§7.1). `demo` audits a bundled vulnerable server; `rules`
   lists the check catalog.
7. **Bundled vulnerable demo server** (`examples/vulnerable-server/`): a tiny MCP server intentionally
   exposing `run_shell`, `read_file` (unrestricted path), `http_fetch` (arbitrary URL), a secret in env,
   and a resource exposing the environment — so the demo/tests find a rich set of issues offline.
8. **Optional LLM analyzer** (`--llm`): sends tool schemas/descriptions to Anthropic Claude to reason
   about subtle risks the heuristics miss. **Off by default; needs a key.** Deterministic rules are the
   default so the tool runs offline.
9. **Config file** (`mcp-audit.config.yaml`, optional) for severity thresholds, disabled rules, and
   secret patterns. **README** with quickstart + `## Screenshot`. **Tests** (vitest).

### Explicitly OUT of scope for v1

- Non-stdio transports (HTTP/SSE MCP servers). v1 audits stdio servers only. (Config scan still lists
  them.)
- Source-code static analysis of the server implementation (we audit the live protocol surface + config).
- Auto-fixing / rewriting servers. Findings include remediation *advice* only.
- Runtime/behavioral fuzzing, actually *invoking* tools, or sending real payloads to a server.
- A hosted service, telemetry, or any network call other than (a) the stdio child server and (b) the
  optional, explicitly-enabled LLM provider.
- Auth protocol verification (OAuth flows). v1 flags *missing* auth heuristically, not protocol
  conformance.

---

## 4. Tech stack + rationale

| Concern | Choice | Rationale |
|---|---|---|
| Language/runtime | **TypeScript on Node ≥ 20** (ESM) | `npx mcp-audit`-able; the official MCP SDK is first-class in TS; matches `prompt-regression`'s distribution story. |
| MCP client | **`@modelcontextprotocol/sdk`** | Official SDK; `Client` + `StdioClientTransport` do the handshake and `*/list` calls. |
| CLI | **commander** | Small, ubiquitous subcommand parsing. |
| Schema/validation | **zod** | Validate config + normalize the SDK's tool/resource shapes; infer types. |
| Config parsing | **yaml** + built-in JSON | `mcp-audit.config.yaml` + JSON MCP configs. |
| Terminal styling | **picocolors** | Tiny, dependency-free color. |
| LLM (optional) | **@anthropic-ai/sdk** (optionalDependency, lazy) | Optional `--llm` deep analysis; not required to run. |
| Tests | **vitest** | Fast, TS-native. |
| Build | **tsup** | ESM + shebang bin in one command. |

> **Deterministic + offline by default.** The rule engine needs no network beyond spawning the target
> stdio server (and the demo server ships in-repo). The LLM pass is opt-in.

---

## 5. Architecture overview

```
              target: "node server.js"  OR  --config claude_desktop_config.json
                         │                              │
                         ▼                              ▼
              ┌────────────────────┐         ┌────────────────────┐
              │  Connector (MCP    │         │  Config Scanner     │
              │  client / stdio)   │         │  (parse + secrets)  │
              │  tools/resources/  │         │                     │
              │  prompts → model   │         └─────────┬──────────┘
              └─────────┬──────────┘                   │
                        │            ServerModel + ConfigModel
                        └───────────────┬───────────────┘
                                        ▼
                            ┌───────────────────────┐
                            │  Classifier            │  tag each tool:
                            │  source | sink |       │  source/sink/executor
                            │  executor              │
                            └───────────┬───────────┘
                                        ▼
                            ┌───────────────────────┐
                            │  Rule Engine           │  run catalog (§7.3)
                            │  per-tool + combination│  incl. taint combos
                            │  + config rules        │  (+ optional LLM pass)
                            └───────────┬───────────┘
                                        ▼  Finding[]
                            ┌───────────────────────┐
                            │  Reporter (terminal +  │  severity-ranked
                            │  --json) + exit code   │
                            └───────────────────────┘
```

**Flow:** resolve target(s) (a single `--server` command, or every server in a `--config`) → for each,
connect and introspect into a `ServerModel`, parse the matching config into a `ConfigModel` → classify
tools → run the rule catalog (per-tool, combination/taint, and config rules; optional LLM pass) → collect
`Finding`s → reporter ranks + prints + returns an exit code.

---

## 6. Key components / modules

- `cli.ts` — commander entrypoint; wires `audit`/`demo`/`rules`; global flags; exit codes.
- `connector.ts` — `introspect(server: ServerSpec): Promise<ServerModel>` using the MCP SDK `Client` +
  `StdioClientTransport`; bounded startup timeout; normalizes tools/resources/prompts via zod.
- `config-scan.ts` — `loadMcpConfig(path): ConfigModel`; extract servers; `scanSecrets(config)` over
  env values + args using the secret-pattern set (§8.4).
- `classify.ts` — `classifyTool(tool): ToolTags` (`source`/`sink`/`executor` booleans + reasons) from
  name/description/input-schema heuristics (§8.3).
- `rules/` — one file per rule *group*; each rule: `{ id, title, severity, category, check(ctx) => Finding[] }`.
  - `rules/tools.ts` — per-tool checks (exec, fs, network, unvalidated input, destructive, overbroad desc).
  - `rules/combinations.ts` — taint/lethal-trifecta combination checks across tools.
  - `rules/config.ts` — secrets-in-config, over-broad server definition, sensitive resource exposure.
  - `rules/index.ts` — the ordered `ALL_RULES` registry + `runRules(ctx, opts)`.
- `llm.ts` — optional `llmAnalyze(model): Promise<Finding[]>` (Anthropic; lazy import; model id from env).
- `reporter.ts` — `renderReport(report, {color}) : string`, `toJson(report)`, severity ranking + counts.
- `schemas.ts` — zod schemas + inferred types for `ServerModel`, `Tool`, `ConfigModel`, `Finding`,
  `AuditReport`, `Config`.
- `audit.ts` — `runAudit(opts): Promise<AuditReport>` orchestrator (connector + config-scan + rules).
- `config.ts` — load `mcp-audit.config.yaml` (thresholds, disabled rules, extra secret patterns).
- `examples/vulnerable-server/` — the bundled insecure demo MCP server + its `mcp.json`.

---

## 7. Interface: CLI / config

Binary: **`mcp-audit`**.

### 7.1 Commands

```
mcp-audit audit  [--server "<cmd> <args...>"] [--config <path>] [--cwd <dir>]
                 [--ci] [--json [<path>]] [--min-severity <level>] [--llm]
                 [--timeout <ms>] [--no-color]
mcp-audit demo   [--json] [--no-color]        # audit the bundled vulnerable server
mcp-audit rules  [--json]                      # list the check catalog (id, severity, title)
```

- `--server "<cmd>"`  Launch and introspect this stdio server, e.g. `--server "node dist/server.js"` or
  `--server "python -m my_server"`. Mutually inclusive-or with `--config`.
- `--config <path>`  A `claude_desktop_config.json` / `mcp.json`; audit **every** `mcpServers` entry
  (introspect each + scan the config). 
- `--min-severity <critical|high|medium|low|info>`  Only report findings at/above this level (default
  `low`).
- `--ci`  Non-interactive; exit non-zero if any finding at/above the **fail threshold** (config
  `failOn`, default `high`). 
- `--json [path]`  Emit the machine-readable `AuditReport` to stdout or `path`.
- `--llm`  Run the optional Anthropic deep-analysis pass (requires `ANTHROPIC_API_KEY`; model id from
  `MCP_AUDIT_MODEL`, default `claude-haiku-4-5`).
- **Exit codes:** `0` = no findings at/above `failOn`; `1` = findings at/above `failOn`; `2` =
  usage/connection/config error.

### 7.2 Example

```bash
npx mcp-audit demo                                  # audit bundled vulnerable server (offline)
npx mcp-audit audit --server "node dist/server.js"  # audit your server
npx mcp-audit audit --config ~/.config/Claude/claude_desktop_config.json --ci
ANTHROPIC_API_KEY=sk-... npx mcp-audit audit --server "node dist/server.js" --llm
```

### 7.3 The check catalog (v1)

| id | severity | category | flags |
|---|---|---|---|
| `MCP001` | critical | exec | A tool exposes arbitrary **command/shell/code** execution. |
| `MCP002` | high | filesystem | A tool takes a **free-form path** with no root/allowlist restriction. |
| `MCP003` | high | network | A tool fetches an **arbitrary URL/host** (SSRF / exfil sink). |
| `MCP004` | critical | exfiltration | **Combination:** a data *source* + an external *sink* → lethal-trifecta exfil path. |
| `MCP005` | critical | secrets | **Secret** (API key/token) present in config `env`/`args`. |
| `MCP006` | medium | validation | Tool input is an unconstrained **string** (no `enum`/`pattern`/`format`) where the name implies a path/command/url. |
| `MCP007` | high | destructive | A **destructive** tool (delete/drop/write/overwrite) with no dry-run/confirmation affordance. |
| `MCP008` | medium | injection | A tool returns **untrusted external content** that flows back to the model (injection surface). |
| `MCP009` | low | description | **Over-broad tool description** inviting unconstrained action ("do anything", "run any…"). |
| `MCP010` | high | secrets | A **resource** exposes sensitive data (env, `.env`, home dir, credentials, `id_rsa`). |
| `MCP011` | info | posture | Server exposes **many** high-capability tools with no scoping — aggregate risk note. |

Each rule emits `Finding{ ruleId, severity, category, title, detail, location, remediation, confidence }`.
Rules are heuristic; `confidence` (`high|medium|low`) is reported so users can triage. `--llm` can add
findings in category `llm` and raise/lower confidence on heuristic ones.

### 7.4 Config file (`mcp-audit.config.yaml`, optional)

```yaml
failOn: high                 # min severity that makes --ci exit non-zero
minSeverity: low             # min severity reported at all
disabledRules: []            # e.g. ["MCP009"]
secretPatterns:              # extra regexes appended to the built-in set
  - "myco_[A-Za-z0-9]{20,}"
timeoutMs: 10000             # server startup/introspection timeout
```

---

## 8. Data models / schemas (zod-backed)

### 8.1 ServerModel (from the connector)

```ts
type ToolParam = { name: string; type: string; required: boolean;
                   constrained: boolean;   // has enum/pattern/format/min/max
                   raw: unknown };
type Tool = { name: string; description: string;
              params: ToolParam[]; rawInputSchema: unknown };
type Resource = { uri: string; name?: string; description?: string; mimeType?: string };
type Prompt   = { name: string; description?: string };
type ServerModel = {
  server: { name: string; version?: string };
  spec: ServerSpec;                         // how it was launched
  tools: Tool[]; resources: Resource[]; prompts: Prompt[];
};
type ServerSpec = { command: string; args: string[]; env?: Record<string,string>; cwd?: string; label: string };
```

### 8.2 ConfigModel (from a claude_desktop_config.json / mcp.json)

```ts
type ConfigServer = { name: string; command: string; args: string[]; env: Record<string,string> };
type ConfigModel  = { path: string; servers: ConfigServer[] };
```

### 8.3 Classification (heuristic, deterministic)

`classifyTool(tool)` returns `{ source: boolean; sink: boolean; executor: boolean; reasons: string[] }`:
- **executor** — name/description matches `exec|run|shell|command|eval|spawn|sql|query|script`.
- **source** — reads local/private data: `read|get|list|load|file|fs|cat|fetch_file|db|query|search|env|secret`.
- **sink** — sends/writes externally: `http|fetch|request|post|url|webhook|upload|send|email|write_url|publish|dns`.
  (A tool can be several at once. `http_fetch` is both source-of-untrusted-content **and** sink.)
Classification reads tool **name**, **description**, and **param names/types**. Every tag records a
`reason` string for explainability. Heuristics are intentionally conservative and reported with
`confidence`.

### 8.4 Secret patterns (built-in set for MCP005/config scan)

Regexes for common credentials: `sk-[A-Za-z0-9]{20,}` (OpenAI/Anthropic-style), `ghp_[A-Za-z0-9]{36}`
(GitHub), `AKIA[0-9A-Z]{16}` (AWS), `xox[baprs]-…` (Slack), `-----BEGIN [A-Z ]*PRIVATE KEY-----`,
generic `(?i)(api[_-]?key|token|secret|password)\s*[:=]\s*["']?[A-Za-z0-9_\-]{16,}`, plus a
high-entropy fallback for long random-looking env values. Extendable via config `secretPatterns`.

### 8.5 Finding + AuditReport

```ts
type Severity = "critical" | "high" | "medium" | "low" | "info";
type Finding = {
  ruleId: string; severity: Severity; category: string;
  title: string; detail: string;
  location: string;              // e.g. tool name, "config:env.API_KEY", "tools[read_file+http_fetch]"
  remediation: string;
  confidence: "high" | "medium" | "low";
};
type AuditReport = {
  schemaVersion: 1;
  target: string;                // server label or config path
  startedAt: string; finishedAt: string;
  serverSummary: { name: string; tools: number; resources: number; prompts: number } | null;
  findings: Finding[];           // severity-ranked
  totals: Record<Severity, number> & { total: number };
  failOn: Severity; exitCode: 0 | 1;
};
```

---

## 9. End-to-end example (against the bundled vulnerable server)

```
$ npx mcp-audit demo

mcp-audit · target=vulnerable-demo  (3 tools, 1 resource, 0 prompts)

  CRITICAL  MCP001  exec         run_shell executes arbitrary shell commands
      → tool "run_shell" param "command" is passed to a shell. Remove it or replace with a
        fixed allowlist of non-shell operations.
  CRITICAL  MCP004  exfiltration read_file + http_fetch form a data-exfiltration path
      → "read_file" (source: reads local files) + "http_fetch" (sink: arbitrary URL) let an
        injected instruction read a secret and POST it out. Constrain paths AND destination hosts.
  CRITICAL  MCP005  secrets      API token in config env
      → config:env.API_TOKEN matches a secret pattern. Move it out of the committed config.
  HIGH      MCP002  filesystem   read_file accepts an unrestricted path
  HIGH      MCP003  network      http_fetch reaches arbitrary URLs
  HIGH      MCP010  secrets      resource env://all exposes process environment
  MEDIUM    MCP006  validation   run_shell.command is an unconstrained string

Summary: 7 findings — 3 critical · 3 high · 1 medium · 0 low · 0 info
Fail threshold: high → Exit: 1
```

`--json` emits the `AuditReport` from §8.5. `mcp-audit rules` lists the whole catalog.

---

## 10. File & directory structure

```
mcp-audit/
├── DESIGN.md
├── README.md
├── LICENSE
├── .gitignore
├── package.json
├── tsconfig.json
├── tsup.config.ts
├── vitest.config.ts
├── mcp-audit.config.yaml.example
├── src/
│   ├── cli.ts
│   ├── audit.ts
│   ├── connector.ts
│   ├── config-scan.ts
│   ├── classify.ts
│   ├── reporter.ts
│   ├── schemas.ts
│   ├── config.ts
│   ├── llm.ts
│   └── rules/
│       ├── index.ts
│       ├── tools.ts
│       ├── combinations.ts
│       └── config.ts
├── examples/
│   └── vulnerable-server/
│       ├── server.ts          # intentionally-insecure MCP server (bundled, for demo/tests)
│       └── mcp.json           # a config with a planted secret, for the config-scan demo
├── docs/
│   └── screenshot-placeholder.png
└── test/
    ├── classify.test.ts
    ├── rules.tools.test.ts
    ├── rules.combinations.test.ts
    ├── config-scan.test.ts
    ├── reporter.test.ts
    └── e2e.demo.test.ts        # spawn vulnerable-server, audit, assert findings + exit code
```

---

## 11. Build plan (ordered checklist)

> Complete in order; each step leaves the repo working and testable. TDD where a test is named.

1. **Bootstrap.** `package.json` (name `mcp-audit`, bin `mcp-audit`→`dist/cli.js`, ESM, deps:
   `@modelcontextprotocol/sdk`, `commander`, `zod`, `yaml`, `picocolors`; optionalDeps
   `@anthropic-ai/sdk`; dev: `tsup`, `tsx`, `typescript`, `vitest`), `tsconfig.json`,
   `tsup.config.ts` (bundle; `external: ["@anthropic-ai/sdk"]`; shebang banner), `vitest.config.ts`,
   MIT `LICENSE`, `.gitignore`. Confirm `npm run build`/`npm test` (empty) pass.
2. **schemas.ts.** zod schemas + types for §8 (`Tool`, `ServerModel`, `ConfigModel`, `Finding`,
   `AuditReport`, `Config`, `Severity`). Include `SEVERITY_ORDER` + a comparator. Unit-test parse.
3. **classify.ts.** `classifyTool` per §8.3 with reasons. Test: `run_shell`→executor;
   `read_file`→source; `http_fetch`→source+sink; a benign `echo`→none.
4. **rules/tools.ts.** MCP001/002/003/006/007/009 per §7.3 over a single tool. Each returns `Finding[]`.
   Test each rule against synthetic tools (positive + negative cases).
5. **rules/combinations.ts.** MCP004 (source+sink present ⇒ exfil), MCP011 (aggregate high-capability
   count). Test with a source-only model (no MCP004) vs source+sink (MCP004).
6. **rules/config.ts.** MCP005 (secret patterns over env/args), MCP010 (sensitive resource uris). Test
   with a planted secret + a benign config.
7. **rules/index.ts.** `ALL_RULES` ordered registry; `runRules(ctx, {disabled, minSeverity})`; sort
   findings by severity then ruleId. Test disabled-rule + min-severity filtering.
8. **config-scan.ts.** `loadMcpConfig` (parse `mcpServers`), `scanSecrets`. Test on `examples/.../mcp.json`.
9. **connector.ts.** `introspect(spec)` via MCP SDK `Client`+`StdioClientTransport`: connect, `tools/
   list`, `resources/list`, `prompts/list`, normalize to `ServerModel`; bounded timeout; always close
   the transport. (Tested via the e2e in step 14, not a unit mock.)
10. **examples/vulnerable-server/server.ts.** A minimal MCP server (SDK `McpServer`) exposing
    `run_shell`, `read_file` (path param), `http_fetch` (url param), and a resource `env://all`; plus
    `mcp.json` with a planted `API_TOKEN`. This is the offline fixture for demo + e2e.
11. **audit.ts.** `runAudit(opts)`: resolve targets (server spec and/or config servers) → introspect →
    classify → runRules (+ config rules) → assemble `AuditReport` with totals + exitCode (from `failOn`).
12. **reporter.ts.** Severity-ranked colored terminal report (§9) + `toJson`; summary + `Exit:` line.
    Test plain (no-color) output contains rule ids, severities, and the exit line.
13. **config.ts + cli.ts.** Load `mcp-audit.config.yaml`; wire `audit`/`demo`/`rules` with the §7.1 flags
    and exit codes; `demo` targets the bundled server; `--llm` guarded by key.
14. **e2e.demo.test.ts.** Build the vulnerable server, run `runAudit` against it in-process, assert:
    MCP001, MCP004, MCP005, MCP002, MCP003, MCP010 all present and `exitCode === 1`. This encodes the
    core value and guards regressions.
15. **llm.ts.** Optional Anthropic pass (lazy import; model id from env; single bounded retry). Unit-test
    with the SDK **mocked**; never called in CI.
16. **README + docs.** Pitch (security-first), quickstart (`demo` in 60s), the catalog table, `--config`
    usage, CI snippet + exit codes, `## Screenshot` placeholder, clean-room note, MIT.
17. **Publish.** Create `github.com/keithalindsay/mcp-audit` (public) and push. *(Confirm the active `gh`
    account targets `keithalindsay` first.)*

---

## 12. Testing approach

- **Unit:** `classify` (each tag + reasons); every rule in `rules/*` (positive/negative synthetic
  inputs); `config-scan` secret detection (true/false positives); `reporter` output shape; severity
  sort/threshold logic.
- **Integration (offline, deterministic):** `e2e.demo.test.ts` spawns the bundled vulnerable server over
  real stdio MCP, runs the full audit, and asserts the expected finding set + exit code. No network, no
  key — the whole pipeline (connector→classify→rules→report) is exercised against a real MCP handshake.
- **LLM path:** `llm.ts` tested with the Anthropic SDK mocked; never invoked in CI.
- Run: `npm run build && npm test`. Target < 10s (server spawn dominates).

---

## 13. Constraints & non-goals

- **IP clean-room note (required).** Original, clean-room, **generic** security tooling authored by Keith
  Lindsay. It does **not** reference, reproduce, or depend on any employer's (including Kroll's or
  Aerospike's) source, proprietary detections, internal data, or product specifics; all checks derive
  from public, general security concepts (the MCP spec, the "lethal trifecta"/OWASP-LLM-style risk
  categories, common credential formats). The bundled vulnerable server is synthetic. MIT © 2026 Keith
  Lindsay.
- **No hidden network.** Only egress is (a) the stdio child server being audited and (b) the optional,
  explicitly-enabled LLM provider. No telemetry.
- **Read-only / non-destructive.** mcp-audit **lists** capabilities; it never *invokes* a target's tools
  or sends them payloads. Auditing a server cannot trigger its side effects.
- **Secrets never leave.** Detected secrets are reported by **location and pattern name only** — the tool
  never prints or transmits the secret value.
- **Heuristic honesty.** Rules are heuristics with reported `confidence`; the tool is a linter (surfaces
  risk to a human), not a proof of (in)security. Non-goals: HTTP/SSE transports, source static analysis,
  auto-fix, behavioral fuzzing, auth-protocol conformance.

---

## 14. README outline + positioning

**Positioning (GitHub one-liner):** *"A security linter for MCP servers — connect, introspect, and flag
the tool designs that turn an AI agent into an exfiltration or code-execution vector. Runs in 60s on a
bundled vulnerable server, zero setup."*

**Lead with:** (1) one sentence on why MCP servers are unaudited attack surface, (2) the `mcp-audit demo`
screenshot showing the ranked findings on the vulnerable server (esp. the **MCP004 combination** finding
— the "aha"), (3) `audit --server`/`--config` usage, (4) the CI snippet + exit codes. Emphasize:
protocol-level (works on any server), **combination/taint analysis** (the differentiator), offline/no-key
default, secrets-safe, MIT.

**Section order:** 1) Title + one-liner + badges. 2) `## Screenshot` (demo findings). 3) Why (MCP = new
attack surface; the lethal trifecta in 3 sentences). 4) Quickstart (`npx mcp-audit demo`). 5) Audit your
server (`--server`) / your config (`--config`). 6) The checks (the §7.3 catalog table). 7) CI (exit codes
+ GitHub Actions step). 8) How it works (introspect + config scan + classify + combination analysis; link
DESIGN.md). 9) Optional LLM pass. 10) Clean-room note. 11) License.
