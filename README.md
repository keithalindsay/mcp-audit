# mcp-audit

**A security linter for MCP servers** — connect, introspect, and flag the tool designs
that turn an AI agent into an exfiltration or code-execution vector. Runs in 60 seconds
on a bundled vulnerable server, zero setup, no API key.

![MIT License](https://img.shields.io/badge/license-MIT-blue) ![Node >= 20](https://img.shields.io/badge/node-%3E%3D20-brightgreen) ![offline by default](https://img.shields.io/badge/offline-by%20default-success)

---

## Screenshot

![mcp-audit demo output](docs/screenshot-placeholder.png)

```text
$ npx @keithalindsay/mcp-audit demo

mcp-audit · target=vulnerable-demo  (3 tools, 1 resource, 0 prompts)

  CRITICAL MCP001  exec         run_shell executes arbitrary shell/code
      location: run_shell.command
      → tool "run_shell" param "command" is passed to a shell/interpreter …

  CRITICAL MCP004  exfiltration read_file + http_fetch form a data-exfiltration path
      location: tools[read_file+http_fetch]
      → "read_file" reads local/private data and "http_fetch" sends data to an external
        destination. Together they are a lethal-trifecta exfiltration path: an injected
        instruction can read a secret with the first tool and POST it out with the second
        — neither tool is dangerous alone.

  CRITICAL MCP005  secrets      Secret in config:env.API_TOKEN
  HIGH     MCP002  filesystem   read_file accepts an unrestricted path
  HIGH     MCP003  network      http_fetch reaches arbitrary URLs
  HIGH     MCP010  secrets      resource env://all exposes sensitive data
  MEDIUM   MCP006  validation   run_shell.command is an unconstrained string
  MEDIUM   MCP008  injection    http_fetch returns untrusted external content

Summary: 8 findings — 3 critical · 3 high · 2 medium · 0 low · 0 info
Fail threshold: high → Exit: 1
```

The **MCP004** finding is the point: `read_file` and `http_fetch` are each unremarkable
on their own, but together they are a data-exfiltration path. mcp-audit does the
**combination (taint) analysis** so you see the emergent risk, not just the individual
tools.

---

## Why MCP servers are unaudited attack surface

MCP lets an agent call tools, and **every tool a server exposes is attack surface**. The
dangerous risks are *emergent*: the "lethal trifecta" is access to private data +
exposure to untrusted content + the ability to send data out. A `read_file` tool and an
`http_fetch` tool are each fine alone — but wired into the same agent they let an
injected instruction read a secret and POST it out. Teams stand up MCP servers with
free-form string arguments, unrestricted filesystem/network reach, secrets in config,
and tool descriptions an LLM can be socially-engineered through — and there's no `eslint`
for any of it. **mcp-audit is that linter: run it before you connect a server to your
agent.**

---

## Quickstart (60 seconds, offline)

```bash
npx @keithalindsay/mcp-audit demo        # audit the bundled deliberately-vulnerable server, no key
npx @keithalindsay/mcp-audit rules       # list the full check catalog
```

`demo` spawns a bundled insecure MCP server over real stdio MCP, introspects it, scans a
planted config secret, and prints ranked findings — entirely offline.

---

## Audit your own server / config

```bash
# Launch and introspect a single stdio server
npx @keithalindsay/mcp-audit audit --server "node dist/server.js"
npx @keithalindsay/mcp-audit audit --server "python -m my_server"

# Audit every server defined in a Claude Desktop / mcp.json config
npx @keithalindsay/mcp-audit audit --config ~/.config/Claude/claude_desktop_config.json

# Machine-readable output + a minimum severity filter
npx @keithalindsay/mcp-audit audit --server "node dist/server.js" --json report.json --min-severity high
```

- `--server "<cmd>"` — launch + introspect this stdio server.
- `--config <path>` — audit **every** `mcpServers` entry (introspect each + scan the config).
- `--min-severity <critical|high|medium|low|info>` — only report at/above this level.
- `--ci` — non-interactive; exit non-zero if any finding is at/above the fail threshold.
- `--json [path]` — emit the machine-readable `AuditReport`.
- `--timeout <ms>` — server startup/introspection timeout.
- `--llm` — run the optional Anthropic deep-analysis pass (see below).

> **Read-only.** mcp-audit only ever **lists** a server's capabilities (`tools/list`,
> `resources/list`, `prompts/list`). It never invokes a tool, reads a resource, or sends
> a payload, so auditing a server cannot trigger its side effects. Detected secrets are
> reported by **location and pattern name only** — the value is never printed or transmitted.

---

## The checks

| id | severity | category | flags |
|---|---|---|---|
| `MCP001` | critical | exec | A tool exposes arbitrary **command/shell/code** execution. |
| `MCP002` | high | filesystem | A tool takes a **free-form path** with no root/allowlist restriction. |
| `MCP003` | high | network | A tool fetches an **arbitrary URL/host** (SSRF / exfil sink). |
| `MCP004` | critical | exfiltration | **Combination:** a data *source* + an external *sink* → lethal-trifecta exfil path. |
| `MCP005` | critical | secrets | **Secret** (API key/token) present in config `env`/`args`. |
| `MCP006` | medium | validation | Tool input is an unconstrained **string** where the name implies a path/command/url. |
| `MCP007` | high | destructive | A **destructive** tool (delete/drop/write) with no dry-run/confirmation. |
| `MCP008` | medium | injection | A tool returns **untrusted external content** that flows back to the model. |
| `MCP009` | low | description | **Over-broad tool description** inviting unconstrained action. |
| `MCP010` | high | secrets | A **resource** exposes sensitive data (env, `.env`, home dir, `id_rsa`). |
| `MCP011` | info | posture | Server exposes **many** high-capability tools with no scoping. |

Every finding reports a `confidence` (`high`/`medium`/`low`) — these are heuristics that
surface risk to a human, not a proof of (in)security. Configure thresholds, disable
rules, or add secret patterns in an optional `mcp-audit.config.yaml`
(see `mcp-audit.config.yaml.example`).

---

## CI

mcp-audit is built to gate a build. Exit codes:

| code | meaning |
|---|---|
| `0` | no findings at/above the fail threshold (`failOn`, default `high`) |
| `1` | findings at/above the fail threshold |
| `2` | usage / connection / config error |

```yaml
# .github/workflows/mcp-audit.yml
name: mcp-audit
on: [push, pull_request]
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: 20 }
      - run: npm ci && npm run build
      - name: Audit the MCP server
        run: npx @keithalindsay/mcp-audit audit --server "node dist/server.js" --ci --min-severity high
```

---

## How it works

1. **Connect + introspect** — spawn the target over stdio using the official
   `@modelcontextprotocol/sdk`, run the MCP handshake, and list tools/resources/prompts
   into a normalized `ServerModel`.
2. **Config scan** — parse `claude_desktop_config.json` / `mcp.json`, extract server
   definitions, and scan `env`/`args` for secrets (by pattern, value withheld).
3. **Classify** — tag each tool as a `source` (reads private/local or untrusted data),
   `sink` (sends/writes externally), and/or `executor` (runs shell/code/queries), with a
   reason for each tag.
4. **Rule engine + combination analysis** — run the deterministic catalog, including the
   **taint/combination** pass that flags source + sink pairs as exfiltration paths — the
   emergent risk neither tool shows alone.

Protocol-level and language-agnostic: it audits what a server *actually exposes over
MCP*, so it works on any server (Python, TS, Go, a binary) with no access to the source.
Full design in [DESIGN.md](DESIGN.md).

---

## Optional LLM pass

`--llm` sends only tool names, descriptions, and parameter names/types (never secrets) to
Anthropic Claude to reason about subtler risks the heuristics miss. It is **off by
default** — the deterministic rules are the product and run fully offline.

```bash
ANTHROPIC_API_KEY=sk-... npx @keithalindsay/mcp-audit audit --server "node dist/server.js" --llm
```

The model id is read from `MCP_AUDIT_MODEL` (default `claude-haiku-4-5`). The
`@anthropic-ai/sdk` dependency is optional and imported lazily, so mcp-audit installs and
runs with zero LLM dependencies.

---

## Clean-room note

Original, clean-room, **generic** security tooling authored by Keith Lindsay. It does
**not** reference, reproduce, or depend on any employer's source, proprietary detections,
internal data, or product specifics; all checks derive from public, general security
concepts (the MCP spec, the "lethal trifecta" / OWASP-LLM-style risk categories, and
common credential formats). The bundled vulnerable server is synthetic and for
demonstration only. No telemetry; the only network egress is (a) the stdio child server
being audited and (b) the optional, explicitly-enabled LLM provider.

---

## License

MIT © 2026 Keith Lindsay
