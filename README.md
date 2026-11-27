# mcp-sentinel

A minimal, zero-dependency **stdio firewall and JSONL flight recorder** for Model Context Protocol (MCP) servers.

Wrap any local MCP server command to inspect `tools/call` requests and responses in real time, block dangerous tool arguments or prompt injections before they execute, redact leaked secrets, and record auditable JSONL traces.

## Features

- **Zero runtime dependencies** — pure Node.js (`>= 20`) + strict TypeScript.
- **Dual stdio wire framing** — supports both newline-delimited JSON (`ndjson`) and LSP-style `Content-Length` framing without polluting `stdout`.
- **Outbound `tools/call` inspection**:
  - Tool allowlist / denylist with wildcard matching (`db_*`, `*_delete`).
  - Destructive shell & SQL detection (`rm -rf`, `curl | sh`, PowerShell `-EncodedCommand`, `DROP TABLE`, etc.).
  - Sensitive path & traversal blocking (`.env`, `.ssh/id_*`, `.aws/credentials`, `..` traversal, and configurable `allowedRoots`).
  - Outbound secret leak detection (AWS, GitHub, Anthropic, OpenAI, Google, Slack, Stripe, PEM keys, and Shannon-entropy-verified Bearer/credential assignments).
- **Inbound tool response protection**:
  - Indirect prompt-injection detection (instruction overrides, system-prompt exfiltration, spoofed role delimiters, markdown image exfiltration).
  - Automatic secret redaction before responses reach the agent or trace logs.
- **Flight recorder & CLI inspector** — writes sanitized JSONL traces and summarizes tool latency, blocked calls, and triggered rules right in the terminal.

## Quick Start

```bash
npm install
npm run build
npm test
```

### 1. Generate a policy file

```bash
node dist/cli.js init
```

### 2. Wrap any stdio MCP server

```bash
node dist/cli.js proxy \
  --mode enforce \
  --trace sentinel.trace.jsonl \
  --allow-root ./workspace \
  -- npx -y @modelcontextprotocol/server-filesystem ./workspace
```

In `enforce` mode, blocked `tools/call` requests never reach the child MCP server; `mcp-sentinel` immediately returns a spec-compliant JSON-RPC 2.0 error (`code: -32001`) explaining which policy rule tripped. Live telemetry is written strictly to `stderr` so the `stdout` JSON-RPC wire stream stays clean.

### 3. Dry-run a payload against your policy

```bash
node dist/cli.js check payload.json --config sentinel.config.json
```

### 4. Inspect a recorded session trace

```bash
node dist/cli.js inspect sentinel.trace.jsonl
node dist/cli.js inspect sentinel.trace.jsonl --only-findings --severity high
```

## Architecture

```text
src/
├── protocol/
│   ├── jsonrpc.ts     # Strict JSON-RPC 2.0 & MCP types + error response builder
│   └── framing.ts     # Streaming NDJSON & Content-Length parser/serializer
├── policy/
│   ├── types.ts       # Config, severity ranking, and rule finding types
│   ├── config.ts      # Policy defaults & runtime schema validation
│   ├── secrets.ts     # Linear-time secret patterns, Shannon entropy, & deep redaction
│   └── evaluator.ts   # Request/response security rules & path boundary checks
├── runtime/
│   ├── tracer.ts      # Sanitized append-only JSONL recorder & trace summarizer
│   └── proxy.ts       # Stdio child-process proxy with request correlation & cleanup
└── cli/
    ├── format.ts      # TTY/NO_COLOR-aware terminal output
    └── commands.ts    # proxy, inspect, check, and init subcommands
```
