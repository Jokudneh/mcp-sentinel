# Security Policy

## Supported Versions

| Version | Supported |
| --- | --- |
| `0.2.x` | ✅ Supported |
| `0.1.x` | ⚠️ Upgrade to `0.2.x` |

---

## Reporting a Vulnerability

If you discover a security vulnerability in **MCP Sentinel** — such as:

- A firewall bypass allowing a blocked `tools/call` to reach a wrapped child server
- A framing desynchronization or parser crash (e.g., `Content-Length` / `ndjson` smuggling)
- A ReDoS (catastrophic regex backtracking) payload in `src/policy/secrets.ts` or `src/policy/evaluator.ts`
- Secret leakage into JSONL trace files or `stderr` telemetry

**Please do not open a public GitHub issue.**

Instead, report it privately using **GitHub Security Advisories**:
1. Go to the repository's **Security** tab → **Advisories** → **Report a vulnerability**.
2. Include a minimal reproduction payload (e.g., a JSON-RPC message or `mcp-sentinel check` fixture), expected vs. actual behavior, and affected version.

We aim to acknowledge reports within **48 hours** and provide a coordinated fix or mitigation plan promptly.

---

## Scope & Security Model Notes

MCP Sentinel provides **defense-in-depth at the MCP stdio protocol boundary**. Note the following boundaries:

- **Deterministic pattern rules** catch common destructive commands, sensitive file paths, known token formats, and prompt-injection patterns, but heuristic rules cannot guarantee 100% detection of novel obfuscated payloads.
- For high-risk environments, pair MCP Sentinel with **OS-level sandboxing** (containers, least-privilege OS users, read-only filesystem mounts, and strict `allowedTools` allowlists).
