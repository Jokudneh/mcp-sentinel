# Changelog

All notable changes to **MCP Sentinel** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-11-27

### Added
- Sliding-window canonicalized call-loop circuit breaker (`CallLoopBreaker`, `runtime.call_loop_detected`) with configurable `loopProtection` thresholds.
- Declarative `customRules` policy engine (`contains`, `prefix`, and `regex` matchers scoped by direction and `toolPattern`) with built-in ReDoS safety validation (`assertSafeRegexPattern`).
- SARIF 2.1.0 (`--format sarif`) and Markdown (`--format markdown`) trace report exporters for `mcp-sentinel inspect`.
- Adversarial path obfuscation guards for null-byte injection (`path.null_byte`), URL-encoded traversals (`%2e%2e%2f`), and mixed Windows/POSIX slash escapes.
- Seeded PRNG chunk-boundary framing fuzz suite, 64 KB linear-time ReDoS regression tests, compiled CLI integration tests (`test/cli.test.ts`), and reproducible microbenchmarks (`npm run bench`).
- Compact hand-crafted vector banner (`assets/banner.svg`), matching emblem (`assets/logo.svg`), Dependabot, CodeQL, Dependency Review, `Makefile`, `.nvmrc`, and `sentinel.config.example.json`.

## [0.1.0] - 2026-11-27

### Added
- Streaming dual-mode JSON-RPC 2.0 framer (`ndjson` and LSP `Content-Length`) with UTF-8 byte safety and buffer-size limits.
- Stdio MCP proxy (`runStdioProxy`) with `shell: false` spawning, bounded in-flight request correlation, `-32001` policy block responses, response secret redaction, and graceful signal shutdown.
- Policy engine (`evaluateToolCall`, `evaluateToolResponse`) covering wildcard tool allow/deny lists, destructive shell/SQL commands, sensitive path & traversal checks, `allowedRoots` boundaries, linear-time secret detection with Shannon entropy verification, and indirect prompt-injection rules.
- Sanitized append-only JSONL flight recorder (`JsonlTracer`) and terminal trace summarizer (`readTraceFile`, `summarizeTrace`).
- Zero-dependency CLI (`proxy`, `inspect`, `check`, `init`) with TTY / `NO_COLOR`-aware formatting.
- Unit and real child-process end-to-end test suite using `node:test`, plus GitHub Actions matrix CI (Node 20, 22, 24).
