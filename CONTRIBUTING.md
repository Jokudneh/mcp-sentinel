# Contributing to MCP Sentinel

Thank you for your interest in contributing to **MCP Sentinel**! We value minimal, auditable, zero-dependency systems engineering over bloated abstractions.

---

## Development Setup

### Prerequisites
- **Node.js `>= 20.0.0`**
- **npm `>= 10`**

### Local Workflow

```bash
git clone https://github.com/Jokudneh/mcp-sentinel.git
cd mcp-sentinel
npm install
npm run typecheck
npm test
```

All tests use Node's built-in `node:test` runner and execute in under a second (`dist-test/test/*.test.js`).

---

## Engineering Principles

Before opening a pull request, please keep these project invariants in mind:

1. **Zero Runtime Dependencies:** Do not add packages to `dependencies` in `package.json`. Use Node.js standard library modules (`node:*`).
2. **Strict TypeScript:** Code must compile cleanly with `npm run typecheck` (`strict`, `noUncheckedIndexedAccess`, `exactOptionalPropertyTypes`, `verbatimModuleSyntax`).
3. **Linear-Time Regexes Only (No ReDoS):** Every pattern added to `src/policy/secrets.ts` or `src/policy/evaluator.ts` must avoid nested quantifiers and unbounded wildcards (`.*` inside groups). Prefer bounded character classes such as `[^\n]{0,120}`.
4. **No Shell Execution:** Child processes must always be spawned with `shell: false`. Never use `eval()`, `new Function()`, or `child_process.exec()`.
5. **`stdout` Wire Purity:** Proxy telemetry and diagnostic messages must write exclusively to `stderr`, never `stdout`.
6. **Clean Process & Resource Cleanup:** Any timers that should not keep Node alive must call `.unref()`. Always close streams and remove listeners on shutdown.

---

## How to Add a New Detection Rule

1. **Choose the right module:**
   - Secret / token patterns → `src/policy/secrets.ts`
   - Destructive commands, path checks, or indirect prompt injection → `src/policy/evaluator.ts`
2. **Follow the rule ID naming convention:**
   - `policy.*`, `exec.*`, `sql.*`, `path.*`, `secret.*`, `injection.*`
3. **Avoid false positives:**
   - For generic secret/token rules, gate matches with `shannonEntropy()` and placeholder filtering.
   - Include **both positive tests** (malicious input detected) and **negative tests** (benign look-alike input allowed) in `test/policy.test.ts`.
4. **Update documentation:**
   - Add the new rule ID, severity, and description to the Detection Matrix in `README.md`.

---

## Commit Message Guidelines

Use concise [Conventional Commits](https://www.conventionalcommits.org/) prefixes:

- `feat:` — new capability, detector rule, or CLI flag
- `fix:` — bug fix or false-positive correction
- `test:` — unit or end-to-end test additions
- `docs:` — README, changelog, or policy documentation updates
- `refactor:` — internal code restructuring without behavior change
- `chore:` — CI, build config, or maintenance tasks

---

## Pull Request Checklist

- [ ] `npm run typecheck` passes with zero errors
- [ ] `npm test` passes (all unit and E2E tests green)
- [ ] Zero new runtime dependencies added
- [ ] New detection rules include both positive and negative test cases
- [ ] Regex patterns reviewed for linear-time (ReDoS-safe) behavior
- [ ] `README.md` updated if CLI flags, config fields, or rule IDs changed
