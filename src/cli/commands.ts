import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { parseArgs } from 'node:util';
import { ConfigError, DEFAULT_CONFIG, loadConfigFile, serializeDefaultConfig } from '../policy/config.js';
import { evaluateToolCall, evaluateToolResponse } from '../policy/evaluator.js';
import { SEVERITY_RANK, type EnforcementMode, type SentinelConfig, type Severity } from '../policy/types.js';
import { extractToolCallParams, isJsonObject, isJsonRpcNotification, isJsonRpcRequest } from '../protocol/jsonrpc.js';
import { runStdioProxy } from '../runtime/proxy.js';
import { readTraceFile, summarizeTrace } from '../runtime/tracer.js';
import { formatEvaluation, formatLiveEvent, formatTraceSummary } from './format.js';

const VERSION = '0.1.0';

const HELP_TEXT = `mcp-sentinel v${VERSION}
Zero-dependency stdio firewall and flight recorder for MCP servers.

Usage:
  mcp-sentinel proxy [options] -- <server-cmd> [server-args...]
  mcp-sentinel inspect <trace.jsonl> [options]
  mcp-sentinel check <payload.json> [options]
  mcp-sentinel init [config-path] [--force]

Commands:
  proxy     Wrap any stdio MCP server to enforce policies and record JSONL traces.
  inspect   Summarize and filter a recorded JSONL trace in the terminal.
  check     Dry-run a JSON-RPC tool call or response file against active policies.
  init      Generate a default sentinel.config.json policy file.

Proxy options:
  --mode <enforce|audit>     Block violations or log only (default: enforce)
  --config <path>            Load policy JSON file
  --trace <path>             Write JSONL flight-recorder trace to file
  --allow-root <dir>         Restrict file path arguments to directory (repeatable)
  --allow-tool <pattern>     Allowlist tool name/wildcard (repeatable)
  --deny-tool <pattern>      Denylist tool name/wildcard (repeatable)
  --quiet                    Suppress live stderr telemetry

Inspect options:
  --tool <name>              Filter events by tool name
  --severity <level>         Minimum severity (low|medium|high|critical)
  --only-findings            Include only events with policy findings
  --json                     Output summary as JSON

Check options:
  --config <path>            Load policy JSON file
  --mode <enforce|audit>     Override enforcement mode
  --direction <req|res>      Treat payload as request (default) or response
  --json                     Output evaluation result as JSON
`;

function buildConfig(flags: {
  config?: string | undefined;
  mode?: string | undefined;
  allowRoot?: string[] | undefined;
  allowTool?: string[] | undefined;
  denyTool?: string[] | undefined;
}): SentinelConfig {
  const base: SentinelConfig = flags.config
    ? loadConfigFile(flags.config)
    : {
        ...DEFAULT_CONFIG,
        allowedTools: [...DEFAULT_CONFIG.allowedTools],
        deniedTools: [...DEFAULT_CONFIG.deniedTools],
        allowedRoots: [...DEFAULT_CONFIG.allowedRoots],
        loopProtection: { ...DEFAULT_CONFIG.loopProtection },
      };

  if (flags.mode !== undefined) {
    if (flags.mode !== 'enforce' && flags.mode !== 'audit') {
      throw new ConfigError(`Invalid --mode "${flags.mode}" (expected "enforce" or "audit")`);
    }
    base.mode = flags.mode as EnforcementMode;
  }

  if (flags.allowRoot && flags.allowRoot.length > 0) {
    base.allowedRoots.push(...flags.allowRoot.map((dir) => resolve(dir)));
  }
  if (flags.allowTool && flags.allowTool.length > 0) {
    base.allowedTools.push(...flags.allowTool);
  }
  if (flags.denyTool && flags.denyTool.length > 0) {
    base.deniedTools.push(...flags.denyTool);
  }

  return base;
}

async function runProxyCommand(argv: string[]): Promise<number> {
  const separatorIdx = argv.indexOf('--');
  const flagArgs = separatorIdx === -1 ? argv : argv.slice(0, separatorIdx);
  const childCmdArgs = separatorIdx === -1 ? [] : argv.slice(separatorIdx + 1);

  const { values, positionals } = parseArgs({
    args: flagArgs,
    options: {
      mode: { type: 'string' },
      config: { type: 'string', short: 'c' },
      trace: { type: 'string', short: 't' },
      'allow-root': { type: 'string', multiple: true },
      'allow-tool': { type: 'string', multiple: true },
      'deny-tool': { type: 'string', multiple: true },
      quiet: { type: 'boolean', short: 'q' },
    },
    allowPositionals: true,
    strict: true,
  });

  const target = childCmdArgs.length > 0 ? childCmdArgs : positionals;
  const [command, ...args] = target;
  if (!command) {
    process.stderr.write('Error: Missing target MCP server command. Example:\n');
    process.stderr.write('  mcp-sentinel proxy --trace trace.jsonl -- node server.js\n');
    return 2;
  }

  const config = buildConfig({
    config: values.config,
    mode: values.mode,
    allowRoot: values['allow-root'],
    allowTool: values['allow-tool'],
    denyTool: values['deny-tool'],
  });

  const isTty = Boolean(process.stderr.isTTY);
  const proxyOpts: Parameters<typeof runStdioProxy>[0] = {
    command,
    args,
    config,
    quiet: Boolean(values.quiet),
    formatTelemetry: (event) => formatLiveEvent(event, isTty),
  };
  if (values.trace) {
    proxyOpts.tracePath = values.trace;
  }

  return runStdioProxy(proxyOpts);
}

function runInspectCommand(argv: string[]): number {
  const { values, positionals } = parseArgs({
    args: argv,
    options: {
      tool: { type: 'string' },
      severity: { type: 'string' },
      'only-findings': { type: 'boolean' },
      json: { type: 'boolean' },
    },
    allowPositionals: true,
    strict: true,
  });

  const tracePath = positionals[0];
  if (!tracePath) {
    process.stderr.write('Error: Missing trace file path. Usage: mcp-sentinel inspect <trace.jsonl>\n');
    return 2;
  }

  let minRank = 0;
  if (values.severity !== undefined) {
    if (!(values.severity in SEVERITY_RANK)) {
      process.stderr.write(`Error: Invalid --severity "${values.severity}"\n`);
      return 2;
    }
    minRank = SEVERITY_RANK[values.severity as Severity];
  }

  const { events, skippedLines } = readTraceFile(tracePath);
  const filtered = events.filter((event) => {
    if (values.tool && event.toolName !== values.tool) return false;
    if (values['only-findings'] && event.findings.length === 0) return false;
    if (minRank > 0 && !event.findings.some((f) => SEVERITY_RANK[f.severity] >= minRank)) {
      return false;
    }
    return true;
  });

  const summary = summarizeTrace(filtered);
  if (values.json) {
    process.stdout.write(`${JSON.stringify({ file: tracePath, skippedLines, summary }, null, 2)}\n`);
    return 0;
  }

  process.stdout.write(`${formatTraceSummary(tracePath, summary, filtered, Boolean(process.stdout.isTTY))}\n`);
  if (skippedLines > 0) {
    process.stderr.write(`Note: skipped ${skippedLines} malformed line(s) in trace file.\n`);
  }
  return 0;
}

function runCheckCommand(argv: string[]): number {
  const { values, positionals } = parseArgs({
    args: argv,
    options: {
      config: { type: 'string', short: 'c' },
      mode: { type: 'string' },
      direction: { type: 'string', short: 'd' },
      json: { type: 'boolean' },
    },
    allowPositionals: true,
    strict: true,
  });

  const payloadPath = positionals[0];
  if (!payloadPath) {
    process.stderr.write('Error: Missing payload JSON file. Usage: mcp-sentinel check <payload.json>\n');
    return 2;
  }

  const config = buildConfig({ config: values.config, mode: values.mode });
  const parsed: unknown = JSON.parse(readFileSync(payloadPath, 'utf8'));
  const direction = values.direction ?? 'request';

  let label = payloadPath;
  let evaluation;

  if (direction === 'response' || direction === 'res') {
    const resultBody = isJsonObject(parsed) && 'result' in parsed ? parsed['result'] : parsed;
    label = `response (${payloadPath})`;
    evaluation = evaluateToolResponse(resultBody, config);
  } else {
    if (isJsonRpcRequest(parsed) || isJsonRpcNotification(parsed)) {
      const toolCall = extractToolCallParams(parsed);
      if (!toolCall) {
        process.stderr.write('Error: JSON-RPC payload is not a valid tools/call message.\n');
        return 2;
      }
      label = `tools/call ${toolCall.name}`;
      evaluation = evaluateToolCall(toolCall.name, toolCall.arguments, config);
    } else if (isJsonObject(parsed) && typeof parsed['name'] === 'string') {
      const args = isJsonObject(parsed['arguments']) ? parsed['arguments'] : {};
      label = `tools/call ${parsed['name']}`;
      evaluation = evaluateToolCall(parsed['name'], args, config);
    } else {
      process.stderr.write('Error: Expected a JSON-RPC tools/call object or { "name", "arguments" }.\n');
      return 2;
    }
  }

  if (values.json) {
    process.stdout.write(`${JSON.stringify(evaluation, null, 2)}\n`);
  } else {
    process.stdout.write(`${formatEvaluation(label, evaluation, Boolean(process.stdout.isTTY))}\n`);
  }

  return evaluation.decision === 'block' ? 1 : 0;
}

function runInitCommand(argv: string[]): number {
  const { values, positionals } = parseArgs({
    args: argv,
    options: {
      force: { type: 'boolean', short: 'f' },
    },
    allowPositionals: true,
    strict: true,
  });

  const targetPath = resolve(positionals[0] ?? 'sentinel.config.json');
  if (existsSync(targetPath) && !values.force) {
    process.stderr.write(`Error: "${targetPath}" already exists. Pass --force to overwrite.\n`);
    return 2;
  }

  writeFileSync(targetPath, serializeDefaultConfig(), 'utf8');
  process.stdout.write(`Created ${targetPath}\n`);
  return 0;
}

export async function runCli(argv: string[]): Promise<number> {
  const [command, ...rest] = argv;
  if (!command || command === '-h' || command === '--help' || command === 'help') {
    process.stdout.write(HELP_TEXT);
    return 0;
  }
  if (command === '-v' || command === '--version') {
    process.stdout.write(`${VERSION}\n`);
    return 0;
  }

  try {
    switch (command) {
      case 'proxy':
        return await runProxyCommand(rest);
      case 'inspect':
        return runInspectCommand(rest);
      case 'check':
        return runCheckCommand(rest);
      case 'init':
        return runInitCommand(rest);
      default:
        process.stderr.write(`Error: Unknown command "${command}". Run "mcp-sentinel --help".\n`);
        return 2;
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    process.stderr.write(`Error: ${message}\n`);
    return 2;
  }
}
