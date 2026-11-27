import type { EvaluationResult, PolicyDecision, Severity } from '../policy/types.js';
import type { TraceEvent, TraceSummary } from '../runtime/tracer.js';

export interface ColorPalette {
  reset: string;
  dim: string;
  bold: string;
  red: string;
  yellow: string;
  green: string;
  cyan: string;
  magenta: string;
}

const ANSI_PALETTE: ColorPalette = {
  reset: '\x1b[0m',
  dim: '\x1b[2m',
  bold: '\x1b[1m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  green: '\x1b[32m',
  cyan: '\x1b[36m',
  magenta: '\x1b[35m',
};

const PLAIN_PALETTE: ColorPalette = {
  reset: '',
  dim: '',
  bold: '',
  red: '',
  yellow: '',
  green: '',
  cyan: '',
  magenta: '',
};

export function getPalette(isTty: boolean): ColorPalette {
  if (!isTty || process.env['NO_COLOR'] !== undefined) {
    return PLAIN_PALETTE;
  }
  return ANSI_PALETTE;
}

function colorDecision(decision: PolicyDecision, c: ColorPalette): string {
  switch (decision) {
    case 'block':
      return `${c.bold}${c.red}BLOCK${c.reset}`;
    case 'warn':
      return `${c.bold}${c.yellow}WARN ${c.reset}`;
    case 'allow':
      return `${c.green}ALLOW${c.reset}`;
  }
}

function colorSeverity(severity: Severity, c: ColorPalette): string {
  switch (severity) {
    case 'critical':
      return `${c.bold}${c.red}CRITICAL${c.reset}`;
    case 'high':
      return `${c.red}HIGH${c.reset}`;
    case 'medium':
      return `${c.yellow}MEDIUM${c.reset}`;
    case 'low':
      return `${c.cyan}LOW${c.reset}`;
  }
}

export function formatLiveEvent(event: TraceEvent, isTty: boolean): string | null {
  if (!event.toolName && event.findings.length === 0 && event.kind !== 'frame_error') {
    return null;
  }
  const c = getPalette(isTty);
  const dir = event.direction === 'client->server' ? '->' : '<-';
  const subject = event.toolName ?? event.method ?? event.kind;
  const latency = event.latencyMs !== undefined ? ` ${c.dim}${event.latencyMs}ms${c.reset}` : '';
  const redacted =
    event.redactedSecrets && event.redactedSecrets > 0
      ? ` ${c.magenta}[redacted:${event.redactedSecrets}]${c.reset}`
      : '';

  const rules =
    event.findings.length > 0
      ? ` ${c.dim}(${event.findings.map((f) => `${f.severity}:${f.ruleId}`).join(', ')})${c.reset}`
      : '';

  return `${c.dim}[sentinel]${c.reset} ${colorDecision(event.decision, c)} ${dir} ${c.bold}${subject}${c.reset}${latency}${redacted}${rules}`;
}

export function formatEvaluation(
  label: string,
  result: EvaluationResult,
  isTty: boolean,
): string {
  const c = getPalette(isTty);
  const lines: string[] = [];
  lines.push(`${c.bold}${label}${c.reset}  ${colorDecision(result.decision, c)}`);

  if (result.findings.length === 0) {
    lines.push(`  ${c.green}No policy violations detected.${c.reset}`);
    return lines.join('\n');
  }

  for (const finding of result.findings) {
    const location = finding.path ? ` ${c.dim}@ ${finding.path}${c.reset}` : '';
    const preview = finding.matchPreview ? ` ${c.dim}[${finding.matchPreview}]${c.reset}` : '';
    lines.push(
      `  - ${colorSeverity(finding.severity, c)} ${c.bold}${finding.ruleId}${c.reset}${location}: ${finding.summary}${preview}`,
    );
  }
  return lines.join('\n');
}

export function formatTraceSummary(
  filePath: string,
  summary: TraceSummary,
  events: readonly TraceEvent[],
  isTty: boolean,
): string {
  const c = getPalette(isTty);
  const lines: string[] = [];

  lines.push(`${c.bold}MCP Sentinel Trace Report${c.reset} ${c.dim}(${filePath})${c.reset}`);
  lines.push(
    `Events: ${summary.totalEvents}  |  Tool calls: ${summary.toolCalls}  |  ` +
      `${c.red}Blocked: ${summary.blocked}${c.reset}  |  ` +
      `${c.yellow}Warned: ${summary.warned}${c.reset}  |  ` +
      `${c.green}Allowed: ${summary.allowed}${c.reset}` +
      (summary.redactedSecrets > 0 ? `  |  Redacted secrets: ${summary.redactedSecrets}` : ''),
  );

  if (summary.tools.length > 0) {
    lines.push('');
    lines.push(`${c.bold}Tools${c.reset}`);
    for (const tool of summary.tools) {
      const avg = tool.avgLatencyMs !== null ? `${tool.avgLatencyMs}ms avg` : 'n/a';
      lines.push(
        `  ${tool.toolName.padEnd(28)} calls=${String(tool.calls).padEnd(4)} ` +
          `blocked=${String(tool.blocked).padEnd(4)} warned=${String(tool.warned).padEnd(4)} (${avg})`,
      );
    }
  }

  if (summary.ruleCounts.length > 0) {
    lines.push('');
    lines.push(`${c.bold}Triggered Rules${c.reset}`);
    for (const rule of summary.ruleCounts) {
      lines.push(`  ${rule.ruleId.padEnd(34)} ${rule.count}`);
    }
  }

  const flagged = events.filter((e) => e.findings.length > 0);
  if (flagged.length > 0) {
    lines.push('');
    lines.push(`${c.bold}Flagged Timeline (${flagged.length})${c.reset}`);
    for (const event of flagged.slice(0, 25)) {
      const line = formatLiveEvent(event, isTty);
      if (line) {
        lines.push(`  ${c.dim}${event.timestamp}${c.reset} ${line}`);
      }
    }
    if (flagged.length > 25) {
      lines.push(`  ${c.dim}... ${flagged.length - 25} more flagged events omitted${c.reset}`);
    }
  }

  return lines.join('\n');
}
