import { createWriteStream, mkdirSync, readFileSync, type WriteStream } from 'node:fs';
import { dirname } from 'node:path';
import { redactSecretsInValue } from '../policy/secrets.js';
import type { PolicyDecision, RuleFinding, Severity } from '../policy/types.js';
import type { JsonRpcId } from '../protocol/jsonrpc.js';

export type TrafficDirection = 'client->server' | 'server->client';
export type TraceKind = 'request' | 'notification' | 'response' | 'frame_error';

export interface TraceEvent {
  timestamp: string;
  sessionId: string;
  direction: TrafficDirection;
  kind: TraceKind;
  decision: PolicyDecision;
  requestId?: JsonRpcId;
  method?: string;
  toolName?: string;
  latencyMs?: number;
  redactedSecrets?: number;
  findings: RuleFinding[];
  payload?: unknown;
}

export interface ToolStats {
  toolName: string;
  calls: number;
  blocked: number;
  warned: number;
  avgLatencyMs: number | null;
}

export interface TraceSummary {
  totalEvents: number;
  toolCalls: number;
  blocked: number;
  warned: number;
  allowed: number;
  frameErrors: number;
  redactedSecrets: number;
  severityCounts: Record<Severity, number>;
  ruleCounts: Array<{ ruleId: string; count: number }>;
  tools: ToolStats[];
}

export class JsonlTracer {
  private readonly stream: WriteStream;
  private closed = false;

  constructor(filePath: string) {
    mkdirSync(dirname(filePath), { recursive: true });
    this.stream = createWriteStream(filePath, { flags: 'a', encoding: 'utf8' });
    this.stream.on('error', () => {
      // Avoid unhandled stream errors crashing an active MCP proxy session.
    });
  }

  record(event: TraceEvent): void {
    if (this.closed) return;
    const sanitized: TraceEvent = { ...event };
    if (sanitized.payload !== undefined) {
      const { value } = redactSecretsInValue(sanitized.payload);
      sanitized.payload = value;
    }
    this.stream.write(`${JSON.stringify(sanitized)}\n`);
  }

  close(): Promise<void> {
    if (this.closed) return Promise.resolve();
    this.closed = true;
    return new Promise((resolvePromise) => {
      this.stream.end(() => resolvePromise());
    });
  }
}

export function readTraceFile(filePath: string): { events: TraceEvent[]; skippedLines: number } {
  const raw = readFileSync(filePath, 'utf8');
  const lines = raw.split(/\r?\n/);
  const events: TraceEvent[] = [];
  let skippedLines = 0;

  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed.length === 0) continue;
    try {
      const parsed: unknown = JSON.parse(trimmed);
      if (
        typeof parsed === 'object' &&
        parsed !== null &&
        typeof (parsed as TraceEvent).timestamp === 'string' &&
        Array.isArray((parsed as TraceEvent).findings)
      ) {
        events.push(parsed as TraceEvent);
      } else {
        skippedLines += 1;
      }
    } catch {
      skippedLines += 1;
    }
  }

  return { events, skippedLines };
}

export function summarizeTrace(events: readonly TraceEvent[]): TraceSummary {
  const severityCounts: Record<Severity, number> = {
    low: 0,
    medium: 0,
    high: 0,
    critical: 0,
  };
  const ruleMap = new Map<string, number>();
  const toolMap = new Map<
    string,
    { calls: number; blocked: number; warned: number; latencies: number[] }
  >();

  let toolCalls = 0;
  let blocked = 0;
  let warned = 0;
  let allowed = 0;
  let frameErrors = 0;
  let redactedSecrets = 0;

  for (const event of events) {
    if (event.kind === 'frame_error') frameErrors += 1;
    if (event.decision === 'block') blocked += 1;
    else if (event.decision === 'warn') warned += 1;
    else allowed += 1;

    if (event.redactedSecrets) {
      redactedSecrets += event.redactedSecrets;
    }

    for (const finding of event.findings) {
      severityCounts[finding.severity] += 1;
      ruleMap.set(finding.ruleId, (ruleMap.get(finding.ruleId) ?? 0) + 1);
    }

    if (event.toolName) {
      let stats = toolMap.get(event.toolName);
      if (!stats) {
        stats = { calls: 0, blocked: 0, warned: 0, latencies: [] };
        toolMap.set(event.toolName, stats);
      }
      if (event.direction === 'client->server') {
        toolCalls += 1;
        stats.calls += 1;
      }
      if (event.decision === 'block') stats.blocked += 1;
      if (event.decision === 'warn') stats.warned += 1;
      if (typeof event.latencyMs === 'number' && Number.isFinite(event.latencyMs)) {
        stats.latencies.push(event.latencyMs);
      }
    }
  }

  const ruleCounts = [...ruleMap.entries()]
    .map(([ruleId, count]) => ({ ruleId, count }))
    .sort((a, b) => b.count - a.count || a.ruleId.localeCompare(b.ruleId));

  const tools: ToolStats[] = [...toolMap.entries()]
    .map(([toolName, stats]) => ({
      toolName,
      calls: stats.calls,
      blocked: stats.blocked,
      warned: stats.warned,
      avgLatencyMs:
        stats.latencies.length > 0
          ? Math.round(
              (stats.latencies.reduce((sum, v) => sum + v, 0) / stats.latencies.length) * 10,
            ) / 10
          : null,
    }))
    .sort((a, b) => b.calls - a.calls || a.toolName.localeCompare(b.toolName));

  return {
    totalEvents: events.length,
    toolCalls,
    blocked,
    warned,
    allowed,
    frameErrors,
    redactedSecrets,
    severityCounts,
    ruleCounts,
    tools,
  };
}
