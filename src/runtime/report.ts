import type { Severity } from '../policy/types.js';
import type { TraceEvent, TraceSummary } from './tracer.js';

export interface SarifLog {
  $schema: string;
  version: '2.1.0';
  runs: Array<{
    tool: {
      driver: {
        name: string;
        version: string;
        informationUri: string;
        rules: Array<{
          id: string;
          shortDescription: { text: string };
          defaultConfiguration: { level: 'error' | 'warning' | 'note' };
        }>;
      };
    };
    results: Array<{
      ruleId: string;
      level: 'error' | 'warning' | 'note';
      message: { text: string };
      locations: Array<{
        logicalLocations: Array<{
          name: string;
          fullyQualifiedName: string;
          kind: string;
        }>;
      }>;
      properties: {
        timestamp: string;
        sessionId: string;
        direction: string;
        decision: string;
        severity: Severity;
        category: string;
        matchPreview?: string;
      };
    }>;
  }>;
}

function severityToSarifLevel(severity: Severity): 'error' | 'warning' | 'note' {
  switch (severity) {
    case 'critical':
    case 'high':
      return 'error';
    case 'medium':
      return 'warning';
    case 'low':
      return 'note';
  }
}

export function buildSarifReport(
  events: readonly TraceEvent[],
  version = '0.1.0',
): SarifLog {
  const ruleMap = new Map<
    string,
    { id: string; summary: string; level: 'error' | 'warning' | 'note' }
  >();
  const results: SarifLog['runs'][number]['results'] = [];

  for (const event of events) {
    const toolName = event.toolName ?? event.method ?? 'mcp';
    for (const finding of event.findings) {
      const level = severityToSarifLevel(finding.severity);
      if (!ruleMap.has(finding.ruleId)) {
        ruleMap.set(finding.ruleId, {
          id: finding.ruleId,
          summary: finding.summary,
          level,
        });
      }

      const props: SarifLog['runs'][number]['results'][number]['properties'] = {
        timestamp: event.timestamp,
        sessionId: event.sessionId,
        direction: event.direction,
        decision: event.decision,
        severity: finding.severity,
        category: finding.category,
      };
      if (finding.matchPreview) {
        props.matchPreview = finding.matchPreview;
      }

      results.push({
        ruleId: finding.ruleId,
        level,
        message: {
          text: `[${event.decision.toUpperCase()}] ${toolName}: ${finding.summary}`,
        },
        locations: [
          {
            logicalLocations: [
              {
                name: toolName,
                fullyQualifiedName: finding.path ? `${toolName}:${finding.path}` : toolName,
                kind: 'function',
              },
            ],
          },
        ],
        properties: props,
      });
    }
  }

  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'mcp-sentinel',
            version,
            informationUri: 'https://github.com/Jokudneh/mcp-sentinel',
            rules: [...ruleMap.values()].map((r) => ({
              id: r.id,
              shortDescription: { text: r.summary },
              defaultConfiguration: { level: r.level },
            })),
          },
        },
        results,
      },
    ],
  };
}

export function buildMarkdownReport(
  sourceFile: string,
  summary: TraceSummary,
  events: readonly TraceEvent[],
): string {
  const lines: string[] = [];
  lines.push(`# MCP Sentinel Trace Report`);
  lines.push('');
  lines.push(`- **Source:** \`${sourceFile}\``);
  lines.push(`- **Total Events:** ${summary.totalEvents}`);
  lines.push(`- **Tool Calls:** ${summary.toolCalls}`);
  lines.push(`- **Blocked:** ${summary.blocked} | **Warned:** ${summary.warned} | **Allowed:** ${summary.allowed}`);
  if (summary.redactedSecrets > 0) {
    lines.push(`- **Redacted Secrets:** ${summary.redactedSecrets}`);
  }

  if (summary.tools.length > 0) {
    lines.push('');
    lines.push('## Tools');
    lines.push('');
    lines.push('| Tool | Calls | Blocked | Warned | Avg Latency |');
    lines.push('| --- | ---: | ---: | ---: | ---: |');
    for (const tool of summary.tools) {
      const avg = tool.avgLatencyMs !== null ? `${tool.avgLatencyMs}ms` : 'n/a';
      lines.push(`| \`${tool.toolName}\` | ${tool.calls} | ${tool.blocked} | ${tool.warned} | ${avg} |`);
    }
  }

  if (summary.ruleCounts.length > 0) {
    lines.push('');
    lines.push('## Triggered Rules');
    lines.push('');
    lines.push('| Rule ID | Count |');
    lines.push('| --- | ---: |');
    for (const rule of summary.ruleCounts) {
      lines.push(`| \`${rule.ruleId}\` | ${rule.count} |`);
    }
  }

  const flagged = events.filter((e) => e.findings.length > 0);
  if (flagged.length > 0) {
    lines.push('');
    lines.push(`## Flagged Events (${flagged.length})`);
    lines.push('');
    lines.push('| Timestamp | Decision | Direction | Tool | Rules |');
    lines.push('| --- | --- | --- | --- | --- |');
    for (const event of flagged.slice(0, 50)) {
      const rules = event.findings.map((f) => `\`${f.ruleId}\` (${f.severity})`).join(', ');
      lines.push(
        `| ${event.timestamp} | ${event.decision.toUpperCase()} | ${event.direction} | \`${event.toolName ?? event.method ?? '-'}\` | ${rules} |`,
      );
    }
  }

  return `${lines.join('\n')}\n`;
}
