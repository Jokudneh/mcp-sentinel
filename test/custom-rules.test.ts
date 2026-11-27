import assert from 'node:assert/strict';
import test from 'node:test';
import { ConfigError, validateConfig } from '../src/policy/config.js';
import { assertSafeRegexPattern, UnsafeRegexError } from '../src/policy/custom-rules.js';
import { evaluateToolCall, evaluateToolResponse } from '../src/policy/evaluator.js';
import { buildMarkdownReport, buildSarifReport } from '../src/runtime/report.js';
import { summarizeTrace, type TraceEvent } from '../src/runtime/tracer.js';

test('assertSafeRegexPattern rejects nested quantifiers, backreferences, and oversized patterns', () => {
  assert.throws(() => assertSafeRegexPattern('(a+)+$'), UnsafeRegexError);
  assert.throws(() => assertSafeRegexPattern('([a-z]*)*'), UnsafeRegexError);
  assert.throws(() => assertSafeRegexPattern('(foo)\\1'), UnsafeRegexError);
  assert.throws(() => assertSafeRegexPattern('a'.repeat(300)), UnsafeRegexError);

  assert.doesNotThrow(() => assertSafeRegexPattern('prod-db\\.[a-z0-9-]{1,32}\\.internal'));
});

test('validateConfig rejects unsafe custom regex rules at load time', () => {
  assert.throws(
    () =>
      validateConfig({
        customRules: [
          {
            id: 'custom.bad_regex',
            direction: 'request',
            severity: 'high',
            summary: 'Dangerous regex',
            match: 'regex',
            pattern: '(a+)+b',
          },
        ],
      }),
    ConfigError,
  );
});

test('customRules enforce request, response, and toolPattern scoped rules', () => {
  const cfg = validateConfig({
    customRules: [
      {
        id: 'custom.no_prod_host',
        direction: 'request',
        severity: 'critical',
        summary: 'Block production database hostname',
        toolPattern: 'db_*',
        match: 'contains',
        pattern: 'prod-db.internal',
      },
      {
        id: 'custom.block_internal_marker',
        direction: 'response',
        severity: 'high',
        summary: 'Block responses marked CONFIDENTIAL',
        match: 'prefix',
        pattern: 'CONFIDENTIAL:',
        caseSensitive: true,
      },
    ],
  });

  const blockedDb = evaluateToolCall('db_query', { host: 'us-east.prod-db.internal' }, cfg);
  assert.equal(blockedDb.decision, 'block');
  assert.equal(blockedDb.findings.some((f) => f.ruleId === 'custom.no_prod_host'), true);

  // Different tool not matching db_* is allowed.
  const otherTool = evaluateToolCall('docs_search', { query: 'prod-db.internal' }, cfg);
  assert.equal(otherTool.decision, 'allow');

  // Case-sensitive response prefix match.
  const blockedResp = evaluateToolResponse({ text: 'CONFIDENTIAL: board minutes' }, cfg, 'read_doc');
  assert.equal(blockedResp.decision, 'block');
  assert.equal(blockedResp.findings.some((f) => f.ruleId === 'custom.block_internal_marker'), true);

  const lowerResp = evaluateToolResponse({ text: 'confidential: harmless note' }, cfg, 'read_doc');
  assert.equal(lowerResp.decision, 'allow');
});

test('buildSarifReport and buildMarkdownReport produce valid structured outputs', () => {
  const events: TraceEvent[] = [
    {
      timestamp: '2026-11-27T18:00:00.000Z',
      sessionId: 'abc12345',
      direction: 'client->server',
      kind: 'request',
      decision: 'block',
      requestId: 1,
      method: 'tools/call',
      toolName: 'run_shell',
      findings: [
        {
          ruleId: 'exec.rm_rf',
          category: 'destructive_command',
          severity: 'critical',
          summary: 'Recursive forced file deletion (rm -rf)',
          path: 'arguments.command',
          matchPreview: 'rm -rf',
        },
      ],
    },
  ];

  const sarif = buildSarifReport(events, '0.1.0');
  assert.equal(sarif.version, '2.1.0');
  assert.equal(sarif.runs[0]?.tool.driver.name, 'mcp-sentinel');
  assert.equal(sarif.runs[0]?.results.length, 1);
  assert.equal(sarif.runs[0]?.results[0]?.ruleId, 'exec.rm_rf');
  assert.equal(sarif.runs[0]?.results[0]?.level, 'error');

  const md = buildMarkdownReport('trace.jsonl', summarizeTrace(events), events);
  assert.equal(md.includes('# MCP Sentinel Trace Report'), true);
  assert.equal(md.includes('`exec.rm_rf`'), true);
});
