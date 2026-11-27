import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { PassThrough } from 'node:stream';
import test from 'node:test';
import { validateConfig } from '../src/policy/config.js';
import { encodeFrame, MessageFramer } from '../src/protocol/framing.js';
import { SENTINEL_BLOCKED_ERROR_CODE } from '../src/protocol/jsonrpc.js';
import { runStdioProxy } from '../src/runtime/proxy.js';
import { readTraceFile, summarizeTrace } from '../src/runtime/tracer.js';

const MOCK_SERVER_PATH = resolve('test/fixtures/mock-mcp-server.mjs');

async function waitForResponses(
  outputStream: PassThrough,
  expectedCount: number,
  timeoutMs = 5_000,
): Promise<unknown[]> {
  const framer = new MessageFramer();
  const messages: unknown[] = [];

  return new Promise((resolvePromise, rejectPromise) => {
    const timer = setTimeout(() => {
      rejectPromise(new Error(`Timed out waiting for ${expectedCount} responses (got ${messages.length})`));
    }, timeoutMs);
    timer.unref();

    const onData = (chunk: Buffer): void => {
      for (const frame of framer.push(chunk)) {
        if (frame.ok) {
          messages.push(frame.message);
          if (messages.length >= expectedCount) {
            clearTimeout(timer);
            outputStream.off('data', onData);
            resolvePromise(messages);
            return;
          }
        }
      }
    };

    outputStream.on('data', onData);
  });
}

test('runStdioProxy allows safe calls, blocks dangerous calls before execution, and records traces', async () => {
  const tempDir = mkdtempSync(join(tmpdir(), 'mcp-sentinel-test-'));
  const tracePath = join(tempDir, 'session.jsonl');

  try {
    const clientIn = new PassThrough();
    const clientOut = new PassThrough();
    const stderrOut = new PassThrough();

    const proxyPromise = runStdioProxy({
      command: process.execPath,
      args: [MOCK_SERVER_PATH],
      config: validateConfig({ mode: 'enforce', blockOnSeverity: 'high', redactResponses: true }),
      tracePath,
      stdin: clientIn,
      stdout: clientOut,
      stderr: stderrOut,
      quiet: true,
    });

    const responsesPromise = waitForResponses(clientOut, 4);

    // 1. initialize (allowed)
    clientIn.write(encodeFrame({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} }, 'ndjson'));
    // 2. dangerous shell call (blocked — must NEVER reach child server)
    clientIn.write(
      encodeFrame(
        {
          jsonrpc: '2.0',
          id: 2,
          method: 'tools/call',
          params: { name: 'run_shell', arguments: { command: 'rm -rf /tmp/production' } },
        },
        'ndjson',
      ),
    );
    // 3. poisoned response with prompt injection (blocked on response)
    clientIn.write(
      encodeFrame(
        {
          jsonrpc: '2.0',
          id: 3,
          method: 'tools/call',
          params: { name: 'read_doc', arguments: { id: 'q4' } },
        },
        'ndjson',
      ),
    );
    // 4. safe echo (verify executedToolCalls === 2: read_doc + echo, NOT run_shell)
    clientIn.write(
      encodeFrame(
        {
          jsonrpc: '2.0',
          id: 4,
          method: 'tools/call',
          params: { name: 'echo', arguments: { text: 'hello world' } },
        },
        'ndjson',
      ),
    );

    const responses = (await responsesPromise) as Array<Record<string, unknown>>;
    clientIn.end();
    const exitCode = await proxyPromise;
    assert.equal(exitCode, 0);

    const byId = new Map(responses.map((r) => [r['id'], r]));

    const initResp = byId.get(1);
    assert.ok(initResp && 'result' in initResp);

    const blockedShell = byId.get(2) as { error?: { code?: number } } | undefined;
    assert.equal(blockedShell?.error?.code, SENTINEL_BLOCKED_ERROR_CODE);

    const blockedDoc = byId.get(3) as { error?: { code?: number } } | undefined;
    assert.equal(blockedDoc?.error?.code, SENTINEL_BLOCKED_ERROR_CODE);

    const echoResp = byId.get(4) as { result?: { executedToolCalls?: number } } | undefined;
    assert.equal(echoResp?.result?.executedToolCalls, 2);

    const { events, skippedLines } = readTraceFile(tracePath);
    assert.equal(skippedLines, 0);
    const summary = summarizeTrace(events);
    assert.equal(summary.toolCalls, 3);
    assert.equal(summary.blocked, 2);
  } finally {
    rmSync(tempDir, { recursive: true, force: true });
  }
});

test('runStdioProxy redacts secrets in tool responses when severity is below block threshold', async () => {
  const tempDir = mkdtempSync(join(tmpdir(), 'mcp-sentinel-redact-'));
  const tracePath = join(tempDir, 'redact.jsonl');

  try {
    const clientIn = new PassThrough();
    const clientOut = new PassThrough();
    const stderrOut = new PassThrough();

    const proxyPromise = runStdioProxy({
      command: process.execPath,
      args: [MOCK_SERVER_PATH],
      config: validateConfig({ mode: 'enforce', blockOnSeverity: 'critical', redactResponses: true }),
      tracePath,
      stdin: clientIn,
      stdout: clientOut,
      stderr: stderrOut,
      quiet: true,
    });

    const responsesPromise = waitForResponses(clientOut, 1);

    clientIn.write(
      encodeFrame(
        {
          jsonrpc: '2.0',
          id: 10,
          method: 'tools/call',
          params: { name: 'fetch_secret', arguments: {} },
        },
        'ndjson',
      ),
    );

    const [response] = (await responsesPromise) as [
      { result?: { content?: Array<{ text?: string }> } },
    ];
    clientIn.end();
    await proxyPromise;

    const returnedText = response.result?.content?.[0]?.text ?? '';
    assert.equal(returnedText.includes('AKIAIOSFODNN7EXAMPLE'), false);
    assert.equal(returnedText.includes('[REDACTED:secret.aws_access_key]'), true);

    const { events } = readTraceFile(tracePath);
    const summary = summarizeTrace(events);
    assert.equal(summary.redactedSecrets, 1);
    assert.equal(JSON.stringify(events).includes('AKIAIOSFODNN7EXAMPLE'), false);
  } finally {
    rmSync(tempDir, { recursive: true, force: true });
  }
});

test('runStdioProxy trips CallLoopBreaker when an agent repeats identical tool calls', async () => {
  const clientIn = new PassThrough();
  const clientOut = new PassThrough();
  const stderrOut = new PassThrough();

  const proxyPromise = runStdioProxy({
    command: process.execPath,
    args: [MOCK_SERVER_PATH],
    config: validateConfig({
      mode: 'enforce',
      loopProtection: { enabled: true, maxRepeatedCalls: 3, windowMs: 30_000 },
    }),
    stdin: clientIn,
    stdout: clientOut,
    stderr: stderrOut,
    quiet: true,
  });

  const responsesPromise = waitForResponses(clientOut, 4);

  for (let id = 1; id <= 4; id += 1) {
    clientIn.write(
      encodeFrame(
        {
          jsonrpc: '2.0',
          id,
          method: 'tools/call',
          params: { name: 'echo', arguments: { text: 'stuck-in-loop' } },
        },
        'ndjson',
      ),
    );
  }

  const responses = (await responsesPromise) as Array<Record<string, unknown>>;
  clientIn.end();
  await proxyPromise;

  const byId = new Map(responses.map((r) => [r['id'], r]));
  assert.ok('result' in (byId.get(1) ?? {}));
  assert.ok('result' in (byId.get(2) ?? {}));
  assert.ok('result' in (byId.get(3) ?? {}));

  const fourth = byId.get(4) as { error?: { code?: number; data?: { findings?: Array<{ ruleId: string }> } } } | undefined;
  assert.equal(fourth?.error?.code, SENTINEL_BLOCKED_ERROR_CODE);
  assert.equal(fourth?.error?.data?.findings?.[0]?.ruleId, 'runtime.call_loop_detected');
});

test('runStdioProxy answers the oldest in-flight request instead of dropping it when the table overflows', async () => {
  const tempDir = mkdtempSync(join(tmpdir(), 'mcp-sentinel-overflow-'));
  try {
    const clientIn = new PassThrough();
    const clientOut = new PassThrough();
    const stderrOut = new PassThrough();

    const proxyPromise = runStdioProxy({
      command: process.execPath,
      args: [MOCK_SERVER_PATH],
      config: validateConfig({ mode: 'enforce', blockOnSeverity: 'high' }),
      stdin: clientIn,
      stdout: clientOut,
      stderr: stderrOut,
      quiet: true,
      maxPendingRequests: 1,
    });

    const responsesPromise = waitForResponses(clientOut, 2);
    clientIn.write(encodeFrame({ jsonrpc: '2.0', id: 101, method: 'initialize', params: {} }, 'ndjson'));
    clientIn.write(encodeFrame({ jsonrpc: '2.0', id: 102, method: 'initialize', params: {} }, 'ndjson'));

    const responses = (await responsesPromise) as Array<{ id?: number; error?: { message?: string } }>;
    clientIn.end();
    await proxyPromise;

    const evicted = responses.find((r) => r.id === 101);
    assert.ok(evicted, 'the evicted request must still receive a response');
    assert.match(String(evicted.error?.message), /Dropped by mcp-sentinel/);
  } finally {
    rmSync(tempDir, { recursive: true, force: true });
  }
});
