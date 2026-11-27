import assert from 'node:assert/strict';
import test from 'node:test';
import { CallLoopBreaker, fingerprintToolCall } from '../src/policy/circuit-breaker.js';
import { DEFAULT_CONFIG } from '../src/policy/config.js';
import { evaluateToolCall, evaluateToolResponse } from '../src/policy/evaluator.js';
import { scanSecrets } from '../src/policy/secrets.js';
import { encodeFrame, MessageFramer, type FramingMode } from '../src/protocol/framing.js';

function mulberry32(seed: number): () => number {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = Math.imul(state ^ (state >>> 15), 1 | state);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

test('MessageFramer fuzz: 200 mixed NDJSON and Content-Length frames split at arbitrary byte offsets', () => {
  const rand = mulberry32(0x5eed1234);
  const framer = new MessageFramer();

  const expected: unknown[] = [];
  const wireChunks: Buffer[] = [];

  for (let i = 0; i < 200; i += 1) {
    const mode: FramingMode = rand() < 0.5 ? 'ndjson' : 'content-length';
    const unicodeSample = i % 3 === 0 ? 'αβγδε🚀🛡️日本語' : 'plain-ascii-payload';
    const msg = {
      jsonrpc: '2.0',
      id: i,
      method: 'tools/call',
      params: {
        name: `tool_${i % 7}`,
        arguments: {
          seq: i,
          text: `${unicodeSample}_${'x'.repeat(Math.floor(rand() * 48))}`,
        },
      },
    };
    expected.push(msg);
    wireChunks.push(encodeFrame(msg, mode));
  }

  const combined = Buffer.concat(wireChunks);
  const decoded: unknown[] = [];

  let offset = 0;
  while (offset < combined.length) {
    const step = 1 + Math.floor(rand() * 17);
    const slice = combined.subarray(offset, Math.min(combined.length, offset + step));
    offset += slice.length;
    for (const frame of framer.push(slice)) {
      assert.equal(frame.ok, true);
      if (frame.ok) decoded.push(frame.message);
    }
  }

  assert.equal(decoded.length, expected.length);
  assert.deepEqual(decoded, expected);
});

test('evaluator catches adversarial path obfuscation (null byte, URL-encoded, mixed slashes)', () => {
  const nullByte = evaluateToolCall('read_file', { path: 'notes.txt\0.png' }, DEFAULT_CONFIG);
  assert.equal(nullByte.decision, 'block');
  assert.equal(nullByte.findings.some((f) => f.ruleId === 'path.null_byte'), true);

  const encodedTraversal = evaluateToolCall('read_file', { path: '%2e%2e%2f%2e%2e%2f.env' }, DEFAULT_CONFIG);
  assert.equal(encodedTraversal.decision, 'block');
  assert.equal(encodedTraversal.findings.some((f) => f.ruleId === 'path.traversal'), true);
  assert.equal(encodedTraversal.findings.some((f) => f.ruleId === 'path.dotenv_file'), true);

  const mixedSlashes = evaluateToolCall('read_file', { path: 'foo\\..\\..\\.ssh\\id_ed25519' }, DEFAULT_CONFIG);
  assert.equal(mixedSlashes.decision, 'block');
  assert.equal(mixedSlashes.findings.some((f) => f.ruleId === 'path.ssh_private_key'), true);
});

test('regex engine stays strictly linear-time on 64 KB adversarial ReDoS-style inputs', () => {
  const adversarialSecret = `api_key=${'A'.repeat(65_536)}!`;
  const adversarialMarkdown = `![${'a'.repeat(500)}](https://example.com/${'x'.repeat(65_536)}`;
  const adversarialShell = `curl ${'a'.repeat(65_536)} | echo ok`;

  const start = performance.now();
  scanSecrets(adversarialSecret);
  evaluateToolCall('run_shell', { command: adversarialShell }, DEFAULT_CONFIG);
  evaluateToolResponse({ text: adversarialMarkdown }, DEFAULT_CONFIG);
  const elapsedMs = performance.now() - start;

  assert.equal(elapsedMs < 100, true, `Expected linear-time evaluation (<100ms), got ${elapsedMs.toFixed(2)}ms`);
});

test('CallLoopBreaker canonicalizes argument order and trips after maxRepeatedCalls within window', () => {
  assert.equal(
    fingerprintToolCall('query', { b: 2, a: 1 }),
    fingerprintToolCall('query', { a: 1, b: 2 }),
  );

  const breaker = new CallLoopBreaker({ enabled: true, maxRepeatedCalls: 3, windowMs: 10_000 });
  assert.equal(breaker.recordAndCheck('search', { q: 'status' }, 1_000), null);
  assert.equal(breaker.recordAndCheck('search', { q: 'status' }, 2_000), null);
  assert.equal(breaker.recordAndCheck('search', { q: 'status' }, 3_000), null);

  // 4th identical call within 10s trips the circuit breaker.
  const tripped = breaker.recordAndCheck('search', { q: 'status' }, 4_000);
  assert.ok(tripped);
  assert.equal(tripped.ruleId, 'runtime.call_loop_detected');

  // Different argument still passes.
  assert.equal(breaker.recordAndCheck('search', { q: 'other' }, 4_500), null);

  // Once the 10s window expires, previous calls age out cleanly.
  assert.equal(breaker.recordAndCheck('search', { q: 'status' }, 20_000), null);
});
