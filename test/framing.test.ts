import assert from 'node:assert/strict';
import test from 'node:test';
import { encodeFrame, MessageFramer } from '../src/protocol/framing.js';

test('MessageFramer reassembles chunked NDJSON with multi-byte UTF-8 characters', () => {
  const framer = new MessageFramer();
  const wire = Buffer.concat([
    encodeFrame({ jsonrpc: '2.0', id: 1, method: 'ping', params: { text: 'héllo 🚀' } }, 'ndjson'),
    encodeFrame({ jsonrpc: '2.0', id: 2, method: 'tools/list' }, 'ndjson'),
  ]);

  const collected = [];
  for (let i = 0; i < wire.length; i += 5) {
    collected.push(...framer.push(wire.subarray(i, i + 5)));
  }

  assert.equal(collected.length, 2);
  assert.equal(collected[0]?.ok, true);
  assert.equal(collected[1]?.ok, true);
  if (collected[0]?.ok) {
    assert.deepEqual(collected[0].message, {
      jsonrpc: '2.0',
      id: 1,
      method: 'ping',
      params: { text: 'héllo 🚀' },
    });
  }
  assert.equal(framer.mode, 'ndjson');
});

test('MessageFramer parses split Content-Length frames using byte offsets', () => {
  const framer = new MessageFramer();
  const payload = { jsonrpc: '2.0', id: 'abc', result: { emoji: '🛡️🔥' } };
  const wire = encodeFrame(payload, 'content-length');

  const part1 = wire.subarray(0, 10);
  const part2 = wire.subarray(10, 28);
  const part3 = wire.subarray(28);

  assert.deepEqual(framer.push(part1), []);
  assert.deepEqual(framer.push(part2), []);
  const final = framer.push(part3);

  assert.equal(final.length, 1);
  assert.equal(final[0]?.ok, true);
  if (final[0]?.ok) {
    assert.equal(final[0].mode, 'content-length');
    assert.deepEqual(final[0].message, payload);
  }
});

test('MessageFramer recovers cleanly from malformed JSON lines', () => {
  const framer = new MessageFramer();
  const wire = Buffer.from('{broken json\n{"jsonrpc":"2.0","id":7,"result":{"ok":true}}\n', 'utf8');
  const results = framer.push(wire);

  assert.equal(results.length, 2);
  assert.equal(results[0]?.ok, false);
  assert.equal(results[1]?.ok, true);
  if (results[1]?.ok) {
    assert.deepEqual(results[1].message, { jsonrpc: '2.0', id: 7, result: { ok: true } });
  }
});

test('MessageFramer rejects frames exceeding maxBufferBytes', () => {
  const framer = new MessageFramer(32);
  const results = framer.push(Buffer.from('{"a":"this payload is way longer than 32 bytes"}', 'utf8'));

  assert.equal(results.length, 1);
  assert.equal(results[0]?.ok, false);
});
