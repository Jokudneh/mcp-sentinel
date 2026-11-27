import assert from 'node:assert/strict';
import test from 'node:test';
import { DEFAULT_CONFIG } from '../src/policy/config.js';
import {
  generatePolicyKeyPair,
  PolicySignatureError,
  signPolicyConfig,
  verifySignedPolicyBundle,
} from '../src/policy/signature.js';

test('signs and verifies a SentinelConfig bundle with Ed25519', () => {
  const { privateKeyPem, publicKeyPem } = generatePolicyKeyPair();
  const bundle = signPolicyConfig(
    { ...DEFAULT_CONFIG, deniedTools: ['drop_*', '*_destroy'] },
    privateKeyPem,
    { keyId: 'sec-2026', expiresAt: new Date('2099-01-01T00:00:00.000Z') },
  );

  // Permute JSON key order to confirm canonical serialization invariance.
  const reordered = JSON.parse(
    JSON.stringify({
      signature: bundle.signature,
      policy: { ...bundle.policy, deniedTools: bundle.policy.deniedTools, mode: bundle.policy.mode },
      expiresAt: bundle.expiresAt,
      signedAt: bundle.signedAt,
      keyId: bundle.keyId,
      algorithm: bundle.algorithm,
      formatVersion: bundle.formatVersion,
    }),
  );

  const verified = verifySignedPolicyBundle(reordered, publicKeyPem, { expectedKeyId: 'sec-2026' });
  assert.equal(verified.mode, 'enforce');
  assert.deepEqual(verified.deniedTools, ['drop_*', '*_destroy']);
});

test('rejects tampered policy, wrong public key, and expired bundle', () => {
  const kp1 = generatePolicyKeyPair();
  const kp2 = generatePolicyKeyPair();
  const bundle = signPolicyConfig(DEFAULT_CONFIG, kp1.privateKeyPem, {
    keyId: 'k1',
    expiresAt: new Date('2026-01-01T00:00:00.000Z'),
  });

  // 1. Tampered policy (mode flipped enforce -> audit)
  const tampered = structuredClone(bundle);
  tampered.policy.mode = 'audit';
  assert.throws(
    () => verifySignedPolicyBundle(tampered, kp1.publicKeyPem, { now: new Date('2025-06-01T00:00:00.000Z') }),
    PolicySignatureError,
  );

  // 2. Wrong public key
  assert.throws(
    () => verifySignedPolicyBundle(bundle, kp2.publicKeyPem, { now: new Date('2025-06-01T00:00:00.000Z') }),
    PolicySignatureError,
  );

  // 3. Expired bundle
  assert.throws(
    () => verifySignedPolicyBundle(bundle, kp1.publicKeyPem, { now: new Date('2026-06-01T00:00:00.000Z') }),
    /expired/i,
  );
});
