import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign as cryptoSign,
  verify as cryptoVerify,
} from 'node:crypto';
import { validateConfig } from './config.js';
import type { SentinelConfig } from './types.js';

export interface PolicyKeyPair {
  privateKeyPem: string;
  publicKeyPem: string;
}

export interface SignedPolicyBundle {
  formatVersion: 1;
  algorithm: 'ed25519';
  keyId: string;
  signedAt: string;
  expiresAt?: string;
  policy: SentinelConfig;
  signature: string;
}

export interface SignPolicyOptions {
  keyId?: string;
  signedAt?: Date;
  expiresAt?: Date;
}

export interface VerifyPolicyOptions {
  now?: Date;
  expectedKeyId?: string;
}

export class PolicySignatureError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'PolicySignatureError';
  }
}

export function canonicalizeJson(value: unknown): string {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalizeJson(item)).join(',')}]`;
  }
  const record = value as Record<string, unknown>;
  const sortedKeys = Object.keys(record)
    .filter((k) => record[k] !== undefined)
    .sort();
  const entries = sortedKeys.map((k) => `${JSON.stringify(k)}:${canonicalizeJson(record[k])}`);
  return `{${entries.join(',')}}`;
}

export function generatePolicyKeyPair(): PolicyKeyPair {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519', {
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    publicKeyEncoding: { type: 'spki', format: 'pem' },
  });
  return { privateKeyPem: privateKey, publicKeyPem: publicKey };
}

function buildSigningPayload(bundle: Omit<SignedPolicyBundle, 'signature'>): Buffer {
  return Buffer.from(`mcp-sentinel-policy-v1\n${canonicalizeJson(bundle)}`, 'utf8');
}

export function signPolicyConfig(
  rawPolicy: unknown,
  privateKeyPem: string,
  options: SignPolicyOptions = {},
): SignedPolicyBundle {
  const policy = validateConfig(rawPolicy);
  const signedAt = (options.signedAt ?? new Date()).toISOString();
  const unsigned: Omit<SignedPolicyBundle, 'signature'> = {
    formatVersion: 1,
    algorithm: 'ed25519',
    keyId: options.keyId?.trim() || 'default',
    signedAt,
    policy,
  };
  if (options.expiresAt !== undefined) {
    unsigned.expiresAt = options.expiresAt.toISOString();
  }

  const privateKey = createPrivateKey(privateKeyPem);
  const sig = cryptoSign(null, buildSigningPayload(unsigned), privateKey).toString('base64');

  return {
    ...unsigned,
    signature: sig,
  };
}

export function verifySignedPolicyBundle(
  rawBundle: unknown,
  publicKeyPem: string,
  options: VerifyPolicyOptions = {},
): SentinelConfig {
  if (rawBundle === null || typeof rawBundle !== 'object' || Array.isArray(rawBundle)) {
    throw new PolicySignatureError('Signed policy bundle must be a JSON object');
  }
  const obj = rawBundle as Record<string, unknown>;
  if (obj['formatVersion'] !== 1) {
    throw new PolicySignatureError(`Unsupported bundle formatVersion: ${String(obj['formatVersion'])}`);
  }
  if (obj['algorithm'] !== 'ed25519') {
    throw new PolicySignatureError(`Unsupported bundle algorithm: ${String(obj['algorithm'])}`);
  }
  if (typeof obj['keyId'] !== 'string' || obj['keyId'].trim().length === 0) {
    throw new PolicySignatureError('Signed policy bundle is missing a valid keyId');
  }
  if (options.expectedKeyId && obj['keyId'] !== options.expectedKeyId) {
    throw new PolicySignatureError(`Unexpected keyId "${obj['keyId']}" (expected "${options.expectedKeyId}")`);
  }
  if (typeof obj['signedAt'] !== 'string' || Number.isNaN(Date.parse(obj['signedAt']))) {
    throw new PolicySignatureError('Signed policy bundle has invalid signedAt timestamp');
  }
  if (obj['expiresAt'] !== undefined) {
    if (typeof obj['expiresAt'] !== 'string' || Number.isNaN(Date.parse(obj['expiresAt']))) {
      throw new PolicySignatureError('Signed policy bundle has invalid expiresAt timestamp');
    }
    const nowMs = (options.now ?? new Date()).getTime();
    if (Date.parse(obj['expiresAt']) <= nowMs) {
      throw new PolicySignatureError(`Signed policy bundle expired at ${obj['expiresAt']}`);
    }
  }
  if (typeof obj['signature'] !== 'string' || obj['signature'].length === 0) {
    throw new PolicySignatureError('Signed policy bundle is missing signature');
  }

  const unsigned: Omit<SignedPolicyBundle, 'signature'> = {
    formatVersion: 1,
    algorithm: 'ed25519',
    keyId: obj['keyId'],
    signedAt: obj['signedAt'],
    policy: obj['policy'] as SentinelConfig,
  };
  if (typeof obj['expiresAt'] === 'string') {
    unsigned.expiresAt = obj['expiresAt'];
  }

  let valid = false;
  try {
    const publicKey = createPublicKey(publicKeyPem);
    const sigBytes = Buffer.from(obj['signature'], 'base64');
    valid = cryptoVerify(null, buildSigningPayload(unsigned), publicKey, sigBytes);
  } catch (err) {
    throw new PolicySignatureError(
      `Signature verification failed: ${err instanceof Error ? err.message : String(err)}`,
    );
  }

  if (!valid) {
    throw new PolicySignatureError('Ed25519 signature verification failed (bundle tampered or wrong key)');
  }

  return validateConfig(obj['policy']);
}
