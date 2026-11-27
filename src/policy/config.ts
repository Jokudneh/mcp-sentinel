import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import type { EnforcementMode, SentinelConfig, Severity } from './types.js';

export class ConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ConfigError';
  }
}

export const DEFAULT_CONFIG: Readonly<SentinelConfig> = {
  mode: 'enforce',
  blockOnSeverity: 'high',
  redactResponses: true,
  allowedTools: [],
  deniedTools: [],
  allowedRoots: [],
  detectSecrets: true,
  detectDestructiveCommands: true,
  detectPromptInjection: true,
  maxPayloadBytes: 4 * 1024 * 1024,
};

const VALID_MODES = new Set<EnforcementMode>(['enforce', 'audit']);
const VALID_SEVERITIES = new Set<Severity>(['low', 'medium', 'high', 'critical']);

function assertStringArray(value: unknown, field: string): string[] {
  if (!Array.isArray(value) || !value.every((item) => typeof item === 'string')) {
    throw new ConfigError(`Config field "${field}" must be an array of strings`);
  }
  return value.map((item) => item.trim()).filter((item) => item.length > 0);
}

function assertBoolean(value: unknown, field: string): boolean {
  if (typeof value !== 'boolean') {
    throw new ConfigError(`Config field "${field}" must be a boolean`);
  }
  return value;
}

export function validateConfig(raw: unknown): SentinelConfig {
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
    throw new ConfigError('Configuration root must be a JSON object');
  }

  const input = raw as Record<string, unknown>;
  const config: SentinelConfig = {
    ...DEFAULT_CONFIG,
    allowedTools: [...DEFAULT_CONFIG.allowedTools],
    deniedTools: [...DEFAULT_CONFIG.deniedTools],
    allowedRoots: [...DEFAULT_CONFIG.allowedRoots],
  };

  if ('mode' in input) {
    if (typeof input['mode'] !== 'string' || !VALID_MODES.has(input['mode'] as EnforcementMode)) {
      throw new ConfigError('Config field "mode" must be "enforce" or "audit"');
    }
    config.mode = input['mode'] as EnforcementMode;
  }

  if ('blockOnSeverity' in input) {
    if (
      typeof input['blockOnSeverity'] !== 'string' ||
      !VALID_SEVERITIES.has(input['blockOnSeverity'] as Severity)
    ) {
      throw new ConfigError('Config field "blockOnSeverity" must be "low", "medium", "high", or "critical"');
    }
    config.blockOnSeverity = input['blockOnSeverity'] as Severity;
  }

  if ('redactResponses' in input) {
    config.redactResponses = assertBoolean(input['redactResponses'], 'redactResponses');
  }
  if ('allowedTools' in input) {
    config.allowedTools = assertStringArray(input['allowedTools'], 'allowedTools');
  }
  if ('deniedTools' in input) {
    config.deniedTools = assertStringArray(input['deniedTools'], 'deniedTools');
  }
  if ('allowedRoots' in input) {
    config.allowedRoots = assertStringArray(input['allowedRoots'], 'allowedRoots').map((p) => resolve(p));
  }
  if ('detectSecrets' in input) {
    config.detectSecrets = assertBoolean(input['detectSecrets'], 'detectSecrets');
  }
  if ('detectDestructiveCommands' in input) {
    config.detectDestructiveCommands = assertBoolean(
      input['detectDestructiveCommands'],
      'detectDestructiveCommands',
    );
  }
  if ('detectPromptInjection' in input) {
    config.detectPromptInjection = assertBoolean(input['detectPromptInjection'], 'detectPromptInjection');
  }
  if ('maxPayloadBytes' in input) {
    const val = input['maxPayloadBytes'];
    if (typeof val !== 'number' || !Number.isInteger(val) || val < 1024 || val > 64 * 1024 * 1024) {
      throw new ConfigError('Config field "maxPayloadBytes" must be an integer between 1024 and 67108864');
    }
    config.maxPayloadBytes = val;
  }

  return config;
}

export function loadConfigFile(filePath: string): SentinelConfig {
  let rawText: string;
  try {
    rawText = readFileSync(filePath, 'utf8');
  } catch (err) {
    const detail = err instanceof Error ? err.message : String(err);
    throw new ConfigError(`Unable to read config file "${filePath}": ${detail}`);
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(rawText);
  } catch (err) {
    const detail = err instanceof Error ? err.message : String(err);
    throw new ConfigError(`Invalid JSON in config file "${filePath}": ${detail}`);
  }

  return validateConfig(parsed);
}

export function serializeDefaultConfig(): string {
  return `${JSON.stringify(DEFAULT_CONFIG, null, 2)}\n`;
}
