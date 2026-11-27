import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { assertSafeRegexPattern, UnsafeRegexError } from './custom-rules.js';
import type {
  CustomRuleConfig,
  CustomRuleDirection,
  CustomRuleMatchType,
  EnforcementMode,
  SentinelConfig,
  Severity,
} from './types.js';

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
  loopProtection: {
    enabled: true,
    maxRepeatedCalls: 8,
    windowMs: 30_000,
  },
  customRules: [],
};

const VALID_MODES = new Set<EnforcementMode>(['enforce', 'audit']);
const VALID_SEVERITIES = new Set<Severity>(['low', 'medium', 'high', 'critical']);
const VALID_DIRECTIONS = new Set<CustomRuleDirection>(['request', 'response', 'both']);
const VALID_MATCH_TYPES = new Set<CustomRuleMatchType>(['contains', 'prefix', 'regex']);

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
    loopProtection: { ...DEFAULT_CONFIG.loopProtection },
    customRules: [...DEFAULT_CONFIG.customRules],
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

  if ('loopProtection' in input) {
    const lp = input['loopProtection'];
    if (typeof lp !== 'object' || lp === null || Array.isArray(lp)) {
      throw new ConfigError('Config field "loopProtection" must be an object');
    }
    const lpObj = lp as Record<string, unknown>;
    if ('enabled' in lpObj) {
      config.loopProtection.enabled = assertBoolean(lpObj['enabled'], 'loopProtection.enabled');
    }
    if ('maxRepeatedCalls' in lpObj) {
      const val = lpObj['maxRepeatedCalls'];
      if (typeof val !== 'number' || !Number.isInteger(val) || val < 2 || val > 10_000) {
        throw new ConfigError('Config field "loopProtection.maxRepeatedCalls" must be an integer between 2 and 10000');
      }
      config.loopProtection.maxRepeatedCalls = val;
    }
    if ('windowMs' in lpObj) {
      const val = lpObj['windowMs'];
      if (typeof val !== 'number' || !Number.isInteger(val) || val < 1_000 || val > 3_600_000) {
        throw new ConfigError('Config field "loopProtection.windowMs" must be an integer between 1000 and 3600000');
      }
      config.loopProtection.windowMs = val;
    }
  }

  if ('customRules' in input) {
    const rawRules = input['customRules'];
    if (!Array.isArray(rawRules)) {
      throw new ConfigError('Config field "customRules" must be an array');
    }
    const parsedRules: CustomRuleConfig[] = [];
    for (let i = 0; i < rawRules.length; i += 1) {
      const entry = rawRules[i];
      if (typeof entry !== 'object' || entry === null || Array.isArray(entry)) {
        throw new ConfigError(`customRules[${i}] must be an object`);
      }
      const r = entry as Record<string, unknown>;
      if (typeof r['id'] !== 'string' || r['id'].trim().length === 0) {
        throw new ConfigError(`customRules[${i}].id must be a non-empty string`);
      }
      if (typeof r['direction'] !== 'string' || !VALID_DIRECTIONS.has(r['direction'] as CustomRuleDirection)) {
        throw new ConfigError(`customRules[${i}].direction must be "request", "response", or "both"`);
      }
      if (typeof r['severity'] !== 'string' || !VALID_SEVERITIES.has(r['severity'] as Severity)) {
        throw new ConfigError(`customRules[${i}].severity must be "low", "medium", "high", or "critical"`);
      }
      if (typeof r['summary'] !== 'string' || r['summary'].trim().length === 0) {
        throw new ConfigError(`customRules[${i}].summary must be a non-empty string`);
      }
      if (typeof r['match'] !== 'string' || !VALID_MATCH_TYPES.has(r['match'] as CustomRuleMatchType)) {
        throw new ConfigError(`customRules[${i}].match must be "contains", "prefix", or "regex"`);
      }
      if (typeof r['pattern'] !== 'string' || r['pattern'].length === 0) {
        throw new ConfigError(`customRules[${i}].pattern must be a non-empty string`);
      }
      if (r['match'] === 'regex') {
        try {
          assertSafeRegexPattern(r['pattern']);
        } catch (err) {
          const detail = err instanceof UnsafeRegexError ? err.message : String(err);
          throw new ConfigError(`customRules[${i}].pattern rejected: ${detail}`);
        }
      }
      const rule: CustomRuleConfig = {
        id: r['id'].trim(),
        direction: r['direction'] as CustomRuleDirection,
        severity: r['severity'] as Severity,
        summary: r['summary'].trim(),
        match: r['match'] as CustomRuleMatchType,
        pattern: r['pattern'],
      };
      if ('toolPattern' in r) {
        if (typeof r['toolPattern'] !== 'string' || r['toolPattern'].trim().length === 0) {
          throw new ConfigError(`customRules[${i}].toolPattern must be a non-empty string`);
        }
        rule.toolPattern = r['toolPattern'].trim();
      }
      if ('caseSensitive' in r) {
        rule.caseSensitive = assertBoolean(r['caseSensitive'], `customRules[${i}].caseSensitive`);
      }
      parsedRules.push(rule);
    }
    config.customRules = parsedRules;
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
