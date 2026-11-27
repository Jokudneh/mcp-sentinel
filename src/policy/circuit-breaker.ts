import { createHash } from 'node:crypto';
import type { LoopProtectionConfig, RuleFinding } from './types.js';

const MAX_TRACKED_SIGNATURES = 1_024;
const MAX_CANONICAL_DEPTH = 10;

function canonicalize(value: unknown, depth: number): unknown {
  if (depth > MAX_CANONICAL_DEPTH || value === null || value === undefined || typeof value !== 'object') {
    return value;
  }
  if (Array.isArray(value)) {
    return value.map((item) => canonicalize(item, depth + 1));
  }
  const sorted: Record<string, unknown> = {};
  for (const key of Object.keys(value as Record<string, unknown>).sort()) {
    sorted[key] = canonicalize((value as Record<string, unknown>)[key], depth + 1);
  }
  return sorted;
}

export function fingerprintToolCall(toolName: string, args: Record<string, unknown>): string {
  const canonical = JSON.stringify(canonicalize(args, 0));
  return createHash('sha256').update(toolName).update('\0').update(canonical).digest('hex').slice(0, 16);
}

export class CallLoopBreaker {
  private readonly config: LoopProtectionConfig;
  private readonly history = new Map<string, number[]>();

  constructor(config: LoopProtectionConfig) {
    this.config = config;
  }

  recordAndCheck(
    toolName: string,
    args: Record<string, unknown>,
    nowMs: number = Date.now(),
  ): RuleFinding | null {
    if (!this.config.enabled) return null;

    const sig = fingerprintToolCall(toolName, args);
    const cutoff = nowMs - this.config.windowMs;
    const prev = this.history.get(sig) ?? [];
    const active = prev.filter((ts) => ts >= cutoff);
    active.push(nowMs);

    // Refresh insertion order for bounded LRU eviction.
    this.history.delete(sig);
    this.history.set(sig, active);
    while (this.history.size > MAX_TRACKED_SIGNATURES) {
      const oldest = this.history.keys().next().value;
      if (oldest === undefined) break;
      this.history.delete(oldest);
    }

    if (active.length > this.config.maxRepeatedCalls) {
      return {
        ruleId: 'runtime.call_loop_detected',
        category: 'rate_limit',
        severity: 'high',
        summary: `Identical "${toolName}" call repeated ${active.length} times within ${this.config.windowMs}ms (limit: ${this.config.maxRepeatedCalls})`,
        path: 'params.name',
        matchPreview: `${toolName}#${sig.slice(0, 8)}`,
      };
    }

    return null;
  }
}
