export type EnforcementMode = 'enforce' | 'audit';

export type Severity = 'low' | 'medium' | 'high' | 'critical';

export type FindingCategory =
  | 'tool_policy'
  | 'secret_leak'
  | 'destructive_command'
  | 'path_violation'
  | 'prompt_injection'
  | 'rate_limit';

export type PolicyDecision = 'allow' | 'warn' | 'block';

export interface RuleFinding {
  ruleId: string;
  category: FindingCategory;
  severity: Severity;
  summary: string;
  path?: string;
  matchPreview?: string;
}

export interface EvaluationResult {
  decision: PolicyDecision;
  highestSeverity: Severity | null;
  findings: RuleFinding[];
}

export interface LoopProtectionConfig {
  enabled: boolean;
  maxRepeatedCalls: number;
  windowMs: number;
}

export interface SentinelConfig {
  mode: EnforcementMode;
  blockOnSeverity: Severity;
  redactResponses: boolean;
  allowedTools: string[];
  deniedTools: string[];
  allowedRoots: string[];
  detectSecrets: boolean;
  detectDestructiveCommands: boolean;
  detectPromptInjection: boolean;
  maxPayloadBytes: number;
  loopProtection: LoopProtectionConfig;
}

export const SEVERITY_RANK: Readonly<Record<Severity, number>> = {
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

export function compareSeverity(a: Severity, b: Severity): number {
  return SEVERITY_RANK[a] - SEVERITY_RANK[b];
}

export function maxSeverity(findings: readonly RuleFinding[]): Severity | null {
  let highest: Severity | null = null;
  for (const finding of findings) {
    if (highest === null || SEVERITY_RANK[finding.severity] > SEVERITY_RANK[highest]) {
      highest = finding.severity;
    }
  }
  return highest;
}
