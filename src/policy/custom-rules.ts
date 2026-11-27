import type { CustomRuleConfig, CustomRuleDirection, RuleFinding } from './types.js';

const MAX_REGEX_LENGTH = 256;

// Rejects classic catastrophic backtracking constructs (nested quantifiers and backreferences).
const NESTED_QUANTIFIER_PATTERN = /\((?:[^()\\]|\\.)*[+*](?:[^()\\]|\\.)*\)[+*{]/;
const REPEATED_QUANTIFIER_PATTERN = /[+*?]\s*[+*]/;
const BACKREFERENCE_PATTERN = /\\[1-9]/;

export class UnsafeRegexError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'UnsafeRegexError';
  }
}

export function assertSafeRegexPattern(pattern: string): void {
  if (pattern.length === 0 || pattern.length > MAX_REGEX_LENGTH) {
    throw new UnsafeRegexError(`Regex pattern length must be between 1 and ${MAX_REGEX_LENGTH} characters`);
  }
  if (NESTED_QUANTIFIER_PATTERN.test(pattern) || REPEATED_QUANTIFIER_PATTERN.test(pattern)) {
    throw new UnsafeRegexError(`Regex pattern "${pattern}" contains nested quantifiers with ReDoS risk`);
  }
  if (BACKREFERENCE_PATTERN.test(pattern)) {
    throw new UnsafeRegexError(`Regex pattern "${pattern}" contains backreferences which are disallowed`);
  }
  try {
    new RegExp(pattern);
  } catch (err) {
    const detail = err instanceof Error ? err.message : String(err);
    throw new UnsafeRegexError(`Invalid regex pattern "${pattern}": ${detail}`);
  }
}

export function matchCustomRuleValue(rule: CustomRuleConfig, value: string): string | null {
  const caseSensitive = rule.caseSensitive ?? false;

  if (rule.match === 'contains') {
    const haystack = caseSensitive ? value : value.toLowerCase();
    const needle = caseSensitive ? rule.pattern : rule.pattern.toLowerCase();
    const idx = haystack.indexOf(needle);
    return idx === -1 ? null : value.slice(idx, idx + rule.pattern.length).slice(0, 80);
  }

  if (rule.match === 'prefix') {
    const haystack = caseSensitive ? value : value.toLowerCase();
    const needle = caseSensitive ? rule.pattern : rule.pattern.toLowerCase();
    return haystack.startsWith(needle) ? value.slice(0, Math.min(80, rule.pattern.length)) : null;
  }

  assertSafeRegexPattern(rule.pattern);
  const regex = new RegExp(rule.pattern, caseSensitive ? '' : 'i');
  const match = regex.exec(value);
  return match ? match[0].slice(0, 80) : null;
}

export function evaluateCustomRulesForLeaf(
  rules: readonly CustomRuleConfig[],
  direction: Exclude<CustomRuleDirection, 'both'>,
  toolName: string | undefined,
  leafPath: string,
  leafValue: string,
  matchTool: (tool: string, pattern: string) => boolean,
): RuleFinding[] {
  if (rules.length === 0) return [];
  const findings: RuleFinding[] = [];

  for (const rule of rules) {
    if (rule.direction !== 'both' && rule.direction !== direction) continue;
    if (rule.toolPattern && (!toolName || !matchTool(toolName, rule.toolPattern))) continue;

    const matched = matchCustomRuleValue(rule, leafValue);
    if (matched !== null) {
      findings.push({
        ruleId: rule.id,
        category: 'custom_rule',
        severity: rule.severity,
        summary: rule.summary,
        path: leafPath,
        matchPreview: matched,
      });
    }
  }

  return findings;
}
