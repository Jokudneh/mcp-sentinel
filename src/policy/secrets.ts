export interface SecretMatch {
  ruleId: string;
  label: string;
  start: number;
  end: number;
  preview: string;
}

interface SecretPattern {
  ruleId: string;
  label: string;
  regex: RegExp;
  minEntropy?: number;
  captureGroup?: number;
}

// All regexes use bounded character classes and no nested quantifiers to guarantee linear-time execution.
const SECRET_PATTERNS: readonly SecretPattern[] = [
  {
    ruleId: 'secret.private_key_pem',
    label: 'Private key PEM block',
    regex: /-----BEGIN [A-Z0-9 ]{0,32}PRIVATE KEY-----/g,
  },
  {
    ruleId: 'secret.aws_access_key',
    label: 'AWS access key ID',
    regex: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g,
  },
  {
    ruleId: 'secret.github_token',
    label: 'GitHub personal access token',
    regex: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,80}\b|\bgithub_pat_[A-Za-z0-9_]{30,100}\b/g,
  },
  {
    ruleId: 'secret.anthropic_key',
    label: 'Anthropic API key',
    regex: /\bsk-ant-[A-Za-z0-9_-]{24,120}\b/g,
  },
  {
    ruleId: 'secret.openai_key',
    label: 'OpenAI API key',
    regex: /\bsk-(?:proj|live|svcacct)-[A-Za-z0-9_-]{24,160}\b/g,
  },
  {
    ruleId: 'secret.google_api_key',
    label: 'Google API key',
    regex: /\bAIza[0-9A-Za-z_-]{35}\b/g,
  },
  {
    ruleId: 'secret.slack_token',
    label: 'Slack token',
    regex: /\bxox[baprs]-[0-9A-Za-z-]{16,80}\b/g,
  },
  {
    ruleId: 'secret.stripe_live_key',
    label: 'Stripe live key',
    regex: /\b(?:sk|rk)_live_[0-9A-Za-z]{20,99}\b/g,
  },
  {
    ruleId: 'secret.high_entropy_assignment',
    label: 'High-entropy credential assignment',
    regex: /\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|secret[_-]?key|password)\s{0,4}[:=]\s{0,4}["']?([A-Za-z0-9/+_.-]{20,128})["']?/gi,
    captureGroup: 1,
    minEntropy: 3.7,
  },
  {
    ruleId: 'secret.bearer_token',
    label: 'High-entropy Bearer token',
    regex: /\bBearer\s+([A-Za-z0-9._~+/=-]{24,256})\b/g,
    captureGroup: 1,
    minEntropy: 3.8,
  },
];

const PLACEHOLDER_TOKENS = new Set([
  'your_api_key_here',
  'your-api-key-here',
  'example_secret_value',
  'changeme_placeholder',
  'xxxxxxxxxxxxxxxxxxxx',
]);

export function shannonEntropy(input: string): number {
  if (input.length === 0) return 0;
  const counts = new Map<string, number>();
  for (let i = 0; i < input.length; i += 1) {
    const ch = input[i]!;
    counts.set(ch, (counts.get(ch) ?? 0) + 1);
  }
  let entropy = 0;
  for (const count of counts.values()) {
    const p = count / input.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function maskPreview(secret: string): string {
  if (secret.length <= 8) return '***';
  return `${secret.slice(0, 4)}...${secret.slice(-3)}`;
}

function looksLikePlaceholder(candidate: string): boolean {
  const lower = candidate.toLowerCase();
  if (PLACEHOLDER_TOKENS.has(lower)) return true;
  return lower.includes('example') || lower.includes('placeholder') || lower.includes('dummy');
}

export function scanSecrets(text: string): SecretMatch[] {
  if (text.length < 16) return [];
  const matches: SecretMatch[] = [];

  for (const pattern of SECRET_PATTERNS) {
    pattern.regex.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = pattern.regex.exec(text)) !== null) {
      const fullMatch = match[0];
      const token = pattern.captureGroup !== undefined ? match[pattern.captureGroup] : fullMatch;
      if (!token) continue;

      if (pattern.minEntropy !== undefined) {
        if (looksLikePlaceholder(token)) continue;
        if (shannonEntropy(token) < pattern.minEntropy) continue;
      }

      const tokenOffset =
        pattern.captureGroup !== undefined ? match.index + fullMatch.indexOf(token) : match.index;

      matches.push({
        ruleId: pattern.ruleId,
        label: pattern.label,
        start: tokenOffset,
        end: tokenOffset + token.length,
        preview: maskPreview(token),
      });
    }
  }

  return deduplicateOverlaps(matches);
}

function deduplicateOverlaps(matches: SecretMatch[]): SecretMatch[] {
  if (matches.length <= 1) return matches;
  const sorted = [...matches].sort((a, b) => a.start - b.start || b.end - a.end);
  const kept: SecretMatch[] = [];
  for (const candidate of sorted) {
    const prev = kept[kept.length - 1];
    if (!prev || candidate.start >= prev.end) {
      kept.push(candidate);
    }
  }
  return kept;
}

export function redactSecretsInText(text: string): { redacted: string; matches: SecretMatch[] } {
  const matches = scanSecrets(text);
  if (matches.length === 0) {
    return { redacted: text, matches: [] };
  }

  let cursor = 0;
  let output = '';
  for (const match of matches) {
    output += text.slice(cursor, match.start);
    output += `[REDACTED:${match.ruleId}]`;
    cursor = match.end;
  }
  output += text.slice(cursor);

  return { redacted: output, matches };
}

export function redactSecretsInValue(value: unknown, maxDepth = 12): { value: unknown; count: number } {
  let count = 0;
  const seen = new WeakSet<object>();

  const walk = (node: unknown, depth: number): unknown => {
    if (depth > maxDepth || node === null || node === undefined) return node;
    if (typeof node === 'string') {
      const { redacted, matches } = redactSecretsInText(node);
      count += matches.length;
      return redacted;
    }
    if (typeof node !== 'object') return node;
    if (seen.has(node)) return '[Circular]';
    seen.add(node);

    if (Array.isArray(node)) {
      return node.map((item) => walk(item, depth + 1));
    }

    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(node)) {
      out[k] = walk(v, depth + 1);
    }
    return out;
  };

  return { value: walk(value, 0), count };
}
