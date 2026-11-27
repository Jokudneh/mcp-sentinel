import { isAbsolute, normalize, relative, resolve } from 'node:path';
import { scanSecrets } from './secrets.js';
import {
  SEVERITY_RANK,
  maxSeverity,
  type EvaluationResult,
  type PolicyDecision,
  type RuleFinding,
  type SentinelConfig,
  type Severity,
} from './types.js';

interface StringLeaf {
  path: string;
  key: string;
  value: string;
}

interface PatternRule {
  ruleId: string;
  severity: Severity;
  summary: string;
  regex: RegExp;
}

const DESTRUCTIVE_COMMAND_RULES: readonly PatternRule[] = [
  {
    ruleId: 'exec.rm_rf',
    severity: 'critical',
    summary: 'Recursive forced file deletion (rm -rf)',
    regex: /\brm\s+-(?:[a-zA-Z]*r[a-zA-Z]*f|[a-zA-Z]*f[a-zA-Z]*r)\b/i,
  },
  {
    ruleId: 'exec.windows_destructive_del',
    severity: 'critical',
    summary: 'Recursive forced deletion (Remove-Item -Recurse -Force or rd /s /q)',
    regex: /\b(?:Remove-Item\b[^\n]{0,120}-Recurse[^\n]{0,80}-Force|rd\s+\/s\s+\/q|del\s+\/f\s+\/s\s+\/q)\b/i,
  },
  {
    ruleId: 'exec.pipe_to_shell',
    severity: 'critical',
    summary: 'Remote script piped directly into shell interpreter',
    regex: /\b(?:curl|wget)\b[^\n|]{1,180}\|\s*(?:sh|bash|zsh|pwsh|powershell)\b/i,
  },
  {
    ruleId: 'exec.powershell_encoded',
    severity: 'high',
    summary: 'Obfuscated PowerShell encoded command or remote IEX',
    regex: /\b(?:powershell|pwsh)\b[^\n]{0,100}(?:-enc|-encodedcommand)\b|\biex\s*\(\s*(?:irm|invoke-restmethod|iwr)\b/i,
  },
  {
    ruleId: 'exec.disk_or_perm_wipe',
    severity: 'critical',
    summary: 'Raw disk write or world-writable root chmod',
    regex: /\b(?:mkfs\.[a-z0-9]+|dd\s+if=\/dev\/(?:zero|random|urandom)|chmod\s+-R\s+777\s+\/)\b/i,
  },
  {
    ruleId: 'sql.destructive_ddl',
    severity: 'high',
    summary: 'Destructive SQL statement (DROP/TRUNCATE)',
    regex: /\b(?:DROP\s+(?:TABLE|DATABASE|SCHEMA)|TRUNCATE\s+TABLE)\b/i,
  },
];

const SENSITIVE_PATH_RULES: readonly PatternRule[] = [
  {
    ruleId: 'path.ssh_private_key',
    severity: 'critical',
    summary: 'Access to SSH private key or config',
    regex: /(?:^|[\\/])\.ssh[\\/](?:id_[a-z0-9_]+|authorized_keys|config)\b/i,
  },
  {
    ruleId: 'path.cloud_credentials',
    severity: 'critical',
    summary: 'Access to cloud or package registry credentials',
    regex: /(?:^|[\\/])(?:\.aws[\\/]credentials|\.kube[\\/]config|\.docker[\\/]config\.json|\.npmrc|\.pypirc|\.netrc)\b/i,
  },
  {
    ruleId: 'path.dotenv_file',
    severity: 'high',
    summary: 'Access to environment secret file (.env)',
    regex: /(?:^|[\\/])\.env(?:\.[a-z0-9_-]{1,24})?$/i,
  },
  {
    ruleId: 'path.system_auth_file',
    severity: 'critical',
    summary: 'Access to OS password/shadow database',
    regex: /^\/etc\/(?:shadow|gshadow|sudoers)\b/i,
  },
];

const PROMPT_INJECTION_RULES: readonly PatternRule[] = [
  {
    ruleId: 'injection.override_instructions',
    severity: 'high',
    summary: 'Indirect prompt injection attempting to override prior instructions',
    regex: /\b(?:ignore|disregard|forget)\s+(?:all\s+|any\s+)?(?:previous|prior|above|system)\s+(?:instructions|prompts|rules|directives)\b/i,
  },
  {
    ruleId: 'injection.system_prompt_exfil',
    severity: 'high',
    summary: 'Prompt injection attempting to extract system instructions or secrets',
    regex: /\b(?:reveal|print|output|exfiltrate|leak)\s+(?:your\s+|the\s+)?(?:system\s+prompt|hidden\s+instructions|environment\s+variables|api\s+keys)\b/i,
  },
  {
    ruleId: 'injection.delimiter_spoof',
    severity: 'medium',
    summary: 'Suspicious chat role/system delimiter injected inside tool output',
    regex: /<\s*\/?\s*(?:system|developer_instructions|tool_override)\s*>|\[INST\]|<<SYS>>/i,
  },
  {
    ruleId: 'injection.markdown_exfil_image',
    severity: 'high',
    summary: 'Markdown image URL with query payload (potential data exfiltration)',
    regex: /!\[[^\]]{0,64}\]\(https?:\/\/[^\s)?]{4,160}\?[^\s)]{0,200}(?:token|key|secret|data|exfil|env)=/i,
  },
];

const PATH_KEY_HINTS = new Set([
  'path',
  'filepath',
  'file_path',
  'file',
  'filename',
  'dir',
  'directory',
  'target',
  'source',
  'src',
  'dest',
  'destination',
  'cwd',
  'workdir',
  'root',
]);

const MAX_WALK_NODES = 2_000;
const MAX_WALK_DEPTH = 12;

function extractStringLeaves(input: unknown, rootPath: string): StringLeaf[] {
  const leaves: StringLeaf[] = [];
  let visited = 0;

  const walk = (node: unknown, path: string, key: string, depth: number): void => {
    if (visited >= MAX_WALK_NODES || depth > MAX_WALK_DEPTH || node === null || node === undefined) {
      return;
    }
    visited += 1;

    if (typeof node === 'string') {
      if (node.length > 0) {
        leaves.push({ path, key, value: node });
      }
      return;
    }

    if (Array.isArray(node)) {
      for (let i = 0; i < node.length && visited < MAX_WALK_NODES; i += 1) {
        walk(node[i], `${path}[${i}]`, key, depth + 1);
      }
      return;
    }

    if (typeof node === 'object') {
      for (const [k, v] of Object.entries(node)) {
        if (visited >= MAX_WALK_NODES) break;
        walk(v, `${path}.${k}`, k.toLowerCase(), depth + 1);
      }
    }
  };

  walk(input, rootPath, '', 0);
  return leaves;
}

export function matchesToolPattern(toolName: string, pattern: string): boolean {
  if (pattern === '*') return true;
  if (!pattern.includes('*')) return toolName === pattern;

  // Safe wildcard matching without building unescaped RegExp from user input.
  const parts = pattern.split('*');
  let cursor = 0;

  for (let i = 0; i < parts.length; i += 1) {
    const segment = parts[i]!;
    if (segment.length === 0) continue;

    if (i === 0) {
      if (!toolName.startsWith(segment)) return false;
      cursor = segment.length;
    } else if (i === parts.length - 1) {
      if (!toolName.endsWith(segment) || toolName.length - segment.length < cursor) return false;
      cursor = toolName.length;
    } else {
      const idx = toolName.indexOf(segment, cursor);
      if (idx === -1) return false;
      cursor = idx + segment.length;
    }
  }

  return true;
}

function isWithinAllowedRoots(candidatePath: string, allowedRoots: readonly string[]): boolean {
  const resolvedCandidate = resolve(candidatePath);
  for (const root of allowedRoots) {
    const rel = relative(root, resolvedCandidate);
    if (rel === '' || (!rel.startsWith('..') && !isAbsolute(rel))) {
      return true;
    }
  }
  return false;
}

function looksLikePathValue(leaf: StringLeaf): boolean {
  if (PATH_KEY_HINTS.has(leaf.key)) return true;
  const val = leaf.value.trim();
  if (val.includes('\n') || val.length > 512) return false;
  return (
    val.startsWith('/') ||
    val.startsWith('./') ||
    val.startsWith('../') ||
    /^[a-zA-Z]:[\\/]/.test(val) ||
    /(?:^|[\\/])\.(?:env|ssh|aws|kube|npmrc)\b/i.test(val)
  );
}

function decide(findings: readonly RuleFinding[], config: SentinelConfig): EvaluationResult {
  const highest = maxSeverity(findings);
  if (highest === null) {
    return { decision: 'allow', highestSeverity: null, findings: [] };
  }

  const meetsBlockThreshold = SEVERITY_RANK[highest] >= SEVERITY_RANK[config.blockOnSeverity];
  const decision: PolicyDecision =
    config.mode === 'enforce' && meetsBlockThreshold ? 'block' : 'warn';

  return {
    decision,
    highestSeverity: highest,
    findings: [...findings],
  };
}

export function evaluateToolCall(
  toolName: string,
  args: Record<string, unknown>,
  config: SentinelConfig,
): EvaluationResult {
  const findings: RuleFinding[] = [];

  if (config.deniedTools.some((pattern) => matchesToolPattern(toolName, pattern))) {
    findings.push({
      ruleId: 'policy.tool_denied',
      category: 'tool_policy',
      severity: 'critical',
      summary: `Tool "${toolName}" is explicitly blocked by deniedTools policy`,
      path: 'params.name',
    });
  } else if (
    config.allowedTools.length > 0 &&
    !config.allowedTools.some((pattern) => matchesToolPattern(toolName, pattern))
  ) {
    findings.push({
      ruleId: 'policy.tool_not_allowed',
      category: 'tool_policy',
      severity: 'high',
      summary: `Tool "${toolName}" is not listed in allowedTools policy`,
      path: 'params.name',
    });
  }

  const leaves = extractStringLeaves(args, 'arguments');

  for (const leaf of leaves) {
    if (config.detectSecrets) {
      const secrets = scanSecrets(leaf.value);
      for (const secret of secrets) {
        findings.push({
          ruleId: secret.ruleId,
          category: 'secret_leak',
          severity: 'critical',
          summary: `Outbound secret detected (${secret.label})`,
          path: leaf.path,
          matchPreview: secret.preview,
        });
      }
    }

    if (config.detectDestructiveCommands) {
      for (const rule of DESTRUCTIVE_COMMAND_RULES) {
        const match = rule.regex.exec(leaf.value);
        if (match) {
          findings.push({
            ruleId: rule.ruleId,
            category: 'destructive_command',
            severity: rule.severity,
            summary: rule.summary,
            path: leaf.path,
            matchPreview: match[0].slice(0, 80),
          });
        }
      }
    }

    if (looksLikePathValue(leaf)) {
      const trimmed = leaf.value.trim();
      const normalized = normalize(trimmed);

      for (const rule of SENSITIVE_PATH_RULES) {
        if (rule.regex.test(trimmed) || rule.regex.test(normalized)) {
          findings.push({
            ruleId: rule.ruleId,
            category: 'path_violation',
            severity: rule.severity,
            summary: rule.summary,
            path: leaf.path,
            matchPreview: trimmed.slice(0, 80),
          });
        }
      }

      if (trimmed.includes('..') && (normalized.startsWith('..') || /(?:^|[\\/])\.\.(?:[\\/]|$)/.test(trimmed))) {
        findings.push({
          ruleId: 'path.traversal',
          category: 'path_violation',
          severity: 'high',
          summary: 'Parent-directory path traversal segment detected',
          path: leaf.path,
          matchPreview: trimmed.slice(0, 80),
        });
      }

      if (config.allowedRoots.length > 0 && !isWithinAllowedRoots(trimmed, config.allowedRoots)) {
        findings.push({
          ruleId: 'path.outside_allowed_roots',
          category: 'path_violation',
          severity: 'high',
          summary: 'Path resolves outside configured allowedRoots',
          path: leaf.path,
          matchPreview: trimmed.slice(0, 80),
        });
      }
    }
  }

  return decide(findings, config);
}

export function evaluateToolResponse(
  resultPayload: unknown,
  config: SentinelConfig,
): EvaluationResult {
  const findings: RuleFinding[] = [];
  const leaves = extractStringLeaves(resultPayload, 'result');

  for (const leaf of leaves) {
    if (config.detectPromptInjection) {
      for (const rule of PROMPT_INJECTION_RULES) {
        const match = rule.regex.exec(leaf.value);
        if (match) {
          findings.push({
            ruleId: rule.ruleId,
            category: 'prompt_injection',
            severity: rule.severity,
            summary: rule.summary,
            path: leaf.path,
            matchPreview: match[0].slice(0, 80),
          });
        }
      }
    }

    if (config.detectSecrets) {
      const secrets = scanSecrets(leaf.value);
      for (const secret of secrets) {
        findings.push({
          ruleId: secret.ruleId,
          category: 'secret_leak',
          severity: 'high',
          summary: `Secret exposed in tool response (${secret.label})`,
          path: leaf.path,
          matchPreview: secret.preview,
        });
      }
    }
  }

  return decide(findings, config);
}
