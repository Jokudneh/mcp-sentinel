import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';

const CLI_ENTRY = resolve('dist/cli.js');

function runCliProc(args: string[]): { status: number; stdout: string; stderr: string } {
  try {
    const stdout = execFileSync(process.execPath, [CLI_ENTRY, ...args], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    return { status: 0, stdout, stderr: '' };
  } catch (err) {
    const e = err as { status?: number; stdout?: string; stderr?: string };
    return {
      status: e.status ?? 1,
      stdout: e.stdout ?? '',
      stderr: e.stderr ?? '',
    };
  }
}

test('CLI --version and --help exit cleanly', () => {
  const ver = runCliProc(['--version']);
  assert.equal(ver.status, 0);
  assert.match(ver.stdout.trim(), /^\d+\.\d+\.\d+$/);

  const help = runCliProc(['--help']);
  assert.equal(help.status, 0);
  assert.equal(help.stdout.includes('mcp-sentinel proxy'), true);
});

test('CLI init creates config file and refuses overwrite without --force', () => {
  const dir = mkdtempSync(join(tmpdir(), 'mcp-sentinel-cli-'));
  try {
    const cfgPath = join(dir, 'sentinel.config.json');
    const first = runCliProc(['init', cfgPath]);
    assert.equal(first.status, 0);
    assert.equal(existsSync(cfgPath), true);

    const second = runCliProc(['init', cfgPath]);
    assert.equal(second.status, 2);

    const forced = runCliProc(['init', cfgPath, '--force']);
    assert.equal(forced.status, 0);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('CLI check returns exit 0 on safe payload and exit 1 on blocked payload with custom config', () => {
  const dir = mkdtempSync(join(tmpdir(), 'mcp-sentinel-check-'));
  try {
    const safePath = join(dir, 'safe.json');
    const blockedPath = join(dir, 'blocked.json');
    writeFileSync(safePath, JSON.stringify({ name: 'echo', arguments: { text: 'hello' } }), 'utf8');
    writeFileSync(
      blockedPath,
      JSON.stringify({ name: 'db_query', arguments: { host: 'prod-db.internal' } }),
      'utf8',
    );

    const okRes = runCliProc(['check', safePath, '--json']);
    assert.equal(okRes.status, 0);
    assert.equal(JSON.parse(okRes.stdout).decision, 'allow');

    const blockedRes = runCliProc([
      'check',
      blockedPath,
      '--config',
      resolve('sentinel.config.example.json'),
      '--json',
    ]);
    assert.equal(blockedRes.status, 1);
    const parsed = JSON.parse(blockedRes.stdout) as { decision: string; findings: Array<{ ruleId: string }> };
    assert.equal(parsed.decision, 'block');
    assert.equal(parsed.findings[0]?.ruleId, 'custom.no_prod_db_host');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('CLI inspect exports json, markdown, and SARIF 2.1.0 formats', () => {
  const dir = mkdtempSync(join(tmpdir(), 'mcp-sentinel-inspect-'));
  try {
    const tracePath = join(dir, 'sample.jsonl');
    const event = {
      timestamp: '2026-11-27T18:00:00.000Z',
      sessionId: 'sess0001',
      direction: 'client->server',
      kind: 'request',
      decision: 'block',
      requestId: 9,
      method: 'tools/call',
      toolName: 'read_file',
      findings: [
        {
          ruleId: 'path.dotenv_file',
          category: 'path_violation',
          severity: 'high',
          summary: 'Access to environment secret file (.env)',
          path: 'arguments.path',
          matchPreview: '.env',
        },
      ],
    };
    writeFileSync(tracePath, `${JSON.stringify(event)}\n`, 'utf8');

    const sarifOut = runCliProc(['inspect', tracePath, '--format', 'sarif']);
    assert.equal(sarifOut.status, 0);
    const sarif = JSON.parse(sarifOut.stdout) as { version: string; runs: Array<{ results: unknown[] }> };
    assert.equal(sarif.version, '2.1.0');
    assert.equal(sarif.runs[0]?.results.length, 1);

    const mdOut = runCliProc(['inspect', tracePath, '--format', 'markdown']);
    assert.equal(mdOut.status, 0);
    assert.equal(mdOut.stdout.includes('`path.dotenv_file`'), true);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
