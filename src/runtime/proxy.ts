import { spawn, type ChildProcess } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import type { Readable, Writable } from 'node:stream';
import { evaluateToolCall, evaluateToolResponse } from '../policy/evaluator.js';
import { redactSecretsInValue } from '../policy/secrets.js';
import type { SentinelConfig } from '../policy/types.js';
import { encodeFrame, MessageFramer, type FramingMode } from '../protocol/framing.js';
import {
  createBlockedErrorResponse,
  extractToolCallParams,
  isJsonRpcNotification,
  isJsonRpcRequest,
  isJsonRpcResponse,
  type JsonRpcId,
} from '../protocol/jsonrpc.js';
import { JsonlTracer, type TraceEvent } from './tracer.js';

export interface McpProxyOptions {
  command: string;
  args: string[];
  config: SentinelConfig;
  tracePath?: string;
  cwd?: string;
  env?: NodeJS.ProcessEnv;
  stdin?: Readable;
  stdout?: Writable;
  stderr?: Writable;
  quiet?: boolean;
  onEvent?: (event: TraceEvent) => void;
  formatTelemetry?: (event: TraceEvent) => string | null;
}

interface PendingRequest {
  method: string;
  toolName?: string;
  startedAt: number;
  framingMode: FramingMode;
}

const MAX_PENDING_REQUESTS = 2_048;
const FORCE_KILL_TIMEOUT_MS = 3_000;

function requestKey(id: JsonRpcId): string | null {
  if (id === null) return null;
  return `${typeof id}:${String(id)}`;
}

export async function runStdioProxy(options: McpProxyOptions): Promise<number> {
  const sessionId = randomUUID().slice(0, 8);
  const clientIn = options.stdin ?? process.stdin;
  const clientOut = options.stdout ?? process.stdout;
  const telemetryOut = options.stderr ?? process.stderr;
  const tracer = options.tracePath ? new JsonlTracer(options.tracePath) : null;

  const clientFramer = new MessageFramer(options.config.maxPayloadBytes);
  const serverFramer = new MessageFramer(options.config.maxPayloadBytes);
  const pending = new Map<string, PendingRequest>();

  const child: ChildProcess = spawn(options.command, options.args, {
    cwd: options.cwd,
    env: options.env ?? process.env,
    shell: false,
    stdio: ['pipe', 'pipe', options.stderr ? 'pipe' : 'inherit'],
  });

  if (options.stderr && child.stderr) {
    child.stderr.pipe(options.stderr, { end: false });
  }

  const childStdin = child.stdin;
  const childStdout = child.stdout;
  if (!childStdin || !childStdout) {
    throw new Error('Failed to open stdio pipes to MCP child server');
  }

  const emitEvent = (event: TraceEvent): void => {
    tracer?.record(event);
    options.onEvent?.(event);
    if (!options.quiet && options.formatTelemetry) {
      const line = options.formatTelemetry(event);
      if (line) {
        telemetryOut.write(`${line}\n`);
      }
    }
  };

  const trackPending = (key: string, entry: PendingRequest): void => {
    pending.delete(key);
    pending.set(key, entry);
    while (pending.size > MAX_PENDING_REQUESTS) {
      const oldest = pending.keys().next().value;
      if (oldest === undefined) break;
      pending.delete(oldest);
    }
  };

  const handleClientChunk = (chunk: Buffer): void => {
    const frames = clientFramer.push(chunk);
    for (const frame of frames) {
      const timestamp = new Date().toISOString();
      if (!frame.ok) {
        emitEvent({
          timestamp,
          sessionId,
          direction: 'client->server',
          kind: 'frame_error',
          decision: 'warn',
          findings: [],
          payload: { error: frame.error, rawPreview: frame.rawPreview },
        });
        continue;
      }

      const msg = frame.message;

      if (isJsonRpcRequest(msg) || isJsonRpcNotification(msg)) {
        const isReq = isJsonRpcRequest(msg);
        const toolCall = extractToolCallParams(msg);
        const key = isReq ? requestKey(msg.id) : null;

        if (toolCall) {
          const evalResult = evaluateToolCall(toolCall.name, toolCall.arguments, options.config);
          const event: TraceEvent = {
            timestamp,
            sessionId,
            direction: 'client->server',
            kind: isReq ? 'request' : 'notification',
            decision: evalResult.decision,
            method: msg.method,
            toolName: toolCall.name,
            findings: evalResult.findings,
            payload: toolCall.arguments,
          };
          if (isReq) event.requestId = msg.id;
          emitEvent(event);

          if (evalResult.decision === 'block') {
            if (isReq) {
              const firstSummary = evalResult.findings[0]?.summary ?? 'Policy rule violated';
              const errorResp = createBlockedErrorResponse(msg.id, firstSummary, {
                tool: toolCall.name,
                findings: evalResult.findings,
              });
              clientOut.write(encodeFrame(errorResp, frame.mode));
            }
            continue;
          }
        } else {
          const event: TraceEvent = {
            timestamp,
            sessionId,
            direction: 'client->server',
            kind: isReq ? 'request' : 'notification',
            decision: 'allow',
            method: msg.method,
            findings: [],
          };
          if (isReq) event.requestId = msg.id;
          emitEvent(event);
        }

        if (key !== null) {
          const pendingEntry: PendingRequest = {
            method: msg.method,
            startedAt: performance.now(),
            framingMode: frame.mode,
          };
          if (toolCall) pendingEntry.toolName = toolCall.name;
          trackPending(key, pendingEntry);
        }

        if (!childStdin.destroyed && childStdin.writable) {
          childStdin.write(encodeFrame(msg, frame.mode));
        }
        continue;
      }

      // Forward client-originated responses (e.g. sampling/roots responses) untouched.
      if (!childStdin.destroyed && childStdin.writable) {
        childStdin.write(encodeFrame(msg, frame.mode));
      }
    }
  };

  const handleServerChunk = (chunk: Buffer): void => {
    const frames = serverFramer.push(chunk);
    for (const frame of frames) {
      const timestamp = new Date().toISOString();
      if (!frame.ok) {
        emitEvent({
          timestamp,
          sessionId,
          direction: 'server->client',
          kind: 'frame_error',
          decision: 'warn',
          findings: [],
          payload: { error: frame.error, rawPreview: frame.rawPreview },
        });
        continue;
      }

      const msg = frame.message;

      if (isJsonRpcResponse(msg)) {
        const key = requestKey(msg.id);
        const origin = key !== null ? pending.get(key) : undefined;
        if (key !== null) pending.delete(key);

        const latencyMs =
          origin !== undefined ? Math.round((performance.now() - origin.startedAt) * 10) / 10 : undefined;
        const outMode = origin?.framingMode ?? frame.mode;

        if (origin?.toolName && 'result' in msg) {
          const evalResult = evaluateToolResponse(msg.result, options.config);
          let outboundMessage: unknown = msg;
          let redactedCount = 0;

          if (evalResult.decision === 'block') {
            const firstSummary = evalResult.findings[0]?.summary ?? 'Response violated security policy';
            outboundMessage = createBlockedErrorResponse(msg.id, firstSummary, {
              tool: origin.toolName,
              direction: 'server->client',
              findings: evalResult.findings,
            });
          } else if (options.config.redactResponses && evalResult.findings.some((f) => f.category === 'secret_leak')) {
            const { value, count } = redactSecretsInValue(msg.result);
            redactedCount = count;
            outboundMessage = {
              jsonrpc: '2.0',
              id: msg.id,
              result: value,
            };
          }

          const event: TraceEvent = {
            timestamp,
            sessionId,
            direction: 'server->client',
            kind: 'response',
            decision: evalResult.decision,
            requestId: msg.id,
            method: origin.method,
            toolName: origin.toolName,
            findings: evalResult.findings,
            payload: msg.result,
          };
          if (latencyMs !== undefined) event.latencyMs = latencyMs;
          if (redactedCount > 0) event.redactedSecrets = redactedCount;
          emitEvent(event);

          clientOut.write(encodeFrame(outboundMessage, outMode));
          continue;
        }

        const event: TraceEvent = {
          timestamp,
          sessionId,
          direction: 'server->client',
          kind: 'response',
          decision: 'allow',
          requestId: msg.id,
          findings: [],
        };
        if (origin?.method) event.method = origin.method;
        if (origin?.toolName) event.toolName = origin.toolName;
        if (latencyMs !== undefined) event.latencyMs = latencyMs;
        emitEvent(event);

        clientOut.write(encodeFrame(msg, outMode));
        continue;
      }

      // Server-initiated requests or notifications pass directly to client.
      clientOut.write(encodeFrame(msg, frame.mode));
    }
  };

  let shuttingDown = false;
  const terminateChild = (signal: NodeJS.Signals): void => {
    if (shuttingDown || child.killed || child.exitCode !== null) return;
    shuttingDown = true;
    child.kill(signal);
    const killTimer = setTimeout(() => {
      if (child.exitCode === null) {
        child.kill('SIGKILL');
      }
    }, FORCE_KILL_TIMEOUT_MS);
    killTimer.unref();
  };

  const onSigInt = (): void => terminateChild('SIGINT');
  const onSigTerm = (): void => terminateChild('SIGTERM');

  const onClientEnd = (): void => {
    if (!childStdin.destroyed) {
      childStdin.end();
    }
  };

  clientIn.on('data', handleClientChunk);
  clientIn.on('end', onClientEnd);
  childStdout.on('data', handleServerChunk);
  childStdin.on('error', () => {
    // Ignore EPIPE when child exits before client finishes writing.
  });

  const attachSignals = clientIn === process.stdin;
  if (attachSignals) {
    process.on('SIGINT', onSigInt);
    process.on('SIGTERM', onSigTerm);
  }

  const exitCode = await new Promise<number>((resolveExit, rejectExit) => {
    child.once('error', (err) => rejectExit(err));
    child.once('close', (code, signal) => {
      if (typeof code === 'number') {
        resolveExit(code);
      } else if (signal) {
        resolveExit(128);
      } else {
        resolveExit(0);
      }
    });
  }).finally(async () => {
    clientIn.off('data', handleClientChunk);
    clientIn.off('end', onClientEnd);
    childStdout.off('data', handleServerChunk);
    if (attachSignals) {
      process.off('SIGINT', onSigInt);
      process.off('SIGTERM', onSigTerm);
    }
    await tracer?.close();
  });

  return exitCode;
}
