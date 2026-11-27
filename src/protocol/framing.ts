export type FramingMode = 'ndjson' | 'content-length';

export interface ParsedFrame {
  ok: true;
  mode: FramingMode;
  message: unknown;
  byteLength: number;
}

export interface FrameError {
  ok: false;
  mode: FramingMode;
  error: string;
  rawPreview: string;
}

export type FrameResult = ParsedFrame | FrameError;

const DEFAULT_MAX_BUFFER_BYTES = 16 * 1024 * 1024;
const HEADER_SEPARATOR = Buffer.from('\r\n\r\n', 'ascii');
const LF_HEADER_SEPARATOR = Buffer.from('\n\n', 'ascii');

function previewBuffer(buf: Buffer): string {
  const snippet = buf.subarray(0, 160).toString('utf8').replace(/\s+/g, ' ').trim();
  return buf.length > 160 ? `${snippet}...` : snippet;
}

function parseContentLength(headerBlock: string): number | null {
  const lines = headerBlock.split(/\r?\n/);
  for (const line of lines) {
    const colon = line.indexOf(':');
    if (colon === -1) continue;
    const key = line.slice(0, colon).trim().toLowerCase();
    if (key !== 'content-length') continue;
    const rawValue = line.slice(colon + 1).trim();
    if (!/^\d+$/.test(rawValue)) return null;
    const parsed = Number.parseInt(rawValue, 10);
    if (!Number.isSafeInteger(parsed) || parsed < 0) return null;
    return parsed;
  }
  return null;
}

const HEADER_PREFIXES = ['content-length:', 'content-type:'] as const;

function classifyHeaderPrefix(buffer: Buffer): 'header' | 'partial' | 'none' {
  const head = buffer.subarray(0, 32).toString('ascii').toLowerCase();
  for (const prefix of HEADER_PREFIXES) {
    if (head.startsWith(prefix)) {
      return 'header';
    }
    if (head.length < prefix.length && prefix.startsWith(head)) {
      return 'partial';
    }
  }
  return 'none';
}

export class MessageFramer {
  private buffer: Buffer = Buffer.alloc(0);
  private readonly maxBufferBytes: number;
  private detectedMode: FramingMode = 'ndjson';

  constructor(maxBufferBytes: number = DEFAULT_MAX_BUFFER_BYTES) {
    this.maxBufferBytes = maxBufferBytes;
  }

  get mode(): FramingMode {
    return this.detectedMode;
  }

  push(chunk: Buffer): FrameResult[] {
    if (chunk.length === 0) return [];
    this.buffer = this.buffer.length === 0 ? chunk : Buffer.concat([this.buffer, chunk]);

    if (this.buffer.length > this.maxBufferBytes) {
      const preview = previewBuffer(this.buffer);
      this.buffer = Buffer.alloc(0);
      return [
        {
          ok: false,
          mode: this.detectedMode,
          error: `Frame exceeded maximum buffer size (${this.maxBufferBytes} bytes)`,
          rawPreview: preview,
        },
      ];
    }

    const results: FrameResult[] = [];

    while (this.buffer.length > 0) {
      // Trim leading blank lines between NDJSON frames without eating header starts.
      let start = 0;
      while (start < this.buffer.length && (this.buffer[start] === 0x0a || this.buffer[start] === 0x0d)) {
        start += 1;
      }
      if (start > 0) {
        this.buffer = this.buffer.subarray(start);
        if (this.buffer.length === 0) break;
      }

      const headerKind = classifyHeaderPrefix(this.buffer);
      if (headerKind === 'partial') {
        // Wait for remaining header prefix bytes before choosing framing mode.
        break;
      }

      if (headerKind === 'header') {
        const crlfIdx = this.buffer.indexOf(HEADER_SEPARATOR);
        const lfIdx = crlfIdx === -1 ? this.buffer.indexOf(LF_HEADER_SEPARATOR) : -1;
        const sepIdx = crlfIdx !== -1 ? crlfIdx : lfIdx;
        const sepLen = crlfIdx !== -1 ? 4 : 2;

        if (sepIdx === -1) {
          // Wait for remaining header bytes.
          break;
        }

        const headerText = this.buffer.subarray(0, sepIdx).toString('ascii');
        const contentLength = parseContentLength(headerText);
        if (contentLength === null || contentLength > this.maxBufferBytes) {
          const bad = this.buffer.subarray(0, sepIdx + sepLen);
          this.buffer = this.buffer.subarray(sepIdx + sepLen);
          results.push({
            ok: false,
            mode: 'content-length',
            error: 'Invalid or oversized Content-Length header',
            rawPreview: previewBuffer(bad),
          });
          continue;
        }

        const bodyStart = sepIdx + sepLen;
        const frameEnd = bodyStart + contentLength;
        if (this.buffer.length < frameEnd) {
          // Incomplete body; wait for more chunks.
          break;
        }

        this.detectedMode = 'content-length';
        const body = this.buffer.subarray(bodyStart, frameEnd);
        this.buffer = this.buffer.subarray(frameEnd);
        results.push(this.parseJsonBody(body, 'content-length'));
        continue;
      }

      // If buffer is very short and might be a partial "Content-Length:" header, wait until newline or mismatch.
      if (this.buffer.length < 15 && 'content-length:'.startsWith(this.buffer.toString('ascii').toLowerCase())) {
        break;
      }

      const newlineIdx = this.buffer.indexOf(0x0a);
      if (newlineIdx === -1) {
        break;
      }

      let lineEnd = newlineIdx;
      if (lineEnd > 0 && this.buffer[lineEnd - 1] === 0x0d) {
        lineEnd -= 1;
      }

      const line = this.buffer.subarray(0, lineEnd);
      this.buffer = this.buffer.subarray(newlineIdx + 1);

      if (line.length === 0) continue;

      this.detectedMode = 'ndjson';
      results.push(this.parseJsonBody(line, 'ndjson'));
    }

    return results;
  }

  private parseJsonBody(body: Buffer, mode: FramingMode): FrameResult {
    try {
      const parsed: unknown = JSON.parse(body.toString('utf8'));
      return {
        ok: true,
        mode,
        message: parsed,
        byteLength: body.length,
      };
    } catch (err) {
      const reason = err instanceof Error ? err.message : 'Malformed JSON';
      return {
        ok: false,
        mode,
        error: `JSON parse error: ${reason}`,
        rawPreview: previewBuffer(body),
      };
    }
  }
}

export function encodeFrame(message: unknown, mode: FramingMode): Buffer {
  const payload = Buffer.from(JSON.stringify(message), 'utf8');
  if (mode === 'content-length') {
    const header = Buffer.from(`Content-Length: ${payload.length}\r\n\r\n`, 'ascii');
    return Buffer.concat([header, payload]);
  }
  return Buffer.concat([payload, Buffer.from('\n', 'ascii')]);
}
