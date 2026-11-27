export type JsonRpcId = string | number | null;

export interface JsonObject {
  [key: string]: unknown;
}

export interface JsonRpcRequest {
  jsonrpc: '2.0';
  id: JsonRpcId;
  method: string;
  params?: unknown;
}

export interface JsonRpcNotification {
  jsonrpc: '2.0';
  method: string;
  params?: unknown;
}

export interface JsonRpcErrorObject {
  code: number;
  message: string;
  data?: unknown;
}

export interface JsonRpcSuccessResponse {
  jsonrpc: '2.0';
  id: JsonRpcId;
  result: unknown;
}

export interface JsonRpcErrorResponse {
  jsonrpc: '2.0';
  id: JsonRpcId;
  error: JsonRpcErrorObject;
}

export type JsonRpcResponse = JsonRpcSuccessResponse | JsonRpcErrorResponse;
export type JsonRpcMessage = JsonRpcRequest | JsonRpcNotification | JsonRpcResponse;

export interface McpToolCallParams {
  name: string;
  arguments: Record<string, unknown>;
}

export const SENTINEL_BLOCKED_ERROR_CODE = -32001;

export function isJsonObject(value: unknown): value is JsonObject {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

export function isValidJsonRpcId(value: unknown): value is JsonRpcId {
  return typeof value === 'string' || (typeof value === 'number' && Number.isFinite(value)) || value === null;
}

export function isJsonRpcRequest(message: unknown): message is JsonRpcRequest {
  if (!isJsonObject(message)) return false;
  return (
    message['jsonrpc'] === '2.0' &&
    typeof message['method'] === 'string' &&
    'id' in message &&
    isValidJsonRpcId(message['id'])
  );
}

export function isJsonRpcNotification(message: unknown): message is JsonRpcNotification {
  if (!isJsonObject(message)) return false;
  return (
    message['jsonrpc'] === '2.0' &&
    typeof message['method'] === 'string' &&
    !('id' in message)
  );
}

export function isJsonRpcResponse(message: unknown): message is JsonRpcResponse {
  if (!isJsonObject(message)) return false;
  if (message['jsonrpc'] !== '2.0' || !('id' in message) || !isValidJsonRpcId(message['id'])) {
    return false;
  }
  return 'result' in message || isJsonObject(message['error']);
}

export function extractToolCallParams(message: JsonRpcRequest | JsonRpcNotification): McpToolCallParams | null {
  if (message.method !== 'tools/call') return null;
  if (!isJsonObject(message.params)) return null;
  const name = message.params['name'];
  if (typeof name !== 'string' || name.length === 0) return null;
  const rawArgs = message.params['arguments'];
  const args = isJsonObject(rawArgs) ? rawArgs : {};
  return { name, arguments: args };
}

export function createBlockedErrorResponse(
  id: JsonRpcId,
  reason: string,
  data: unknown,
): JsonRpcErrorResponse {
  return {
    jsonrpc: '2.0',
    id,
    error: {
      code: SENTINEL_BLOCKED_ERROR_CODE,
      message: `Blocked by mcp-sentinel: ${reason}`,
      data,
    },
  };
}
