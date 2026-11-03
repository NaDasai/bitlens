import { InvalidAccountIdError } from "./accountId.js";
import { RpcError } from "./rpc.js";
import { EngineNotReadyError } from "./engine.js";

/** Normalised error shape shared by every front door (HTTP, CLI, MCP). */
/** Caller supplied something invalid (other than the account id). */
export class InputError extends Error {
  readonly code = "BAD_REQUEST";
}

export interface ErrorPayload {
  error: { code: string; message: string };
}

export function toErrorPayload(e: unknown): { status: number; body: ErrorPayload } {
  if (e instanceof InvalidAccountIdError) return { status: 400, body: { error: { code: e.code, message: e.message } } };
  if (e instanceof InputError) return { status: 400, body: { error: { code: e.code, message: e.message } } };
  if (e instanceof EngineNotReadyError) return { status: 503, body: { error: { code: e.code, message: e.message } } };
  if (e instanceof RpcError) {
    const status = e.code === "UNKNOWN_ACCOUNT" || e.code === "NO_CONTRACT_CODE" ? 404 : 502;
    return { status, body: { error: { code: e.code, message: e.message } } };
  }
  const message = e instanceof Error ? e.message : String(e);
  return { status: 500, body: { error: { code: "INTERNAL", message } } };
}
