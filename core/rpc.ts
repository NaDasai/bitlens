/**
 * Minimal NEAR JSON-RPC client. Read-only: only `query` view requests are
 * ever sent. NEAR X-Ray never signs or submits transactions to any network.
 */
import { EnvHttpProxyAgent, fetch as undiciFetch } from "undici";
import { assertAccountId } from "./accountId.js";

// Node's global fetch ignores HTTPS_PROXY. If a proxy is configured, route RPC
// calls through it (NO_PROXY is honoured, so local test RPCs still go direct).
const PROXY_SET = Boolean(
  process.env.HTTPS_PROXY || process.env.https_proxy || process.env.HTTP_PROXY || process.env.http_proxy,
);
const proxyAgent = PROXY_SET ? new EnvHttpProxyAgent() : undefined;
/** fetch that honours HTTPS_PROXY / NO_PROXY (Node's built-in fetch ignores them). */
export const httpFetch = (url: string, init: Parameters<typeof undiciFetch>[1]) =>
  proxyAgent ? undiciFetch(url, { ...init, dispatcher: proxyAgent }) : undiciFetch(url, init);

export const DEFAULT_RPC_URLS = [
  "https://free.rpc.fastnear.com",
  "https://rpc.mainnet.near.org",
];

export type RpcErrorCode =
  | "UNKNOWN_ACCOUNT"
  | "NO_CONTRACT_CODE"
  | "RPC_UNAVAILABLE"
  | "RPC_ERROR";

export class RpcError extends Error {
  constructor(
    readonly code: RpcErrorCode,
    message: string,
  ) {
    super(message);
  }
}

export interface RpcOptions {
  /** Explicit RPC URL(s). Defaults to $NEAR_RPC_URL, then DEFAULT_RPC_URLS (tried in order). */
  rpcUrls?: string[];
  timeoutMs?: number;
}

export function rpcUrlsFrom(opts?: RpcOptions): string[] {
  if (opts?.rpcUrls?.length) return opts.rpcUrls;
  const env = process.env.NEAR_RPC_URL;
  if (env) return env.split(",").map((s) => s.trim()).filter(Boolean);
  return DEFAULT_RPC_URLS;
}

/** Map a JSON-RPC error object onto our error codes. Handles old and new nearcore shapes. */
function classifyRpcError(accountId: string, err: any): RpcError {
  const causeName: string | undefined = err?.cause?.name;
  const text = JSON.stringify(err ?? {});
  if (causeName === "UNKNOWN_ACCOUNT" || /does not exist while viewing|UnknownAccount/i.test(text)) {
    return new RpcError("UNKNOWN_ACCOUNT", `Account "${accountId}" does not exist on this network.`);
  }
  if (causeName === "NO_CONTRACT_CODE" || /has never been deployed|NoContractCode|CodeDoesNotExist/i.test(text)) {
    return new RpcError(
      "NO_CONTRACT_CODE",
      `Account "${accountId}" exists but has no contract deployed (it is a plain wallet account).`,
    );
  }
  return new RpcError("RPC_ERROR", `RPC error for "${accountId}": ${err?.message ?? text}`);
}

async function rpcQuery<T>(params: Record<string, unknown>, opts?: RpcOptions): Promise<{ result: T; rpcUrl: string }> {
  const accountId = String(params.account_id);
  const urls = rpcUrlsFrom(opts);
  const failures: string[] = [];
  for (const rpcUrl of urls) {
    let body: any;
    try {
      const res = await httpFetch(rpcUrl, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: "near-xray", method: "query", params }),
        signal: AbortSignal.timeout(opts?.timeoutMs ?? 15_000),
      });
      body = (await res.json().catch(() => undefined)) as any;
      if (!body && !res.ok) throw new Error(`HTTP ${res.status}`);
    } catch (e: any) {
      // Network / timeout / non-JSON: try the next endpoint.
      failures.push(`${rpcUrl}: ${e?.cause?.code || e?.cause?.message || e?.message || e}`);
      continue;
    }
    if (body?.error) throw classifyRpcError(accountId, body.error);
    // Some nearcore versions report view errors inside `result.error` (string).
    if (body?.result?.error) throw classifyRpcError(accountId, { message: body.result.error });
    return { result: body.result as T, rpcUrl };
  }
  throw new RpcError("RPC_UNAVAILABLE", `Could not reach any NEAR RPC endpoint (${failures.join("; ")}).`);
}

export interface ViewCodeResult {
  code_base64: string;
  hash: string;
  block_height: number;
}

export async function viewCode(accountId: string, opts?: RpcOptions) {
  const id = assertAccountId(accountId);
  return rpcQuery<ViewCodeResult>({ request_type: "view_code", finality: "final", account_id: id }, opts);
}

export interface AccessKeyInfo {
  public_key: string;
  access_key: {
    nonce: number;
    permission: "FullAccess" | { FunctionCall: { allowance: string | null; receiver_id: string; method_names: string[] } };
  };
}

export async function viewAccessKeyList(accountId: string, opts?: RpcOptions) {
  const id = assertAccountId(accountId);
  return rpcQuery<{ keys: AccessKeyInfo[] }>({ request_type: "view_access_key_list", finality: "final", account_id: id }, opts);
}

/** Network label for a given RPC URL — informational only. */
export function networkOf(rpcUrl: string): string {
  return /testnet/i.test(rpcUrl) ? "testnet" : /mainnet|fastnear|near\.org/i.test(rpcUrl) ? "mainnet" : "custom";
}
