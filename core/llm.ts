/**
 * The LLM behind text-to-test (a typed plain-English attack description →
 * scenario JSON). Both providers speak the OpenAI chat-completions API and are
 * called in JSON mode. BitLens analyses public on-chain bytecode; the LLM is
 * used only for the translation step and never writes code.
 *
 * 1. NEAR AI Cloud (primary): https://cloud-api.near.ai/v1
 *      NEAR_AI_API_KEY, NEAR_AI_MODEL (default below), NEAR_AI_BASE_URL
 * 2. OpenRouter (fallback): https://openrouter.ai/api/v1
 *      OPEN_ROUTER_KEY, OPEN_ROUTER_MODEL (default below), OPEN_ROUTER_BASE_URL
 *
 * A request goes to the first configured provider that is not cooling down.
 * If NEAR AI has no key, rejects it, is unreachable or errors, the request
 * falls through to OpenRouter, and NEAR AI is skipped for a few minutes so
 * every call does not pay for the failure again.
 * LLM_TIMEOUT_S: per-request timeout, default 120.
 * LLM_MAX_TOKENS: output cap per request, default 4096.
 */
import { UpstreamError } from "./errors.js";
import { httpFetch } from "./rpc.js";

export const DEFAULT_NEAR_AI_BASE_URL = "https://cloud-api.near.ai/v1";
export const DEFAULT_NEAR_AI_MODEL = "deepseek/deepseek-v3.2";
export const DEFAULT_OPEN_ROUTER_BASE_URL = "https://openrouter.ai/api/v1";
/** Same open-weight model as the NEAR AI default, so both providers behave alike. */
export const DEFAULT_OPEN_ROUTER_MODEL = "deepseek/deepseek-v3.2";
/**
 * Output cap per request. A scenario is ~1-2k tokens; OpenRouter reserves the
 * whole cap up front and refuses a key whose credit does not cover it (HTTP 402),
 * so the cap is kept small: 4096 is well above what a scenario needs.
 */
export const DEFAULT_MAX_TOKENS = 4096;
const COOL_DOWN_MS = 5 * 60_000;

const env = (k: string) => process.env[k]?.trim() || undefined;

export interface Provider {
  name: "NEAR AI Cloud" | "OpenRouter";
  key: string | null;
  baseUrl: string;
  model: string;
  headers: Record<string, string>;
}

/** Providers in fallback order (read from the environment at call time). */
export function llmProviders(): Provider[] {
  return [
    {
      name: "NEAR AI Cloud",
      key: env("NEAR_AI_API_KEY") ?? null,
      baseUrl: (env("NEAR_AI_BASE_URL") ?? DEFAULT_NEAR_AI_BASE_URL).replace(/\/+$/, ""),
      model: env("NEAR_AI_MODEL") ?? DEFAULT_NEAR_AI_MODEL,
      headers: {},
    },
    {
      name: "OpenRouter",
      key: env("OPEN_ROUTER_KEY") ?? null,
      baseUrl: (env("OPEN_ROUTER_BASE_URL") ?? DEFAULT_OPEN_ROUTER_BASE_URL).replace(/\/+$/, ""),
      model: env("OPEN_ROUTER_MODEL") ?? DEFAULT_OPEN_ROUTER_MODEL,
      // OpenRouter's optional app attribution headers.
      headers: { "X-Title": "BitLens" },
    },
  ];
}

/** When each provider last failed (for the cool-down). */
const failedAt = new Map<string, number>();

/** Reset the cool-down (tests). */
export function resetLlmCooldown() {
  failedAt.clear();
}

/** Public view of the configuration (never includes keys). */
export function llmStatus() {
  const providers = llmProviders().map((p) => ({
    name: p.name,
    configured: Boolean(p.key),
    model: p.model,
    base_url: p.baseUrl,
    cooling_down: Date.now() - (failedAt.get(p.name) ?? 0) < COOL_DOWN_MS,
  }));
  const active = providers.find((p) => p.configured && !p.cooling_down) ?? providers.find((p) => p.configured) ?? null;
  return { configured: Boolean(active), provider: active?.name ?? null, model: active?.model ?? null, providers };
}

export type ChatMessage = { role: "system" | "user" | "assistant"; content: string };

class ProviderFailure extends Error {
  constructor(
    message: string,
    readonly code: string,
  ) {
    super(message);
  }
}

function maxTokens() {
  const n = Math.floor(Number(env("LLM_MAX_TOKENS") ?? DEFAULT_MAX_TOKENS));
  return Number.isFinite(n) && n >= 256 ? Math.min(n, 65536) : DEFAULT_MAX_TOKENS;
}

async function callProvider(p: Provider, messages: ChatMessage[], timeoutMs: number) {
  let res;
  try {
    res = await httpFetch(`${p.baseUrl}/chat/completions`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${p.key}`, ...p.headers },
      body: JSON.stringify({ model: p.model, messages, max_tokens: maxTokens(), response_format: { type: "json_object" } }),
      signal: AbortSignal.timeout(timeoutMs),
    });
  } catch (e: any) {
    const why = e?.name === "TimeoutError" ? `timed out after ${timeoutMs / 1000}s` : (e?.cause?.code ?? e?.message ?? String(e));
    throw new ProviderFailure(`unreachable (${why})`, "LLM_UNAVAILABLE");
  }
  const text = await res.text();
  if (!res.ok) {
    let detail = text.slice(0, 300);
    try {
      const j = JSON.parse(text);
      detail = j?.error?.message ?? j?.message ?? j?.detail ?? detail;
    } catch {}
    const code = res.status === 401 || res.status === 403 ? "LLM_AUTH" : "LLM_ERROR";
    throw new ProviderFailure(`HTTP ${res.status}: ${String(detail).slice(0, 300)}`, code);
  }
  let content: string;
  try {
    const body = JSON.parse(text);
    if (body?.error) throw new ProviderFailure(`error: ${String(body.error.message ?? body.error).slice(0, 300)}`, "LLM_ERROR");
    content = body?.choices?.[0]?.message?.content ?? "";
  } catch (e) {
    if (e instanceof ProviderFailure) throw e;
    throw new ProviderFailure("returned a non-JSON response", "LLM_ERROR");
  }
  if (!content.trim()) throw new ProviderFailure("returned an empty answer", "LLM_ERROR");
  return content;
}

/** Parse the JSON object out of a JSON-mode answer (tolerates code fences and stray prose). */
function extractJson(content: string): unknown {
  const cleaned = content.trim().replace(/^```(?:json)?\s*/i, "").replace(/\s*```$/, "");
  const start = cleaned.indexOf("{");
  const end = cleaned.lastIndexOf("}");
  if (start === -1 || end <= start) return null;
  try {
    return JSON.parse(cleaned.slice(start, end + 1));
  } catch {
    return null;
  }
}

/**
 * Chat completion in JSON mode with provider fallback. `prefer` sends the
 * request to that provider first (a translation's repair round stays on the
 * provider that answered). Returns the parsed object, the raw text and who answered.
 */
export async function chatJson(messages: ChatMessage[], opts: { prefer?: string; timeoutMs?: number } = {}) {
  const timeoutMs = opts.timeoutMs ?? Math.max(10, Number(env("LLM_TIMEOUT_S") ?? 120)) * 1000;
  const all = llmProviders();
  const configured = all.filter((p) => p.key);
  if (!configured.length)
    throw new UpstreamError(
      "Text-to-test needs an LLM key: set NEAR_AI_API_KEY (NEAR AI Cloud, https://cloud.near.ai) and/or OPEN_ROUTER_KEY (OpenRouter, used as the fallback). Scans, preset attacks and hand-written scenario JSON work without one.",
      "LLM_NOT_CONFIGURED",
      503,
    );
  const now = Date.now();
  const cool = (p: Provider) => now - (failedAt.get(p.name) ?? 0) < COOL_DOWN_MS;
  // Preferred first, then providers not cooling down, then the cooling ones as a last resort.
  const order = [
    ...configured.filter((p) => p.name === opts.prefer),
    ...configured.filter((p) => p.name !== opts.prefer && !cool(p)),
    ...configured.filter((p) => p.name !== opts.prefer && cool(p)),
  ];
  const skipped = all.filter((p) => !p.key).map((p) => `${p.name}: no key`);
  const errors: string[] = [];
  let lastCode = "LLM_UNAVAILABLE";
  for (const p of order) {
    try {
      const raw = await callProvider(p, messages, timeoutMs);
      failedAt.delete(p.name);
      return { json: extractJson(raw), raw, model: p.model, provider: p.name, fallback_from: errors.length ? errors : undefined };
    } catch (e) {
      if (!(e instanceof ProviderFailure)) throw e;
      failedAt.set(p.name, Date.now());
      errors.push(`${p.name}: ${e.message}`);
      lastCode = e.code;
    }
  }
  throw new UpstreamError(`No LLM provider answered. ${[...errors, ...skipped].join("; ")}`, lastCode, 502);
}
