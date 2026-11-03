/**
 * NEAR AI Cloud client (OpenAI-compatible): https://cloud-api.near.ai/v1
 *
 * Used for speech-to-test only: turning a plain-English attack description
 * into scenario JSON (chat completions in JSON mode), and optionally turning a
 * voice recording into that sentence (Whisper). X-Ray analyses public on-chain
 * bytecode; NEAR AI is simply the ecosystem's LLM for the translation step.
 *
 *   NEAR_AI_API_KEY    bearer key (required for these features)
 *   NEAR_AI_MODEL      chat model (default below: an open-weight reasoning model with JSON mode)
 *   NEAR_AI_STT_MODEL  speech-to-text model (default openai/whisper-large-v3)
 *   NEAR_AI_BASE_URL   override the endpoint (tests point it at a local fake)
 */
import { UpstreamError } from "./errors.js";
import { FormData } from "undici";
import { httpFetch } from "./rpc.js";

export const DEFAULT_NEAR_AI_BASE_URL = "https://cloud-api.near.ai/v1";
export const DEFAULT_NEAR_AI_MODEL = "Qwen/Qwen3.6-35B-A3B-FP8";
export const DEFAULT_NEAR_AI_STT_MODEL = "openai/whisper-large-v3";

export function nearAiConfig() {
  const key = process.env.NEAR_AI_API_KEY?.trim() || null;
  return {
    configured: Boolean(key),
    key,
    baseUrl: (process.env.NEAR_AI_BASE_URL?.trim() || DEFAULT_NEAR_AI_BASE_URL).replace(/\/+$/, ""),
    model: process.env.NEAR_AI_MODEL?.trim() || DEFAULT_NEAR_AI_MODEL,
    sttModel: process.env.NEAR_AI_STT_MODEL?.trim() || DEFAULT_NEAR_AI_STT_MODEL,
  };
}

/** Public view of the config (never includes the key). */
export function nearAiStatus() {
  const { configured, baseUrl, model, sttModel } = nearAiConfig();
  return { configured, base_url: baseUrl, model, stt_model: sttModel };
}

function requireKey() {
  const cfg = nearAiConfig();
  if (!cfg.key)
    throw new UpstreamError(
      "Speech-to-test needs a NEAR AI Cloud key: set NEAR_AI_API_KEY (create one at https://cloud.near.ai). Scans, preset attacks and hand-written scenario JSON work without it.",
      "NEAR_AI_NOT_CONFIGURED",
      503,
    );
  return cfg as typeof cfg & { key: string };
}

async function post(url: string, key: string, body: BodyInit | string, headers: Record<string, string>, timeoutMs: number) {
  let res;
  try {
    res = await httpFetch(url, {
      method: "POST",
      headers: { authorization: `Bearer ${key}`, ...headers },
      body: body as any,
      signal: AbortSignal.timeout(timeoutMs),
    });
  } catch (e: any) {
    const why = e?.name === "TimeoutError" ? `timed out after ${timeoutMs / 1000}s` : (e?.cause?.code ?? e?.message ?? String(e));
    throw new UpstreamError(`NEAR AI Cloud unreachable (${why})`, "NEAR_AI_UNAVAILABLE", 502);
  }
  const text = await res.text();
  if (!res.ok) {
    let detail = text.slice(0, 300);
    try {
      const j = JSON.parse(text);
      detail = j?.error?.message ?? j?.message ?? j?.detail ?? detail;
    } catch {}
    const code = res.status === 401 || res.status === 403 ? "NEAR_AI_AUTH" : "NEAR_AI_ERROR";
    throw new UpstreamError(`NEAR AI Cloud returned HTTP ${res.status}: ${String(detail).slice(0, 300)}`, code, 502);
  }
  return text;
}

export type ChatMessage = { role: "system" | "user" | "assistant"; content: string };

/** Chat completion in JSON mode; returns the parsed JSON object plus the raw text. */
export async function chatJson(messages: ChatMessage[], opts: { model?: string; timeoutMs?: number } = {}) {
  const cfg = requireKey();
  const model = opts.model ?? cfg.model;
  const text = await post(
    `${cfg.baseUrl}/chat/completions`,
    cfg.key,
    JSON.stringify({ model, messages, response_format: { type: "json_object" } }),
    { "content-type": "application/json" },
    opts.timeoutMs ?? 120_000,
  );
  let content: string;
  try {
    content = JSON.parse(text)?.choices?.[0]?.message?.content ?? "";
  } catch {
    throw new UpstreamError("NEAR AI Cloud returned a non-JSON response", "NEAR_AI_ERROR", 502);
  }
  // JSON mode should give a bare object; tolerate code fences and leading prose anyway.
  const cleaned = content.trim().replace(/^```(?:json)?\s*/i, "").replace(/\s*```$/, "");
  const start = cleaned.indexOf("{");
  const end = cleaned.lastIndexOf("}");
  let json: unknown = null;
  if (start !== -1 && end > start) {
    try {
      json = JSON.parse(cleaned.slice(start, end + 1));
    } catch {}
  }
  return { json, raw: content, model };
}

/** Speech to text (Whisper on NEAR AI Cloud). */
export async function transcribe(audio: Uint8Array, mime: string, opts: { timeoutMs?: number } = {}) {
  const cfg = requireKey();
  const ext = /ogg/.test(mime) ? "ogg" : /mp4|m4a|aac/.test(mime) ? "m4a" : /wav/.test(mime) ? "wav" : /mpeg|mp3/.test(mime) ? "mp3" : "webm";
  const form = new FormData();
  form.append("file", new Blob([audio as Uint8Array<ArrayBuffer>], { type: mime || "audio/webm" }), `speech.${ext}`);
  form.append("model", cfg.sttModel);
  form.append("response_format", "json");
  const text = await post(`${cfg.baseUrl}/audio/transcriptions`, cfg.key, form as any, {}, opts.timeoutMs ?? 60_000);
  let out = text;
  try {
    out = JSON.parse(text)?.text ?? text;
  } catch {}
  return { text: String(out).trim(), model: cfg.sttModel };
}
