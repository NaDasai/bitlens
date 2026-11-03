/**
 * Speech-to-test against a fake NEAR AI Cloud (OpenAI-compatible) server:
 * request shape, JSON-mode parsing, validation + one repair retry, errors,
 * Whisper transcription. No network, no real key.
 */
import assert from "node:assert/strict";
import { createServer, type IncomingMessage, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { after, before, beforeEach, test } from "node:test";
import { DEFAULT_NEAR_AI_MODEL, scan, transcribe, translateToScenario, UpstreamError, ScenarioError } from "./index.js";

type Seen = { path: string; headers: IncomingMessage["headers"]; body: string };
let srv: Server;
let seen: Seen[] = [];
let replies: Array<{ status?: number; body: unknown }> = [];

const chat = (content: string) => ({ choices: [{ message: { role: "assistant", content } }] });
const DRAIN = {
  id: "drain",
  name: "Attacker drains the vault",
  steps: [{ op: "call", id: "hit", as: "attacker", method: "admin_drain", args: { receiver_id: "attacker.near" }, attack: true }],
  checks: [{ check: "net_at_most", account: "attacker", near: "0" }],
};

before(async () => {
  srv = createServer(async (req, res) => {
    let body = "";
    for await (const c of req) body += c;
    seen.push({ path: req.url ?? "", headers: req.headers, body });
    const r = replies.shift() ?? { status: 500, body: { error: { message: "no reply queued" } } };
    res.writeHead(r.status ?? 200, { "content-type": "application/json" });
    res.end(JSON.stringify(r.body));
  });
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
  process.env.NEAR_AI_BASE_URL = `http://127.0.0.1:${(srv.address() as AddressInfo).port}/v1`;
});
after(() => srv.close());
beforeEach(() => {
  seen = [];
  replies = [];
  process.env.NEAR_AI_API_KEY = "test-key";
  delete process.env.NEAR_AI_MODEL;
});

test("no NEAR_AI_API_KEY → NEAR_AI_NOT_CONFIGURED (503), nothing sent", async () => {
  delete process.env.NEAR_AI_API_KEY;
  const card = await scan("vulnerable-vault.xray-demo");
  await assert.rejects(translateToScenario("attacker drains it", card), (e: any) => e instanceof UpstreamError && e.code === "NEAR_AI_NOT_CONFIGURED" && e.status === 503);
  assert.equal(seen.length, 0);
});

test("sentence → chat/completions in JSON mode → validated scenario", async () => {
  const card = await scan("vulnerable-vault.xray-demo");
  replies.push({ body: chat(JSON.stringify(DRAIN)) });
  const t = await translateToScenario("  The attacker calls admin_drain and keeps the money  ", card);
  assert.equal(seen.length, 1);
  assert.equal(seen[0].path, "/v1/chat/completions");
  assert.equal(seen[0].headers.authorization, "Bearer test-key");
  const req = JSON.parse(seen[0].body);
  assert.equal(req.model, DEFAULT_NEAR_AI_MODEL);
  assert.deepEqual(req.response_format, { type: "json_object" });
  assert.equal(req.messages[1].content, "The attacker calls admin_drain and keeps the money");
  assert.match(req.messages[0].content, /admin_drain/, "the prompt lists the contract's real methods");
  assert.equal(t.scenario.id, "custom:drain");
  assert.equal(t.scenario.description, "The attacker calls admin_drain and keeps the money");
  assert.equal(t.attempts, 1);
});

test("NEAR_AI_MODEL overrides the model; fenced JSON is tolerated", async () => {
  process.env.NEAR_AI_MODEL = "z-ai/glm-5.3-flash";
  const card = await scan("vulnerable-vault.xray-demo");
  replies.push({ body: chat("```json\n" + JSON.stringify(DRAIN) + "\n```") });
  const t = await translateToScenario("drain it", card);
  assert.equal(JSON.parse(seen[0].body).model, "z-ai/glm-5.3-flash");
  assert.equal(t.model, "z-ai/glm-5.3-flash");
});

test("invented method → one repair round with the error → valid", async () => {
  const card = await scan("vulnerable-vault.xray-demo");
  const bad = { ...DRAIN, steps: [{ ...DRAIN.steps[0], method: "steal_everything" }] };
  replies.push({ body: chat(JSON.stringify(bad)) }, { body: chat(JSON.stringify(DRAIN)) });
  const t = await translateToScenario("drain it", card);
  assert.equal(t.attempts, 2);
  const second = JSON.parse(seen[1].body).messages;
  assert.match(second.at(-1).content, /steal_everything is not a method/);
});

test("still invalid after the retry → SCENARIO_INVALID; unsafe shapes never pass", async () => {
  const card = await scan("vulnerable-vault.xray-demo");
  const evil = { ...DRAIN, steps: [{ op: "call", as: "alice.near", method: "admin_drain" }] };
  replies.push({ body: chat(JSON.stringify(evil)) }, { body: chat("not json at all") });
  await assert.rejects(translateToScenario("drain it", card), (e: any) => e instanceof ScenarioError && e.code === "SCENARIO_INVALID");
});

test("HTTP 401 → NEAR_AI_AUTH, key never echoed", async () => {
  const card = await scan("vulnerable-vault.xray-demo");
  replies.push({ status: 401, body: { error: { message: "invalid api key" } } });
  await assert.rejects(translateToScenario("drain it", card), (e: any) => e.code === "NEAR_AI_AUTH" && !String(e.message).includes("test-key"));
});

test("transcribe: multipart to /audio/transcriptions with the Whisper model", async () => {
  replies.push({ body: { text: " attacker calls admin drain " } });
  const r = await transcribe(new Uint8Array([1, 2, 3]), "audio/webm");
  assert.equal(r.text, "attacker calls admin drain");
  assert.equal(seen[0].path, "/v1/audio/transcriptions");
  assert.match(String(seen[0].headers["content-type"]), /multipart\/form-data/);
  assert.match(seen[0].body, /name="model"\r\n\r\nopenai\/whisper-large-v3/);
  assert.match(seen[0].body, /filename="speech.webm"/);
});
