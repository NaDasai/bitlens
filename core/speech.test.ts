/**
 * Speech-to-test against two fake OpenAI-compatible servers standing in for
 * NEAR AI Cloud (primary) and OpenRouter (fallback): request shape, JSON mode,
 * fallback rules, validation + one repair round, errors. No network, no real keys.
 */
import assert from "node:assert/strict";
import { createServer, type IncomingMessage, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { after, before, beforeEach, test } from "node:test";
import { DEFAULT_NEAR_AI_MODEL, DEFAULT_OPEN_ROUTER_MODEL, llmStatus, resetLlmCooldown, scan, translateToScenario, UpstreamError, ScenarioError } from "./index.js";

type Seen = { path: string; headers: IncomingMessage["headers"]; body: any };
type Reply = { status?: number; body: unknown };

function fake() {
  const f = { seen: [] as Seen[], replies: [] as Reply[], srv: null as unknown as Server, url: "" };
  f.srv = createServer(async (req, res) => {
    let body = "";
    for await (const c of req) body += c;
    f.seen.push({ path: req.url ?? "", headers: req.headers, body: body ? JSON.parse(body) : null });
    const r = f.replies.shift() ?? { status: 500, body: { error: { message: "no reply queued" } } };
    res.writeHead(r.status ?? 200, { "content-type": "application/json" });
    res.end(JSON.stringify(r.body));
  });
  return f;
}
const near = fake();
const router = fake();

const chat = (content: string) => ({ choices: [{ message: { role: "assistant", content } }] });
const DRAIN = {
  id: "drain",
  name: "Attacker drains the vault",
  steps: [{ op: "call", id: "hit", as: "attacker", method: "admin_drain", args: { receiver_id: "attacker.near" }, attack: true }],
  checks: [{ check: "net_at_most", account: "attacker", near: "0" }],
};
const GOOD = { body: chat(JSON.stringify(DRAIN)) };

before(async () => {
  for (const f of [near, router]) {
    await new Promise<void>((r) => f.srv.listen(0, "127.0.0.1", r));
    f.url = `http://127.0.0.1:${(f.srv.address() as AddressInfo).port}/v1`;
  }
});
after(() => {
  near.srv.close();
  router.srv.close();
});
beforeEach(() => {
  for (const f of [near, router]) (f.seen = []), (f.replies = []);
  resetLlmCooldown();
  process.env.NEAR_AI_BASE_URL = near.url;
  process.env.OPEN_ROUTER_BASE_URL = router.url;
  process.env.NEAR_AI_API_KEY = "near-key";
  process.env.OPEN_ROUTER_KEY = "router-key";
  delete process.env.NEAR_AI_MODEL;
  delete process.env.OPEN_ROUTER_MODEL;
});

test("no key at all → LLM_NOT_CONFIGURED (503), nothing sent", async () => {
  delete process.env.NEAR_AI_API_KEY;
  delete process.env.OPEN_ROUTER_KEY;
  assert.equal(llmStatus().configured, false);
  const card = await scan("vulnerable-vault.xray-demo");
  await assert.rejects(translateToScenario("attacker drains it", card), (e: any) => e instanceof UpstreamError && e.code === "LLM_NOT_CONFIGURED" && e.status === 503);
  assert.equal(near.seen.length + router.seen.length, 0);
});

test("NEAR AI first: chat/completions in JSON mode → validated scenario; OpenRouter untouched", async () => {
  const card = await scan("vulnerable-vault.xray-demo");
  near.replies.push(GOOD);
  const t = await translateToScenario("  The attacker calls admin_drain and keeps the money  ", card);
  assert.equal(router.seen.length, 0);
  const [req] = near.seen;
  assert.equal(req.path, "/v1/chat/completions");
  assert.equal(req.headers.authorization, "Bearer near-key");
  assert.equal(req.body.model, DEFAULT_NEAR_AI_MODEL);
  assert.deepEqual(req.body.response_format, { type: "json_object" });
  assert.equal(req.body.max_tokens, 8192, "output is capped so low-credit keys are not refused");
  assert.equal(req.body.messages[1].content, "The attacker calls admin_drain and keeps the money");
  assert.match(req.body.messages[0].content, /admin_drain/, "the prompt lists the contract's real methods");
  assert.equal(t.provider, "NEAR AI Cloud");
  assert.equal(t.fallback_from, undefined);
  assert.equal(t.scenario.id, "custom:drain");
  assert.equal(t.scenario.description, "The attacker calls admin_drain and keeps the money");
});

test("NEAR AI key rejected (401) → OpenRouter answers; NEAR AI then skipped while cooling down", async () => {
  const card = await scan("vulnerable-vault.xray-demo");
  near.replies.push({ status: 401, body: { error: { message: "invalid api key" } } });
  router.replies.push(GOOD);
  const t = await translateToScenario("drain it", card);
  assert.equal(t.provider, "OpenRouter");
  assert.equal(t.model, DEFAULT_OPEN_ROUTER_MODEL);
  assert.deepEqual(t.fallback_from, ["NEAR AI Cloud: HTTP 401: invalid api key"]);
  const [req] = router.seen;
  assert.equal(req.headers.authorization, "Bearer router-key");
  assert.equal(req.headers["x-title"], "NEAR X-Ray");
  assert.equal(req.body.model, DEFAULT_OPEN_ROUTER_MODEL);
  assert.deepEqual(req.body.response_format, { type: "json_object" });

  router.replies.push(GOOD);
  const again = await translateToScenario("drain it again", card);
  assert.equal(again.provider, "OpenRouter");
  assert.equal(near.seen.length, 1, "NEAR AI is not retried during its cool-down");
  assert.equal(llmStatus().provider, "OpenRouter");
});

test("NEAR AI unreachable or erroring → OpenRouter", async () => {
  const card = await scan("vulnerable-vault.xray-demo");
  process.env.NEAR_AI_BASE_URL = "http://127.0.0.1:1/v1";
  router.replies.push(GOOD);
  const t = await translateToScenario("drain it", card);
  assert.equal(t.provider, "OpenRouter");
  assert.match(t.fallback_from![0], /^NEAR AI Cloud: unreachable/);

  resetLlmCooldown();
  process.env.NEAR_AI_BASE_URL = near.url;
  near.replies.push({ status: 503, body: { error: { message: "model overloaded" } } });
  router.replies.push(GOOD);
  assert.equal((await translateToScenario("drain it", card)).provider, "OpenRouter");
});

test("no NEAR AI key → straight to OpenRouter (not counted as a fallback)", async () => {
  delete process.env.NEAR_AI_API_KEY;
  const card = await scan("vulnerable-vault.xray-demo");
  router.replies.push(GOOD);
  const t = await translateToScenario("drain it", card);
  assert.equal(t.provider, "OpenRouter");
  assert.equal(t.fallback_from, undefined);
  assert.equal(near.seen.length, 0);
});

test("both fail → one error naming both, keys never echoed", async () => {
  const card = await scan("vulnerable-vault.xray-demo");
  near.replies.push({ status: 401, body: { error: { message: "bad key" } } });
  router.replies.push({ status: 402, body: { error: { message: "insufficient credits" } } });
  await assert.rejects(translateToScenario("drain it", card), (e: any) => {
    assert.equal(e.code, "LLM_ERROR");
    assert.match(e.message, /NEAR AI Cloud: HTTP 401: bad key; OpenRouter: HTTP 402: insufficient credits/);
    assert.ok(!/near-key|router-key/.test(e.message));
    return true;
  });
});

test("model env overrides; fenced JSON tolerated", async () => {
  process.env.NEAR_AI_MODEL = "z-ai/glm-5.3-flash";
  const card = await scan("vulnerable-vault.xray-demo");
  near.replies.push({ body: chat("```json\n" + JSON.stringify(DRAIN) + "\n```") });
  const t = await translateToScenario("drain it", card);
  assert.equal(near.seen[0].body.model, "z-ai/glm-5.3-flash");
  assert.equal(t.model, "z-ai/glm-5.3-flash");
});

test("invented method → one repair round, on the provider that answered", async () => {
  const card = await scan("vulnerable-vault.xray-demo");
  const bad = { ...DRAIN, steps: [{ ...DRAIN.steps[0], method: "steal_everything" }] };
  near.replies.push({ status: 500, body: { error: { message: "boom" } } });
  router.replies.push({ body: chat(JSON.stringify(bad)) }, GOOD);
  const t = await translateToScenario("drain it", card);
  assert.equal(t.attempts, 2);
  assert.equal(t.provider, "OpenRouter");
  assert.equal(near.seen.length, 1);
  assert.match(router.seen[1].body.messages.at(-1).content, /steal_everything is not a method/);
});

test("still invalid after the repair round → SCENARIO_INVALID; unsafe shapes never pass", async () => {
  const card = await scan("vulnerable-vault.xray-demo");
  const evil = { ...DRAIN, steps: [{ op: "call", as: "alice.near", method: "admin_drain" }] };
  near.replies.push({ body: chat(JSON.stringify(evil)) }, { body: chat("not json at all") });
  await assert.rejects(translateToScenario("drain it", card), (e: any) => e instanceof ScenarioError && e.code === "SCENARIO_INVALID");
});

test("inverted checks (pass when the attack works) → repair round; setup preconditions allowed", async () => {
  const card = await scan("vulnerable-vault.xray-demo");
  const inverted = {
    ...DRAIN,
    checks: [
      { check: "step_succeeded", step: "hit" },
      { check: "net_at_least", account: "attacker", near: "20" },
    ],
  };
  near.replies.push({ body: chat(JSON.stringify(inverted)) }, GOOD);
  const t = await translateToScenario("the attacker calls admin_drain and keeps the money", card);
  assert.equal(t.attempts, 2);
  const repair = near.seen[1].body.messages.at(-1).content;
  assert.match(repair, /step_succeeded.*attack call "hit"/);
  assert.match(repair, /net_at_least.*attacker profits/);
  assert.match(near.seen[0].body.messages[0].content, /CHECK POLARITY/);

  const precondition = { ...DRAIN, checks: [{ check: "step_succeeded", step: "hit", else: "inconclusive" }, ...DRAIN.checks] };
  near.replies.push({ body: chat(JSON.stringify(precondition)) });
  assert.equal((await translateToScenario("drain it", card)).attempts, 1);
});
