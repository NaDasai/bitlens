/**
 * Pre-signature check: the allow / confirm / block policy as a pure function
 * of the evaluation (fabricated reports, no sim), and input validation.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { decide, normaliseTransaction, scan, type AttackReport } from "./index.js";

const V = "vulnerable-vault.bitlens-demo";
const result = (id: string, status: string, deltas: Record<string, string> = {}, calls: string[] = []) => ({
  id,
  name: id,
  status,
  explanation: `${id} ${status}`,
  event_sequence: calls.map((m) => ({ block: 10, from: "attacker.near", to: V, action: `call ${m}`, deposit_near: "0.0000", ok: true, detail: "ok", step: "" })),
  token_deltas: Object.fromEntries(Object.entries(deltas).map(([k, near]) => [k, { near: `${near} NEAR`, yocto: "0" }])),
  findings: [],
  trace: "",
  duration_ms: 1,
});
const report = (results: ReturnType<typeof result>[]) =>
  ({ account_id: V, code_hash: "x", engine: "t", init: { ok: true, tried: [] }, victim_deposit: null, accounts: {}, results, summary: {}, duration_ms: 1 }) as unknown as AttackReport;
const tx = (method: string, deposit = "0") => normaliseTransaction({ receiver_id: V, method, deposit_near: deposit });

const DANGEROUS = report([
  result("double_withdraw", "broken", { "attacker.near": "+5.0000", [V]: "-5.0000" }, ["deposit", "withdraw"]),
  result("unauth:admin_drain", "broken", { "attacker.near": "+67.8015", [V]: "-67.8015" }, ["admin_drain"]),
  result("unauth:set_owner", "held"),
]);
const CAUTION = report([result("unauth:set_owner", "held"), result("unauth:upgrade", "inconclusive")]);

test("dangerous + NEAR attached → block, biggest loss first as evidence, replay link", async () => {
  const card = await scan(V);
  const r = decide(card, DANGEROUS, tx("deposit", "20"));
  assert.equal(r.decision, "block");
  assert.deepEqual(r.evidence.map((e) => e.id), ["unauth:admin_drain", "double_withdraw"], "the 67.8 NEAR drain before the 5 NEAR double spend");
  assert.equal(r.replay_path, `/app?account=${V}&replay=unauth%3Aadmin_drain`);
  assert.match(r.reasons[0], /attach 20 NEAR to a contract where BitLens proved 2 attack/);
  assert.match(r.signing, /never signs/);
  assert.equal(decide(card, DANGEROUS, tx("get_balance")).decision, "confirm", "no NEAR attached: ask a human");
  assert.equal(decide(card, DANGEROUS, tx("get_balance"), "strict").decision, "block");
});

test("caution: confirm with NEAR, allow without; strict tightens both", async () => {
  const card = await scan(V);
  assert.equal(decide(card, CAUTION, tx("deposit", "20")).decision, "confirm");
  assert.equal(decide(card, CAUTION, tx("get_balance")).decision, "allow");
  assert.equal(decide(card, CAUTION, tx("deposit", "20"), "strict").decision, "block");
  assert.equal(decide(card, CAUTION, tx("get_balance"), "strict").decision, "confirm");
});

test("safe → allow; unknown method → block; attacks not run → never allow NEAR", async () => {
  const clean = await scan("clean-vault.bitlens-demo");
  const safe = decide(clean, report([result("unauth:set_owner", "held")]), normaliseTransaction({ receiver_id: clean.account_id, method: "deposit", deposit_near: 20 }));
  assert.equal(safe.decision, "allow");
  assert.match(safe.reasons.at(-1)!, /Not an audit/);
  const card = await scan(V);
  const fake = decide(card, DANGEROUS, tx("steal_everything", "1"));
  assert.equal(fake.decision, "block");
  assert.match(fake.reasons[0], /not exported/);
  assert.equal(decide(card, null, tx("deposit", "20")).decision, "confirm");
  assert.equal(decide(card, null, tx("deposit", "20"), "strict").decision, "block");
  assert.equal(decide(card, null, tx("get_balance")).decision, "allow");
});

test("input is validated: account id, method name, deposit, args", () => {
  assert.throws(() => normaliseTransaction({ receiver_id: "Not Valid!", method: "x" }), /Invalid NEAR account id/);
  assert.throws(() => normaliseTransaction({ receiver_id: V, method: "drop table" }), /method must be/);
  assert.throws(() => normaliseTransaction({ receiver_id: V, method: "deposit", deposit_near: "-1" }), /deposit_near/);
  assert.throws(() => normaliseTransaction({ receiver_id: V, method: "deposit", args: [1] }), /args must be a JSON object/);
  assert.deepEqual(normaliseTransaction({ receiver_id: V, method: "deposit" }), { receiver_id: V, method: "deposit", deposit_near: "0", args: null });
});
