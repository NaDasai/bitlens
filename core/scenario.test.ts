import assert from "node:assert/strict";
import { test } from "node:test";
import { PRESETS, fillPreset, scan, suggestAttacks, validateScenario } from "./index.js";

test("every preset fills into a valid scenario for the demo contracts", async () => {
  assert.ok(Object.keys(PRESETS).length >= 6);
  for (const id of ["clean-vault.xray-demo", "risky-vault.xray-demo", "vulnerable-vault.xray-demo", "yield-escrow.xray-demo"]) {
    for (const a of suggestAttacks(await scan(id))) {
      assert.equal(a.scenario.id, a.id);
      assert.ok(!JSON.stringify(a.scenario).includes("{{"), `${a.id}: unfilled placeholder`);
      validateScenario(a.scenario);
    }
  }
});

test("args placeholder becomes an object; keys are interpolated", () => {
  const sc = fillPreset("double_withdraw", { deposit: "deposit", withdraw: "pull", amount_arg: "amt" });
  const call = sc.steps.find((s) => s.op === "call") as any;
  assert.deepEqual(Object.keys(call.args), ["amt"]);
  const u = fillPreset("unauthorized_call", { method: "m", args: { a: 1 }, contract: "c.near", title: "t", summary: "s" });
  assert.deepEqual((u.steps[0] as any).args, { a: 1 });
});

test("validation rejects what an LLM must not be able to do", () => {
  const ok = { id: "x", name: "x", steps: [{ op: "call", as: "attacker", method: "m" }], checks: [] };
  validateScenario(ok);
  const bad: Array<[string, unknown]> = [
    ["arbitrary signer", { ...ok, steps: [{ op: "call", as: "alice.near", method: "m" }] }],
    ["unknown op", { ...ok, steps: [{ op: "shell", cmd: "rm -rf /" }] }],
    ["unknown field", { ...ok, steps: [{ op: "call", as: "attacker", method: "m", receiver: "other.near" }] }],
    ["bad method name", { ...ok, steps: [{ op: "call", as: "attacker", method: "m; drop" }] }],
    ["huge deposit", { ...ok, steps: [{ op: "call", as: "attacker", method: "m", deposit_near: "1000000" }] }],
    ["too many steps", { ...ok, steps: Array.from({ length: 41 }, () => ({ op: "settle" })) }],
    ["dangling step ref", { ...ok, checks: [{ check: "step_failed", step: "nope" }] }],
    ["$tgas outside sweep", { ...ok, steps: [{ op: "call", as: "attacker", method: "m", gas_tgas: "$tgas" }] }],
    ["duplicate ids", { ...ok, steps: [{ op: "call", id: "a", as: "attacker", method: "m" }, { op: "call", id: "a", as: "user", method: "m" }] }],
  ];
  for (const [why, sc] of bad) assert.throws(() => validateScenario(sc), (e: any) => e.code === "SCENARIO_INVALID", why);
});
