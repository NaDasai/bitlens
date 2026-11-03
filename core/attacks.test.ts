import { test } from "node:test";
import assert from "node:assert/strict";
import { scan, suggestAttacks, verdictOf, kitchenSinkArgs, type AttackReport } from "./index.js";

test("suggested attacks for the demo contracts", async () => {
  const vuln = suggestAttacks(await scan("vulnerable-vault.xray-demo")).map((a) => a.id);
  for (const id of ["unauth:admin_drain", "unauth:set_owner", "unauth:on_withdraw", "double_withdraw", "failed_transfer_refund", "callback_gas"])
    assert.ok(vuln.includes(id), id);
  const risky = suggestAttacks(await scan("risky-vault.xray-demo")).map((a) => a.id);
  assert.ok(risky.includes("addkey:add_full_access_key"), "add-key template replaces the plain call");
  assert.ok(!risky.includes("unauth:add_full_access_key"));
  assert.ok(risky.includes("unauth:upgrade"));
});

test("kitchen-sink args point every account field at the beneficiary", () => {
  const a = kitchenSinkArgs("attacker.near");
  assert.equal(a.receiver_id, "attacker.near");
  assert.equal(a.owner_id, "attacker.near");
  assert.match(String(a.public_key), /^ed25519:[1-9A-HJ-NP-Za-km-z]{43,44}$/);
});

test("verdict: broken → dangerous; all held + LOW → safe; HIGH → caution", async () => {
  const clean = await scan("clean-vault.xray-demo");
  const rep = (statuses: string[]): AttackReport => ({
    account_id: "x", code_hash: "x", engine: "sim", init: { ok: true, method: "new", tried: [] }, victim_deposit: null,
    accounts: { owner: "", victim: "", attacker: "", user: "" },
    results: statuses.map((s, i) => ({ id: `s${i}`, name: `s${i}`, status: s as any, explanation: "", event_sequence: [], token_deltas: {}, findings: [], trace: "", duration_ms: 0 })),
    summary: { held: 0, broken: 0, inconclusive: 0, error: 0 }, duration_ms: 0,
  });
  assert.equal(verdictOf(clean, rep(["held", "held"])).verdict, "safe");
  assert.equal(verdictOf(clean, rep(["held", "broken"])).verdict, "dangerous");
  assert.equal(verdictOf(clean, rep(["held", "inconclusive"])).verdict, "caution");
  assert.equal(verdictOf(clean, null).verdict, "caution"); // attacks not run: never "safe"
  assert.equal(verdictOf(await scan("risky-vault.xray-demo"), rep(["held"])).verdict, "caution");
});
