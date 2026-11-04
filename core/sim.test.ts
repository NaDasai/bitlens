/**
 * Demo regression: every scenario's status on the four bundled demo contracts,
 * run through the real attack engine. If a change to the scanner, the attack
 * selection or the runner moves any of these, the demo story changed: this fails.
 * Needs the runner binary (npm run build:runner); skipped otherwise.
 */
import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { test } from "node:test";
import { RUNNER_BIN, runAttacks, scan, verdictOf } from "./index.js";

const built = existsSync(RUNNER_BIN);
const H = "held", B = "broken";

const EXPECTED: Record<string, { risk: string; verdict: string; results: Record<string, string> }> = {
  "clean-vault.bitlens-demo": {
    risk: "low",
    verdict: "safe",
    results: { "unauth:on_withdraw": H, "unauth:set_owner": H, "unauth:set_paused": H, "unauth:withdraw": H, double_withdraw: H, failed_transfer_refund: H, callback_gas: H },
  },
  "risky-vault.bitlens-demo": {
    risk: "high",
    verdict: "caution",
    results: {
      "addkey:add_full_access_key": H, "unauth:on_withdraw": H, "unauth:set_owner": H, "unauth:set_paused": H, "unauth:upgrade": H,
      "unauth:withdraw": H, double_withdraw: H, failed_transfer_refund: H, callback_gas: H,
    },
  },
  "vulnerable-vault.bitlens-demo": {
    risk: "high",
    verdict: "dangerous",
    results: {
      "unauth:admin_drain": B, "unauth:on_withdraw": H, "unauth:set_owner": H, "unauth:set_paused": H, "unauth:withdraw": H,
      double_withdraw: B, failed_transfer_refund: H, callback_gas: H,
    },
  },
  "yield-escrow.bitlens-demo": {
    risk: "low",
    verdict: "dangerous",
    results: {
      "unauth:approve_payout": H, "unauth:on_payout_decision": H, "unauth:on_withdraw": H, "unauth:set_approver": H, "unauth:withdraw": H,
      double_withdraw: H, failed_transfer_refund: H, callback_gas: H, "yield:request_payout": B,
    },
  },
};

for (const [id, want] of Object.entries(EXPECTED)) {
  test(`demo ${id}: ${want.risk.toUpperCase()} card, ${want.verdict.toUpperCase()} verdict, every scenario as expected`, { skip: !built && "runner not built (npm run build:runner)" }, async () => {
    const card = await scan(id);
    assert.equal(card.risk.level, want.risk);
    const { report } = await runAttacks(id);
    const got = Object.fromEntries(report.results.map((r) => [r.id, r.status]));
    assert.deepEqual(got, want.results);
    assert.equal(verdictOf(card, report).verdict, want.verdict);
    for (const r of report.results.filter((r) => r.status === "broken")) {
      assert.ok(r.event_sequence.length > 0, `${r.id}: a BROKEN result must carry its receipt sequence`);
    }
  });
}

test("vulnerable admin_drain: the NEAR really moves to the attacker", { skip: !built && "runner not built" }, async () => {
  const { report } = await runAttacks("vulnerable-vault.bitlens-demo", ["unauth:admin_drain"]);
  const d = report.results[0].token_deltas;
  assert.ok(BigInt(d["attacker.near"].yocto) > 60n * 10n ** 24n, "attacker gains > 60 NEAR");
  assert.equal(BigInt(d["attacker.near"].yocto), -BigInt(d["vulnerable-vault.bitlens-demo"].yocto));
});

// --- custom scenario JSON (what text-to-test produces) through the real runner ---

const DRAIN = {
  id: "custom:drain",
  name: "Attacker drains the vault",
  steps: [{ op: "call", id: "hit", as: "attacker", method: "admin_drain", args: { receiver_id: "attacker.near" }, attack: true }],
  checks: [{ check: "net_at_most", account: "attacker", near: "0", message: "attacker.near walked away with {net.attacker}." }],
  explain: { rejected: "admin_drain refused the attacker: {error.hit}" },
};

test("custom JSON: anyone can drain the vulnerable vault → BROKEN with the money trail", { skip: !built && "runner not built" }, async () => {
  const { report } = await runAttacks("vulnerable-vault.bitlens-demo", undefined, { custom: [DRAIN] });
  assert.equal(report.results.length, 1, "custom scenarios replace the presets when no ids are given");
  const r = report.results[0];
  assert.equal(r.status, "broken");
  assert.match(r.explanation, /^attacker.near walked away with \+67\.8015 NEAR\.$/);
  assert.ok(r.event_sequence.some((e) => e.action.startsWith("Transfer") && e.to === "attacker.near"));
});

test("custom JSON: attacker tries to take over the clean vault → HELD (rejected)", { skip: !built && "runner not built" }, async () => {
  const takeover = {
    id: "custom:takeover",
    name: "Attacker makes itself owner, then pauses",
    steps: [
      { op: "call", id: "own", as: "attacker", method: "set_owner", args: { owner_id: "attacker.near" }, attack: true },
      { op: "call", id: "pause", as: "attacker", method: "set_paused", args: { paused: true }, attack: true },
    ],
    checks: [{ check: "unchanged", what: "state" }],
    explain: { rejected: "Both admin calls were refused: {error.own}" },
  };
  const { report } = await runAttacks("clean-vault.bitlens-demo", undefined, { custom: [takeover] });
  assert.equal(report.results[0].status, "held");
  assert.equal(report.results[0].explanation, "Both admin calls were refused: panicked: only the owner can call this");
});

test("runner re-validates: a malformed scenario becomes an error result, the others still run", { skip: !built && "runner not built" }, async () => {
  const { runSpec } = await import("./engine.js");
  const { buildSpec, suggestAttacks } = await import("./attacks.js");
  const { scanWithCode } = await import("./scan.js");
  const { card } = await scanWithCode("vulnerable-vault.bitlens-demo");
  const spec: any = buildSpec(card, "contracts/res/vulnerable_vault.wasm", suggestAttacks(card).slice(0, 1));
  spec.scenarios.push({ id: "x", name: "x", steps: [{ op: "call", as: "mallory.near", method: "admin_drain" }] });
  spec.scenarios.push({ id: "y", name: "y", steps: [{ op: "advance_blocks", blocks: 999999 }] });
  const out = await runSpec<any>(spec);
  assert.deepEqual(out.scenarios.map((s: any) => s.status), ["broken", "error", "error"]);
  assert.match(out.scenarios[1].explanation, /unknown variant `mallory.near`/);
  assert.match(out.scenarios[2].explanation, /advance_blocks must be 1-5000/);
});
