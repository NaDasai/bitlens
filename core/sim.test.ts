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
  "clean-vault.xray-demo": {
    risk: "low",
    verdict: "safe",
    results: { "unauth:on_withdraw": H, "unauth:set_owner": H, "unauth:set_paused": H, "unauth:withdraw": H, double_withdraw: H, failed_transfer_refund: H, callback_gas: H },
  },
  "risky-vault.xray-demo": {
    risk: "high",
    verdict: "caution",
    results: {
      "addkey:add_full_access_key": H, "unauth:on_withdraw": H, "unauth:set_owner": H, "unauth:set_paused": H, "unauth:upgrade": H,
      "unauth:withdraw": H, double_withdraw: H, failed_transfer_refund: H, callback_gas: H,
    },
  },
  "vulnerable-vault.xray-demo": {
    risk: "high",
    verdict: "dangerous",
    results: {
      "unauth:admin_drain": B, "unauth:on_withdraw": H, "unauth:set_owner": H, "unauth:set_paused": H, "unauth:withdraw": H,
      double_withdraw: B, failed_transfer_refund: H, callback_gas: H,
    },
  },
  "yield-escrow.xray-demo": {
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
  const { report } = await runAttacks("vulnerable-vault.xray-demo", ["unauth:admin_drain"]);
  const d = report.results[0].token_deltas;
  assert.ok(BigInt(d["attacker.near"].yocto) > 60n * 10n ** 24n, "attacker gains > 60 NEAR");
  assert.equal(BigInt(d["attacker.near"].yocto), -BigInt(d["vulnerable-vault.xray-demo"].yocto));
});
