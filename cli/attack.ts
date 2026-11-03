/**
 * CLI: run attack scenarios in near-contract-sim.
 *   npm run attack -- vulnerable-vault.xray-demo
 *   npm run attack -- <account> --list             # suggested scenarios only
 *   npm run attack -- <account> --only unauth:admin_drain,double_withdraw
 *   add --json for the raw report, --trace for full receipt trees
 */
import { listAttacks, runAttacks, toErrorPayload, verdictOf } from "../core/index.js";

const ICON = { held: "✅ HELD", broken: "❌ BROKEN", inconclusive: "❔ INCONCLUSIVE", error: "⚠️ ERROR" } as const;

async function main() {
  const args = process.argv.slice(2);
  const id = args.find((a) => !a.startsWith("--") && args[args.indexOf(a) - 1] !== "--only");
  if (!id) {
    console.error("usage: npm run attack -- <account_id> [--list] [--only id1,id2] [--json] [--trace]");
    process.exit(2);
  }
  const onlyIdx = args.indexOf("--only");
  const only = onlyIdx >= 0 ? args[onlyIdx + 1]?.split(",").filter(Boolean) : undefined;
  try {
    if (args.includes("--list")) {
      const { card, attacks } = await listAttacks(id);
      if (args.includes("--json")) return console.log(JSON.stringify(attacks, null, 2));
      console.log(`${card.summary}\n\nSuggested attacks (${attacks.length}):`);
      for (const a of attacks) console.log(`  ${a.id.padEnd(32)} ${a.name}\n  ${"".padEnd(32)} checks: ${a.checks}`);
      return;
    }
    console.error(`Running attacks on ${id} in near-contract-sim (local, no transactions sent anywhere)…`);
    const { card, report } = await runAttacks(id, only);
    if (args.includes("--json")) return console.log(JSON.stringify({ card, report, ...verdictOf(card, report) }, null, 2));
    console.log(`\n=== NEAR X-Ray attack report: ${report.account_id} ===`);
    console.log(`init: ${report.init.ok ? `${report.init.method} (by ${report.init.signer})` : "not initialised (no init call succeeded)"}`);
    for (const r of report.results) {
      console.log(`\n${ICON[r.status]}  ${r.name}  [${r.id}]`);
      console.log(`  ${r.explanation}`);
      for (const e of r.event_sequence)
        console.log(`    #${e.block} ${e.from} → ${e.to}: ${e.action}${e.deposit_near !== "0.0000" ? ` (${e.deposit_near} NEAR)` : ""} ${e.ok ? "✓" : "✗"} ${e.ok ? "" : e.detail}`);
      const deltas = Object.entries(r.token_deltas).map(([k, v]) => `${k} ${v.near}`);
      if (deltas.length) console.log(`  net NEAR: ${deltas.join(", ")}`);
      if (r.findings.length) console.log(`  sim findings: ${r.findings.join(" | ")}`);
      if (args.includes("--trace")) console.log(r.trace);
    }
    const v = verdictOf(card, report);
    const s = report.summary;
    console.log(`\nSummary: ${s.held} held, ${s.broken} broken, ${s.inconclusive} inconclusive, ${s.error} error  (${report.duration_ms} ms)`);
    console.log(`VERDICT: ${v.verdict.toUpperCase()}`);
    for (const r of v.reasons) console.log(`  - ${r}`);
    process.exit(s.broken ? 3 : 0);
  } catch (e) {
    const { body } = toErrorPayload(e);
    console.error(`✘ ${body.error.code}: ${body.error.message}`);
    process.exit(1);
  }
}
main();
