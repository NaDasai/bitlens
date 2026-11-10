/**
 * CLI: run attack scenarios in near-contract-sim.
 *   npm run attack -- vulnerable-vault.bitlens-demo
 *   npm run attack -- <account> --list             # suggested scenarios only
 *   npm run attack -- <account> --only unauth:admin_drain,double_withdraw
 *   npm run attack -- <account> --scenario my-attack.json    # run your own scenario JSON
 *   npm run attack -- <account> --say "the attacker calls admin_drain and keeps the money"
 *                                   # English → scenario JSON via the LLM (NEAR AI Cloud, fallback OpenRouter)
 *   add --json for the raw report, --trace for full receipt trees,
 *   --print-scenario to print the scenario JSON (with --list: every preset's JSON)
 */
import { readFile } from "node:fs/promises";
import { listAttacks, runAttacks, scan, toErrorPayload, translateToScenario, verdictOf } from "../core/index.js";

const ICON = { held: "✅ HELD", broken: "❌ BROKEN", inconclusive: "❔ INCONCLUSIVE", not_applicable: "➖ N/A", error: "⚠️ ERROR" } as const;

async function main() {
  const args = process.argv.slice(2);
  const valued = ["--only", "--say", "--scenario"];
  const id = args.find((a, i) => !a.startsWith("--") && !valued.includes(args[i - 1]));
  if (!id) {
    console.error('usage: npm run attack -- <account_id> [--list] [--only id1,id2] [--scenario file.json] [--say "english"] [--print-scenario] [--json] [--trace]');
    process.exit(2);
  }
  const opt = (name: string) => (args.indexOf(name) >= 0 ? args[args.indexOf(name) + 1] : undefined);
  const only = opt("--only")?.split(",").filter(Boolean);
  const printScenario = args.includes("--print-scenario");
  try {
    if (args.includes("--list")) {
      const { card, attacks } = await listAttacks(id);
      if (args.includes("--json") || printScenario) return console.log(JSON.stringify(printScenario ? attacks.map((a) => a.scenario) : attacks, null, 2));
      console.log(`${card.summary}\n\nSuggested attacks (${attacks.length}):`);
      for (const a of attacks) console.log(`  ${a.id.padEnd(32)} ${a.name}\n  ${"".padEnd(32)} checks: ${a.description}`);
      return;
    }
    let custom: unknown[] | undefined;
    if (opt("--scenario")) custom = [JSON.parse(await readFile(opt("--scenario")!, "utf8"))];
    if (opt("--say")) {
      console.error(`Translating into scenario JSON…`);
      const t = await translateToScenario(opt("--say"), await scan(id));
      console.error(`  ${t.provider}, ${t.model}, ${t.attempts} attempt(s)${t.fallback_from ? ` (fallback: ${t.fallback_from.join("; ")})` : ""}`);
      custom = [t.scenario];
    }
    if (custom && printScenario) console.log(JSON.stringify(custom[0], null, 2));
    console.error(`Running ${custom ? "the custom scenario" : "attacks"} on ${id} in near-contract-sim (local, no transactions sent anywhere)…`);
    const { card, report } = await runAttacks(id, only, { custom });
    if (args.includes("--json")) return console.log(JSON.stringify({ card, report, ...verdictOf(card, report) }, null, 2));
    console.log(`\n=== BitLens attack report: ${report.account_id} ===`);
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
    console.log(`\nSummary: ${s.held} held, ${s.broken} broken, ${s.inconclusive} inconclusive, ${s.not_applicable} n/a, ${s.error} error  (${report.duration_ms} ms${report.cache ? `, cached: same code simulated ${report.cache.age_s}s ago` : ""})`);
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
