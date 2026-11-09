/**
 * CLI: judge a transaction before signing it (BitLens never signs).
 *   npm run check -- <contract> <method> [--deposit 20] [--args '{"k":"v"}'] [--strict] [--json]
 *   npm run check -- vulnerable-vault.bitlens-demo deposit --deposit 20
 * Exit code: 0 allow, 1 confirm, 2 block, 3 error (never "sign" on 1-3).
 */
import { checkTransaction, toErrorPayload } from "../core/index.js";

const ICON = { allow: "✅ ALLOW", confirm: "⚠️  CONFIRM", block: "⛔ BLOCK" } as const;
const CODE = { allow: 0, confirm: 1, block: 2 } as const;

async function main() {
  const args = process.argv.slice(2);
  const opt = (name: string) => (args.includes(name) ? args[args.indexOf(name) + 1] : undefined);
  const valued = ["--deposit", "--args"];
  const pos = args.filter((a, i) => !a.startsWith("--") && !valued.includes(args[i - 1]));
  const [receiver_id, method] = pos;
  if (!receiver_id || !method) {
    console.error("usage: npm run check -- <contract> <method> [--deposit 20] [--args '{...}'] [--strict] [--json]");
    process.exit(3);
  }
  try {
    const txArgs = opt("--args") ? JSON.parse(opt("--args")!) : undefined;
    console.error(`Checking ${method} on ${receiver_id}${opt("--deposit") ? ` with ${opt("--deposit")} NEAR attached` : ""} (scan + attacks in the local sim; nothing is signed or sent)…`);
    const r = await checkTransaction({ receiver_id, method, deposit_near: opt("--deposit"), args: txArgs }, args.includes("--strict") ? "strict" : "standard");
    if (args.includes("--json")) console.log(JSON.stringify(r, null, 2));
    else {
      console.log(`\n${ICON[r.decision]}  ${r.summary.replace(/^[A-Z]+: /, "")}`);
      for (const why of r.reasons) console.log(`  - ${why}`);
      for (const ev of r.evidence.slice(0, 1)) {
        console.log(`\n  Proof (${ev.name}):`);
        for (const e of ev.event_sequence) console.log(`    #${e.block} ${e.from} → ${e.to}: ${e.action}${e.deposit_near !== "0.0000" ? ` (${e.deposit_near} NEAR)` : ""} ${e.ok ? "✓" : `✗ ${e.detail}`}`);
      }
      if (r.replay_path) console.log(`\n  Replay it: http://localhost:8787${r.replay_path}  (npm run server)`);
      console.log(`\n  ${r.signing}`);
    }
    process.exit(CODE[r.decision]);
  } catch (e) {
    const { body } = toErrorPayload(e);
    console.error(`✘ ${body.error.code}: ${body.error.message}`);
    console.error("  An error is not an allow: do not sign.");
    process.exit(3);
  }
}
main();
