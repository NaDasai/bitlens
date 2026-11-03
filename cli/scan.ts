/**
 * CLI front door.
 *   npm run scan -- wrap.near            # fetch from mainnet RPC and scan
 *   npm run scan -- --wasm path.wasm     # scan a local WASM file (no network)
 *   add --json for the raw risk card
 */
import { readFile } from "node:fs/promises";
import { basename } from "node:path";
import { scan, scanWasm, toErrorPayload, type RiskCard } from "../core/index.js";

function render(card: RiskCard): string {
  const L: string[] = [];
  L.push(`\n=== NEAR X-Ray risk card: ${card.account_id} ===`);
  L.push(card.summary);
  L.push(
    `source: ${card.source}${card.rpc_url ? ` (${card.rpc_network} via ${card.rpc_url}, block ${card.block_height})` : ""}`,
  );
  L.push(`code_hash: ${card.code_hash}${card.code_hash_verified === null ? "" : card.code_hash_verified ? "  ✔ matches RPC" : "  ✘ MISMATCH vs RPC"}  (${card.code_size_bytes} bytes)`);
  L.push(`\nStandards: ${card.standards.length ? card.standards.map((s) => `${s.id} (${s.name})`).join(", ") : "none detected"}`);
  L.push(`\nCapabilities (from WASM host imports):`);
  if (!card.capabilities.length) L.push("  (none — contract cannot transfer, deploy, add keys, or make calls)");
  L.push(`  import profile: ${card.import_profile.note}`);
  for (const c of card.capabilities)
    L.push(
      `  ${c.icon} [${c.severity}/${c.confidence}] ${c.label}   ← ${c.evidence.join(", ")}` +
        (c.corroborated_by.length ? `   (methods: ${c.corroborated_by.slice(0, 4).join(", ")})` : ""),
    );
  if (card.access_keys)
    L.push(`\nAccess keys: ${card.access_keys.full_access} full-access, ${card.access_keys.function_call} function-call${card.access_keys.locked ? "  (locked: no full-access keys)" : ""}`);
  const priv = card.notable_methods.filter((m) => m.privileged);
  const custom = card.notable_methods.filter((m) => !m.privileged);
  L.push(`\nPrivileged-looking methods (${priv.length}):`);
  for (const m of priv) L.push(`  ⚠️  ${m.name}  (matches ${m.matched.join(", ")})`);
  L.push(`Other custom methods (${custom.length}): ${custom.map((m) => m.name).join(", ") || "-"}`);
  L.push(`\nAll methods (${card.methods.length}): ${card.methods.join(", ")}`);
  L.push(`\nRisk: ${card.risk.level.toUpperCase()}`);
  for (const r of card.risk.reasons) L.push(`  - ${r}`);
  return L.join("\n");
}

async function main() {
  const args = process.argv.slice(2);
  const json = args.includes("--json");
  const wasmIdx = args.indexOf("--wasm");
  const positional = args.filter((a, i) => !a.startsWith("--") && (wasmIdx === -1 || i !== wasmIdx + 1));
  if (wasmIdx === -1 && positional.length === 0) {
    console.error("usage: npm run scan -- <account_id> [--json]\n       npm run scan -- --wasm <file.wasm> [--json]");
    process.exit(2);
  }
  const targets: Array<() => Promise<RiskCard>> = [];
  if (wasmIdx !== -1) {
    const file = args[wasmIdx + 1];
    targets.push(async () => scanWasm(new Uint8Array(await readFile(file)), { accountId: basename(file), source: "file" }));
  } else {
    for (const id of positional) targets.push(() => scan(id));
  }
  let failed = false;
  for (const run of targets) {
    try {
      const card = await run();
      console.log(json ? JSON.stringify(card, null, 2) : render(card));
    } catch (e) {
      failed = true;
      const { body } = toErrorPayload(e);
      console.error(json ? JSON.stringify(body) : `\n✘ ${body.error.code}: ${body.error.message}`);
    }
  }
  process.exit(failed ? 1 : 0);
}

main();
