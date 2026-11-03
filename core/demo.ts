/**
 * Built-in demo contracts (contracts/res/*.wasm, built from contracts/*).
 * Addressable by reserved pseudo account ids so the web UI / MCP demo works
 * offline and deterministically. They never touch an RPC.
 */
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

export const DEMO_SUFFIX = ".xray-demo";

export const DEMO_CONTRACTS: Record<string, { file: string; description: string }> = {
  "clean-vault.xray-demo": { file: "clean_vault.wasm", description: "Correct native-NEAR vault. Every attack should be HELD." },
  "risky-vault.xray-demo": {
    file: "risky_vault.wasm",
    description: "Vault with owner-gated upgrade + add_full_access_key. Red capabilities, attacks HELD.",
  },
  "vulnerable-vault.xray-demo": {
    file: "vulnerable_vault.wasm",
    description: "Planted bugs: admin_drain has no owner check; withdraw debits only in its callback (double-spend).",
  },
};

export const DEMO_DIR = fileURLToPath(new URL("../contracts/res/", import.meta.url));

export function isDemoAccount(id: string): boolean {
  return id.endsWith(DEMO_SUFFIX);
}

export async function readDemoWasm(id: string): Promise<Uint8Array> {
  const entry = DEMO_CONTRACTS[id];
  if (!entry) {
    throw new Error(`Unknown demo contract "${id}". Available: ${Object.keys(DEMO_CONTRACTS).join(", ")}`);
  }
  return new Uint8Array(await readFile(DEMO_DIR + entry.file));
}
