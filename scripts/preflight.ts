/**
 * Pre-demo checklist: `npm run preflight`. Run it an hour before presenting.
 * Checks everything the demo path touches and warms the offline code cache for
 * the mainnet example chips, so the demo survives the venue wifi dropping out.
 * Exit 1 if anything the demo needs is broken; warnings (⚠) do not fail.
 */
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { DEMO_CONTRACTS, llmStatus, RUNNER_BIN, runAttacks, scan, verdictOf } from "../core/index.js";

const root = fileURLToPath(new URL("../", import.meta.url));
const PORT = Number(process.env.PORT ?? 8787);
let failed = 0;
const ok = (m: string) => console.log(`✔ ${m}`);
const warn = (m: string) => console.log(`⚠ ${m}`);
const bad = (m: string) => (failed++, console.log(`✘ ${m}`));

// 1. Toolchain + engine
const major = Number(process.versions.node.split(".")[0]);
major >= 20 ? ok(`Node ${process.versions.node}`) : bad(`Node ${process.versions.node}: need 20+`);
if (existsSync(RUNNER_BIN)) ok(`attack runner built (${RUNNER_BIN})`);
else bad("attack runner not built: run `npm run build:runner` (first build 10-30 min) BEFORE the demo");

// 2. Demo contracts: the story the demo tells
const WANT: Record<string, string> = {
  "clean-vault.bitlens-demo": "safe",
  "risky-vault.bitlens-demo": "caution",
  "vulnerable-vault.bitlens-demo": "dangerous",
  "yield-escrow.bitlens-demo": "dangerous",
};
for (const id of Object.keys(DEMO_CONTRACTS)) {
  try {
    const card = await scan(id);
    if (!existsSync(RUNNER_BIN)) {
      warn(`${id}: card ${card.risk.level.toUpperCase()} (attacks skipped, runner missing)`);
      continue;
    }
    const t0 = Date.now();
    const { report } = await runAttacks(id);
    const { verdict } = verdictOf(card, report);
    const s = report.summary;
    const line = `${id}: card ${card.risk.level.toUpperCase()}, ${s.broken} broken / ${s.held} held → ${verdict.toUpperCase()} (${Date.now() - t0} ms)`;
    verdict === WANT[id] ? ok(line) : bad(`${line}; expected ${WANT[id]?.toUpperCase()}`);
  } catch (e: any) {
    bad(`${id}: ${e.message}`);
  }
}

// 3. Mainnet examples: live RPC, and refresh the offline cache
for (const id of ["wrap.near", "token.sweat", "aurora"]) {
  try {
    const card = await scan(id);
    if (card.source === "rpc") ok(`${id}: live RPC ok (${card.rpc_url}, block ${card.block_height}), risk ${card.risk.level.toUpperCase()}, cached for offline use`);
    else warn(`${id}: RPC unreachable; the demo will use the cached copy from ${card.cached_at}`);
  } catch (e: any) {
    warn(`${id}: ${e.code ?? ""} ${e.message}. No live RPC and no cached copy: stick to the demo contracts`);
  }
}

// 4. Text-to-test (optional)
const ai = llmStatus();
const chain = ai.providers.map((p) => `${p.name} ${p.configured ? `✓ (${p.model})` : "no key"}`).join(" → ");
ai.configured
  ? ok(`text-to-test: ${chain}`)
  : warn("text-to-test: no LLM key (set NEAR_AI_API_KEY and/or OPEN_ROUTER_KEY); the custom-attack box accepts hand-written scenario JSON only");

// 5. Web server port
try {
  const r = await fetch(`http://localhost:${PORT}/health`);
  r.ok ? ok(`a server is already answering on :${PORT} (/health ok)`) : warn(`port ${PORT} answers /health with ${r.status}: something else is running there?`);
} catch {
  ok(`port ${PORT} is free for \`npm run server\``);
}

// 6. MCP server: starts and lists its tools
try {
  const transport = new StdioClientTransport({ command: `${root}node_modules/.bin/tsx`, args: [`${root}mcp/server.ts`], stderr: "ignore" });
  const client = new Client({ name: "bitlens-preflight", version: "0.0.0" });
  await client.connect(transport);
  const { tools } = await client.listTools();
  const names = tools.map((t) => t.name).sort().join(", ");
  tools.length === 5 ? ok(`MCP server starts over stdio; tools: ${names}`) : bad(`MCP server lists ${tools.length} tools: ${names}`);
  await client.close();
} catch (e: any) {
  bad(`MCP server: ${e.message}`);
}

console.log(failed ? `\n${failed} problem(s): fix before demoing.` : "\nReady to demo.");
process.exit(failed ? 1 : 0);
