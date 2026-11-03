/**
 * End-to-end MCP check, the way an agent sees it: spawns the server over
 * stdio with the official client, lists tools, calls them.
 *   npx tsx scripts/mcp-smoke.ts [account_id] [--wait]
 * --wait polls assess_contract until the attack engine is warm.
 */
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../", import.meta.url));
const target = process.argv.slice(2).find((a) => !a.startsWith("--")) ?? "vulnerable-vault.xray-demo";
const wait = process.argv.includes("--wait");

const transport = new StdioClientTransport({
  command: `${root}node_modules/.bin/tsx`,
  args: [`${root}mcp/server.ts`],
  stderr: "inherit",
});
const client = new Client({ name: "xray-smoke", version: "0.0.0" });
await client.connect(transport);

const text = (r: any) => r.content?.[0]?.text ?? "";
const { tools } = await client.listTools();
console.log("tools:", tools.map((t) => t.name).join(", "));

const sc: any = await client.callTool({ name: "scan_contract", arguments: { account_id: target } });
console.log("\nscan_contract →", text(sc).split("\n")[0]);
const bad: any = await client.callTool({ name: "scan_contract", arguments: { account_id: "Robert'); DROP TABLE" } });
console.log("scan_contract(bad id) → isError:", bad.isError, "|", text(bad));
const la: any = await client.callTool({ name: "list_attacks", arguments: { account_id: target } });
console.log("list_attacks →", la.structuredContent.attacks.map((a: any) => a.id).join(", "));

for (let i = 0; ; i++) {
  const as: any = await client.callTool({ name: "assess_contract", arguments: { account_id: target } });
  const sc = as.structuredContent;
  console.log(`\nassess_contract → ${text(as).split("\n")[0]}`);
  if (sc.attacks_run || !wait || i > 120) {
    console.log(JSON.stringify({ verdict: sc.verdict, verdict_reasons: sc.verdict_reasons, summary: sc.attacks?.summary }, null, 2));
    break;
  }
  await new Promise((r) => setTimeout(r, 15_000));
}
await client.close();
