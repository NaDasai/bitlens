/**
 * MCP over HTTP (POST /mcp): the official SDK client talks to the real HTTP
 * server on a random port. Only demo contracts, so no network and no runner.
 */
import assert from "node:assert/strict";
import type { AddressInfo } from "node:net";
import { after, before, test } from "node:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { server } from "./index.js";

const TOKEN = "test-token";
let base = "";

before(async () => {
  process.env.BITLENS_MCP_TOKEN = TOKEN;
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});
after(() => {
  delete process.env.BITLENS_MCP_TOKEN;
  server.close();
});

async function connect(token = TOKEN) {
  const client = new Client({ name: "bitlens-http-test", version: "0.0.0" });
  await client.connect(new StreamableHTTPClientTransport(new URL(`${base}/mcp`), { requestInit: { headers: { Authorization: `Bearer ${token}` } } }));
  return client;
}

const initialize = {
  jsonrpc: "2.0",
  id: 1,
  method: "initialize",
  params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "raw", version: "0" } },
};
const post = (headers: Record<string, string>) =>
  fetch(`${base}/mcp`, {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json, text/event-stream", ...headers },
    body: JSON.stringify(initialize),
  });

test("the SDK client lists the same six tools as stdio, including check_transaction", async () => {
  const client = await connect();
  const names = (await client.listTools()).tools.map((t) => t.name).sort();
  assert.deepEqual(names, ["assess_contract", "check_transaction", "list_attacks", "run_attacks", "run_custom_attack", "scan_contract"]);
  await client.close();
});

test("scan_contract works over HTTP; a bad account id is an isError result", async () => {
  const client = await connect();
  const ok: any = await client.callTool({ name: "scan_contract", arguments: { account_id: "vulnerable-vault.bitlens-demo" } });
  assert.ok(!ok.isError, ok.content?.[0]?.text);
  assert.equal(ok.structuredContent.risk_level, "high");
  const bad: any = await client.callTool({ name: "scan_contract", arguments: { account_id: "Not A Valid ID!!" } });
  assert.equal(bad.isError, true);
  assert.match(bad.content[0].text, /INVALID_ACCOUNT_ID/);
  await client.close();
});

test("initialize over raw HTTP answers with serverInfo bitlens", async () => {
  const res = await post({ authorization: `Bearer ${TOKEN}` });
  assert.equal(res.status, 200);
  const body: any = await res.json();
  assert.equal(body.result.serverInfo.name, "bitlens");
});

test("no token or a wrong token → 401 with WWW-Authenticate; GET → 405", async () => {
  const none = await post({});
  assert.equal(none.status, 401);
  assert.equal(none.headers.get("www-authenticate"), "Bearer");
  assert.equal(((await none.json()) as any).error.code, "UNAUTHORIZED");
  assert.equal((await post({ authorization: "Bearer wrong-token" })).status, 401);
  assert.equal((await post({ authorization: `Bearer ${TOKEN}x` })).status, 401, "a longer token is rejected too");

  const get = await fetch(`${base}/mcp`, { headers: { authorization: `Bearer ${TOKEN}` } });
  assert.equal(get.status, 405);
  assert.deepEqual(await get.json(), { jsonrpc: "2.0", error: { code: -32000, message: "Method not allowed." }, id: null });
});

test("BITLENS_MCP_TOKEN unset → 404 MCP_DISABLED (off by default)", async () => {
  delete process.env.BITLENS_MCP_TOKEN;
  try {
    const res = await post({ authorization: `Bearer ${TOKEN}` });
    assert.equal(res.status, 404);
    assert.equal(((await res.json()) as any).error.code, "MCP_DISABLED");
  } finally {
    process.env.BITLENS_MCP_TOKEN = TOKEN;
  }
});
