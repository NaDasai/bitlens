import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { assertAccountId, codeHash, isValidAccountId, RpcError, scan, scanWasm } from "./index.js";
import { makeWasm } from "./testutil/makeWasm.js";

test("account id validation", () => {
  for (const ok of ["wrap.near", "token.sweat", "aurora", "a1", "app-1.dao_x.near", "0x" + "a".repeat(40), "f".repeat(64)])
    assert.ok(isValidAccountId(ok), ok);
  for (const bad of ["", "a", "Wrap.near", "wrap..near", ".near", "near.", "a-", "-a", "x".repeat(65), "a b", "a/../b", "wrap.near\n", 42, null])
    assert.ok(!isValidAccountId(bad), String(bad));
  assert.equal(assertAccountId("  wrap.near "), "wrap.near");
  assert.throws(() => assertAccountId("DROP TABLE"), /Invalid NEAR account id/);
});

test("capabilities come from imports; absence means absent", async () => {
  const wasm = makeWasm(
    ["promise_batch_action_transfer", "promise_batch_action_add_key_with_full_access", "promise_then"],
    ["ft_transfer", "ft_transfer_call", "ft_total_supply", "ft_balance_of", "admin_drain", "get_owner", "withdraw"],
  );
  const card = await scanWasm(wasm, { accountId: "x.near", source: "file" });
  const ids = card.capabilities.map((c) => c.id);
  assert.deepEqual(ids.sort(), ["add_full_access_key", "callbacks", "transfer"]);
  assert.ok(!ids.includes("deploy_contract"));
  // selective import profile → every capability is strong
  assert.equal(card.import_profile.kind, "selective");
  assert.ok(card.capabilities.every((c) => c.confidence === "strong"));
  assert.equal(card.risk.level, "high");
  assert.ok(card.standards.some((s) => s.id === "nep141"));
  const priv = card.notable_methods.filter((m) => m.privileged).map((m) => m.name);
  assert.deepEqual(priv.sort(), ["admin_drain", "withdraw"]); // get_owner is view-like; ft_* are standard
});

test("bulk-linked SDK imports are weak unless a method corroborates them", async () => {
  const all = [
    "promise_batch_action_create_account", "promise_batch_action_deploy_contract", "promise_batch_action_function_call",
    "promise_batch_action_transfer", "promise_batch_action_stake", "promise_batch_action_add_key_with_full_access",
    "promise_batch_action_add_key_with_function_call", "promise_batch_action_delete_key", "promise_batch_action_delete_account",
  ];
  const plain = await scanWasm(makeWasm(all, ["deposit", "withdraw"]), { accountId: "v.near", source: "file" });
  assert.equal(plain.import_profile.kind, "bulk");
  assert.equal(plain.capabilities.find((c) => c.id === "deploy_contract")?.confidence, "weak");
  assert.equal(plain.capabilities.find((c) => c.id === "transfer")?.confidence, "strong");
  assert.equal(plain.risk.level, "low"); // sending NEAR + bulk-linked boilerplate is normal
  const upgradeable = await scanWasm(makeWasm(all, ["deposit", "withdraw", "upgrade"]), { accountId: "u.near", source: "file" });
  assert.equal(upgradeable.capabilities.find((c) => c.id === "deploy_contract")?.confidence, "strong");
  assert.equal(upgradeable.risk.level, "high");
});

test("drain-style method + transfer capability → HIGH", async () => {
  const card = await scanWasm(makeWasm(["promise_batch_action_transfer"], ["deposit", "withdraw", "admin_drain"]), {
    accountId: "d.near",
    source: "file",
  });
  assert.equal(card.risk.level, "high");
  assert.match(card.risk.reasons[0], /admin_drain/);
  const noTransfer = await scanWasm(makeWasm([], ["admin_drain"]), { accountId: "d.near", source: "file" });
  assert.equal(noTransfer.risk.level, "low"); // cannot send NEAR, so "drain" is just a name
});

test("demo contracts: clean LOW, risky HIGH (redeploy + add key), vulnerable HIGH (admin_drain)", async () => {
  const clean = await scan("clean-vault.xray-demo");
  assert.equal(clean.source, "demo");
  assert.equal(clean.risk.level, "low");
  const risky = await scan("risky-vault.xray-demo");
  assert.equal(risky.risk.level, "high");
  for (const id of ["deploy_contract", "add_full_access_key"])
    assert.equal(risky.capabilities.find((c) => c.id === id)?.confidence, "strong", id);
  const vuln = await scan("vulnerable-vault.xray-demo");
  assert.equal(vuln.risk.level, "high");
  assert.match(vuln.risk.reasons.join("\n"), /admin_drain/);
  await assert.rejects(scan("nope.xray-demo"), /Unknown demo contract/);
});

test("base58 code hash", () => {
  // sha256("") in base58, as NEAR would report it
  assert.equal(codeHash(new Uint8Array()), "GKot5hBsd81kMupNCXHaqbhv3huEbxAFMLnpcX2hniwn");
});

// --- RPC path against a local fake RPC speaking NEAR's JSON-RPC error shapes ---
let srv: Server;
let rpcUrl: string;
const FIXTURE = makeWasm(["promise_batch_action_transfer"], ["withdraw"]);
before(async () => {
  srv = createServer(async (req, res) => {
    let raw = "";
    for await (const c of req) raw += c;
    const { params } = JSON.parse(raw);
    const reply = (body: unknown) => res.end(JSON.stringify({ jsonrpc: "2.0", id: "near-xray", ...body as object }));
    const handlerError = (name: string, data: string) =>
      reply({ error: { name: "HANDLER_ERROR", cause: { name, info: {} }, code: -32000, message: "Server error", data } });
    if (params.account_id === "ghost.near") return handlerError("UNKNOWN_ACCOUNT", "account ghost.near does not exist while viewing");
    if (params.account_id === "wallet.near")
      return handlerError("NO_CONTRACT_CODE", "Contract code for contract ID #wallet.near has never been observed on the node");
    if (params.request_type === "view_access_key_list")
      return reply({ result: { keys: [{ public_key: "ed25519:x", access_key: { nonce: 1, permission: "FullAccess" } }] } });
    reply({ result: { code_base64: Buffer.from(FIXTURE).toString("base64"), hash: codeHash(FIXTURE), block_height: 123 } });
  });
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
  rpcUrl = `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;
});
after(() => srv.close());

test("scan(): view_code → card, hash verified, keys counted", async () => {
  const card = await scan("vault.near", { rpcUrls: [rpcUrl] });
  assert.equal(card.source, "rpc");
  assert.equal(card.code_hash_verified, true);
  assert.equal(card.block_height, 123);
  assert.deepEqual(card.access_keys, { full_access: 1, function_call: 0, locked: false });
  assert.deepEqual(card.methods, ["withdraw"]);
});

test("scan(): UNKNOWN_ACCOUNT / NO_CONTRACT_CODE / unreachable RPC", async () => {
  await assert.rejects(scan("ghost.near", { rpcUrls: [rpcUrl] }), (e: any) => e instanceof RpcError && e.code === "UNKNOWN_ACCOUNT");
  await assert.rejects(scan("wallet.near", { rpcUrls: [rpcUrl] }), (e: any) => e instanceof RpcError && e.code === "NO_CONTRACT_CODE");
  await assert.rejects(scan("x.near", { rpcUrls: ["http://127.0.0.1:1"] }), (e: any) => e.code === "RPC_UNAVAILABLE");
  await assert.rejects(scan("NOT VALID"), /Invalid NEAR account id/);
});
