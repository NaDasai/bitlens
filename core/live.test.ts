/** Live mainnet smoke test (needs network). Run: npm run test:live */
import { test } from "node:test";
import assert from "node:assert/strict";
import { RpcError, scan } from "./index.js";

const LIVE = process.env.XRAY_LIVE === "1";

test("mainnet: wrap.near / token.sweat / aurora scan with verified code hash", { skip: !LIVE }, async () => {
  const expect: Record<string, { std: string; strong: string }> = {
    "wrap.near": { std: "nep141", strong: "transfer" },
    "token.sweat": { std: "nep141", strong: "deploy_contract" },
    aurora: { std: "nep141", strong: "deploy_contract" },
  };
  for (const [id, e] of Object.entries(expect)) {
    const card = await scan(id);
    assert.equal(card.code_hash_verified, true, `${id} code hash`);
    assert.ok(card.methods.length > 5, `${id} methods`);
    assert.ok(card.standards.some((s) => s.id === e.std), `${id} standards`);
    assert.ok(card.capabilities.some((c) => c.id === e.strong && c.confidence === "strong"), `${id} ${e.strong}`);
    console.log(`  ${card.summary}`);
  }
});

test("mainnet: UNKNOWN_ACCOUNT and NO_CONTRACT_CODE", { skip: !LIVE }, async () => {
  await assert.rejects(scan("xray-no-such-account-4242.near"), (err: any) => err instanceof RpcError && err.code === "UNKNOWN_ACCOUNT");
  await assert.rejects(scan("root.near"), (err: any) => err instanceof RpcError && err.code === "NO_CONTRACT_CODE");
});
