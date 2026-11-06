/**
 * NEP standard signatures: argument names and JSON types from the standards'
 * public interfaces, required deposits from the NEP specs. No network.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { argTypeProblems, formatSignature, standardArgs, standardSignatures } from "./index.js";

const FT = {
  standards: [{ id: "nep141", name: "FT Core (NEP-141)" }, { id: "nep145", name: "Storage Management (NEP-145)" }],
  methods: ["ft_transfer", "ft_transfer_call", "ft_total_supply", "ft_balance_of", "storage_deposit", "storage_withdraw", "storage_unregister", "storage_balance_bounds", "storage_balance_of", "new"],
};

test("signatures: only methods of detected standards that the contract exports", () => {
  const sigs = standardSignatures(FT);
  assert.deepEqual(sigs.map((s) => s.method).sort(), FT.methods.filter((m) => m !== "new").sort());
  assert.deepEqual(standardSignatures({ standards: [], methods: ["ft_transfer"] }), [], "no standard detected → no signatures");
  assert.deepEqual(standardSignatures({ standards: FT.standards, methods: ["ft_transfer"] }).map((s) => s.method), ["ft_transfer"], "not exported → not listed");
});

test("ft_transfer: exact NEP-141 arguments, 1 yoctoNEAR; storage_deposit is payable", () => {
  const sigs = new Map(standardSignatures(FT).map((s) => [s.method, s]));
  const ft = sigs.get("ft_transfer")!;
  assert.deepEqual(ft.args, [
    { name: "receiver_id", types: ["string"] },
    { name: "amount", types: ["string"] },
    { name: "memo", types: ["string", "null"] },
  ]);
  assert.equal(ft.deposit, "1 yocto");
  assert.equal(formatSignature(ft), "ft_transfer(receiver_id: string, amount: string, memo: string|null) [NEP141] · attach exactly 1 yoctoNEAR");
  assert.equal(sigs.get("storage_deposit")!.deposit, "storage deposit");
  assert.equal(sigs.get("ft_total_supply")!.deposit, null);
});

test("standardArgs: accounts are the signer, optional arguments null, types match the signature", () => {
  const sigs = new Map(standardSignatures(FT).map((s) => [s.method, s]));
  assert.deepEqual(standardArgs(sigs.get("ft_transfer")!, "attacker.near"), { receiver_id: "attacker.near", amount: "1", memo: null });
  assert.deepEqual(standardArgs(sigs.get("ft_transfer_call")!, "attacker.near"), { receiver_id: "attacker.near", amount: "1", memo: null, msg: "" });
  for (const s of standardSignatures(FT)) assert.deepEqual(argTypeProblems(s, standardArgs(s, "user.near")), [], `${s.method}: built args match its signature`);
});

test("argTypeProblems: wrong JSON types are named; unknown fields are ignored", () => {
  const ft = standardSignatures(FT).find((s) => s.method === "ft_transfer")!;
  assert.deepEqual(argTypeProblems(ft, { amount: 5, receiver_id: "x.near", extra: 1 }), ["ft_transfer.amount must be string (NEP141), not number"]);
  assert.deepEqual(argTypeProblems(ft, { memo: null }), []);
  assert.deepEqual(argTypeProblems(ft, undefined), []);
});
