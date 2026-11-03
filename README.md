# NEAR X-Ray

**A security scanner for NEAR smart contracts. It answers "is it safe to connect my wallet to this contract?" from the on-chain bytecode alone, so it works even when no source code was published.**

> Status: work in progress (hackathon build). **Layer 1 (capability scan) works.** Layer 2 (attack simulation in `near-contract-sim`), the web UI and the MCP server are next. This README is updated after each step.

## Problem

Most NEAR contracts people interact with have no verified source. Wallets show a method name and a deposit, but not what the contract *can do*: send NEAR out, add a full-access key, or redeploy itself with new logic. AI agents that transact on-chain have the same blind spot.

## How it works (Layer 1)

```
account id ──view_code RPC──▶ WASM bytes ──┬─ near-contract-parser ─▶ exported methods + NEP standards
                                           └─ WebAssembly.Module.imports ─▶ host capabilities (what it CAN do)
                                                    ▼
                                               risk card
```

NEAR features used: the `view_code` and `view_access_key_list` JSON-RPC queries, NEP standard detection (NEP-141/145/148/171/177/178/199/330), and **WASM host imports**. A contract can only perform an action through a runtime host function such as `promise_batch_action_deploy_contract`. **If the import is absent, the contract cannot do it.**

| Host import | Flag |
|---|---|
| `promise_batch_action_add_key_with_full_access` | 🔴 can add full-access keys |
| `promise_batch_action_deploy_contract` (+ global-contract variants) | 🔴 can redeploy itself |
| `promise_batch_action_delete_account` | 🔴 can delete an account |
| `promise_batch_action_add_key_with_function_call` | 🟠 can add function-call keys |
| `promise_batch_action_transfer` | 💰 can send NEAR out |
| `promise_batch_action_stake` | ⚠️ can stake |
| `promise_then` / `promise_result*`, `promise_yield_*` | info: callbacks, yield/resume (used to pick attacks) |

**Strong vs weak evidence.** near-sdk links *every* Promise action into the binary as soon as a contract builds any Promise, so a plain wrapped-NEAR contract still imports `deploy_contract`. X-Ray reports this honestly:
- `import_profile.kind = "bulk"`: the module links 7 or more of the 9 Promise actions.
- A capability is **strong** when the module links actions selectively, or when a public non-standard method name supports it (for example `upgrade` for deploy, `attach_full_access_key` for add-key). Otherwise it is **weak**: it is still shown, but does not raise the risk level on its own.

Method-name heuristics: non-standard methods are "notable". Of those, any name containing `owner admin upgrade migrate set_ withdraw drain pause self deploy _key grant revoke mint burn` is flagged ⚠️ *privileged-looking: check who can call it*. View-like names (`get_*`, `is_*`, `*_of`) are skipped.

## Quickstart (Layer 1)

Prerequisites: Node.js 20 or later, and outbound HTTPS to a NEAR RPC.

Verified expected output (mainnet, Nov 2026):

| Account | Methods | Standards | Strong capabilities | Risk |
|---|---|---|---|---|
| `wrap.near` | 15 | NEP-141/145/148 | 💰 sends NEAR (`near_withdraw`); no full-access keys | MEDIUM |
| `token.sweat` | 60 | NEP-141/145/148/330 | 🔴 redeploys (`up_deploy_code`); 16 admin-looking `acl_*` methods | HIGH |
| `aurora` | 77 | NEP-141/148 | 🔴 adds full-access keys (`attach_full_access_key`), 🔴 redeploys (`upgrade`), 🟠 function-call keys, 💰 sends NEAR; 1 full-access key | HIGH |

1. `npm install`
2. `npm test` → expect `# pass 6`, `# fail 0`. This covers account-id validation, capability detection, and RPC error handling against a local fake RPC.
3. `npm run test:live` → expect `# pass 2`. This scans wrap.near, token.sweat and aurora on mainnet, checks each locally computed code hash against the RPC's, and checks `UNKNOWN_ACCOUNT` / `NO_CONTRACT_CODE`.
4. `npm run scan -- wrap.near token.sweat aurora` → one risk card per account (methods, standards, capabilities with the exact import as evidence, privileged methods, risk level).
5. `npm run server`, then `curl "http://localhost:8787/scan?account_id=wrap.near"` → the risk card as JSON. `POST /scan` with `{"account_id":"..."}` works too.

Error cases, each returned with a clear code:
- `curl "localhost:8787/scan?account_id=Bad..Id"` → HTTP 400 `INVALID_ACCOUNT_ID`
- `account_id=xray-no-such-account-4242.near` → HTTP 404 `UNKNOWN_ACCOUNT`
- `account_id=root.near` (a wallet, no contract) → HTTP 404 `NO_CONTRACT_CODE`
- RPC unreachable → HTTP 502 `RPC_UNAVAILABLE`

Options:
- `NEAR_RPC_URL=https://rpc.testnet.near.org npm run scan -- <testnet-account>` uses a different RPC. Comma-separate several URLs to try them in order.
- `npm run scan -- <id> --json` prints the raw card.
- **Offline:** `./scripts/fetch-reference-wasm.sh`, then `npm run scan -- --wasm fixtures/reference/aurora.wasm` scans a local WASM file. The script downloads public GitHub builds of wrap.near, Aurora and SWEAT. They are not guaranteed byte-identical to the deployed code.
- `HTTPS_PROXY` / `NO_PROXY` are honoured automatically.

## Repo layout

```
core/      shared engine (scan, RPC, capability rules). No transport code.
server/    HTTP backend: thin wrapper over core/
cli/       CLI: thin wrapper over core/
mcp/       MCP server (stdio), coming next
web/       web UI, coming next
runner/    Rust attack runner over near-contract-sim, coming next
contracts/ demo contracts (clean / risky / vulnerable), coming next
```

## Limitations

The analysis works from bytecode only. Capability detection is reliable in one direction: if an import is absent, that capability is impossible. A present import means the code *can* reach that action, not that any caller can trigger it. Layer 2 attacks test who can trigger it. Deep logic is not inferred. The method-name heuristics are hints, not proofs.

NEAR X-Ray never signs or sends transactions. It only makes read-only RPC view calls.
