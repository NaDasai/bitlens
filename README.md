# NEAR X-Ray

**A security scanner for NEAR smart contracts. Paste a mainnet account and X-Ray reads the deployed WASM, tells you what the contract *can* do, then attacks the real bytecode in a local NEAR runtime and reports which defences held and which broke. It works without source code, for people (web UI) and for AI agents (MCP server).**

Hackathon track: AI Security & Defense.

```
account id ─view_code RPC─▶ WASM ─▶ ① risk card ─▶ ② attacks in near-contract-sim ─▶ verdict
                                     (capabilities,     (local nearcore runtime:          safe /
                                      standards,         real gas, receipts, callbacks)   caution /
                                      privileged methods)                                  dangerous
             web UI ◀── HTTP ──┐                                  ┌── MCP (stdio) ──▶ AI agents
                               └────────── core/ (one engine) ────┘
```

## Contents
- [Quickstart](#quickstart)
- [What you will see](#what-you-will-see)
- [MCP server (for AI agents)](#mcp-server-for-ai-agents)
- [How it works](#how-it-works)
- [Attack catalogue](#attack-catalogue)
- [NEAR features used](#near-features-used)
- [HTTP API and CLI](#http-api-and-cli)
- [Repo layout](#repo-layout)
- [Limitations (honest)](#limitations-honest)

## Quickstart

### Prerequisites

| Need | Why | Check |
|---|---|---|
| Node.js 20+ | scanner, web server, MCP server | `node --version` |
| Rust via rustup | attack runner. `runner/rust-toolchain.toml` pins **Rust 1.95.0** + `wasm32-unknown-unknown`; rustup installs both on first build | `rustup --version` |
| clang + libclang (`apt-get install clang libclang-dev` on Debian/Ubuntu; Xcode CLT on macOS) | nearcore builds RocksDB through bindgen | `ls /usr/lib/llvm-*/lib/libclang.so` |
| outbound HTTPS to a NEAR RPC | fetching deployed code (not needed for the demo contracts) | |
| *optional:* `cargo install cargo-near --version 0.22.0 --locked` | only to rebuild the demo contracts; their WASM is committed | |

> ⚠️ **First build of the attack engine compiles nearcore: 10-30 minutes and ~3.5 GB of disk** (≈2.2 GB `runner/target`, ≈1 GB cargo cache). It took 11 min on 4 cores here. Later builds are seconds. The scanner, web UI and MCP server all start immediately and work during the build; attack features say "warming up" until it is done.

### Steps (each with expected output)

1. `npm install`
2. `npm test` → `# pass 12`, `# fail 0` (account-id validation, capability detection, RPC errors and the offline fallback against a fake RPC, attack selection, verdict rules; no network).
3. `npm run build:runner` (the first-build warning above applies) → ends with `Finished \`release\` profile [optimized]`; the binary is `runner/target/release/xray-runner`. You can skip this: the server and MCP server start the same build in the background if the binary is missing.
4. `npm run test:sim` → `# pass 5`, ~2 s. Pins the status of **every** scenario on all four demo contracts, plus the risk level and verdict, through the real engine. If it passes, the demo tells the same story.
   By hand: `npm run attack -- vulnerable-vault.xray-demo` → 8 scenarios, `Summary: 6 held, 2 broken, 0 inconclusive`, `VERDICT: DANGEROUS`, exit code 3; `npm run attack -- clean-vault.xray-demo` → `7 held, 0 broken`, `VERDICT: SAFE`, exit code 0.
5. `npm run server` → `NEAR X-Ray backend on http://localhost:8787` and, a few seconds later, `[engine] attack engine ready`.
6. Open **http://localhost:8787** and follow the demo path below.
7. **Before a live demo:** `npm run preflight` (~4 s) → a ✔/⚠/✘ checklist ending in `Ready to demo.`:
   - Node version and runner build.
   - All four demo verdicts.
   - Live RPC for wrap.near / token.sweat / aurora. This also refreshes the offline copy of their code (see below).
   - Port 8787 free.
   - MCP server starts and lists 4 tools.

   Exit code 1 if anything the demo needs is broken.
8. *Optional, live mainnet:* `npm run test:live` → `# pass 2` (scans wrap.near, token.sweat and aurora; checks each locally computed code hash against the RPC's; checks the `UNKNOWN_ACCOUNT` / `NO_CONTRACT_CODE` errors).

### Demo path (web)
1. Click **clean-vault** → green **LOW** card. In *Attack proof*, click **Run 7 attacks** → **SAFE**, all ✅ HELD (each one shows why: "only the owner can call this", "Method on_withdraw is private"…).
2. Click **vulnerable-vault** → red **HIGH** card, first reason: `admin_drain` looks like a fund-drain method.
3. **Run 8 attacks** → **DANGEROUS**:
   - ❌ `admin_drain`: attacker.near → contract `call admin_drain` ✓, contract → attacker.near `Transfer 67.8015 NEAR` ✓, net NEAR: `attacker.near +67.8015`, `vulnerable-vault.xray-demo −67.8015`.
   - ❌ double-withdraw: deposit 5 NEAR, two same-block withdraws, 10 NEAR back.
   - Each result has the receipt sequence and a collapsible full receipt trace from the sim.
4. Click **yield-escrow** → green **LOW** card: nothing in the bytecode looks dangerous. **Run 9 attacks** → **DANGEROUS**:
   - ❌ stale yield: the user locks 5 NEAR in `request_payout` (block 16), nobody approves, the yield times out, and `on_payout_decision` runs at block 217 but never re-credits. The user's `withdraw` at block 220 fails, and 5 NEAR is stuck with no owner.
   - **The scan alone would have passed it; the attack proves the bug.**
5. Paste `wrap.near` → real mainnet code, **LOW**; attacks → **SAFE** (4 held, 1 not applicable).

**Venue wifi down?** Every successful fetch saves the code to `.cache/code/` (gitignored). If every RPC endpoint is unreachable, X-Ray analyses that copy instead. The card says so in yellow ("⚠ RPC unreachable: showing the copy of this code fetched …"), `source` is `"cache"`, and MCP results carry an `offline_cache` note. Only *unreachable* falls back: "unknown account" / "no contract" answers from a live RPC are never masked. The four demo contracts never need the network.

Links can be shared: `http://localhost:8787/?account=vulnerable-vault.xray-demo`.

## What you will see

Verified output (Nov 2026). Mainnet code is fetched read-only and attacked **only in the local sim**.

| Account | Risk card | Attacks | Verdict |
|---|---|---|---|
| `clean-vault.xray-demo` | LOW | 7 held | **SAFE** |
| `risky-vault.xray-demo` | HIGH: 🔴 redeploy (`upgrade`), 🔴 add full-access key (`add_full_access_key`) | 9 held (both are owner-gated) | **CAUTION** (powerful admin, correctly gated) |
| `vulnerable-vault.xray-demo` | HIGH: `admin_drain` + can send NEAR | **2 broken** (drain, double-spend), 6 held | **DANGEROUS** |
| `yield-escrow.xray-demo` | LOW: sends NEAR, uses yield/resume; nothing dangerous-looking | **1 broken** (timeout strands 5 NEAR), 8 held | **DANGEROUS** |
| `wrap.near` | LOW: 15 methods, NEP-141/145/148, sends NEAR via `near_withdraw`, 0 full-access keys | 4 held, 1 n/a | **SAFE** |
| `token.sweat` | HIGH: 🔴 redeploy (`up_deploy_code`), 16 admin-looking `acl_*` methods | 15 inconclusive (could not initialise) | **CAUTION** |
| `aurora` | HIGH: 🔴 add full-access key (`attach_full_access_key`), 🔴 redeploy (`upgrade`), 1 full-access key on the account | 20 inconclusive (could not initialise) | **CAUTION** |

The four demo contracts (`contracts/*/src/lib.rs`, WASM committed in `contracts/res/`) share one interface (`deposit` / `withdraw(amount)` / `get_balance`):
- **clean:** debits before paying out; a `#[private]` callback re-credits a failed payout; admin methods check the owner.
- **risky:** clean, plus owner-only `upgrade` (redeploy) and `add_full_access_key`.
- **vulnerable:** two planted bugs. `admin_drain` has no owner check, and `withdraw` debits only in its callback, so two withdraws in flight both pass.
- **yield-escrow:** payouts wait for an approver via NEP-519 yield/resume (`request_payout` → `approve_payout` → `on_payout_decision`). Planted bug: on timeout, the callback logs "expired" but never re-credits. `cargo near build … --features fixed` builds the corrected contract, and every scenario, including the stale-yield one, is HELD on it (verified). So the template tells a correct timeout path from a broken one.

## MCP server (for AI agents)

An agent that is about to call, deposit into or approve a NEAR contract can ask X-Ray first. The server speaks stdio with the official `@modelcontextprotocol/sdk`.

| Tool | Does | Speed |
|---|---|---|
| `scan_contract(account_id)` | capability risk card | instant |
| `list_attacks(account_id)` | scenarios that apply, with ids | instant |
| `run_attacks(account_id, scenario_ids?)` | runs them in the local sim: status, explanation, receipt sequence, NEAR deltas | ~1 s |
| `assess_contract(account_id)` | scan + all attacks → `safe` / `caution` / `dangerous` with reasons | ~1 s |

Every tool is read-only (`readOnlyHint`). Inputs are untrusted: `account_id` is validated against NEAR's account-id rules before any use, and bad ids return `isError` with `INVALID_ACCOUNT_ID`. While the engine is still building or warming, `run_attacks` says so, and `assess_contract` returns a scan-only `caution` marked `attacks_run: false`. Neither blocks. Logs go to stderr.

**Config.** Use absolute paths. Run `npm install` first, and preferably `npm run build:runner`.

```json
{
  "mcpServers": {
    "near-xray": {
      "command": "/ABSOLUTE/PATH/TO/near-xray/node_modules/.bin/tsx",
      "args": ["/ABSOLUTE/PATH/TO/near-xray/mcp/server.ts"]
    }
  }
}
```

That block goes in Claude Desktop's `claude_desktop_config.json` (or any MCP client's equivalent). For Claude Code:

```bash
claude mcp add near-xray -- "$PWD/node_modules/.bin/tsx" "$PWD/mcp/server.ts"
```

`claude mcp list` → `near-xray: … - ✓ Connected`.

**Verified agent run** (headless Claude Code with only this server's tools allowed):

> *Prompt:* "I'm about to deposit 20 NEAR into the contract vulnerable-vault.xray-demo. Is that safe?"
>
> *Agent:* **No, don't deposit.** NEAR X-Ray rates `vulnerable-vault.xray-demo` **dangerous** after two attacks succeeded in its local simulator.
> 1. Anyone can call `admin_drain`: an attacker account emptied the whole vault (67.8 NEAR) with no owner check.
> 2. Two `withdraw` calls in the same block both paid out (5 NEAR deposited, 10 NEAR back), with the extra coming from other depositors' money.

Without an agent: `node_modules/.bin/tsx scripts/mcp-smoke.ts --wait` drives the server with the SDK client. It lists the 4 tools, checks that a bad id is rejected, lists attacks, then calls `assess_contract` until the engine is warm → `DANGEROUS`.

## How it works

### ① Capability scan (instant, no source needed)

A NEAR contract can only act through runtime host functions it imports. **If the import is absent, the contract cannot do the action.** X-Ray reads `WebAssembly.Module.imports` from the deployed code:

| Host import | Flag |
|---|---|
| `promise_batch_action_add_key_with_full_access` | 🔴 can add full-access keys (hand over control) |
| `promise_batch_action_deploy_contract` (+ global-contract variants) | 🔴 can redeploy itself |
| `promise_batch_action_delete_account` | 🔴 can delete an account |
| `promise_batch_action_add_key_with_function_call` | 🟠 can add function-call keys |
| `promise_batch_action_transfer` | 💰 can send NEAR out |
| `promise_batch_action_stake` | ⚠️ can stake |
| `promise_then` / `promise_result*`, `promise_yield_*` | info: callbacks, yield/resume (used to pick attacks) |

**Strong vs weak evidence.** near-sdk links *every* Promise action as soon as a contract builds any Promise, so a plain wrapped-NEAR contract imports `deploy_contract` too. When 7 or more of the 9 actions are linked (`import_profile: "bulk"`), a capability counts as **strong** only if a public non-standard, non-view method name supports it (`upgrade` for deploy, `attach_full_access_key` for add-key). Otherwise it is **weak**: shown, but it does not raise the risk on its own.

Risk: **HIGH** for a strong critical capability, or a drain-style method (`drain`, `sweep`, `rescue`, `emergency_withdraw`, `withdraw_all`) on a contract that sends NEAR. **MEDIUM** for full-access keys on the account, or a strong add-function-call-key / delete-key / stake capability. **LOW** otherwise. Admin-looking methods (`owner admin upgrade set_ withdraw pause _key mint burn…`) are listed as "check who can call it". The attacks check exactly that.

### ② Attack simulation

`runner/` is a small Rust binary over [near-contract-sim](https://github.com/near/near-contract-sim) (pinned by git rev). That is nearcore 2.14's own runtime in-process: real gas, receipts, callbacks, refunds and yields. Node passes it a JSON spec on stdin and gets JSON results back.

For each contract it builds one world: `owner.near`, `victim.near`, `attacker.near` and `user.near` with 100 NEAR each; the contract deployed with 50 NEAR; `new`/`init` tried with guessed arguments; the victim deposits 20 NEAR. Each scenario then runs on its own **clone** of that world (~2 ms). Arguments come from the bytecode alone: a "kitchen-sink" object where every account-like field is the attacker, plus `amount`, `public_key`, `code` and similar.

Rules that keep the verdicts honest:
- **BROKEN** needs evidence in the sim: NEAR reached the attacker, an access key was added, the contract code changed, contract state changed, or a deposit was paid out twice or lost.
- **Control run first.** Value-flow scenarios first check, on a scratch copy, that a normal deposit then withdraw works. They attach 1 yoctoNEAR when the contract demands it and register NEP-145 storage first. If the control fails, the result is **INCONCLUSIVE**, not BROKEN.
- **No false HELD.** If no init call succeeded, a rejection proves nothing about access control. That result is **INCONCLUSIVE** too (aurora and token.sweat are like this).
- **N/A** when the precondition is missing, e.g. no callback after the payout, so there is no failure branch to test.

Verdict: any BROKEN → **dangerous**. Otherwise **caution** if the card is not LOW, anything was inconclusive, init failed or no attacks ran. Otherwise **safe**.

## Attack catalogue

| # | Scenario (id) | Picked when | What happens in the sim | HELD when |
|---|---|---|---|---|
| 1 | Unauthorised privileged call (`unauth:<m>`) | privileged-looking method | `attacker.near` calls it with attacker-controlled args (retries with 1 yocto if required) | rejected, or a no-op (no NEAR to attacker, no state/key/code change) |
| 2 | Unauthorised key addition (`addkey:<m>`) | add-key capability + a key-ish method | as 1, plus a check of the contract's access keys | no key added |
| 3 | Double-spend before callback (`double_withdraw`) | deposit + withdraw methods, transfer, callbacks | deposit 5 NEAR, submit two withdraws in the same block, settle | total paid ≤ deposit |
| 4 | Failed-transfer refund (`failed_transfer_refund`) | same | hold the payout receipt, the recipient deletes itself so the transfer really fails, recipient comes back and withdraws again | full 5 NEAR recoverable (N/A if no callback) |
| 5 | Callback out-of-gas (`callback_gas`) | same | withdraw at 8-300 Tgas, then withdraw the rest at normal gas | paid + still withdrawable = deposit at every gas level |
| 6 | Stale yield / timeout (`yield:<m>`) | `promise_yield_create` imported + a `request`/`sign`/`wait`/`ask`-style method | with a deposit/withdraw pair: deposit 5 NEAR and request it; start the yield, never resume, advance past the deadline; then withdraw | no pending receipts or sim findings, and paid + withdrawable afterwards = 5 NEAR (control run first, as for 3-5) |

Each result has: name, status (`held` / `broken` / `inconclusive` / `not_applicable` / `error`), a plain-English explanation, the receipt sequence (block, from → to, action, deposit, ok/failed), net NEAR per account, sim findings and the full receipt trace.

## NEAR features used

- JSON-RPC `query`: `view_code` (deployed WASM + code hash) and `view_access_key_list` (full-access keys on the account). The base58 SHA-256 of the WASM is checked against the RPC's `hash`.
- NEP standard detection: NEP-141/145/148/171/177/178/199/330, via near-contract-parser.
- NEAR runtime host imports as a capability model: Promise batch actions, `promise_then`/`promise_result`, `promise_yield_create`/`resume`.
- NEAR execution semantics, exercised in near-contract-sim: async receipts, callbacks and `#[private]`, 1-yoctoNEAR guards, NEP-145 storage, gas and refunds, `DeleteAccount`, NEP-519 yield/resume timeouts (advancing the chain ~200 blocks past a yield's deadline), access keys, code hash.
- near-sdk 5.29 demo contracts built with cargo-near.

## HTTP API and CLI

- `GET /scan?account_id=…` / `POST /scan {"account_id"}` → risk card.
- `GET /attacks?account_id=…` → applicable scenarios.
- `POST /attack {"account_id", "scenario_ids"?}` → `{report, verdict, reasons}`.
- `GET /engine` → `{state: cold|building|warming|ready|failed, elapsed_s}`.
- Errors return a code: `400 INVALID_ACCOUNT_ID` / `BAD_REQUEST`, `404 UNKNOWN_ACCOUNT` / `NO_CONTRACT_CODE`, `502 RPC_UNAVAILABLE`, `503 ENGINE_WARMING_UP`.

CLI:
- `npm run scan -- <ids…> [--json]`, or `npm run scan -- --wasm file.wasm` (offline; `scripts/fetch-reference-wasm.sh` downloads public builds of wrap/aurora/sweat).
- `npm run attack -- <id> [--list] [--only a,b] [--json] [--trace]` (exit code 3 if anything is broken).

Environment:
- `NEAR_RPC_URL`: comma-separated RPC URLs. Testnet works too.
- `PORT`: default 8787.
- `XRAY_RUNNER_BIN`: path to a prebuilt runner.
- `XRAY_CACHE_DIR`: where the offline code copies go (default `.cache/code/`).
- `HTTPS_PROXY` / `NO_PROXY`: honoured.

## Repo layout

```
core/       the one engine: RPC, scan, capability rules, attack selection, verdict, runner bridge
server/     HTTP front door (thin) + static web UI from web/
mcp/        MCP front door (thin, stdio)
cli/        scan / attack CLIs (thin)
web/        static HTML/CSS/JS; all text rendered via textContent
runner/     Rust attack runner over near-contract-sim (JSON in, JSON out)
contracts/  clean / risky / vulnerable / yield-escrow demo contracts (near-sdk 5.29) + res/*.wasm
scripts/    preflight.ts (pre-demo checklist), mcp-smoke.ts, fetch-reference-wasm.sh
.cache/     last fetched code per account, for the offline fallback (gitignored)
```

## Limitations (honest)

- **Never touches mainnet state.** X-Ray only makes RPC *view* calls. Attacks run in a local, in-process runtime, never against a live contract, and nothing is ever signed or sent.
- **Bytecode only, no source.** A present import means the code *can* reach an action, not that anyone can trigger it. Method-name heuristics are hints. An absent import is a proof.
- **Arguments are guessed.** X-Ray cannot always build valid arguments or initialise complex contracts (aurora, token.sweat). It reports INCONCLUSIVE in those cases and never claims HELD from a rejection it cannot explain. A SAFE verdict means "the six templates found nothing", not "audited".
- **Templates, not fuzzing.** Six scenario templates aimed at common NEAR bug classes, driven by the risk card. Logic bugs outside them (pricing, oracle, cross-contract token flows with real counterparties) are not tested. Other contracts the target calls are not deployed, so those calls fail in the sim.
- **Yield detection needs a hint in the method name.** Template 6 picks methods named like `request`/`sign`/`wait`/`ask`. A yield started from a differently named method is not attacked. It is verified on yield-escrow, both the buggy and the fixed build.
- **Offline cache is a last-known copy.** If the contract was redeployed since the cached fetch, a cached card describes the old code. The card shows the fetch time and block height.
- **Fresh state.** The sim starts from a fresh `init`, not a copy of the contract's mainnet storage.
- **First build is heavy** (see above). After that a full assessment takes ~0.2-1 s.
