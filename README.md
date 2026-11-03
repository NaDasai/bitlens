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

  "the attacker calls admin_drain and keeps the money" ─LLM─▶ scenario JSON ─▶ same runner
   (typed plain English; NEAR AI Cloud, fallback OpenRouter)     (presets are scenario JSON too)
```

## Contents
- [Quickstart](#quickstart)
- [What you will see](#what-you-will-see)
- [MCP server (for AI agents)](#mcp-server-for-ai-agents)
- [Speech-to-test (plain English → test)](#speech-to-test-plain-english--test)
- [Scenario JSON](#scenario-json)
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
2. `npm test` → `# pass 26`, `# fail 0` (account-id validation, capability detection, RPC errors and the offline fallback against a fake RPC, attack selection, verdict rules, scenario validation, and speech-to-test with its NEAR AI → OpenRouter fallback against two fake LLM servers; no network).
3. `npm run build:runner` (the first-build warning above applies) → ends with `Finished \`release\` profile [optimized]`; the binary is `runner/target/release/xray-runner`. You can skip this: the server and MCP server start the same build in the background if the binary is missing.
4. `npm run test:sim` → `# pass 8`, ~2 s. Pins the status of **every** scenario on all four demo contracts, plus the risk level and verdict, through the real engine. It also runs custom scenario JSON end to end, and checks that the runner rejects malformed scenarios on its own. If it passes, the demo tells the same story.
   By hand: `npm run attack -- vulnerable-vault.xray-demo` → 8 scenarios, `Summary: 6 held, 2 broken, 0 inconclusive`, `VERDICT: DANGEROUS`, exit code 3; `npm run attack -- clean-vault.xray-demo` → `7 held, 0 broken`, `VERDICT: SAFE`, exit code 0.
5. `npm run server` → `NEAR X-Ray backend on http://localhost:8787` and, a few seconds later, `[engine] attack engine ready`.
6. Open **http://localhost:8787** and follow the demo path below.
7. **Before a live demo:** `npm run preflight` (~4 s) → a ✔/⚠/✘ checklist ending in `Ready to demo.`:
   - Node version and runner build.
   - All four demo verdicts.
   - Live RPC for wrap.near / token.sweat / aurora. This also refreshes the offline copy of their code (see below).
   - Port 8787 free.
   - LLM keys for speech-to-test: NEAR AI → OpenRouter (⚠ if neither is set; speech-to-test is optional).
   - MCP server starts and lists 5 tools.

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
| `list_attacks(account_id, include_scenarios?)` | scenarios that apply, with ids (and their scenario JSON, as examples) | instant |
| `run_attacks(account_id, scenario_ids?)` | runs them in the local sim: status, explanation, receipt sequence, NEAR deltas | ~1 s |
| `assess_contract(account_id)` | scan + all attacks → `safe` / `caution` / `dangerous` with reasons | ~1 s |
| `run_custom_attack(account_id, description \| scenario, dry_run?)` | your own attack idea: plain English (translated by the LLM) or scenario JSON the agent wrote, run in the sim; returns the scenario and its result | ~1 s (+ LLM) |

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

Without an agent: `node_modules/.bin/tsx scripts/mcp-smoke.ts --wait` drives the server with the SDK client. It lists the 5 tools, checks that a bad id is rejected, lists attacks, then calls `assess_contract` until the engine is warm → `DANGEROUS`.

## Speech-to-test (plain English → test)

Type an attack in plain English, for example *"the attacker calls admin_drain and keeps the money"*. X-Ray turns it into a test and runs it on the contract's real bytecode in the local sim.

The LLM has one job: translate the sentence into a **scenario JSON object** in the [format below](#scenario-json). It never writes code. The JSON then runs through the same runner as the built-in presets.

- **Providers:** both speak the OpenAI chat-completions API, and every request uses `response_format: {"type": "json_object"}`.
  1. [NEAR AI Cloud](https://cloud.near.ai) (`https://cloud-api.near.ai/v1`) is the primary, used here simply as the NEAR ecosystem's LLM for the translation step. X-Ray only analyses public on-chain bytecode.
  2. [OpenRouter](https://openrouter.ai) (`https://openrouter.ai/api/v1`) is the fallback. It is used when NEAR AI has no key, rejects the key, is unreachable or returns an error. After a failure NEAR AI is skipped for 5 minutes, so each request doesn't wait on it again. The UI, CLI and MCP say which provider answered and why a fallback happened.
- **Prompt:** the model sees the scenario language, this contract's real method list and capabilities, and two of its presets as worked examples.
- **Untrusted output:** what comes back is
  1. checked against the schema (`core/scenario.ts`, zod);
  2. checked so every method it calls is one the contract really exports;
  3. sent back once with the error if it fails, so the model can fix it (on the provider that answered);
  4. validated and bounded again by the Rust runner.

  A scenario can only sign as the four sim accounts, only call the contract under test, and is size-limited.
- **Results:** you see the JSON before it runs and can edit it. A run made only of custom scenarios never reports SAFE: one idea tested is not an assessment.

| Env var | Default | |
|---|---|---|
| `NEAR_AI_API_KEY` | (none) | NEAR AI Cloud bearer key (primary) |
| `NEAR_AI_MODEL` | `deepseek/deepseek-v3.2` | any chat model from the [catalogue](https://cloud-api.near.ai/v1/models) with JSON mode; the default is an open-weight, non-reasoning model (a few seconds per translation) |
| `OPEN_ROUTER_KEY` | (none) | OpenRouter key (fallback) |
| `OPEN_ROUTER_MODEL` | `deepseek/deepseek-v3.2` | the same open-weight model as the NEAR AI default, so both providers behave alike |
| `NEAR_AI_BASE_URL`, `OPEN_ROUTER_BASE_URL` | the URLs above | overrides (the tests point them at local fakes) |
| `LLM_TIMEOUT_S` | `120` | per-request timeout |
| `LLM_MAX_TOKENS` | `8192` | output cap per request (without one, OpenRouter reserves the model's full output budget and refuses low-credit keys with HTTP 402) |

With neither key set, speech-to-test is off. Everything else works, including hand-written scenario JSON.

Try it:
- **Web:** `OPEN_ROUTER_KEY=… npm run server` (and/or `NEAR_AI_API_KEY=…`) → scan `vulnerable-vault` → *Your own attack* → type the attack → **Translate to a test** (or Ctrl/⌘+Enter) → review the JSON → **Run this scenario** → ❌ BROKEN, with the drain's receipt trail.
- **CLI:**
  ```bash
  npm run attack -- vulnerable-vault.xray-demo --say "the attacker calls admin_drain and keeps the money" --print-scenario
  ```
- **No key:** `npm run attack -- vulnerable-vault.xray-demo --scenario scenarios/examples/drain.json` → ❌ BROKEN, `attacker.near called admin_drain and walked away with +67.8015 NEAR.` In the web UI, pick *start from a preset…*, edit the JSON and run it.
- **MCP:** `run_custom_attack` with `description` (plain English, via the LLM) or `scenario` (JSON the agent wrote).

## Scenario JSON

Every attack is one JSON object: the six built-in presets (`scenarios/presets/*.json`, filled in from the risk card), the examples in `scenarios/examples/`, and whatever speech-to-test produces. The Rust runner (`runner/src/interp.rs`) maps each step onto a near-contract-sim operation against the contract under test. It then evaluates the checks in order: the first one that fails decides the result (BROKEN unless the check says `"else": "inconclusive"` or `"not_applicable"`). If all hold, the result is HELD.

```json
{
  "id": "custom:drain",
  "name": "Anyone can empty the vault",
  "steps": [
    { "op": "call", "id": "hit", "as": "attacker", "method": "admin_drain",
      "args": { "receiver_id": "attacker.near" }, "attack": true }
  ],
  "checks": [
    { "check": "net_at_most", "account": "attacker", "near": "0",
      "message": "attacker.near called admin_drain and walked away with {net.attacker}." }
  ],
  "explain": { "rejected": "admin_drain refused the attacker: {error.hit}" }
}
```

| Steps (`op`) | |
|---|---|
| `call` | `as` (owner / victim / attacker / user), `method`, `args`, `deposit_near` or `deposit_yocto`, `gas_tgas`, `async` (lands in the same block as other async calls), `hold_transfer_blocks` (hold the payout in flight), `attack` (the call under test), `expect` (setup expectation), `guard_deposit` |
| `deposit` | fund an account via a payable method (registers NEP-145 storage first) |
| `control` | prove a plain deposit → withdraw works on a scratch copy; otherwise the scenario is INCONCLUSIVE |
| `settle`, `wait_for_receipt`, `wait_for_yield`, `advance_past_yield`, `advance_blocks` | drive the chain |
| `delete_account`, `create_account` | test-harness moves (kept out of the NEAR totals) |
| `sweep` | repeat steps per gas value (`"gas_tgas": "$tgas"`), checking each time |

| Checks (`check`) | |
|---|---|
| `net_at_most` / `net_at_least` / `net_equals` | net NEAR of `account` (a role or `contract`), over all steps or the listed `steps` |
| `unchanged` | the contract's `code` / `keys` / `state` vs. before the steps |
| `step_succeeded` / `step_failed` / `any_succeeded` | call outcomes |
| `transfer_failed`, `callback_after_transfer`, `completed`, `yielded` | receipt-level facts |

`message` and `explain` texts can use `{net.attacker}`, `{net.contract}`, `{error.<step>}`, `{status.<step>}`, `{tgas}`, `{sweep}` and `{deadline}`. `xray-runner --validate file.json` checks a scenario on its own.

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

`runner/` is a small Rust binary over [near-contract-sim](https://github.com/near/near-contract-sim) (pinned by git rev). That is nearcore 2.14's own runtime in-process: real gas, receipts, callbacks, refunds and yields. Node passes it a JSON spec on stdin: the WASM path, init candidates, and a list of [scenario JSON](#scenario-json) objects. The runner gets JSON results back. The runner is an interpreter for scenarios; no attack logic is hard-coded in Rust.

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
- `POST /attack {"account_id", "scenarios": [<scenario JSON>]}` → runs custom scenarios instead of the presets.
- `POST /translate {"account_id", "sentence"}` → `{scenario, provider, model, attempts, fallback_from?}`.
- `GET /llm` → `{configured, provider, model, providers: [...]}` (never the keys).
- Errors return a code:
  - `400`: `INVALID_ACCOUNT_ID`, `BAD_REQUEST`, `SCENARIO_INVALID`
  - `404`: `UNKNOWN_ACCOUNT`, `NO_CONTRACT_CODE`
  - `502`: `RPC_UNAVAILABLE`, `LLM_ERROR`, `LLM_AUTH`, `LLM_UNAVAILABLE` (only after every LLM provider failed)
  - `503`: `ENGINE_WARMING_UP`, `LLM_NOT_CONFIGURED`

CLI:
- `npm run scan -- <ids…> [--json]`, or `npm run scan -- --wasm file.wasm` (offline; `scripts/fetch-reference-wasm.sh` downloads public builds of wrap/aurora/sweat).
- `npm run attack -- <id> [--list] [--only a,b] [--json] [--trace]` (exit code 3 if anything is broken).
- `npm run attack -- <id> --scenario file.json` runs your own scenario JSON. `--say "english"` translates a sentence with the LLM first. `--print-scenario` prints the JSON; with `--list`, it prints every preset's JSON.

Environment:
- `NEAR_RPC_URL`: comma-separated RPC URLs. Testnet works too.
- `PORT`: default 8787.
- `XRAY_RUNNER_BIN`: path to a prebuilt runner.
- `XRAY_CACHE_DIR`: where the offline code copies go (default `.cache/code/`).
- `HTTPS_PROXY` / `NO_PROXY`: honoured.

## Repo layout

```
core/       the one engine: RPC, scan, capability rules, attack selection, scenario schema + presets, speech-to-test (LLM: NEAR AI → OpenRouter), verdict, runner bridge
server/     HTTP front door (thin) + static web UI from web/
mcp/        MCP front door (thin, stdio)
cli/        scan / attack CLIs (thin)
web/        static HTML/CSS/JS; all text rendered via textContent
runner/     Rust scenario interpreter over near-contract-sim (scenario.rs: format + validation, interp.rs: execution)
scenarios/  presets/*.json (the six attack templates as canned scenario JSON), examples/*.json
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
- **Speech-to-test is only as good as the translation.** The LLM can misread a sentence. That is why the JSON is shown, and can be edited, before it runs, and why a result only means what its checks say. The provider chain is unit-tested against two fake OpenAI-compatible servers: request shape, JSON mode, every fallback path, the cool-down, and the repair round.
- **Fresh state.** The sim starts from a fresh `init`, not a copy of the contract's mainnet storage.
- **First build is heavy** (see above). After that a full assessment takes ~0.2-1 s.
