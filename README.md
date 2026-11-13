# BitLens

**A security scanner for NEAR smart contracts. Paste a mainnet account and BitLens reads the deployed WASM, tells you what the contract *can* do, then attacks the real bytecode in a local NEAR runtime and reports which defences held and which broke. It works without source code, for people (web UI) and for AI agents (MCP server).**

Hackathon track: AI Security & Defense.

**Live demo:** https://bitlens-web.vercel.app (web app at `/app`; try the `vulnerable-vault` demo → **Run 8 attacks** → DANGEROUS). MCP over HTTPS: `https://bitlens-api.buoya.space/mcp` (bearer token).

```
account id ─view_code RPC─▶ WASM ─▶ ① risk card ─▶ ② attacks in near-contract-sim ─▶ verdict
                                     (capabilities,     (local nearcore runtime:          safe /
                                      standards,         real gas, receipts, callbacks)   caution /
                                      privileged methods)                                  dangerous
             web UI ◀── HTTP ──┐                                  ┌── MCP (stdio / HTTPS) ──▶ AI agents
                               └────────── core/ (one engine) ────┘

  "the attacker calls admin_drain and keeps the money" ─LLM─▶ scenario JSON ─▶ same runner
   (typed plain English; NEAR AI Cloud, fallback OpenRouter)     (presets are scenario JSON too)
```

## Contents
- [Quickstart](#quickstart)
- [What you will see](#what-you-will-see)
- [MCP server (for AI agents)](#mcp-server-for-ai-agents)
- [Text-to-test (plain English → test)](#text-to-test-plain-english--test)
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

> ⚠️ **First build of the attack engine compiles nearcore: 10-30 minutes and ~3.5 GB of disk** (≈2.2 GB `runner/target`, ≈1 GB cargo cache). It took 11 min 43 s from a fresh clone here. Later builds are seconds. The scanner, web UI and MCP server all start immediately and work during the build; attack features say "warming up" until it is done.

### Steps (each with expected output)

1. `npm install`
2. `npm test` → `# pass 45`, `# fail 0` (account-id validation, capability detection, RPC errors and the offline fallback against a fake RPC, attack selection, verdict rules, the pre-signature allow / confirm / block policy, scenario validation, text-to-test with its NEAR AI → OpenRouter fallback against two fake LLM servers, and MCP over HTTP with the SDK client; no network).
3. `npm run build:runner` (the first-build warning above applies) → ends with `Finished \`release\` profile [optimized]`; the binary is `runner/target/release/bitlens-runner`. You can skip this: the server and MCP server start the same build in the background if the binary is missing.
4. `npm run test:sim` → `# pass 11`, ~3 s. Pins the status of **every** scenario on all four demo contracts, plus the risk level and verdict, through the real engine. It also runs custom scenario JSON end to end, checks that the runner rejects malformed scenarios on its own, checks that the text-to-test eval set's expected results match these pinned statuses, pins `check_transaction`'s decision for a 20 NEAR deposit into each demo contract, and checks the results cache. If it passes, the demo tells the same story.
   `npm run test:runner` runs the runner's Rust unit tests (argument discovery from contract errors).
   By hand: `npm run attack -- vulnerable-vault.bitlens-demo` → 8 scenarios, `Summary: 6 held, 2 broken, 0 inconclusive`, `VERDICT: DANGEROUS`, exit code 3; `npm run attack -- clean-vault.bitlens-demo` → `7 held, 0 broken`, `VERDICT: SAFE`, exit code 0.
5. `npm run server` → `BitLens backend on http://localhost:8787` and, a few seconds later, `[engine] attack engine ready`.
6. Open **http://localhost:8787** for the landing page (what BitLens does, the MCP server and how to add it; its hero replays a real run on the vulnerable-vault demo on a loop: the `admin_drain` drain, then a refused `set_owner`), then **Open the app**, or go straight to **http://localhost:8787/app**, and follow the demo path below.
7. **Before a live demo:** `npm run preflight` (~4 s) → a ✔/⚠/✘ checklist ending in `Ready to demo.`:
   - Node version and runner build.
   - All four demo verdicts.
   - Live RPC for wrap.near / token.sweat / aurora. This also refreshes the offline copy of their code (see below).
   - Port 8787 free.
   - LLM keys for text-to-test: NEAR AI → OpenRouter (⚠ if neither is set; text-to-test is optional).
   - MCP server starts and lists 6 tools, including `check_transaction`.

   Exit code 1 if anything the demo needs is broken.

**Verified from a fresh clone of `NaDasai/bitlens`:** `npm ci` (0 vulnerabilities), typecheck clean, `npm test` 27 pass, `npm run build:runner` 11 min 43 s, `npm run test:sim` 8 pass, `npm run preflight` → `Ready to demo.` Demo verdicts: clean-vault SAFE, risky-vault CAUTION, vulnerable-vault DANGEROUS, yield-escrow DANGEROUS. Live scans of wrap.near, token.sweat and aurora work. The web UI, the CLI and the MCP server were each checked end to end ([text-to-test results](#text-to-test-plain-english--test), [MCP](#mcp-server-for-ai-agents)).
8. *Optional, live mainnet:* `npm run test:live` → `# pass 2` (scans wrap.near, token.sweat and aurora; checks each locally computed code hash against the RPC's; checks the `UNKNOWN_ACCOUNT` / `NO_CONTRACT_CODE` errors).

### Demo path (web)
1. Click **clean-vault** → green **LOW** card. In *Attack proof*, click **Run 7 attacks** → **SAFE**, all ✅ HELD (each one shows why: "only the owner can call this", "Method on_withdraw is private"…).
2. Click **vulnerable-vault** → red **HIGH** card, first reason: `admin_drain` looks like a fund-drain method.
3. **Run 8 attacks** → **DANGEROUS**:
   - ❌ `admin_drain`: attacker.near → contract `call admin_drain` ✓, contract → attacker.near `Transfer 67.8015 NEAR` ✓, net NEAR: `attacker.near +67.8015`, `vulnerable-vault.bitlens-demo −67.8015`.
   - ❌ double-withdraw: deposit 5 NEAR, two same-block withdraws, 10 NEAR back.
   - Each result has the receipt sequence and a collapsible full receipt trace from the sim.
   - **▶ Replay the attack** plays the receipts back as an animation (`web/replay.js`): one card per account with a live net-NEAR counter, each receipt a token travelling from sender to receiver (gold = NEAR moving, red = failed, with the contract's reason), in block order so same-block races show side by side. Play / pause / step / speed 0.5×–2×; the cards end on the report's net NEAR. With reduced motion turned on, rows appear without movement.
4. Click **yield-escrow** → green **LOW** card: nothing in the bytecode looks dangerous. **Run 9 attacks** → **DANGEROUS**:
   - ❌ stale yield: the user locks 5 NEAR in `request_payout` (block 16), nobody approves, the yield times out, and `on_payout_decision` runs at block 217 but never re-credits. The user's `withdraw` at block 220 fails, and 5 NEAR is stuck with no owner.
   - **The scan alone would have passed it; the attack proves the bug.**
5. Paste `wrap.near` → real mainnet code, **LOW**; attacks → **SAFE** (4 held, 1 not applicable).

**Venue wifi down?** Every successful fetch saves the code to `.cache/code/` (gitignored). If every RPC endpoint is unreachable, BitLens analyses that copy instead. The card says so in yellow ("⚠ RPC unreachable: showing the copy of this code fetched …"), `source` is `"cache"`, and MCP results carry an `offline_cache` note. Only *unreachable* falls back: "unknown account" / "no contract" answers from a live RPC are never masked. The four demo contracts never need the network.

Links can be shared: `http://localhost:8787/app?account=vulnerable-vault.bitlens-demo` (old `/?account=…` links forward to `/app`).

## What you will see

Verified output (Nov 2026). Mainnet code is fetched read-only and attacked **only in the local sim**.

| Account | Risk card | Attacks | Verdict |
|---|---|---|---|
| `clean-vault.bitlens-demo` | LOW | 7 held | **SAFE** |
| `risky-vault.bitlens-demo` | HIGH: 🔴 redeploy (`upgrade`), 🔴 add full-access key (`add_full_access_key`) | 9 held (both are owner-gated) | **CAUTION** (powerful admin, correctly gated) |
| `vulnerable-vault.bitlens-demo` | HIGH: `admin_drain` + can send NEAR | **2 broken** (drain, double-spend), 6 held | **DANGEROUS** |
| `yield-escrow.bitlens-demo` | LOW: sends NEAR, uses yield/resume; nothing dangerous-looking | **1 broken** (timeout strands 5 NEAR), 8 held | **DANGEROUS** |
| `wrap.near` | LOW: 15 methods, NEP-141/145/148, sends NEAR via `near_withdraw`, 0 full-access keys | 4 held, 1 n/a | **SAFE** |
| `token.sweat` | HIGH: 🔴 redeploy (`up_deploy_code`), 16 admin-looking `acl_*` methods | 10 held, 5 inconclusive (init arguments discovered, see below) | **CAUTION** |
| `aurora` | HIGH: 🔴 add full-access key (`attach_full_access_key`), 🔴 redeploy (`upgrade`), 1 full-access key on the account | 20 inconclusive (could not initialise: Borsh arguments) | **CAUTION** |

**Argument discovery.** Bytecode has no argument names, but near-sdk contracts say exactly what is wrong with their JSON input (`missing field 'holding_account_id' at line 1 column 810`, `invalid type: string "", expected u64`, `unknown variant`). The column points into the JSON BitLens sent, so the runner finds the object or value at fault, fixes it and calls again (up to 30 times), in the local sim only (`runner/src/argfix.rs`). This applies to the init call and to every synchronous call in a scenario.
- token.sweat went from 15 INCONCLUSIVE (never initialised) to 10 HELD and 5 INCONCLUSIVE. Its `new` needed 6 arguments, all found from its own errors: `holding_account_id`, `super_admin_account_id` and four lists of manager accounts.
- Discovered arguments contain guessed values, so after a fix a rejection counts as HELD only when the contract's message names the caller's rights (`is private`, `Insufficient permissions … Requires one of these roles`, `only the owner`, …). On token.sweat, 5 `acl_*` calls were rejected with `Value does not correspond to a role`: that is about our guessed role, not the attacker, so they stay INCONCLUSIVE.
- Contracts that take Borsh (binary) arguments, like aurora, give no field names (`ERR_BORSH_DESERIALIZE`), so they stay INCONCLUSIVE.

The four demo contracts (`contracts/*/src/lib.rs`, WASM committed in `contracts/res/`) share one interface (`deposit` / `withdraw(amount)` / `get_balance`):
- **clean:** debits before paying out; a `#[private]` callback re-credits a failed payout; admin methods check the owner.
- **risky:** clean, plus owner-only `upgrade` (redeploy) and `add_full_access_key`.
- **vulnerable:** two planted bugs. `admin_drain` has no owner check, and `withdraw` debits only in its callback, so two withdraws in flight both pass.
- **yield-escrow:** payouts wait for an approver via NEP-519 yield/resume (`request_payout` → `approve_payout` → `on_payout_decision`). Planted bug: on timeout, the callback logs "expired" but never re-credits. `cargo near build … --features fixed` builds the corrected contract, and every scenario, including the stale-yield one, is HELD on it (verified). So the template tells a correct timeout path from a broken one.

## MCP server (for AI agents)

An agent that is about to call, deposit into or approve a NEAR contract can ask BitLens first. The server uses the official `@modelcontextprotocol/sdk`, over stdio (self-hosted, below) or over HTTPS at `POST /mcp` with a bearer token (see *MCP over HTTP*).

| Tool | Does | Speed |
|---|---|---|
| `scan_contract(account_id)` | capability risk card | instant |
| `list_attacks(account_id, include_scenarios?)` | scenarios that apply, with ids (and their scenario JSON, as examples) | instant |
| `run_attacks(account_id, scenario_ids?)` | runs them in the local sim: status, explanation, receipt sequence, NEAR deltas | ~1 s |
| `assess_contract(account_id)` | scan + all attacks → `safe` / `caution` / `dangerous` with reasons | ~1 s |
| `check_transaction(receiver_id, method, deposit_near?, args?, mode?)` | **call it right before signing**: judges the transaction the agent is about to sign → `allow` / `confirm` / `block`, with the reasons, the simulated attack that justifies a block (receipts, who gained NEAR) and a replay link. BitLens never signs. | ~1-2 s |
| `run_custom_attack(account_id, description \| scenario, dry_run?)` | your own attack idea: plain English (translated by the LLM) or scenario JSON the agent wrote, run in the sim; returns the scenario and its result | ~1 s (+ LLM) |

### Pre-signature check (`check_transaction`)

The agent proposes the transaction it is about to sign (contract, method, attached NEAR, args). BitLens runs the same evaluation as `assess_contract` and answers with a decision. **It never signs or sends anything**: the agent's wallet signs only on `allow`, asks a human on `confirm`, and does not sign on `block` or on any error.

| Situation | `standard` (default) | `strict` |
|---|---|---|
| method not exported by the contract, account missing or without a contract | block | block |
| DANGEROUS (an attack succeeded) and NEAR attached | **block** | block |
| DANGEROUS, no NEAR attached | confirm | block |
| CAUTION (not proven safe) and NEAR attached | confirm | block |
| CAUTION, no NEAR attached | allow | confirm |
| SAFE (all attacks held, low capability risk) | allow | allow |
| attack engine not built yet, NEAR attached | confirm | block |

On a block, `evidence` lists the successful attacks, the one that moved the most NEAR first, with their receipts and NEAR deltas. `replay_path` (`/app?account=…&replay=<attack id>`) opens the web app, runs the attacks and replays that one as an animation. Also available as `POST /check` and `npm run check -- <contract> <method> --deposit 20` (exit code 0 allow, 1 confirm, 2 block, 3 error).

**Results cache.** The same contract code, the same attacks and the same runner build give the same results, so the server and the MCP server keep each attack report in memory, keyed by account, `code_hash`, the set of attacks and the runner build (default 10 min, `BITLENS_CACHE_TTL_S`, `0` disables). The code is still fetched on every call, which is what notices an upgrade: new code, new key, fresh simulation. Custom scenarios (text-to-test, hand-written JSON) and failed runs are never cached, and concurrent identical requests share one simulation. A cached answer says so: `cache: {hit, age_s}` in the report, `contract.attacks_cached_age_s` in `check_transaction`, a "cached" line in MCP, the CLI and the web app. Measured in one MCP session, `check_transaction` called twice: vulnerable-vault 162 → **10 ms**, token.sweat 1278 → 459 ms, wrap.near 493 → 339 ms (what remains on mainnet is fetching the code over RPC).

Demo contracts, `deposit` with 20 NEAR (pinned by `npm run test:sim`): vulnerable-vault **block** (proof: the `admin_drain` drain, +67.8015 NEAR to the attacker), yield-escrow **block**, risky-vault **confirm**, clean-vault **allow**.

Every tool is read-only (`readOnlyHint`). Inputs are untrusted: `account_id` is validated against NEAR's account-id rules before any use, and bad ids return `isError` with `INVALID_ACCOUNT_ID`. While the engine is still building or warming, `run_attacks` says so, and `assess_contract` returns a scan-only `caution` marked `attacks_run: false`. Neither blocks. Logs go to stderr.

**Config.** Use absolute paths. Run `npm install` first, and preferably `npm run build:runner`.

```json
{
  "mcpServers": {
    "bitlens": {
      "command": "/ABSOLUTE/PATH/TO/bitlens/node_modules/.bin/tsx",
      "args": ["/ABSOLUTE/PATH/TO/bitlens/mcp/server.ts"]
    }
  }
}
```

That block goes in Claude Desktop's `claude_desktop_config.json` (or any MCP client's equivalent). For Claude Code:

```bash
claude mcp add bitlens -- "$PWD/node_modules/.bin/tsx" "$PWD/mcp/server.ts"
```

`claude mcp list` → `bitlens: … - ✓ Connected`.

### MCP over HTTP (remote agents)

**Hosted instance:** `https://bitlens-api.buoya.space/mcp` (ask the BitLens team for a token; the web app is at `https://bitlens-web.vercel.app`).

The HTTP server also serves the same six tools at **`POST /mcp`** (MCP Streamable HTTP, stateless: a fresh MCP server per request, JSON responses, no sessions or SSE). It runs in the same process as the web app, so it shares the engine warm-up and the results cache. A remote agent needs no SSH and no local build.

- **Off by default.** Set `BITLENS_MCP_TOKEN` (e.g. `openssl rand -hex 32`) to turn it on; without it `/mcp` answers `404 MCP_DISABLED`.
- **Bearer token.** Every request needs `Authorization: Bearer <token>` (constant-time compare; the token is never logged). Missing or wrong → `401` with `WWW-Authenticate: Bearer`. `GET`/`DELETE /mcp` → `405`.
- **Behind nginx,** give `/mcp` the same long timeout as the slow endpoints (`location ~ ^/(attack|translate|check|mcp)$`): one `check_transaction` runs every attack.
- **Add it to Claude Code:**
  ```bash
  claude mcp add --transport http bitlens https://<your-api-host>/mcp --header "Authorization: Bearer <token>"
  claude mcp list    # bitlens: … (HTTP) - ✓ Connected
  ```
- **Check it with curl:** `curl -s -X POST https://<your-api-host>/mcp -H "Authorization: Bearer <token>" -H "content-type: application/json" -H "accept: application/json, text/event-stream" -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"curl","version":"0"}}}'` → JSON with `"serverInfo":{"name":"bitlens",…}`.
- **stdio is unchanged:** `npm run mcp` and the config blocks above work as before.
- **The token sits in plain text** in each client's Claude Code config. Rotate it by changing `BITLENS_MCP_TOKEN` and restarting the server.

Verified locally: `BITLENS_MCP_TOKEN=dev npm run server`, the `claude mcp add --transport http … http://localhost:8787/mcp` config, and headless Claude Code asked "is it safe to deposit 20 NEAR into vulnerable-vault.bitlens-demo?" → **BLOCK**, with the `admin_drain` drain (67.8 NEAR) as proof and the replay link (3 turns, ~10 s). `npm test` covers the tool list, a tool call, bad input, 401 / 405 / 404 through the SDK's HTTP client (`server/mcpHttp.test.ts`).

### Web frontend on Vercel

`web/` is static and calls the API with relative URLs (`fetch("/scan")`), so it can be served by Vercel while the API runs elsewhere. `web/vercel.json` rewrites `/health`, `/scan`, `/attacks`, `/attack`, `/engine`, `/llm`, `/translate` and `/check` to the API host (no CORS, no JS change), turns off Vercel's caching of those rewrites (scan results must never be cached), and uses `cleanUrls` so `/app` serves `app.html` as the Node server does. `/mcp` is deliberately not rewritten: MCP clients talk to the API host directly. Vercel project: Root Directory `web`, preset Other, no build command.

**Verified agent run: pre-signature check** (headless Claude Code, only `check_transaction` and `assess_contract` allowed; 3 turns, ~11 s):

> *Prompt:* "You are a wallet agent. Your user asked: 'Deposit 20 NEAR into vulnerable-vault.bitlens-demo by calling its deposit method.' Before you sign any transaction you must check it with BitLens."
>
> *Agent:* I would **not sign** this transaction. BitLens checked `deposit` with 20 NEAR attached on `vulnerable-vault.bitlens-demo` and returned **BLOCK**: it rated the contract dangerous and high risk, and two attacks worked in its simulation. 1. **Anyone can drain it:** the simulated attacker's call to `admin_drain` moved the vault's whole simulated balance (+67.8 NEAR) to itself. 2. **Double withdrawal:** two `withdraw` calls in the same block both paid out. Your 20 NEAR would be at risk from both bugs. I won't sign this one.

**Verified agent run: assessment** (headless Claude Code with only this server's tools allowed):

> *Prompt:* "I'm about to deposit 20 NEAR into the contract vulnerable-vault.bitlens-demo. Is that safe?"
>
> *Agent:* **No, don't deposit.** BitLens rates `vulnerable-vault.bitlens-demo` **dangerous** after two attacks succeeded in its local simulator.
> 1. Anyone can call `admin_drain`: an attacker account emptied the whole vault (67.8 NEAR) with no owner check.
> 2. Two `withdraw` calls in the same block both paid out (5 NEAR deposited, 10 NEAR back), with the extra coming from other depositors' money.

Without an agent: `node_modules/.bin/tsx scripts/mcp-smoke.ts --wait` drives the server with the SDK client. It lists the 6 tools, checks that a bad id is rejected, lists attacks, calls `assess_contract` until the engine is warm → `DANGEROUS`, then `check_transaction` for a 20 NEAR deposit → `BLOCK` with the drain as proof.

**Verified on a fresh clone:** the server starts as `bitlens` with all its tools (5 at the time; `check_transaction` was added later). `scan_contract wrap.near` returns the live card (risk LOW). A bad id comes back as `isError` with `INVALID_ACCOUNT_ID`. `assess_contract vulnerable-vault.bitlens-demo` returns DANGEROUS. `run_custom_attack` returns HELD on clean-vault with the takeover scenario JSON (`scenarios/examples/takeover.json`), and HELD on risky-vault with a plain-English attack (see the table under [Text-to-test](#text-to-test-plain-english--test)).

## Text-to-test (plain English → test)

Type an attack in plain English, for example *"the attacker calls admin_drain and keeps the money"*. BitLens turns it into a test and runs it on the contract's real bytecode in the local sim.

The LLM has one job: translate the sentence into a **scenario JSON object** in the [format below](#scenario-json). It never writes code. The JSON then runs through the same runner as the built-in presets.

- **Providers:** both speak the OpenAI chat-completions API, and every request uses `response_format: {"type": "json_object"}`.
  1. [NEAR AI Cloud](https://cloud.near.ai) (`https://cloud-api.near.ai/v1`) is the primary, used here simply as the NEAR ecosystem's LLM for the translation step. BitLens only analyses public on-chain bytecode.
  2. [OpenRouter](https://openrouter.ai) (`https://openrouter.ai/api/v1`) is the fallback. It is used when NEAR AI has no key, rejects the key, is unreachable or returns an error. After a failure NEAR AI is skipped for 5 minutes, so each request doesn't wait on it again. The UI, CLI and MCP say which provider answered and why a fallback happened.
- **Prompt:** the model sees the scenario language, this contract's real method list and capabilities, and two of its presets as worked examples.
- **Untrusted output:** what comes back is
  1. checked against the schema (`core/scenario.ts`, zod);
  2. checked so every method it calls is one the contract really exports;
  3. checked for inverted polarity: a check that passes when the attack works (`step_succeeded` on the attack call, a positive `net_at_least` for the attacker) is rejected, so a real exploit can't be reported as HELD;
  4. sent back once with the error if it fails, so the model can fix it (on the provider that answered);
  5. validated and bounded again by the Rust runner.

  **NEP standard methods** (NEP-141, 145, 148, 171, 177, 178, 199, 330) have public, fixed signatures. When the scan detects a standard, the model sees the exact signature of each of its methods the contract exports, e.g. `ft_transfer(receiver_id: string, amount: string, memo: string|null) [NEP141] · attach exactly 1 yoctoNEAR`. Calls to them get their arguments from the signature (accounts are the signer, optional ones `null`) and the 1 yoctoNEAR the NEP requires. An argument of the wrong JSON type (e.g. `amount` as a number) is rejected with the reason, for the repair round. Argument names and types come from near-contract-parser's interface table; required deposits from the NEP specs (`core/standards.ts`).

  For every other method, argument names can't be read from bytecode, so every translated call gets the same generic argument set as the presets (account fields, `amount`, a tiny valid WASM, the attacker's key); only the args the model sets explicitly (usually `amount`) override it.

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
| `LLM_MAX_TOKENS` | `4096` | output cap per request. OpenRouter reserves the whole cap up front and refuses a key whose credit does not cover it (HTTP 402); a scenario is ~1-2k tokens, so 4096 is plenty |

With neither key set, text-to-test is off. Everything else works, including hand-written scenario JSON.

**Verified live** on a fresh clone of BitLens (OpenRouter, `deepseek/deepseek-v3.2`; NEAR AI had no key, so the chain fell straight through). Command: `npm run attack -- <contract> --say "…"`. Time = translation + scan + sim run.

| Contract | Sentence | Result | Attempts | Time |
|---|---|---|---|---|
| vulnerable-vault | *the attacker calls admin_drain and keeps the money* | ❌ BROKEN, attacker +67.8015 NEAR | 1 | 8.9 s |
| vulnerable-vault | *the attacker deposits 5 NEAR and withdraws twice in the same block; it must not get more than it deposited* | ❌ BROKEN, attacker +5.0000 NEAR | 2 | 27.7 s |
| clean-vault | *a random account tries to make itself the owner* | ✅ HELD (`only the owner can call this`) | 1 | 9.9 s |
| yield-escrow | *a user requests a payout of 5 NEAR, nobody approves it, and after the timeout the user must get the 5 NEAR back* | ❌ BROKEN, user −5.0000 NEAR stuck | 1 | 13.7 s |
| risky-vault | *the attacker tries to upgrade the contract with its own code* | ✅ HELD (`only the owner can call this`) | 1 | 12.7 s |
| risky-vault (via MCP `run_custom_attack`) | *the attacker adds its own full-access key to the contract* | ✅ HELD (`only the owner can call this`) | 1 | 15.4 s |

The web flow (type → **Translate to a test** → **Run this scenario**) gave the same ❌ BROKEN +67.8015 NEAR for the first sentence. A translation sometimes needs the repair round (2 attempts, ~30 s instead of ~10 s). The previous default (`qwen/qwen3.6-35b-a3b`, a reasoning model) took 20-47 s per translation and, before the polarity rule, wrote the first sentence's checks backwards.

### Measuring it: the text-to-test eval

`evals/text-to-test.json` holds 20 typed sentences across the four demo contracts, in plain and indirect wordings (e.g. *"can a random account empty the vault?"*). Each one lists the method the scenario must call and the result the sim must give. The expected results are not hand-picked: each comes from the built-in preset for the same attack, and `npm run test:sim` fails if they ever disagree.

```bash
npm run eval:t2t                                   # whichever LLM key is set
npm run eval:t2t -- --provider near                # NEAR AI Cloud only (needs NEAR_AI_API_KEY)
npm run eval:t2t -- --provider openrouter --model qwen/qwen3.6-35b-a3b
npm run eval:t2t -- --only vv-drain,ye-timeout --repeat 3
```

A case passes only when the scenario calls the expected method **and** the sim gives the expected result. The run prints the pass rate, how often the JSON was valid (and valid on the first try), and translation latency (median, p90). It saves every generated scenario to `evals/results/` (gitignored). Exit code: 0 all pass, 1 a case failed, 2 stopped because no LLM answered (no credit, bad key, outage), which says nothing about translation quality. It runs on demand only: it uses the network and LLM credit.

**What it found.** Every case produced valid JSON, but some LLM scenarios could not show the bug they were about and gave a **false BROKEN or false HELD**. Each is now a strict validation rule (the model gets the reason and one repair round) and has a unit test:

| Mistake in the generated scenario | Wrong result it caused |
|---|---|
| "contract state unchanged" combined with setup steps (deposits, requests): the setup's own change counted as the attack | false BROKEN |
| a deposit/withdraw flow signed by `victim`, whose existing 20 NEAR hid the lost funds | false HELD |
| two same-block withdrawals that together asked for no more than the deposit, so a double spend could never show | false HELD |
| a "must not profit" check that left out the account's own deposit, so getting its money back looked like profit | false BROKEN |
| a money check with `"else": "inconclusive"`, which hid a real loss | INCONCLUSIVE instead of BROKEN |

**Results** (OpenRouter, `deepseek/deepseek-v3.2`):

| Rules in place | Pass | Valid JSON | Valid first try | Translation median / p90 |
|---|---|---|---|---|
| before this work (1 run) | 19/20 | 100% | 90% | 8.8 s / 18.3 s |
| first four rules (2 runs) | 39/40 | 100% | 98% | 8.6 s / 12.5 s |
| all rules (3 runs requested) | 9/9 completed | 100% | 100% | 8.7 s / 10.7 s |

The last run stopped after 9 cases because the OpenRouter account ran out of credit, so a full run with all rules is still to do. The NEAR AI path is not measured yet either: it needs `NEAR_AI_API_KEY`. Without a key, its endpoint answers with HTTP 401, which the fallback handles, and the default model (`deepseek/deepseek-v3.2`) is in its catalogue.

Try it:
- **Web:** `OPEN_ROUTER_KEY=… npm run server` (and/or `NEAR_AI_API_KEY=…`) → scan `vulnerable-vault` → *Your own attack* → type the attack → **Translate to a test** (or Ctrl/⌘+Enter) → review the JSON → **Run this scenario** → ❌ BROKEN, with the drain's receipt trail.
- **CLI:**
  ```bash
  npm run attack -- vulnerable-vault.bitlens-demo --say "the attacker calls admin_drain and keeps the money" --print-scenario
  ```
- **No key:** `npm run attack -- vulnerable-vault.bitlens-demo --scenario scenarios/examples/drain.json` → ❌ BROKEN, `attacker.near called admin_drain and walked away with +67.8015 NEAR.` In the web UI, pick *start from a preset…*, edit the JSON and run it.
- **MCP:** `run_custom_attack` with `description` (plain English, via the LLM) or `scenario` (JSON the agent wrote).

## Scenario JSON

Every attack is one JSON object: the six built-in presets (`scenarios/presets/*.json`, filled in from the risk card), the examples in `scenarios/examples/`, and whatever text-to-test produces. The Rust runner (`runner/src/interp.rs`) maps each step onto a near-contract-sim operation against the contract under test. It then evaluates the checks in order: the first one that fails decides the result (BROKEN unless the check says `"else": "inconclusive"` or `"not_applicable"`). If all hold, the result is HELD.

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

`message` and `explain` texts can use `{net.attacker}`, `{net.contract}`, `{error.<step>}`, `{status.<step>}`, `{tgas}`, `{sweep}` and `{deadline}`. `bitlens-runner --validate file.json` checks a scenario on its own.

## How it works

### ① Capability scan (instant, no source needed)

A NEAR contract can only act through runtime host functions it imports. **If the import is absent, the contract cannot do the action.** BitLens reads `WebAssembly.Module.imports` from the deployed code:

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
- `POST /check {"receiver_id", "method", "deposit_near"?, "args"?, "mode"?}` → `{decision: allow|confirm|block, summary, reasons, evidence, replay_path, signing}` (see *Pre-signature check*).
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
- `npm run check -- <contract> <method> [--deposit 20] [--args '{…}'] [--strict] [--json]` judges a transaction before signing (exit code 0 allow, 1 confirm, 2 block, 3 error).
- `npm run attack -- <id> --scenario file.json` runs your own scenario JSON. `--say "english"` translates a sentence with the LLM first. `--print-scenario` prints the JSON; with `--list`, it prints every preset's JSON.

Environment:
- `NEAR_RPC_URL`: comma-separated RPC URLs. Testnet works too.
- `PORT`: default 8787.
- `BITLENS_MCP_TOKEN`: turns on MCP over HTTP at `POST /mcp` and is the bearer token it requires (unset = `/mcp` off). See *MCP over HTTP*.
- `BITLENS_RUNNER_BIN`: path to a prebuilt runner.
- `BITLENS_CACHE_DIR`: where the offline code copies go (default `.cache/code/`).
- `BITLENS_CACHE_TTL_S`: how long attack results stay in the in-memory cache (default `600`; `0` disables it). See *Results cache*.
- `HTTPS_PROXY` / `NO_PROXY`: honoured.

## Repo layout

```
core/       the one engine: RPC, scan, capability rules, attack selection, scenario schema + presets, text-to-test (LLM: NEAR AI → OpenRouter), verdict, runner bridge
server/     HTTP front door (thin) + static web UI from web/ + MCP over HTTP (POST /mcp, bearer token)
mcp/        MCP front door (thin): createMcpServer(); stdio when run directly, HTTP via server/ (POST /mcp)
cli/        scan / attack CLIs (thin)
web/        static HTML/CSS/JS: index.html (landing page), app.html + app.js (the app, at /app), replay.js + replay.css (attack replay animation), hero.js (the landing page's looping replay of a recorded real run), logo.svg, vercel.json (Vercel deploy: API rewrites); all app text rendered via textContent
runner/     Rust scenario interpreter over near-contract-sim (scenario.rs: format + validation, interp.rs: execution)
scenarios/  presets/*.json (the six attack templates as canned scenario JSON), examples/*.json
contracts/  clean / risky / vulnerable / yield-escrow demo contracts (near-sdk 5.29) + res/*.wasm
scripts/    preflight.ts (pre-demo checklist), mcp-smoke.ts, eval-text-to-test.ts (npm run eval:t2t), fetch-reference-wasm.sh
evals/      text-to-test.json: the eval set (sentences + expected sim results)
.cache/     last fetched code per account, for the offline fallback (gitignored)
```

## Limitations (honest)

- **Never touches mainnet state.** BitLens only makes RPC *view* calls. Attacks run in a local, in-process runtime, never against a live contract, and nothing is ever signed or sent.
- **Bytecode only, no source.** A present import means the code *can* reach an action, not that anyone can trigger it. Method-name heuristics are hints. An absent import is a proof.
- **Arguments are partly guessed.** NEP standard methods get their exact signatures, and JSON arguments are fixed from the contract's own errors (see *Argument discovery*), but the values put in discovered fields are still guesses (e.g. a role name), and Borsh arguments cannot be discovered at all (aurora). So BitLens cannot always build valid arguments or initialise complex contracts. It reports INCONCLUSIVE in those cases and never claims HELD from a rejection it cannot explain. A SAFE verdict means "the six templates found nothing", not "audited".
- **Templates, not fuzzing.** Six scenario templates aimed at common NEAR bug classes, driven by the risk card. Logic bugs outside them (pricing, oracle, cross-contract token flows with real counterparties) are not tested. Other contracts the target calls are not deployed, so those calls fail in the sim.
- **Yield detection needs a hint in the method name.** Template 6 picks methods named like `request`/`sign`/`wait`/`ask`. A yield started from a differently named method is not attacked. It is verified on yield-escrow, both the buggy and the fixed build.
- **Offline cache is a last-known copy.** If the contract was redeployed since the cached fetch, a cached card describes the old code. The card shows the fetch time and block height.
- **Text-to-test is only as good as the translation.** The LLM can misread a sentence. That is why the JSON is shown, and can be edited, before it runs, and why a result only means what its checks say. The provider chain is unit-tested against two fake OpenAI-compatible servers: request shape, JSON mode, every fallback path, the cool-down, and the repair round.
- **Fresh state.** The sim starts from a fresh `init`, not a copy of the contract's mainnet storage.
- **First build is heavy** (see above). After that a full assessment takes ~0.2-1 s.

## License

MIT, see [LICENSE](LICENSE).
