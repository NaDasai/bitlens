/**
 * MCP front door (stdio): BitLens as a tool for AI agents.
 * A thin wrapper over core/: no scan/attack logic here.
 *
 * Tools: scan_contract, list_attacks, run_attacks, assess_contract, check_transaction, run_custom_attack.
 * Transports: stdio when run directly (npm run mcp); HTTP via server/index.ts
 * (POST /mcp, bearer token, stateless) using createMcpServer().
 * All are read-only with respect to every real network: scans make RPC view
 * queries; attacks run in a local near-contract-sim and never sign or send a
 * transaction anywhere. stdout is the MCP channel, so all logging goes to stderr.
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { z } from "zod";
import {
  assertAccountId,
  checkTransaction,
  engineStatus,
  EngineNotReadyError,
  listAttacks,
  runAttacks,
  scan,
  startWarmup,
  toErrorPayload,
  translateToScenario,
  InputError,
  verdictOf,
  warmReady,
  warmupSpec,
  type AttackReport,
  type AttackResult,
  type RiskCard,
} from "../core/index.js";

const log = (m: string) => process.stderr.write(`[bitlens] ${m}\n`);

const accountId = z
  .string()
  .min(2)
  .max(64)
  .describe(
    'NEAR account id of the contract, e.g. "wrap.near" (mainnet). Built-in demo contracts: "clean-vault.bitlens-demo", "risky-vault.bitlens-demo", "vulnerable-vault.bitlens-demo".',
  );

type ToolResult = { content: { type: "text"; text: string }[]; structuredContent?: Record<string, unknown>; isError?: boolean };

function ok(summary: string, data: Record<string, unknown>): ToolResult {
  return { content: [{ type: "text", text: `${summary}\n\n${JSON.stringify(data, null, 2)}` }], structuredContent: data };
}

function fail(e: unknown): ToolResult {
  const { body } = toErrorPayload(e);
  return { content: [{ type: "text", text: `${body.error.code}: ${body.error.message}` }], structuredContent: body as any, isError: true };
}

/** The card as an agent wants it: severity + label per capability, no noise. */
function cardForAgent(card: RiskCard) {
  return {
    account_id: card.account_id,
    rpc_network: card.rpc_network ?? card.source,
    ...(card.cached_at ? { offline_cache: `RPC unreachable: analysed the last fetched copy of this code (${card.cached_at}, block ${card.block_height})` } : {}),
    code_hash: card.code_hash,
    code_hash_verified: card.code_hash_verified,
    risk_level: card.risk.level,
    risk_reasons: card.risk.reasons,
    standards: card.standards.map((s) => s.id),
    capabilities: card.capabilities.map((c) => ({
      id: c.id,
      severity: c.severity,
      confidence: c.confidence,
      label: c.label,
      evidence: c.evidence,
      via_methods: c.corroborated_by,
    })),
    notable_methods: card.notable_methods.filter((m) => m.privileged).map((m) => ({ name: m.name, note: m.note })),
    access_keys: card.access_keys,
    methods: card.methods,
  };
}

/** Per-scenario result as the brief specifies, without the long receipt-tree text. */
function resultForAgent(r: AttackResult) {
  return {
    id: r.id,
    name: r.name,
    status: r.status,
    explanation: r.explanation,
    event_sequence: r.event_sequence.map(
      (e) => `#${e.block} ${e.from} -> ${e.to}: ${e.action}${e.deposit_near !== "0.0000" ? ` (${e.deposit_near} NEAR)` : ""} ${e.ok ? "ok" : e.detail}`,
    ),
    token_deltas: Object.fromEntries(Object.entries(r.token_deltas).map(([k, v]) => [k, v.near])),
    findings: r.findings,
  };
}

function reportForAgent(report: AttackReport) {
  return {
    engine: report.engine,
    sim_accounts: report.accounts,
    contract_initialised: report.init.ok ? `${report.init.method} (by ${report.init.signer})` : false,
    summary: report.summary,
    ...(report.cache ? { cached: `results from the cache: same contract code (${report.code_hash}), simulated ${report.cache.age_s}s ago` } : {}),
    results: report.results.map(resultForAgent),
  };
}

function engineNotReady(): EngineNotReadyError {
  const st = engineStatus();
  return new EngineNotReadyError(
    `Attack engine still warming up (${st.state}${st.detail ? `: ${st.detail}` : ""}; ${st.elapsed_s}s so far). Retry in a minute. scan_contract works meanwhile and gives the capability signal.`,
  );
}

/**
 * A fresh MCP server with BitLens's six tools registered. stdio (main below)
 * uses one for the whole process; HTTP (server/index.ts, POST /mcp) creates one
 * per request. Creating it has no side effects: no transport, no warm-up.
 */
export function createMcpServer(): McpServer {
  const server = new McpServer({ name: "bitlens", version: "0.1.0" });

  server.registerTool(
    "scan_contract",
    {
      title: "Scan a NEAR contract's capabilities",
      description:
        "Instant, read-only capability scan of a deployed NEAR contract, from its on-chain bytecode (no source needed). Use FIRST, before interacting with an unknown NEAR contract, to learn whether it can send NEAR out, add full-access keys (hand over control), redeploy itself (change its logic later) or delete accounts, which NEP standards it implements, and which admin-looking methods exist. Returns risk_level (low/medium/high) with reasons. Does not run attacks; see assess_contract for a verdict.",
      inputSchema: { account_id: accountId },
      annotations: { readOnlyHint: true, openWorldHint: true },
    },
    async ({ account_id }) => {
      try {
        const card = await scan(assertAccountId(account_id));
        return ok(card.summary, cardForAgent(card));
      } catch (e) {
        return fail(e);
      }
    },
  );

  server.registerTool(
    "list_attacks",
    {
      title: "List attack scenarios for a NEAR contract",
      description:
        "List the attack scenarios BitLens would run against this contract, derived from its capabilities: unauthorised admin calls, unauthorised key addition, double-spend before a callback resolves, failed-transfer refund, callback out-of-gas, stale yield timeout. Each has an id to pass to run_attacks. With include_scenarios, also returns each one's scenario JSON (the format run_custom_attack accepts). Read-only, instant.",
      inputSchema: {
        account_id: accountId,
        include_scenarios: z.boolean().optional().describe("Also return the scenario JSON of each attack (useful as examples for run_custom_attack)."),
      },
      annotations: { readOnlyHint: true, openWorldHint: true },
    },
    async ({ account_id, include_scenarios }) => {
      try {
        const { card, attacks } = await listAttacks(assertAccountId(account_id));
        const data = {
          account_id: card.account_id,
          attacks: attacks.map((a) => ({ id: a.id, name: a.name, kind: a.kind, checks: a.description, ...(include_scenarios ? { scenario: a.scenario } : {}) })),
        };
        return ok(`${attacks.length} attack scenario(s) apply to ${card.account_id}.`, data);
      } catch (e) {
        return fail(e);
      }
    },
  );

  server.registerTool(
    "run_attacks",
    {
      title: "Run attacks on a NEAR contract in a local simulator",
      description:
        "Deploy the contract's real bytecode in a LOCAL NEAR runtime (near-contract-sim: nearcore's own runtime, real gas and callbacks) and run attack scenarios as an attacker account. Returns per scenario: status held/broken/inconclusive/not_applicable, an explanation, the receipt sequence, and net NEAR movement per account. Never sends transactions to any real network. Omit scenario_ids to run all suggested ones. Takes seconds; if the engine is still warming up it says so; retry shortly.",
      inputSchema: {
        account_id: accountId,
        scenario_ids: z.array(z.string().max(128)).max(50).optional().describe("Scenario ids from list_attacks. Omit to run all suggested."),
      },
      annotations: { readOnlyHint: true, openWorldHint: true },
    },
    async ({ account_id, scenario_ids }) => {
      try {
        const id = assertAccountId(account_id);
        if (!warmReady()) throw engineNotReady();
        const { report } = await runAttacks(id, scenario_ids);
        const s = report.summary;
        return ok(`${id}: ${s.broken} broken, ${s.held} held, ${s.inconclusive} inconclusive.`, { account_id: id, ...reportForAgent(report) });
      } catch (e) {
        return fail(e);
      }
    },
  );

  server.registerTool(
    "assess_contract",
    {
      title: "Should I interact with this NEAR contract?",
      description:
        "One-shot safety check before interacting with an unknown NEAR contract: scans its bytecode for dangerous capabilities (can it drain funds, add keys, redeploy itself?), then runs every suggested attack in a local simulator, and returns a verdict: safe / caution / dangerous, with the findings. Use this before calling, depositing into, or approving any NEAR contract you have not verified. Read-only: no transactions are sent to any network.",
      inputSchema: { account_id: accountId },
      annotations: { readOnlyHint: true, openWorldHint: true },
    },
    async ({ account_id }) => {
      try {
        const id = assertAccountId(account_id);
        if (!warmReady()) {
          // Do not block the agent: give the capability-based answer now, clearly marked partial.
          const card = await scan(id);
          const { verdict, reasons } = verdictOf(card, null);
          const st = engineStatus();
          const data = {
            account_id: id,
            verdict,
            verdict_reasons: [
              `Attack engine ${st.state} (${st.elapsed_s}s): call assess_contract again shortly for the full verdict.`,
              ...reasons,
            ],
            attacks_run: false,
            capabilities: cardForAgent(card),
          };
          return ok(`${id}: ${verdict.toUpperCase()} (capability scan only; attack engine still warming up).`, data);
        }
        const { card, report } = await runAttacks(id);
        const { verdict, reasons } = verdictOf(card, report);
        const data = { account_id: id, verdict, verdict_reasons: reasons, attacks_run: true, capabilities: cardForAgent(card), attacks: reportForAgent(report) };
        return ok(`${id}: ${verdict.toUpperCase()}. ${reasons[0] ?? ""}`, data);
      } catch (e) {
        return fail(e);
      }
    },
  );

  server.registerTool(
    "check_transaction",
    {
      title: "Check a NEAR transaction before signing it",
      description:
        "Call this right BEFORE signing any NEAR function-call transaction (deposit, swap, approve, ...). Give the transaction you are about to sign; BitLens evaluates the receiving contract (bytecode capabilities + every suggested attack run in a local simulator) and answers decision: allow / confirm / block, with the reasons and, on block, the simulated attack that justifies it (receipts and who gained NEAR) plus a replay link. " +
        'Sign only on "allow". On "confirm", ask the human first. On "block" or any error, do not sign. ' +
        'Policy (mode "standard"): block when NEAR would be attached to a contract where an attack succeeded, or when the method does not exist; confirm when attaching NEAR to a contract not proven safe. mode "strict": block anything not proven safe. ' +
        "BitLens never signs or sends anything.",
      inputSchema: {
        receiver_id: accountId.describe("The contract the transaction calls."),
        method: z.string().min(1).max(64).describe("The method the transaction calls, e.g. \"deposit\"."),
        deposit_near: z.string().max(40).optional().describe('NEAR attached to the call, as a decimal string, e.g. "20". Default "0".'),
        args: z.record(z.string(), z.unknown()).optional().describe("The call arguments (recorded in the answer)."),
        mode: z.enum(["standard", "strict"]).optional().describe('"standard" (default) or "strict".'),
      },
      annotations: { readOnlyHint: true, openWorldHint: true },
    },
    async ({ receiver_id, method, deposit_near, args, mode }) => {
      try {
        const r = await checkTransaction({ receiver_id, method, deposit_near, args }, mode ?? "standard");
        return ok(`${r.summary}\n${r.signing}`, r as unknown as Record<string, unknown>);
      } catch (e) {
        return fail(e);
      }
    },
  );

  server.registerTool(
    "run_custom_attack",
    {
      title: "Test your own attack idea against a NEAR contract",
      description:
        "Turn an attack idea into a test and run it on the contract's real bytecode in the LOCAL simulator. Give EITHER `description` (plain English, e.g. \"the attacker calls admin_drain and keeps the money\"; an LLM translates it into scenario JSON: NEAR AI Cloud, falling back to OpenRouter; the server needs NEAR_AI_API_KEY or OPEN_ROUTER_KEY) OR `scenario` (scenario JSON you wrote yourself). " +
        'Scenario JSON: {"id","name","steps":[...],"checks":[...]}. Steps ("op"): call {as: owner|victim|attacker|user, method, args, deposit_near, async, attack:true for the call under test}, deposit {as, method, near}, settle, advance_blocks {blocks}, wait_for_yield, advance_past_yield, sweep. ' +
        'Checks ("check"), first failure decides: net_at_most|net_at_least|net_equals {account: role|contract, near}, unchanged {what: code|keys|state}, step_succeeded|step_failed {step}. ' +
        "Call list_attacks with include_scenarios for complete examples. Returns the scenario that ran and its result (held / broken / inconclusive). dry_run: only translate. Never sends transactions to any network.",
      inputSchema: {
        account_id: accountId,
        description: z.string().min(3).max(1000).optional().describe("The attack idea in plain English."),
        scenario: z.record(z.string(), z.unknown()).optional().describe("Scenario JSON to run as-is (validated)."),
        dry_run: z.boolean().optional().describe("Only translate the description to scenario JSON; do not run it."),
      },
      annotations: { readOnlyHint: true, openWorldHint: true },
    },
    async ({ account_id, description, scenario, dry_run }) => {
      try {
        const id = assertAccountId(account_id);
        if (Boolean(description) === Boolean(scenario)) throw new InputError("Give exactly one of `description` (plain English) or `scenario` (scenario JSON).");
        let sc: unknown = scenario;
        let translatedBy: string | undefined;
        if (description) {
          const t = await translateToScenario(description, await scan(id));
          sc = t.scenario;
          translatedBy = `${t.provider} (${t.model})`;
        }
        if (dry_run) return ok(`Scenario for ${id}${translatedBy ? ` (translated by ${translatedBy})` : ""}; not run.`, { account_id: id, scenario: sc as Record<string, unknown>, translated_by: translatedBy ?? null });
        if (!warmReady()) throw engineNotReady();
        const { report } = await runAttacks(id, undefined, { custom: [sc] });
        const r = report.results[0];
        return ok(`${id}: ${r.status.toUpperCase()}: ${r.explanation}`, {
          account_id: id,
          translated_by: translatedBy ?? null,
          scenario: sc as Record<string, unknown>,
          result: resultForAgent(r),
        });
      } catch (e) {
        return fail(e);
      }
    },
  );
  return server;
}

async function main() {
  await createMcpServer().connect(new StdioServerTransport());
  log("MCP server ready on stdio (tools: scan_contract, list_attacks, run_attacks, assess_contract, check_transaction, run_custom_attack)");
  void startWarmup(log, warmupSpec); // background, never awaited
}

// Only when run directly (npm run mcp): importing this module has no side effects.
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((e) => {
    log(`fatal: ${e?.stack ?? e}`);
    process.exit(1);
  });
}
