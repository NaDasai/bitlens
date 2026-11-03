/**
 * MCP front door (stdio): NEAR X-Ray as a tool for AI agents.
 * A thin wrapper over core/: no scan/attack logic here.
 *
 * Tools: scan_contract, list_attacks, run_attacks, assess_contract.
 * All are read-only with respect to every real network: scans make RPC view
 * queries; attacks run in a local near-contract-sim and never sign or send a
 * transaction anywhere. stdout is the MCP channel, so all logging goes to stderr.
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import {
  assertAccountId,
  engineStatus,
  EngineNotReadyError,
  listAttacks,
  runAttacks,
  scan,
  startWarmup,
  toErrorPayload,
  verdictOf,
  warmReady,
  warmupSpec,
  type AttackReport,
  type AttackResult,
  type RiskCard,
} from "../core/index.js";

const log = (m: string) => process.stderr.write(`[near-xray] ${m}\n`);

const accountId = z
  .string()
  .min(2)
  .max(64)
  .describe(
    'NEAR account id of the contract, e.g. "wrap.near" (mainnet). Built-in demo contracts: "clean-vault.xray-demo", "risky-vault.xray-demo", "vulnerable-vault.xray-demo".',
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
    results: report.results.map(resultForAgent),
  };
}

function engineNotReady(): EngineNotReadyError {
  const st = engineStatus();
  return new EngineNotReadyError(
    `Attack engine still warming up (${st.state}${st.detail ? `: ${st.detail}` : ""}; ${st.elapsed_s}s so far). Retry in a minute. scan_contract works meanwhile and gives the capability signal.`,
  );
}

const server = new McpServer({ name: "near-xray", version: "0.1.0" });

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
      "List the attack scenarios NEAR X-Ray would run against this contract, derived from its capabilities: unauthorised admin calls, unauthorised key addition, double-spend before a callback resolves, failed-transfer refund, callback out-of-gas, stale yield timeout. Each has an id to pass to run_attacks. Read-only, instant.",
    inputSchema: { account_id: accountId },
    annotations: { readOnlyHint: true, openWorldHint: true },
  },
  async ({ account_id }) => {
    try {
      const { card, attacks } = await listAttacks(assertAccountId(account_id));
      const data = { account_id: card.account_id, attacks: attacks.map((a) => ({ id: a.id, name: a.name, kind: a.kind, checks: a.checks })) };
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

async function main() {
  await server.connect(new StdioServerTransport());
  log("MCP server ready on stdio (tools: scan_contract, list_attacks, run_attacks, assess_contract)");
  void startWarmup(log, warmupSpec); // background, never awaited
}

main().catch((e) => {
  log(`fatal: ${e?.stack ?? e}`);
  process.exit(1);
});
