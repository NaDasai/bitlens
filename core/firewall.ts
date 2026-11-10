/**
 * Pre-signature check: an agent (or a wallet) proposes a function-call
 * transaction; BitLens judges it and answers allow / confirm / block, with the
 * reasons and the simulated attack that justifies them.
 *
 * BitLens never signs and never sends anything: the caller's wallet signs only
 * when the answer is "allow" (and asks a human on "confirm"). Any error is not
 * an "allow" either. The judgement is the same evaluation as assess_contract:
 * the deployed bytecode's capabilities plus every suggested attack run in the
 * local simulator.
 */
import { assertAccountId } from "./accountId.js";
import { runAttacks, verdictOf, type AttackReport, type AttackResult, type Verdict } from "./attacks.js";
import { InputError } from "./errors.js";
import { EngineNotReadyError } from "./engine.js";
import { RpcError } from "./rpc.js";
import { scan, type RiskCard } from "./scan.js";

export type Decision = "allow" | "confirm" | "block";
/** standard: block when NEAR would go into a proven-vulnerable contract. strict: block anything not proven safe. */
export type FirewallMode = "standard" | "strict";

export interface ProposedTransaction {
  /** The contract the transaction calls. */
  receiver_id: string;
  method: string;
  /** NEAR attached to the call, as a decimal string ("20", "0.5") or number. Default 0. */
  deposit_near?: string | number;
  /** Call arguments (recorded for the report; the judgement does not depend on them). */
  args?: Record<string, unknown>;
}

export interface FirewallResult {
  decision: Decision;
  /** One line, for a log or a chat reply. */
  summary: string;
  reasons: string[];
  mode: FirewallMode;
  transaction: { receiver_id: string; method: string; deposit_near: string; args: Record<string, unknown> | null };
  contract: {
    account_id: string;
    verdict: Verdict | null;
    risk_level: string | null;
    code_hash: string | null;
    attacks_run: boolean;
    /** Set when the attack results came from the cache (same code, simulated this many seconds ago). */
    attacks_cached_age_s?: number | null;
  };
  /** The broken attacks behind a block (status, explanation, receipts, NEAR deltas). */
  evidence: Pick<AttackResult, "id" | "name" | "status" | "explanation" | "event_sequence" | "token_deltas">[];
  /** Opens the web app on this contract and replays the first attack in `evidence`. */
  replay_path: string | null;
  signing: string;
}

const METHOD_RE = /^[A-Za-z0-9_]{1,64}$/;
const NEAR_RE = /^\d{1,9}(\.\d{1,24})?$/;
const SIGNING_NOTE = 'BitLens never signs or sends transactions. Sign only on "allow"; on "confirm" ask a human; on "block" or any error, do not sign.';

/** Validate and normalise untrusted input (tool / HTTP). */
export function normaliseTransaction(tx: unknown): FirewallResult["transaction"] {
  if (!tx || typeof tx !== "object" || Array.isArray(tx)) throw new InputError("Give the transaction as an object: { receiver_id, method, deposit_near?, args? }.");
  const t = tx as Record<string, unknown>;
  const receiver_id = assertAccountId(t.receiver_id);
  if (typeof t.method !== "string" || !METHOD_RE.test(t.method)) throw new InputError("method must be a NEAR method name (1-64 letters, digits or _).");
  const dep = t.deposit_near === undefined || t.deposit_near === null || t.deposit_near === "" ? "0" : String(t.deposit_near).trim();
  if (!NEAR_RE.test(dep)) throw new InputError('deposit_near must be a non-negative decimal amount of NEAR, e.g. "20" or "0.5".');
  let args: Record<string, unknown> | null = null;
  if (t.args !== undefined && t.args !== null) {
    if (typeof t.args !== "object" || Array.isArray(t.args)) throw new InputError("args must be a JSON object.");
    if (JSON.stringify(t.args).length > 16_384) throw new InputError("args larger than 16 KB.");
    args = t.args as Record<string, unknown>;
  }
  return { receiver_id, method: t.method, deposit_near: dep, args };
}

const strip = (r: AttackResult) => ({ id: r.id, name: r.name, status: r.status, explanation: r.explanation, event_sequence: r.event_sequence, token_deltas: r.token_deltas });

/**
 * The policy, as a pure function of the evaluation (unit-tested without the sim).
 * `report` is null when the attack engine is not ready yet.
 */
export function decide(card: RiskCard, report: AttackReport | null, tx: FirewallResult["transaction"], mode: FirewallMode = "standard"): FirewallResult {
  const deposit = Number(tx.deposit_near);
  const paying = deposit > 0;
  const { verdict, reasons: verdictReasons } = verdictOf(card, report);
  const broken = report?.results.filter((r) => r.status === "broken") ?? [];
  const base = {
    mode,
    transaction: tx,
    contract: { account_id: card.account_id, verdict, risk_level: card.risk.level, code_hash: card.code_hash, attacks_run: Boolean(report), attacks_cached_age_s: report?.cache?.age_s ?? null },
    signing: SIGNING_NOTE,
  };
  const out = (decision: Decision, summary: string, reasons: string[], evidence: AttackResult[] = []): FirewallResult => ({
    decision,
    summary,
    reasons,
    ...base,
    evidence: evidence.map(strip),
    replay_path: evidence.length ? `/app?account=${encodeURIComponent(card.account_id)}&replay=${encodeURIComponent(evidence[0].id)}` : null,
  });
  const call = `${tx.method}(${paying ? `, ${tx.deposit_near} NEAR attached` : ""})`.replace("(, ", "(");

  if (!card.methods.includes(tx.method))
    return out("block", `BLOCK: ${card.account_id} has no method \`${tx.method}\`.`, [
      `\`${tx.method}\` is not exported by ${card.account_id}: the call would fail, or the request is not what it claims to be.`,
    ]);

  if (!report) {
    const why = "BitLens's attack engine is not ready yet, so only the bytecode was checked and nothing was proven in simulation. Check again shortly.";
    if (paying || mode === "strict") return out(mode === "strict" ? "block" : "confirm", `${mode === "strict" ? "BLOCK" : "CONFIRM"}: ${call} on ${card.account_id}: not verified yet.`, [why, ...verdictReasons]);
    return out("allow", `ALLOW: ${call} on ${card.account_id} (no NEAR attached; attacks not run yet).`, [why, ...verdictReasons]);
  }

  // Evidence order: the attack that moved the most NEAR away from its owner first
  // (what the caller's money is exposed to), then attacks through the method being called.
  const ranked = [...broken].sort(
    (a, b) => lossOf(b, card.account_id) - lossOf(a, card.account_id) || Number(methodsOf(b).includes(tx.method)) - Number(methodsOf(a).includes(tx.method)),
  );

  if (verdict === "dangerous") {
    const proven = ranked.map((r) => `❌ ${r.name}: ${r.explanation}`);
    if (paying || mode === "strict")
      return out(
        "block",
        `BLOCK: ${call} on ${card.account_id}: ${broken.length} attack(s) succeeded in simulation.`,
        [paying ? `You would attach ${tx.deposit_near} NEAR to a contract where BitLens proved ${broken.length} attack(s) in simulation:` : `BitLens proved ${broken.length} attack(s) on this contract in simulation:`, ...proven],
        ranked,
      );
    return out("confirm", `CONFIRM: ${call} on ${card.account_id}: no NEAR attached, but the contract is DANGEROUS.`, [
      "No NEAR is attached to this call, but BitLens proved attack(s) on this contract in simulation; funds you already hold there may be at risk:",
      ...proven,
    ], ranked);
  }

  if (verdict === "caution") {
    if (paying)
      return out(mode === "strict" ? "block" : "confirm", `${mode === "strict" ? "BLOCK" : "CONFIRM"}: ${call} on ${card.account_id}: not proven safe.`, [
        `No attack succeeded, but the contract is not proven safe (verdict CAUTION), and you would attach ${tx.deposit_near} NEAR:`,
        ...verdictReasons,
      ]);
    return out(mode === "strict" ? "confirm" : "allow", `${mode === "strict" ? "CONFIRM" : "ALLOW"}: ${call} on ${card.account_id} (no NEAR attached; verdict CAUTION).`, verdictReasons);
  }

  return out("allow", `ALLOW: ${call} on ${card.account_id}: all attacks held.`, [
    ...verdictReasons,
    "Not an audit: it means the attacks BitLens knows found nothing.",
  ]);
}

/** NEAR that left someone it should not have: the contract's or a user's loss in this attack. */
function lossOf(r: AttackResult, contract: string): number {
  const deltas = Object.entries(r.token_deltas ?? {}).map(([id, d]) => ({ id, near: Number.parseFloat(d.near) || 0 }));
  const contractLoss = -(deltas.find((d) => d.id === contract)?.near ?? 0);
  const userLoss = Math.max(0, ...deltas.filter((d) => d.id !== contract).map((d) => -d.near));
  return Math.max(contractLoss, userLoss, 0);
}

function methodsOf(r: AttackResult): string[] {
  return [...new Set(r.event_sequence.filter((e) => e.action.startsWith("call ")).map((e) => e.action.slice(5)))];
}

/** Judge a proposed transaction: scan + attacks in the local sim, then the policy. Never signs. */
export async function checkTransaction(tx: unknown, mode: FirewallMode = "standard"): Promise<FirewallResult> {
  if (mode !== "standard" && mode !== "strict") throw new InputError('mode must be "standard" or "strict".');
  const t = normaliseTransaction(tx);
  try {
    try {
      const { card, report } = await runAttacks(t.receiver_id);
      return decide(card, report, t, mode);
    } catch (e) {
      // Runner not built yet: judge on the bytecode alone, clearly marked as unproven.
      if (e instanceof EngineNotReadyError) return decide(await scan(t.receiver_id), null, t, mode);
      throw e;
    }
  } catch (e) {
    if (e instanceof RpcError && (e.code === "UNKNOWN_ACCOUNT" || e.code === "NO_CONTRACT_CODE")) {
      const reason = e.code === "UNKNOWN_ACCOUNT" ? `${t.receiver_id} does not exist.` : `${t.receiver_id} has no contract deployed (a plain wallet account), so a function call to it fails.`;
      return {
        decision: "block",
        summary: `BLOCK: ${reason}`,
        reasons: [reason],
        mode,
        transaction: t,
        contract: { account_id: t.receiver_id, verdict: null, risk_level: null, code_hash: null, attacks_run: false },
        evidence: [],
        replay_path: null,
        signing: SIGNING_NOTE,
      };
    }
    throw e;
  }
}
