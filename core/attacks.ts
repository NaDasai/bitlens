/**
 * Layer 2: attack proof.
 *   risk card → suggested scenarios (canned scenario JSON from
 *   scenarios/presets/, filled with method names from the card) → runner spec
 *   → near-contract-sim → results. Custom scenarios (hand-written, or
 *   translated from English by speech.ts) are the same JSON.
 */
import { createHash } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { base58, scanWithCode, type RiskCard } from "./scan.js";
import { DEMO_CONTRACTS, readDemoWasm } from "./demo.js";
import { runSpec } from "./engine.js";
import { InputError } from "./errors.js";
import { fillPreset, validateScenario, type Scenario } from "./scenario.js";
import type { RpcOptions } from "./rpc.js";

export const SIM_ACCOUNTS = { owner: "owner.near", victim: "victim.near", attacker: "attacker.near", user: "user.near" };

/** Preset file the scenario came from, or "custom". */
export type AttackKind =
  | "unauthorized_call"
  | "unauthorized_add_key"
  | "double_withdraw"
  | "failed_transfer_refund"
  | "callback_gas"
  | "yield_timeout"
  | "custom";

export interface AttackScenario {
  id: string;
  name: string;
  kind: AttackKind;
  /** What the scenario checks, in one sentence. */
  description: string;
  target_method?: string;
  /** The scenario JSON the runner executes. */
  scenario: Scenario;
}

export type AttackStatus = "held" | "broken" | "inconclusive" | "not_applicable" | "error";

export interface AttackEvent {
  step: string;
  block: number;
  from: string;
  to: string;
  action: string;
  deposit_near: string;
  ok: boolean;
  detail: string;
  logs?: string[];
}

export interface AttackResult {
  id: string;
  name: string;
  status: AttackStatus;
  explanation: string;
  event_sequence: AttackEvent[];
  token_deltas: Record<string, { yocto: string; near: string }>;
  findings: string[];
  trace: string;
  duration_ms: number;
}

export interface AttackReport {
  account_id: string;
  code_hash: string;
  engine: string;
  init: { ok: boolean; method?: string; signer?: string; tried: unknown[] };
  victim_deposit: unknown;
  accounts: typeof SIM_ACCOUNTS;
  results: AttackResult[];
  summary: { held: number; broken: number; inconclusive: number; not_applicable: number; error: number };
  duration_ms: number;
}

// --- argument guessing -------------------------------------------------------

const ONE_NEAR = "1000000000000000000000000";
/** A syntactically valid ed25519 public key that belongs to the attacker in the sim. */
export const ATTACKER_PUBLIC_KEY = "ed25519:" + base58(new Uint8Array(32).fill(7));
/** The smallest valid WASM module (8 bytes), base64: what an attacker would "upgrade" a contract to. */
const TINY_WASM_B64 = "AGFzbQEAAAA=";

/**
 * near-sdk ignores JSON fields a method doesn't declare, so one object with
 * every common argument name lets us call an unknown method plausibly.
 * Everything points at `who`, the account that would benefit.
 */
export function kitchenSinkArgs(who: string): Record<string, unknown> {
  const ids = [
    "account_id", "receiver_id", "owner_id", "new_owner_id", "new_owner", "owner", "to", "recipient", "recipient_id",
    "beneficiary_id", "admin", "admin_id", "new_admin", "user", "user_id", "sender_id", "predecessor_id", "address",
    "approver_id", "operator_id",
  ];
  const args: Record<string, unknown> = Object.fromEntries(ids.map((k) => [k, who]));
  Object.assign(args, {
    amount: ONE_NEAR,
    paused: true,
    pause: true,
    value: true,
    enabled: true,
    status: true,
    public_key: ATTACKER_PUBLIC_KEY,
    code: TINY_WASM_B64,
    msg: "",
    memo: null,
    request_id: 0,
    approved: true,
  });
  return args;
}

const DEPOSIT_RE = /^(deposit|near_deposit|deposit_near)$|^deposit_|_deposit$/;
const WITHDRAW_RE = /withdraw/;
const VIEW_RE = /(^|_)(get|view|is|has)_|(_of|_view|_info|_metadata)$/;
const CALLBACK_RE = /^on_|_callback$|^resolve_|_resolve_|^callback_/;

function custom(card: RiskCard): string[] {
  return card.notable_methods.map((m) => m.name);
}

function findDeposit(card: RiskCard): string | undefined {
  const c = custom(card).filter((m) => DEPOSIT_RE.test(m) && !m.startsWith("storage_"));
  return c.find((m) => m === "deposit") ?? c[0];
}

function findWithdraw(card: RiskCard): string | undefined {
  const c = custom(card).filter((m) => WITHDRAW_RE.test(m) && !m.startsWith("storage_") && !VIEW_RE.test(m) && !CALLBACK_RE.test(m));
  return c.find((m) => m === "withdraw") ?? c[0];
}

const has = (card: RiskCard, id: string) => card.capabilities.some((c) => c.id === id);

/** Derive the attack list from the risk card. Pure: no network, no sim. */
const FIVE_NEAR = "5000000000000000000000000";

function preset(kind: Exclude<AttackKind, "custom">, file: string, params: Record<string, unknown>, target?: string): AttackScenario {
  const scenario = fillPreset(file, params);
  return { id: scenario.id, name: scenario.name, kind, description: scenario.description ?? "", target_method: target, scenario };
}

/** Derive the attack list from the risk card. Pure: no network, no sim. */
export function suggestAttacks(card: RiskCard): AttackScenario[] {
  const out: AttackScenario[] = [];
  const attacker = SIM_ACCOUNTS.attacker;
  const contract = card.account_id;
  const keyMethods = new Set(
    card.capabilities
      .filter((c) => c.id === "add_full_access_key" || c.id === "add_function_call_key")
      .flatMap((c) => c.corroborated_by),
  );

  // 2. Unauthorised key addition (before 1, so the key methods get the stronger check).
  for (const m of keyMethods) {
    out.push(preset("unauthorized_add_key", "unauthorized_add_key", { method: m, args: kitchenSinkArgs(attacker), contract }, m));
  }

  // 1. Unauthorised privileged call, for each privileged-looking method.
  for (const m of card.notable_methods.filter((x) => x.privileged && !keyMethods.has(x.name)).slice(0, 15)) {
    const cb = CALLBACK_RE.test(m.name);
    const params = {
      method: m.name,
      args: kitchenSinkArgs(attacker),
      contract,
      title: cb ? `Direct call to callback ${m.name}` : `Unauthorised call to ${m.name}`,
      summary: cb
        ? `attacker.near calls the callback \`${m.name}\` directly; it must be private to the contract.`
        : `attacker.near (not the owner) calls \`${m.name}\`; it must be rejected or have no effect.`,
    };
    out.push(preset("unauthorized_call", "unauthorized_call", params, m.name));
  }

  // 3-5. Withdraw-flow attacks: need a deposit + withdraw pair and the ability to send NEAR.
  const dep = findDeposit(card);
  const wd = findWithdraw(card);
  const flow = dep && wd ? { deposit: dep, withdraw: wd, amount_arg: "amount" } : null;
  if (flow && has(card, "transfer")) {
    if (has(card, "callbacks")) out.push(preset("double_withdraw", "double_withdraw", flow, wd));
    out.push(preset("failed_transfer_refund", "failed_transfer_refund", flow, wd));
    if (has(card, "callbacks")) out.push(preset("callback_gas", "callback_gas", flow, wd));
  }

  // 6. Stale yield / timeout. With a deposit/withdraw pair the user is funded first,
  // so the runner can check the timed-out request's NEAR comes back.
  if (has(card, "yield_resume")) {
    const candidates = custom(card).filter((m) => !VIEW_RE.test(m) && !CALLBACK_RE.test(m) && /request|yield|sign|wait|ask/.test(m));
    for (const m of candidates.slice(0, 3)) {
      const args = { ...kitchenSinkArgs(SIM_ACCOUNTS.user), ...(flow ? { [flow.amount_arg]: FIVE_NEAR } : {}) };
      out.push(flow ? preset("yield_timeout", "yield_timeout", { ...flow, method: m, args }, m) : preset("yield_timeout", "yield_timeout_plain", { method: m, args }, m));
    }
  }
  return out;
}

function initCandidates(card: RiskCard) {
  const owner = SIM_ACCOUNTS.owner;
  const args = { ...kitchenSinkArgs(owner), total_supply: "1000000000000000000000000000000", metadata: null };
  const names = ["new", "new_default_meta", "init", "initialize"].filter((m) => card.methods.includes(m));
  return names.flatMap((method) => [
    { method, args },
    { method, args: {} },
  ]);
}

async function wasmFile(wasm: Uint8Array): Promise<string> {
  const dir = join(tmpdir(), "near-xray");
  await mkdir(dir, { recursive: true });
  const file = join(dir, createHash("sha256").update(wasm).digest("hex").slice(0, 16) + ".wasm");
  await writeFile(file, wasm);
  return file;
}

export function buildSpec(card: RiskCard, wasmPath: string, scenarios: AttackScenario[]) {
  return {
    wasm_path: wasmPath,
    contract_id: card.account_id,
    init_candidates: initCandidates(card),
    deposit_method: findDeposit(card) ?? null,
    scenarios: scenarios.map((s) => s.scenario),
  };
}

/** Scan + suggested attacks, without running anything. */
export async function listAttacks(accountId: string, opts?: RpcOptions) {
  const { card } = await scanWithCode(accountId, opts);
  return { card, attacks: suggestAttacks(card) };
}

/**
 * Run the chosen scenarios (default: all suggested) against the contract's real
 * bytecode in near-contract-sim. Local only: nothing is sent to any network.
 */
/** Wrap custom scenario JSON (validated) as attacks. */
export function customAttacks(scenarios: unknown[]): AttackScenario[] {
  if (scenarios.length > 10) throw new InputError("At most 10 custom scenarios per run");
  return scenarios.map((raw) => {
    const scenario = validateScenario(raw);
    // Custom results are recognisable in every report (and never pass for a preset).
    if (!scenario.id.startsWith("custom:")) scenario.id = `custom:${scenario.id}`.slice(0, 96);
    return { id: scenario.id, name: scenario.name, kind: "custom" as const, description: scenario.description ?? "", scenario };
  });
}

/**
 * Run attacks in the sim. `scenarioIds` picks among the suggested presets
 * (all of them when omitted and no custom scenarios are given); `custom` adds
 * scenario JSON objects (validated here and again by the runner).
 */
export async function runAttacks(
  accountId: string,
  scenarioIds?: string[],
  opts?: RpcOptions & { custom?: unknown[] },
): Promise<{ card: RiskCard; report: AttackReport }> {
  const t0 = Date.now();
  const extra = customAttacks(opts?.custom ?? []);
  const { card, wasm } = await scanWithCode(accountId, opts);
  const all = suggestAttacks(card);
  let chosen = extra.length && !scenarioIds?.length ? [] : all;
  if (scenarioIds?.length) {
    const unknown = scenarioIds.filter((id) => !all.some((a) => a.id === id));
    if (unknown.length) throw new InputError(`Unknown scenario id(s) for ${card.account_id}: ${unknown.join(", ")}. Valid: ${all.map((a) => a.id).join(", ") || "(none)"}`);
    chosen = all.filter((a) => scenarioIds.includes(a.id));
  }
  chosen = [...chosen, ...extra];
  if (!chosen.length) {
    return {
      card,
      report: {
        account_id: card.account_id,
        code_hash: card.code_hash,
        engine: "near-contract-sim",
        init: { ok: false, tried: [] },
        victim_deposit: null,
        accounts: SIM_ACCOUNTS,
        results: [],
        summary: { held: 0, broken: 0, inconclusive: 0, not_applicable: 0, error: 0 },
        duration_ms: Date.now() - t0,
      },
    };
  }
  const raw = await runSpec<any>(buildSpec(card, await wasmFile(wasm), chosen));
  const results: AttackResult[] = raw.scenarios;
  const summary = { held: 0, broken: 0, inconclusive: 0, not_applicable: 0, error: 0 };
  for (const r of results) summary[r.status]++;
  return {
    card,
    report: {
      account_id: card.account_id,
      code_hash: card.code_hash,
      engine: raw.engine,
      init: raw.init,
      victim_deposit: raw.victim_deposit,
      accounts: raw.accounts,
      results,
      summary,
      duration_ms: Date.now() - t0,
    },
  };
}

/** The throwaway warm-up spec: one attack on the bundled clean vault. */
export async function warmupSpec() {
  const id = "clean-vault.xray-demo";
  const wasm = await readDemoWasm(id);
  const { card } = await scanWithCode(id);
  const one = suggestAttacks(card).filter((a) => a.id === "unauth:set_owner");
  return buildSpec(card, await wasmFile(wasm), one);
}

// --- verdict ----------------------------------------------------------------

export type Verdict = "safe" | "caution" | "dangerous";

export function verdictOf(card: RiskCard, report: AttackReport | null): { verdict: Verdict; reasons: string[] } {
  const reasons: string[] = [];
  const broken = report?.results.filter((r) => r.status === "broken") ?? [];
  for (const b of broken) reasons.push(`❌ BROKEN: ${b.name}: ${b.explanation}`);
  if (broken.length) return { verdict: "dangerous", reasons };

  // Only hand-written / spoken scenarios ran: they say nothing about the rest of the contract.
  if (report?.results.length && report.results.every((r) => r.id.startsWith("custom:"))) {
    const held = report.results.filter((r) => r.status === "held").length;
    return {
      verdict: "caution",
      reasons: [`Your custom scenario${report.results.length > 1 ? "s" : ""}: ${held} of ${report.results.length} held. That tests one idea, not the contract: run the suggested attacks for a verdict.`],
    };
  }

  if (card.risk.level !== "low") reasons.push(`Capability risk ${card.risk.level.toUpperCase()}: ${card.risk.reasons.slice(0, 3).join("; ")}`);
  const unsure = report?.results.filter((r) => r.status === "inconclusive" || r.status === "error") ?? [];
  if (unsure.length) reasons.push(`${unsure.length} attack(s) inconclusive: ${unsure.map((r) => r.name).join(", ")}`);
  if (!report) reasons.push("Attack simulation not run: capability scan only, so nothing was proven.");
  if (report && report.results.length === 0) reasons.push("No attack scenarios applied to this contract, so nothing was proven in simulation.");
  if (report && !report.init.ok && report.results.length) reasons.push("The contract could not be initialised in the sim with guessed arguments; results may be shallow.");
  const held = report?.results.filter((r) => r.status === "held").length ?? 0;
  if (reasons.length) return { verdict: "caution", reasons };
  return { verdict: "safe", reasons: [`Capability risk LOW and all ${held} attack(s) HELD.`] };
}

export { DEMO_CONTRACTS };
