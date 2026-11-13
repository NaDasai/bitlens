/**
 * The scenario language, TypeScript side.
 *
 * One JSON object per attack. Canned presets (scenarios/presets/*.json) and
 * scenarios an LLM translates from plain English are the same data; the Rust
 * runner (runner/src/scenario.rs) executes them step by step in
 * near-contract-sim and validates them again. Scenarios are untrusted input:
 * everything is bounded, signers are the four sim roles, and every call
 * targets the contract under test.
 */
import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { z } from "zod";
import { InputError } from "./errors.js";

export const PRESET_DIR = fileURLToPath(new URL("../scenarios/presets/", import.meta.url));

// --- schema (mirrors runner/src/scenario.rs) ---------------------------------

const role = z.enum(["owner", "victim", "attacker", "user"]);
const acct = z.enum(["owner", "victim", "attacker", "user", "contract"]);
const outcome = z.enum(["broken", "inconclusive", "not_applicable"]);
const stepId = z.string().regex(/^[A-Za-z0-9_-]{1,32}$/, "step ids: 1-32 of A-Z a-z 0-9 _ -");
const methodName = z.string().regex(/^[A-Za-z0-9_]{1,64}$/, "a NEAR method name (letters, digits, _)");
const nearAmount = z.union([z.number().nonnegative().max(1000), z.string().regex(/^\d{0,4}(\.\d{1,24})?$/, 'NEAR as a decimal string, e.g. "5" or "0.5"')]);
const signedNear = z.union([z.number().min(-1000).max(1000), z.string().regex(/^-?\d{0,4}(\.\d{1,24})?$/, 'NEAR as a decimal string, e.g. "0" or "-1"')]);
const yocto = z.union([z.number().int().nonnegative(), z.string().regex(/^\d{1,28}$/)]);
const message = z.string().max(600).optional();
const otherwise = outcome.optional();

const callStep = z
  .object({
    op: z.literal("call"),
    id: stepId.optional(),
    as: role,
    method: methodName,
    args: z.record(z.string(), z.unknown()).optional(),
    deposit_near: nearAmount.optional(),
    deposit_yocto: yocto.optional(),
    guard_deposit: z.boolean().optional(),
    gas_tgas: z.union([z.number().int().min(1).max(300), z.literal("$tgas")]).optional(),
    async: z.boolean().optional(),
    hold_transfer_blocks: z.number().int().min(1).max(50).optional(),
    attack: z.boolean().optional(),
    harness: z.boolean().optional(),
    expect: z.enum(["success", "failure"]).optional(),
  })
  .strict();

const simpleSteps = [
  callStep,
  z.object({ op: z.literal("deposit"), id: stepId.optional(), as: role, method: methodName, near: nearAmount }).strict(),
  z
    .object({
      op: z.literal("control"),
      as: role,
      deposit_method: methodName,
      withdraw_method: methodName,
      amount_arg: methodName.optional(),
      near: nearAmount,
    })
    .strict(),
  z.object({ op: z.literal("settle") }).strict(),
  z.object({ op: z.literal("wait_for_receipt"), step: stepId, method: methodName }).strict(),
  z.object({ op: z.literal("wait_for_yield"), step: stepId }).strict(),
  z.object({ op: z.literal("advance_past_yield") }).strict(),
  z.object({ op: z.literal("advance_blocks"), blocks: z.number().int().min(1).max(5000) }).strict(),
  z.object({ op: z.literal("delete_account"), account: role, beneficiary: role }).strict(),
  z.object({ op: z.literal("create_account"), account: role, near: nearAmount }).strict(),
] as const;

const netCheck = (name: "net_at_most" | "net_at_least" | "net_equals") =>
  z.object({ check: z.literal(name), account: acct, near: signedNear, steps: z.array(stepId).max(20).optional(), else: otherwise, message }).strict();
const stepCheck = (name: string) => z.object({ check: z.literal(name), step: stepId, else: otherwise, message }).strict();

export const checkSchema = z.discriminatedUnion("check", [
  netCheck("net_at_most"),
  netCheck("net_at_least"),
  netCheck("net_equals"),
  z.object({ check: z.literal("unchanged"), what: z.enum(["code", "keys", "state"]), else: otherwise, message }).strict(),
  stepCheck("step_succeeded"),
  stepCheck("step_failed"),
  z.object({ check: z.literal("any_succeeded"), steps: z.array(stepId).min(1).max(20), else: otherwise, message }).strict(),
  stepCheck("transfer_failed"),
  stepCheck("callback_after_transfer"),
  stepCheck("completed"),
  stepCheck("yielded"),
]);

const sweepStep = z
  .object({
    op: z.literal("sweep"),
    gas_tgas: z.array(z.number().int().min(1).max(300)).min(1).max(20),
    steps: z.array(z.discriminatedUnion("op", simpleSteps)).min(1).max(20),
    checks: z.array(checkSchema).max(20).optional(),
    label: z.string().max(200).optional(),
  })
  .strict();

export const stepSchema = z.discriminatedUnion("op", [...simpleSteps, sweepStep]);

export const scenarioSchema = z
  .object({
    id: z.string().regex(/^[A-Za-z0-9_:-]{1,96}$/, "scenario id: 1-96 of A-Z a-z 0-9 _ - :"),
    name: z.string().min(1).max(160),
    description: z.string().max(1000).optional(),
    steps: z.array(stepSchema).min(1).max(40),
    checks: z.array(checkSchema).max(20).optional(),
    explain: z.object({ held: z.string().max(600).optional(), rejected: z.string().max(600).optional() }).strict().optional(),
  })
  .strict();

export type Scenario = z.infer<typeof scenarioSchema>;
export type ScenarioStep = z.infer<typeof stepSchema>;

export class ScenarioError extends InputError {
  constructor(message: string) {
    super(message, "SCENARIO_INVALID");
  }
}

/** Validate untrusted scenario JSON (schema + references). Throws ScenarioError with a readable reason. */
export function validateScenario(input: unknown): Scenario {
  const r = scenarioSchema.safeParse(input);
  if (!r.success) {
    const issues = r.error.issues.slice(0, 5).map((i) => `${i.path.join(".") || "(root)"}: ${i.message}`);
    throw new ScenarioError(`Invalid scenario: ${issues.join("; ")}`);
  }
  const sc = r.data;
  // References: step ids unique; checks and waits refer to earlier steps; "$tgas" only in sweeps.
  const ids: string[] = [];
  let total = 0;
  const walk = (steps: ScenarioStep[], scope: string[], inSweep: boolean) => {
    for (const st of steps) {
      total++;
      if ("id" in st && st.id) {
        if (scope.includes(st.id)) throw new ScenarioError(`Invalid scenario: duplicate step id "${st.id}"`);
        scope.push(st.id);
      }
      if (st.op === "call") {
        if (st.gas_tgas === "$tgas" && !inSweep) throw new ScenarioError('Invalid scenario: gas_tgas "$tgas" is only allowed inside a sweep');
        if (st.hold_transfer_blocks && !st.async) throw new ScenarioError("Invalid scenario: hold_transfer_blocks needs async: true");
        if (st.async && st.expect) throw new ScenarioError("Invalid scenario: expect is only for synchronous calls");
        if (st.deposit_near !== undefined && st.deposit_yocto !== undefined) throw new ScenarioError(`Invalid scenario: ${st.method}: give deposit_near or deposit_yocto, not both`);
        if (JSON.stringify(st.args ?? {}).length > 16 * 1024) throw new ScenarioError(`Invalid scenario: args of ${st.method} too large`);
      }
      if ((st.op === "wait_for_receipt" || st.op === "wait_for_yield") && !scope.includes(st.step))
        throw new ScenarioError(`Invalid scenario: ${st.op} refers to unknown step "${st.step}"`);
      if (st.op === "delete_account" && st.account === st.beneficiary) throw new ScenarioError("Invalid scenario: delete_account beneficiary must differ");
      if (st.op === "sweep") {
        const inner = [...scope];
        walk(st.steps as ScenarioStep[], inner, true);
        checkRefs(st.checks ?? [], inner);
      }
    }
  };
  walk(sc.steps, ids, false);
  if (total > 40) throw new ScenarioError(`Invalid scenario: too many steps (${total} > 40)`);
  checkRefs(sc.checks ?? [], ids);
  return sc;
}

function checkRefs(checks: z.infer<typeof checkSchema>[], ids: string[]) {
  for (const c of checks) {
    const refs = "step" in c ? [c.step] : "steps" in c && c.steps ? c.steps : [];
    for (const s of refs) if (!ids.includes(s)) throw new ScenarioError(`Invalid scenario: check ${c.check} refers to unknown step "${s}"`);
  }
}

/** Method names a scenario calls (to check them against the contract's exports). */
export function scenarioMethods(sc: Scenario): string[] {
  const out = new Set<string>();
  const walk = (steps: ScenarioStep[]) => {
    for (const st of steps) {
      if (st.op === "call" || st.op === "deposit") out.add(st.method);
      if (st.op === "control") (out.add(st.deposit_method), out.add(st.withdraw_method));
      if (st.op === "sweep") walk(st.steps as ScenarioStep[]);
    }
  };
  walk(sc.steps);
  return [...out];
}

// --- presets -------------------------------------------------------------------

export const PRESETS: Record<string, unknown> = Object.fromEntries(
  readdirSync(PRESET_DIR)
    .filter((f) => f.endsWith(".json"))
    .map((f) => [f.replace(/\.json$/, ""), JSON.parse(readFileSync(PRESET_DIR + f, "utf8"))]),
);

/**
 * Fill a preset's `{{name}}` placeholders. A string that is exactly "{{name}}"
 * becomes the parameter's value (objects too, e.g. args); elsewhere, including
 * object keys, the value is interpolated as text. Runtime placeholders the
 * runner fills ({net.attacker}, {error.step}) use single braces and are kept.
 */
export function fillPreset(name: string, params: Record<string, unknown>): Scenario {
  const tpl = PRESETS[name];
  if (!tpl) throw new Error(`no preset ${name}`);
  const sub = (s: string) =>
    s.replace(/\{\{(\w+)\}\}/g, (_m, k: string) => {
      if (!(k in params)) throw new Error(`preset ${name}: missing parameter ${k}`);
      return String(params[k]);
    });
  const fill = (v: unknown): unknown => {
    if (typeof v === "string") {
      const whole = /^\{\{(\w+)\}\}$/.exec(v);
      if (whole && whole[1] in params && typeof params[whole[1]] !== "string") return params[whole[1]];
      return sub(v);
    }
    if (Array.isArray(v)) return v.map(fill);
    if (v && typeof v === "object") return Object.fromEntries(Object.entries(v).map(([k, x]) => [sub(k), fill(x)]));
    return v;
  };
  return validateScenario(fill(tpl));
}
