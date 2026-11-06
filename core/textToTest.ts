/**
 * Text-to-test: a typed plain-English sentence → scenario JSON → the same
 * runner as the presets.
 *
 * The LLM (NEAR AI Cloud, falling back to OpenRouter; JSON mode) has one job: translate a sentence into a
 * valid scenario object for THIS contract. It never writes code. Its output is
 * untrusted: it is validated against the scenario schema, its method names are
 * checked against the contract's real exports, and the runner validates and
 * bounds it again before executing anything in the local sim.
 */
import { InputError } from "./errors.js";
import { chatJson, type ChatMessage } from "./llm.js";
import type { RiskCard } from "./scan.js";
import { kitchenSinkArgs, SIM_ACCOUNTS, suggestAttacks } from "./attacks.js";
import { argTypeProblems, formatSignature, standardArgs, standardSignatures } from "./standards.js";
import { ScenarioError, scenarioMethods, validateScenario, type Scenario } from "./scenario.js";

const MAX_ATTEMPTS = 2;

const STANDARD_ARG_KEYS = Object.keys(kitchenSinkArgs("x.near")).join(", ");

const LANGUAGE = `
SCENARIO JSON (one object):
{ "id": "custom:<short-slug>", "name": "<short title>", "description": "<the user's sentence>",
  "steps": [ ...steps ], "checks": [ ...checks ],
  "explain": { "held": "<one sentence if every check holds>", "rejected": "<optional: if the attack call was rejected>" } }

WORLD (fixed, local simulator, nothing touches a real network):
- The contract under test is already deployed with 50 NEAR and initialised by "owner" (owner.near).
- "victim" (victim.near) already deposited 20 NEAR into it when it has a payable deposit method.
  So never use "victim" for a deposit / request / withdraw flow: its 20 NEAR would hide lost funds.
  For "a user deposits / requests / gets its money back", use "user" (nothing deposited yet).
- Signers ("as") can ONLY be: "owner", "victim", "attacker", "user". Each starts with 100 NEAR.
- Every "call" goes to the contract under test. Args must be a JSON object; account ids in args are
  "owner.near", "victim.near", "attacker.near", "user.near". NEAR amounts inside args are yoctoNEAR
  strings (1 NEAR = "1000000000000000000000000").

STEPS ("op"):
- call: {"op":"call","id":"<id>","as":<role>,"method":"<exported method>","args":{...},
         "deposit_near":"1" | "deposit_yocto":"1", "gas_tgas":30, "async":true (submit; several async calls
         land in the same block; they are recorded at the next settle), "attack":true (mark THE call under
         test), "expect":"success"|"failure" (setup expectation; sync calls only)}
- deposit: {"op":"deposit","id":"<id>","as":<role>,"method":"<payable deposit method>","near":"5"}
- control: {"op":"control","as":<role>,"deposit_method":"..","withdraw_method":"..","amount_arg":"amount","near":"5"}
    proves deposit→withdraw works first; then calls with "guard_deposit":true attach the 1 yocto the
    contract may require.
- settle: {"op":"settle"}            wait_for_receipt: {"op":"wait_for_receipt","step":"<async id>","method":".."}
- wait_for_yield: {"op":"wait_for_yield","step":"<async id>"}   advance_past_yield: {"op":"advance_past_yield"}
- advance_blocks: {"op":"advance_blocks","blocks":100}
- delete_account / create_account: test-harness moves on the test accounts.
- sweep: {"op":"sweep","gas_tgas":[10,30,100],"steps":[...with "gas_tgas":"$tgas"],"checks":[...]}

CHECKS ("check"), evaluated in order after the steps; the first that fails decides the result
(default "broken"; set "else":"inconclusive" for setup preconditions):
- net_at_most / net_at_least / net_equals: {"check":..,"account":<role>|"contract","near":"0",
    "steps":["<ids>"] (optional: only these steps; default all)}  net NEAR the account gained (+) or lost (-).
    "The attacker must not profit" = {"check":"net_at_most","account":"attacker","near":"0"}.
- unchanged: {"check":"unchanged","what":"code"|"keys"|"state"}  vs. before the steps.
- step_succeeded / step_failed: {"check":..,"step":"<id>"}   any_succeeded: {"check":..,"steps":[..]}
- transfer_failed, callback_after_transfer, completed, yielded: {"check":..,"step":"<id>"}
- optional "message" on any check: text shown when it fails; may use {net.attacker}, {net.contract},
  {error.<step id>}, {status.<step id>}.

CHECK POLARITY (most important rule):
- Checks state what a SECURE contract guarantees. Every check passing = HELD (the defence worked);
  the first failing check = BROKEN (the attack worked). Write the checks a careful auditor would
  want to stay true, never the attacker's goal.
- WRONG for "the attacker calls admin_drain and keeps the money":
    {"check":"step_succeeded","step":"attack"}, {"check":"net_at_least","account":"attacker","near":"20"}
  (these pass when the drain works, so a real exploit would be reported as HELD).
- RIGHT: {"check":"net_at_most","account":"attacker","near":"0"} plus {"check":"unchanged","what":"state"}.
- Never use step_succeeded / any_succeeded on the attacker's call, and never net_at_least with a
  positive amount for "attacker", unless it is a setup precondition with "else":"inconclusive".
- "explain.held" describes the defence working; "explain.rejected" the attack call being refused.

PATTERNS:
- Unauthorised call ("a random account / the attacker calls X", "the attacker approves / sets /
  pauses / upgrades ..."): ONE call as "attacker" with "attack":true and no setup steps, even when
  the sentence mentions context ("its own payout"): the world already has a deposit and an owner.
  Checks: unchanged code, net_at_most attacker 0, unchanged keys, unchanged state.
- "unchanged" compares with the state before ALL steps, so never combine it with setup steps that
  change the contract (deposits, requests, other calls): those would count as the attack. With setup,
  check the attack call itself: {"check":"step_failed","step":"<attack id>"} and/or net_at_most with
  "steps":["<attack id>"].
- Never put "expect":"success" on a call the sentence says is not allowed.
- A call that yields (waits for an approval or answer) stays pending: it is not "succeeded" until it
  resolves. To check such a request was made, use {"check":"yielded","step":"<id>"}, not step_succeeded.
- Same-block double withdraw: control, deposit, two "async" withdraw calls, settle;
  checks: any_succeeded (else inconclusive), net_at_most attacker 0. EACH withdraw must ask for the
  whole deposit (args.amount = the deposit in yoctoNEAR), otherwise no double spend can show.
- Checks on money (net_*) are the property under test: never give them "else":"inconclusive".
  A "must not profit" check (net_at_most) must include the account's own deposits: leave out "steps".
- A request that yields / waits for an approval or answer and times out: control, deposit, the
  request as an "async" call, wait_for_yield, advance_past_yield, settle, then a withdraw;
  checks: yielded, completed, net_equals for the requester over ["<request id>","<withdraw id>"].

ARGUMENTS:
- Methods listed under STANDARD METHODS below have exact, known signatures: BitLens fills their
  arguments from the signature (accounts = the signer) and attaches the 1 yoctoNEAR they require.
- For every other method, argument names cannot be read from bytecode. BitLens fills every call with
  its standard argument set:
  ${STANDARD_ARG_KEYS}
  (account fields = the signer's account, amount = 1 NEAR, a valid tiny WASM in "code", the attacker's
  key in "public_key"). Only put the args you need to change in "args", usually just "amount"
  (e.g. {"amount":"5000000000000000000000000"}), or {} for none.
- Never invent byte payloads (WASM, keys, hex, base64): "code" and "public_key" are always replaced by
  BitLens's own valid values. Never guess other argument names.

RULES:
- Output ONLY the JSON object. Use ONLY method names from the contract's list below.
- In "message" texts, {net.<role>} already ends with "NEAR"; do not write "NEAR" after it.
- Mark the attacker's call under test with "attack": true.
- When an EXAMPLE below already tests the sentence's idea, reuse its steps and checks.
- Keep it minimal: the fewest steps that test the sentence.`;

/**
 * Fill each call's args with the standard argument set the presets use (the
 * model cannot know argument names from bytecode); the model's own args win,
 * except the byte payloads "code" and "public_key", which are always BitLens's.
 */
function withStandardArgs(sc: Scenario, card: RiskCard): Scenario {
  const sigs = new Map(standardSignatures(card).map((s) => [s.method, s]));
  const fill = (steps: any[]): any[] =>
    steps.map((st) => {
      if (st.op === "sweep") return { ...st, steps: fill(st.steps) };
      if (st.op !== "call") return st;
      const who = SIM_ACCOUNTS[st.as as keyof typeof SIM_ACCOUNTS];
      const sig = sigs.get(st.method);
      if (sig) {
        // A NEP standard method: its exact signature, not the generic argument set.
        const noDeposit = st.deposit_near === undefined && st.deposit_yocto === undefined && !st.guard_deposit;
        return { ...st, args: { ...standardArgs(sig, who), ...(st.args ?? {}) }, ...(sig.deposit === "1 yocto" && noDeposit ? { deposit_yocto: "1" } : {}) };
      }
      const std = kitchenSinkArgs(who);
      // Byte payloads always come from BitLens (a valid tiny WASM, the attacker's key): a model can't produce valid ones.
      return { ...st, args: { ...std, ...(st.args ?? {}), code: std.code, public_key: std.public_key } };
    });
  return validateScenario({ ...sc, steps: fill(sc.steps as any[]) });
}

function contractFacts(card: RiskCard): string {
  const privileged = card.notable_methods.filter((m) => m.privileged).map((m) => m.name);
  const caps = card.capabilities.filter((c) => c.severity !== "info").map((c) => c.id);
  return [
    `CONTRACT: ${card.account_id}`,
    `Exported methods: ${card.methods.join(", ")}`,
    privileged.length ? `Admin/privileged-looking methods: ${privileged.join(", ")}` : "",
    card.standards.length ? `Standards: ${card.standards.map((s) => s.id).join(", ")}` : "",
    standardSignatures(card).length
      ? `STANDARD METHODS (exact signatures from the NEP specs; use these argument names and JSON types; FT amounts are token units as strings, not NEAR):\n${standardSignatures(card).map((s) => "  " + formatSignature(s)).join("\n")}`
      : "",
    caps.length ? `Capabilities from bytecode: ${caps.join(", ")}` : "",
  ]
    .filter(Boolean)
    .join("\n");
}

function onlyChanged(args: Record<string, unknown>, as: string) {
  const std: Record<string, unknown> = kitchenSinkArgs(SIM_ACCOUNTS[as as keyof typeof SIM_ACCOUNTS]);
  return Object.fromEntries(Object.entries(args).filter(([k, v]) => JSON.stringify(std[k]) !== JSON.stringify(v)));
}

/** Up to three real presets for this contract, as worked examples of the format. */
function examples(card: RiskCard): string {
  const all = suggestAttacks(card);
  const pick = (["unauthorized_call", "double_withdraw", "yield_timeout"] as const).map((k) => all.find((a) => a.kind === k)).filter(Boolean);
  if (!pick.length) return "";
  // Standard args are filled in automatically, so the examples show only what differs.
  const strip = (s: Scenario) => ({ ...s, steps: s.steps.map((st) => (st.op === "call" && st.args && Object.keys(st.args).length > 6 ? { ...st, args: onlyChanged(st.args, st.as) } : st)) });
  return "EXAMPLES (built-in presets for this contract):\n" + pick.map((a) => JSON.stringify(strip(a!.scenario))).join("\n");
}

function slug(s: string) {
  return s.toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_|_$/g, "").slice(0, 40) || "scenario";
}

/** Normalise what the model returned (ids, description) and check it against the contract. */
function finalise(raw: unknown, sentence: string, card: RiskCard): Scenario {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) throw new ScenarioError("Invalid scenario: expected one JSON object");
  const obj = { ...(raw as Record<string, unknown>) };
  const base = typeof obj.id === "string" ? obj.id.replace(/^custom:/, "") : String(obj.name ?? sentence);
  obj.id = `custom:${slug(base)}`;
  obj.description = sentence.slice(0, 1000);
  if (typeof obj.name !== "string" || !obj.name.trim()) obj.name = sentence.slice(0, 120);
  const sc = validateScenario(obj);
  const unknown = scenarioMethods(sc).filter((m) => !card.methods.includes(m) && m !== "storage_deposit");
  if (unknown.length) throw new ScenarioError(`Invalid scenario: ${unknown.join(", ")} is not a method of ${card.account_id}. Its methods are: ${card.methods.join(", ")}`);
  if (!(sc.checks?.length)) throw new ScenarioError("Invalid scenario: it has no checks, so nothing would be tested. Add the property that must hold as a check.");
  const inverted = invertedChecks(sc);
  if (inverted.length)
    throw new ScenarioError(
      `Invalid scenario: ${inverted.join("; ")}. Checks must state what a SECURE contract guarantees (all pass = HELD), not that the attack succeeded; e.g. {"check":"net_at_most","account":"attacker","near":"0"}.`,
    );
  const victimFlow = (sc.steps as any[]).filter((st) => (st.op === "deposit" || st.op === "control") && st.as === "victim");
  if (victimFlow.length)
    throw new ScenarioError(
      `Invalid scenario: "victim" already has 20 NEAR deposited, so a deposit/withdraw flow signed by it (${victimFlow.map((st) => st.id ?? st.op).join(", ")}) cannot show whether funds were lost. Use "user" (nothing deposited yet) for that flow.`,
    );
  const misattributed = [...unchangedWithSetup(sc), ...cannotShowBug(sc)];
  if (misattributed.length) throw new ScenarioError(`Invalid scenario: ${misattributed.join("; ")}.`);
  const sigs = new Map(standardSignatures(card).map((s) => [s.method, s]));
  const typeProblems = (sc.steps as any[]).flatMap((st) => (st.op === "call" && sigs.has(st.method) ? argTypeProblems(sigs.get(st.method)!, st.args) : []));
  if (typeProblems.length) throw new ScenarioError(`Invalid scenario: ${typeProblems.join("; ")}`);
  return withStandardArgs(sc, card);
}

/**
 * Checks with the polarity backwards: they pass when the attack works, so a
 * real exploit would be reported as HELD. Setup preconditions that fall back
 * to INCONCLUSIVE are fine.
 */
function invertedChecks(sc: Scenario): string[] {
  const attackSteps = new Set<string>();
  const walk = (steps: Scenario["steps"]) => {
    for (const st of steps as any[]) {
      if (st.op === "call" && st.attack && st.id) attackSteps.add(st.id);
      if (st.op === "sweep") walk(st.steps);
    }
  };
  walk(sc.steps);
  const out: string[] = [];
  const all = [...(sc.checks ?? []), ...(sc.steps as any[]).filter((s) => s.op === "sweep").flatMap((s) => s.checks ?? [])] as any[];
  for (const c of all) {
    if (c.else && c.else !== "broken") continue;
    if (c.check === "step_succeeded" && attackSteps.has(c.step)) out.push(`"step_succeeded" on the attack call "${c.step}" passes when the attack works`);
    if (c.check === "any_succeeded" && (c.steps as string[]).length === 1 && attackSteps.has(c.steps[0])) out.push(`"any_succeeded" on only the attack call passes when the attack works`);
    if (c.check === "net_at_least" && c.account === "attacker" && !String(c.near).trim().startsWith("-") && Number(c.near) > 0)
      out.push(`"net_at_least" ${c.near} NEAR for the attacker passes when the attacker profits`);
  }
  return out;
}

const YOCTO = 10n ** 24n;
function nearToYocto(v: unknown): bigint {
  const [w, f = ""] = String(v).split(".");
  return BigInt(w || "0") * YOCTO + BigInt((f + "0".repeat(24)).slice(0, 24));
}

/**
 * Two problems that make a scenario unable to show the bug it is about:
 * a money check that falls back to INCONCLUSIVE (hides real losses), and a
 * same-block double withdraw whose calls together ask for no more than was
 * deposited (a double spend could never show).
 */
function cannotShowBug(sc: Scenario): string[] {
  const out: string[] = [];
  for (const c of (sc.checks ?? []) as any[])
    if (c.check.startsWith("net_") && c.else && c.else !== "broken")
      out.push(`"${c.check}" for ${c.account} has "else":"${c.else}", which would hide a real loss: money checks are the property under test, so drop the "else"`);
  const steps = sc.steps as any[];
  for (const c of (sc.checks ?? []) as any[]) {
    if (c.check !== "net_at_most" || !c.steps) continue;
    const own = steps.filter((st) => st.op === "deposit" && st.as === c.account && st.id && !c.steps.includes(st.id)).map((st) => st.id);
    if (own.length)
      out.push(`"net_at_most" for ${c.account} is limited to steps ${JSON.stringify(c.steps)} and leaves out its own deposit (${own.join(", ")}), so getting its own money back would look like a profit: drop "steps" or include ${own.join(", ")}`);
  }
  const deposited = steps.filter((st) => st.op === "deposit").reduce((sum, st) => sum + nearToYocto(st.near), 0n);
  const asyncBy = new Map<string, any[]>();
  for (const st of steps) if (st.op === "call" && st.async) asyncBy.set(st.method, [...(asyncBy.get(st.method) ?? []), st]);
  for (const [method, calls] of asyncBy) {
    if (calls.length < 2 || deposited === 0n) continue;
    const amounts = calls.map((st) => (st.args?.amount !== undefined ? BigInt(String(st.args.amount)) : YOCTO)); // standard amount: 1 NEAR
    if (amounts.every((a) => a < deposited) && amounts.reduce((x, y) => x + y, 0n) <= deposited)
      out.push(
        `the ${calls.length} same-block \`${method}\` calls ask for ${amounts.map((a) => `${Number(a / 10n ** 20n) / 10000} NEAR`).join(" + ")}, no more than the deposit, so a double spend could never show: set each call's args.amount to the whole deposit ("${deposited}")`,
      );
  }
  return out;
}

/**
 * "unchanged" compares with the state before every step, so with setup steps
 * that change the contract it would blame them on the attack and report a
 * false BROKEN.
 */
function unchangedWithSetup(sc: Scenario): string[] {
  const changes = new Set(["call", "deposit", "control", "create_account", "delete_account"]);
  const setup = (sc.steps as any[]).filter((st) => changes.has(st.op) && !(st.op === "call" && st.attack));
  if (!setup.length) return [];
  const bad = (sc.checks ?? []).filter((c: any) => c.check === "unchanged" && (!c.else || c.else === "broken"));
  if (!bad.length) return [];
  const ids = setup.map((st) => st.id ?? st.op).join(", ");
  return [
    `"unchanged" ${bad.map((c: any) => c.what).join("/")} compares with the state before ALL steps, so your setup steps (${ids}) would be counted as the attack. Either drop the setup and make the attack call directly, or replace "unchanged" with checks on the attack call itself, e.g. {"check":"step_failed","step":"<attack id>"} or net_at_most with "steps":["<attack id>"]`,
  ];
}

export interface Translation {
  scenario: Scenario;
  model: string;
  provider: string;
  attempts: number;
  /** Set when the primary provider failed and another one answered. */
  fallback_from?: string[];
}

/** Plain-English sentence → validated scenario JSON for this contract. */
export async function translateToScenario(sentence: unknown, card: RiskCard): Promise<Translation> {
  if (typeof sentence !== "string" || sentence.trim().length < 3) throw new InputError("Describe the attack in a sentence (3-1000 characters).");
  const text = sentence.trim().slice(0, 1000);
  const messages: ChatMessage[] = [
    {
      role: "system",
      content: `You translate a security tester's plain-English attack idea into a test scenario for BitLens, which runs it against a NEAR smart contract in a local simulator. You output JSON only, never code.\n${LANGUAGE}\n\n${contractFacts(card)}\n\n${examples(card)}`,
    },
    { role: "user", content: text },
  ];
  let lastError = "";
  let model = "";
  let provider = "";
  let fallback: string[] | undefined;
  for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
    // The repair round stays on the provider that answered the first time.
    const res = await chatJson(messages, { prefer: provider || undefined });
    model = res.model;
    provider = res.provider;
    fallback ??= res.fallback_from;
    try {
      if (res.json === null) throw new ScenarioError("Invalid scenario: the reply was not a JSON object");
      return { scenario: finalise(res.json, text, card), model, provider, attempts: attempt, ...(fallback ? { fallback_from: fallback } : {}) };
    } catch (e: any) {
      if (!(e instanceof ScenarioError)) throw e;
      lastError = e.message;
      messages.push({ role: "assistant", content: res.raw.slice(0, 8000) });
      messages.push({ role: "user", content: `That JSON was rejected: ${lastError}\nReturn the corrected scenario as one JSON object only.` });
    }
  }
  throw new ScenarioError(`${provider} (${model}) did not produce a valid scenario after ${MAX_ATTEMPTS} attempts. Last problem: ${lastError.replace(/^Invalid scenario: /, "")}`);
}

