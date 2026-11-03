/**
 * Speech-to-test: a typed plain-English sentence → scenario JSON → the same
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
import { suggestAttacks } from "./attacks.js";
import { ScenarioError, scenarioMethods, validateScenario, type Scenario } from "./scenario.js";

const MAX_ATTEMPTS = 2;

const LANGUAGE = `
SCENARIO JSON (one object):
{ "id": "custom:<short-slug>", "name": "<short title>", "description": "<the user's sentence>",
  "steps": [ ...steps ], "checks": [ ...checks ],
  "explain": { "held": "<one sentence if every check holds>", "rejected": "<optional: if the attack call was rejected>" } }

WORLD (fixed, local simulator, nothing touches a real network):
- The contract under test is already deployed with 50 NEAR and initialised by "owner" (owner.near).
- "victim" (victim.near) already deposited 20 NEAR into it when it has a payable deposit method.
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

RULES:
- Output ONLY the JSON object. Use ONLY method names from the contract's list below.
- Put the security property the user cares about in "checks" (a held check = the defence worked).
- Mark the attacker's call under test with "attack": true.
- Keep it minimal: the fewest steps that test the sentence.`;

function contractFacts(card: RiskCard): string {
  const privileged = card.notable_methods.filter((m) => m.privileged).map((m) => m.name);
  const caps = card.capabilities.filter((c) => c.severity !== "info").map((c) => c.id);
  return [
    `CONTRACT: ${card.account_id}`,
    `Exported methods: ${card.methods.join(", ")}`,
    privileged.length ? `Admin/privileged-looking methods: ${privileged.join(", ")}` : "",
    card.standards.length ? `Standards: ${card.standards.map((s) => s.id).join(", ")}` : "",
    caps.length ? `Capabilities from bytecode: ${caps.join(", ")}` : "",
  ]
    .filter(Boolean)
    .join("\n");
}

/** Two real presets for this contract, as worked examples of the format. */
function examples(card: RiskCard): string {
  const all = suggestAttacks(card);
  const pick = [all.find((a) => a.kind === "unauthorized_call"), all.find((a) => a.kind === "double_withdraw")].filter(Boolean);
  if (!pick.length) return "";
  const strip = (s: Scenario) => ({ ...s, steps: s.steps.map((st) => (st.op === "call" && st.args && Object.keys(st.args).length > 6 ? { ...st, args: { receiver_id: "attacker.near", "...": "only the fields the method needs" } } : st)) });
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
  return sc;
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
      content: `You translate a security tester's plain-English attack idea into a test scenario for NEAR X-Ray, which runs it against a NEAR smart contract in a local simulator. You output JSON only, never code.\n${LANGUAGE}\n\n${contractFacts(card)}\n\n${examples(card)}`,
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

