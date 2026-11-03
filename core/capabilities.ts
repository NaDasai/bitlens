/**
 * Capability detection from WASM *imports* (what host functions the contract
 * can call) plus method-name heuristics on *exports* (what anyone can call).
 *
 * Imports are reliable: a NEAR contract cannot perform an action the runtime
 * does not give it, and every action is a named host import in module "env".
 * If the import is absent, the contract cannot do it — full stop.
 */

/** Read-only-looking names — skipped by name heuristics to cut noise (`get_owner` is harmless). */
const VIEW_LIKE = /(^|_)(get|view|is|has)_|(_of|_view|_info|_metadata)$/;

export type Severity = "critical" | "high" | "medium" | "info";

export interface CapabilityRule {
  id: string;
  /** Host import names (module "env") that grant this capability. */
  imports: string[];
  severity: Severity;
  icon: string;
  label: string;
  why: string;
  /** Method names that corroborate this capability is reachable from a public entry point. */
  corroborate?: RegExp;
}

export const CAPABILITY_RULES: CapabilityRule[] = [
  {
    id: "add_full_access_key",
    imports: ["promise_batch_action_add_key_with_full_access"],
    severity: "critical",
    icon: "🔴",
    label: "Can add full-access keys (can hand over control of an account)",
    why: "A full-access key can do anything on the account it is added to: drain NEAR, redeploy code, delete the account.",
    corroborate: /full_access|access_key|add_key|attach_key|owner_key/,
  },
  {
    id: "deploy_contract",
    imports: [
      "promise_batch_action_deploy_contract",
      "promise_batch_action_deploy_global_contract",
      "promise_batch_action_deploy_global_contract_by_account_id",
      "promise_batch_action_use_global_contract",
      "promise_batch_action_use_global_contract_by_account_id",
    ],
    severity: "critical",
    icon: "🔴",
    label: "Can redeploy contract code (logic can change later)",
    why: "The code you are reviewing today can be replaced by different code tomorrow, by whoever is allowed to trigger the upgrade.",
    corroborate: /deploy|upgrade|stage_code|update_contract|update_code/,
  },
  {
    id: "delete_account",
    imports: ["promise_batch_action_delete_account"],
    severity: "critical",
    icon: "🔴",
    label: "Can delete an account (destructive)",
    why: "Deleting an account wipes its state and sends the remaining NEAR to a beneficiary.",
    corroborate: /delete_account|self_destruct|selfdestruct|destroy|close_account|delete_self/,
  },
  {
    id: "add_function_call_key",
    imports: ["promise_batch_action_add_key_with_function_call"],
    severity: "high",
    icon: "🟠",
    label: "Can add function-call access keys",
    why: "A function-call key lets its holder call (limited) methods and spend gas allowance on the account's behalf.",
    corroborate: /key/,
  },
  {
    id: "delete_key",
    imports: ["promise_batch_action_delete_key"],
    severity: "medium",
    icon: "🟠",
    label: "Can delete access keys",
    why: "Can remove keys — including locking out the legitimate owner of an account it controls.",
    corroborate: /delete_key|remove_\w*key|revoke_\w*key/,
  },
  {
    id: "transfer",
    imports: ["promise_batch_action_transfer"],
    severity: "high",
    icon: "💰",
    label: "Can send NEAR out",
    why: "The contract can transfer native NEAR from its own balance. Who can trigger that is what the attack tests check.",
    corroborate: /withdraw|send|payout|claim|drain|refund|pay|transfer_near|near_transfer/,
  },
  {
    id: "stake",
    imports: ["promise_batch_action_stake"],
    severity: "medium",
    icon: "⚠️",
    label: "Can stake NEAR",
    why: "Can lock the contract's NEAR into staking with a validator.",
    corroborate: /stake|staking|delegat/,
  },
  {
    id: "cross_contract_call",
    imports: ["promise_batch_action_function_call", "promise_batch_action_function_call_weight", "promise_create"],
    severity: "info",
    icon: "🔗",
    label: "Makes cross-contract calls",
    why: "Calls other contracts asynchronously — state can change between the call and its callback (re-entrancy window).",
  },
  {
    id: "callbacks",
    imports: ["promise_then", "promise_results_count", "promise_result"],
    severity: "info",
    icon: "↩️",
    label: "Uses callbacks / reads promise results",
    why: "Has async callback logic; a callback that mishandles a failed promise can lose or double-count funds.",
  },
  {
    id: "yield_resume",
    imports: ["promise_yield_create", "promise_yield_resume"],
    severity: "info",
    icon: "⏳",
    label: "Uses yield/resume (pauses execution awaiting an external signal)",
    why: "Yielded receipts time out after a fixed number of blocks; the timeout path must handle funds correctly.",
  },
  {
    id: "create_account",
    imports: ["promise_batch_action_create_account"],
    severity: "info",
    icon: "🆕",
    label: "Can create sub-accounts",
    why: "Can create new accounts (often combined with deploy/add-key to set them up).",
  },
];

export type Confidence = "strong" | "weak";

export interface DetectedCapability {
  id: string;
  severity: Severity;
  icon: string;
  label: string;
  why: string;
  /** The exact host imports that triggered this capability. */
  evidence: string[];
  /**
   * strong: the import is present AND (the module links imports selectively, or
   *         a public method name corroborates it).
   * weak:   the module links nearly every Promise action (near-sdk does this
   *         whenever any Promise is built), and no public method name points at
   *         this one — the code *can* emit it, but likely only via SDK
   *         boilerplate. Shown, but does not by itself raise the risk level.
   */
  confidence: Confidence;
  /** Public methods whose names corroborate the capability. */
  corroborated_by: string[];
}

export interface WasmImport {
  module: string;
  name: string;
  kind: string;
}

/** Promise batch actions. A module importing most of them is SDK bulk-linking, not intent. */
const ACTION_IMPORTS = [
  "promise_batch_action_create_account",
  "promise_batch_action_deploy_contract",
  "promise_batch_action_function_call",
  "promise_batch_action_transfer",
  "promise_batch_action_stake",
  "promise_batch_action_add_key_with_full_access",
  "promise_batch_action_add_key_with_function_call",
  "promise_batch_action_delete_key",
  "promise_batch_action_delete_account",
];
export const BULK_LINK_THRESHOLD = 7;

export interface ImportProfile {
  /** "bulk": links >= BULK_LINK_THRESHOLD of the 9 classic Promise actions. */
  kind: "bulk" | "selective";
  action_imports: number;
  note: string;
}

export function importProfile(imports: WasmImport[]): ImportProfile {
  const env = new Set(imports.filter((i) => i.module === "env").map((i) => i.name));
  const n = ACTION_IMPORTS.filter((a) => env.has(a)).length;
  const bulk = n >= BULK_LINK_THRESHOLD;
  return {
    kind: bulk ? "bulk" : "selective",
    action_imports: n,
    note: bulk
      ? `Links ${n}/9 Promise action host functions — typical of near-sdk, which links every action whenever any Promise is built. Capabilities without a corroborating public method are marked "weak".`
      : `Links ${n}/9 Promise action host functions selectively — each one present is likely intentional.`,
  };
}

/**
 * @param customMethods public methods that are NOT part of a detected NEP standard
 *   (standard methods have known semantics, e.g. `ft_transfer` moves tokens, not NEAR).
 */
export function detectCapabilities(imports: WasmImport[], customMethods: string[] = []): DetectedCapability[] {
  const envFuncs = new Set(imports.filter((i) => i.module === "env" && i.kind === "function").map((i) => i.name));
  const bulk = importProfile(imports).kind === "bulk";
  const out: DetectedCapability[] = [];
  for (const rule of CAPABILITY_RULES) {
    const evidence = rule.imports.filter((n) => envFuncs.has(n));
    if (!evidence.length) continue;
    const { imports: _i, corroborate, ...rest } = rule;
    const corroborated_by = corroborate
      ? customMethods.filter((m) => !VIEW_LIKE.test(m.toLowerCase()) && corroborate.test(m.toLowerCase()))
      : [];
    const confidence: Confidence = !bulk || rule.severity === "info" || corroborated_by.length ? "strong" : "weak";
    out.push({ ...rest, evidence, confidence, corroborated_by });
  }
  return out;
}

// ---------------------------------------------------------------------------
// Method-name heuristics
// ---------------------------------------------------------------------------

/** The brief's list, plus a few high-signal additions (deploy, keys, roles, supply). */
export const PRIVILEGED_PATTERNS = [
  "owner", "admin", "upgrade", "migrate", "set_", "withdraw", "drain", "pause", "self",
  "deploy", "_key", "grant", "revoke", "mint", "burn",
];


export interface NotableMethod {
  name: string;
  /** Privileged-looking patterns the name matched (empty = custom but not obviously privileged). */
  matched: string[];
  privileged: boolean;
  note: string;
}

/**
 * Notable = not part of any detected NEP standard (custom logic). Of those,
 * names matching privileged patterns get flagged ⚠️ "check who can call it".
 * Standard methods (e.g. NEP-145 `storage_withdraw`) have well-known
 * semantics and are not flagged by name.
 */
export function classifyMethods(methodNames: string[], byMethod: Record<string, string[]>): NotableMethod[] {
  const out: NotableMethod[] = [];
  for (const name of methodNames) {
    if ((byMethod[name] ?? []).length > 0) continue; // standard method
    const lower = name.toLowerCase();
    const matched = VIEW_LIKE.test(lower) ? [] : PRIVILEGED_PATTERNS.filter((p) => lower.includes(p));
    out.push({
      name,
      matched,
      privileged: matched.length > 0,
      note: matched.length
        ? `⚠️ privileged/admin-looking method (matches ${matched.map((m) => `"${m}"`).join(", ")}) — check who can call it`
        : "custom (non-standard) method",
    });
  }
  // Privileged first, then alphabetical.
  return out.sort((a, b) => Number(b.privileged) - Number(a.privileged) || a.name.localeCompare(b.name));
}
