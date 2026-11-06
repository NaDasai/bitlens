/**
 * Exact signatures of NEP standard methods. Bytecode carries no argument
 * names, but a detected standard (NEP-141, 145, 148, 171, 177, 178, 199, 330)
 * has a public, fixed interface: argument names and JSON types come from
 * near-contract-parser's interface table, and the attached deposits each
 * method requires come from the NEP specifications.
 */
// CJS bundle: use the default import (named-export detection misses `interfaces`).
import nearContractParser from "near-contract-parser";
const { interfaces } = nearContractParser;
import type { RiskCard } from "./scan.js";

type JsonType = "string" | "number" | "object" | "array" | "boolean" | "null";

export interface StandardArg {
  name: string;
  types: JsonType[];
}

export interface StandardSignature {
  method: string;
  /** e.g. "nep141" */
  standard: string;
  standard_name: string;
  args: StandardArg[];
  /** What the NEP requires to be attached: exactly 1 yoctoNEAR, a storage deposit, or nothing. */
  deposit: "1 yocto" | "storage deposit" | null;
}

/**
 * Attached deposits required by the NEP specs. "1 yocto" methods assert
 * exactly 1 yoctoNEAR (a full-access-key confirmation); "storage deposit"
 * methods are payable and need enough NEAR to cover storage.
 */
const DEPOSITS: Record<string, StandardSignature["deposit"]> = {
  // NEP-141
  ft_transfer: "1 yocto",
  ft_transfer_call: "1 yocto",
  // NEP-145
  storage_deposit: "storage deposit",
  storage_withdraw: "1 yocto",
  storage_unregister: "1 yocto",
  // NEP-171
  nft_transfer: "1 yocto",
  nft_transfer_call: "1 yocto",
  // NEP-178
  nft_approve: "storage deposit",
  nft_revoke: "1 yocto",
  nft_revoke_all: "1 yocto",
};

const all = Object.values(interfaces as unknown as Record<string, { id: string; name: string; methods: { name: string; args: { name: string; type: JsonType | JsonType[] }[] }[] }>);

/** Signatures of every method of the standards detected on this contract that it actually exports. */
export function standardSignatures(card: Pick<RiskCard, "standards" | "methods">): StandardSignature[] {
  const detected = new Set(card.standards.map((s) => s.id));
  const exported = new Set(card.methods);
  const out: StandardSignature[] = [];
  const seen = new Set<string>();
  for (const iface of all) {
    if (!detected.has(iface.id)) continue;
    for (const m of iface.methods) {
      if (!exported.has(m.name) || seen.has(m.name)) continue;
      seen.add(m.name);
      out.push({
        method: m.name,
        standard: iface.id,
        standard_name: iface.name,
        args: m.args.map((a) => ({ name: a.name, types: Array.isArray(a.type) ? a.type : [a.type] })),
        deposit: DEPOSITS[m.name] ?? null,
      });
    }
  }
  return out;
}

/** One line per method, for the LLM prompt and for people. */
export function formatSignature(s: StandardSignature): string {
  const args = s.args.map((a) => `${a.name}: ${a.types.join("|")}`).join(", ");
  const dep = s.deposit === "1 yocto" ? " · attach exactly 1 yoctoNEAR" : s.deposit === "storage deposit" ? " · payable (attach a storage deposit)" : "";
  return `${s.method}(${args}) [${s.standard.toUpperCase()}]${dep}`;
}

/**
 * Arguments that match a standard method's signature, pointing at `who`
 * (the signer) wherever an account goes. Optional (nullable) arguments are null.
 */
export function standardArgs(sig: StandardSignature, who: string): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const a of sig.args) {
    if (a.types.includes("null")) out[a.name] = null;
    else if (a.types.includes("string")) out[a.name] = /(_id$|^account)/.test(a.name) && a.name !== "token_id" ? who : a.name === "amount" ? "1" : a.name === "token_id" ? "0" : "";
    else if (a.types.includes("number")) out[a.name] = 0;
    else if (a.types.includes("boolean")) out[a.name] = false;
    else if (a.types.includes("array")) out[a.name] = [];
    else if (a.types.includes("object")) out[a.name] = {};
  }
  return out;
}

const jsonTypeOf = (v: unknown): JsonType =>
  v === null ? "null" : Array.isArray(v) ? "array" : typeof v === "number" ? "number" : typeof v === "boolean" ? "boolean" : typeof v === "object" ? "object" : "string";

/** Arguments whose JSON type does not match the standard signature, as readable problems. */
export function argTypeProblems(sig: StandardSignature, args: Record<string, unknown> | undefined): string[] {
  if (!args) return [];
  const out: string[] = [];
  for (const a of sig.args) {
    if (!(a.name in args)) continue;
    const got = jsonTypeOf(args[a.name]);
    if (!a.types.includes(got)) out.push(`${sig.method}.${a.name} must be ${a.types.join(" or ")} (${sig.standard.toUpperCase()}), not ${got}`);
  }
  return out;
}
