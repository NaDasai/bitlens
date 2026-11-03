/**
 * Layer 1 — capability scan.
 *   address → view_code (RPC) → near-contract-parser (exports, NEP standards)
 *           + WebAssembly.Module.imports (host capabilities) → risk card.
 * Pure engine: no HTTP/MCP/CLI concerns live here.
 */
import { createHash } from "node:crypto";
// CJS bundle: use the default import (named-export detection misses `interfaces`).
import nearContractParser from "near-contract-parser";
const { parseContract, interfaces } = nearContractParser;
import { assertAccountId } from "./accountId.js";
import {
  classifyMethods,
  detectCapabilities,
  importProfile,
  type ImportProfile,
  type DetectedCapability,
  type NotableMethod,
  type WasmImport,
} from "./capabilities.js";
import { isDemoAccount, readDemoWasm } from "./demo.js";
import { networkOf, RpcError, viewAccessKeyList, viewCode, type RpcOptions } from "./rpc.js";

export interface Standard {
  id: string;
  name: string;
}

export type RiskLevel = "high" | "medium" | "low";

export interface AccessKeySummary {
  full_access: number;
  function_call: number;
  /** No full-access keys: code can only change through the contract's own logic. */
  locked: boolean;
}

export interface RiskCard {
  account_id: string;
  source: "rpc" | "file" | "demo";
  rpc_network: string | null;
  rpc_url: string | null;
  block_height: number | null;
  /** base58(sha256(wasm)) — same format as NEAR's code hash. */
  code_hash: string;
  /** True when our locally computed hash equals the hash returned by RPC. */
  code_hash_verified: boolean | null;
  code_size_bytes: number;
  methods: string[];
  standards: Standard[];
  capabilities: DetectedCapability[];
  notable_methods: NotableMethod[];
  access_keys: AccessKeySummary | null;
  host_imports: string[];
  import_profile: ImportProfile;
  risk: { level: RiskLevel; reasons: string[] };
  summary: string;
}

// --- helpers ---------------------------------------------------------------

const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
export function base58(bytes: Uint8Array): string {
  let n = BigInt("0x" + (Buffer.from(bytes).toString("hex") || "0"));
  let out = "";
  while (n > 0n) {
    out = B58[Number(n % 58n)] + out;
    n /= 58n;
  }
  for (const b of bytes) {
    if (b !== 0) break;
    out = "1" + out;
  }
  return out;
}

export function codeHash(wasm: Uint8Array): string {
  return base58(createHash("sha256").update(wasm).digest());
}

/** Method names that read as "move everything out". Combined with a strong transfer capability → HIGH. */
const DRAIN_RE = /drain|sweep|rescue|emergency_withdraw|withdraw_all/;

/**
 * Capability risk (Layer 1). Deliberately conservative about what raises the level:
 *   HIGH   — a strongly-evidenced critical capability (redeploy, add full-access key,
 *            delete account), or a drain-style method on a contract that can send NEAR.
 *   MEDIUM — someone outside the code can change it (full-access key on the account),
 *            or a strong non-transfer high capability (e.g. adds function-call keys).
 *   LOW    — otherwise. Sending NEAR + admin methods is what most contracts do; those
 *            methods are listed and are exactly what the Layer 2 attacks then test.
 */
function computeRisk(caps: DetectedCapability[], notable: NotableMethod[], keys: AccessKeySummary | null) {
  const reasons: string[] = [];
  const strong = caps.filter((c) => c.confidence === "strong");
  const canTransfer = strong.some((c) => c.id === "transfer");
  const drains = notable.filter((m) => DRAIN_RE.test(m.name.toLowerCase()));
  if (canTransfer)
    for (const m of drains)
      reasons.push(`🔴 \`${m.name}\` looks like a fund-drain method and the contract can send NEAR: if it is not owner-gated, anyone can empty it`);
  for (const c of strong)
    if (c.severity === "critical" || c.severity === "high")
      reasons.push(`${c.icon} ${c.label}${c.corroborated_by.length ? ` (via ${c.corroborated_by.slice(0, 3).join(", ")})` : ""}`);
  const priv = notable.filter((m) => m.privileged);
  if (priv.length)
    reasons.push(
      `⚠️ ${priv.length} privileged/admin-looking method(s) to verify: ${priv.slice(0, 8).map((m) => m.name).join(", ")}${priv.length > 8 ? ", …" : ""}`,
    );
  if (keys && keys.full_access > 0)
    reasons.push(`🔑 Account has ${keys.full_access} full-access key(s): the key holder can replace the code at any time`);
  const weak = caps.filter((c) => c.confidence === "weak" && c.severity !== "info");
  if (weak.length) reasons.push(`(${weak.length} more capability(ies) linked but not exposed by any method name — likely SDK boilerplate)`);

  let level: RiskLevel = "low";
  if (strong.some((c) => c.severity === "critical") || (canTransfer && drains.length)) level = "high";
  else if ((keys && keys.full_access > 0) || strong.some((c) => c.severity === "high" && c.id !== "transfer")) level = "medium";
  return { level, reasons };
}

function summarize(card: Omit<RiskCard, "summary">): string {
  const std = card.standards.length ? card.standards.map((s) => s.id.toUpperCase()).join("+") : "no NEP standards";
  const top = card.capabilities.filter((c) => c.severity !== "info" && c.confidence === "strong").map((c) => c.label.split(" (")[0].toLowerCase());
  const priv = card.notable_methods.filter((m) => m.privileged).length;
  return (
    `${card.account_id}: ${card.methods.length} methods, ${std}; ` +
    (top.length ? top.join("; ") : "no strongly-evidenced dangerous capabilities") +
    (priv ? `; ${priv} privileged-looking method(s)` : "") +
    `. Risk: ${card.risk.level.toUpperCase()}.`
  );
}

// --- core API --------------------------------------------------------------

export interface ScanWasmMeta {
  accountId: string;
  source: "rpc" | "file" | "demo";
  rpcUrl?: string | null;
  blockHeight?: number | null;
  rpcHash?: string | null;
  accessKeys?: AccessKeySummary | null;
}

/** Analyse raw WASM bytes. Used by `scan()` and directly for local files / demo contracts. */
export async function scanWasm(wasm: Uint8Array, meta: ScanWasmMeta): Promise<RiskCard> {
  let module: WebAssembly.Module;
  try {
    module = await WebAssembly.compile(wasm as Uint8Array<ArrayBuffer>);
  } catch (e: any) {
    throw new Error(`Contract code is not valid WebAssembly: ${e?.message ?? e}`);
  }
  // near-contract-parser is async — must be awaited, or you get an empty-looking object.
  const parsed = await parseContract(Buffer.from(wasm).toString("base64"));
  const imports = WebAssembly.Module.imports(module) as WasmImport[];

  const customMethods = parsed.methodNames.filter((m) => !(parsed.byMethod[m]?.length));
  const capabilities = detectCapabilities(imports, customMethods);
  const notable_methods = classifyMethods(parsed.methodNames, parsed.byMethod);
  const standards: Standard[] = parsed.probableInterfaces.map((id) => ({
    id,
    name: (interfaces as Record<string, { name: string }>)[id]?.name ?? id,
  }));
  const hash = codeHash(wasm);
  const access_keys = meta.accessKeys ?? null;

  const card: Omit<RiskCard, "summary"> = {
    account_id: meta.accountId,
    source: meta.source,
    rpc_network: meta.rpcUrl ? networkOf(meta.rpcUrl) : null,
    rpc_url: meta.rpcUrl ?? null,
    block_height: meta.blockHeight ?? null,
    code_hash: hash,
    code_hash_verified: meta.rpcHash ? meta.rpcHash === hash : null,
    code_size_bytes: wasm.byteLength,
    methods: [...parsed.methodNames].sort(),
    standards,
    capabilities,
    notable_methods,
    access_keys,
    host_imports: imports.filter((i) => i.module === "env").map((i) => i.name).sort(),
    import_profile: importProfile(imports),
    risk: computeRisk(capabilities, notable_methods, access_keys),
  };
  return { ...card, summary: summarize(card) };
}

export interface FetchedCode {
  accountId: string;
  wasm: Uint8Array;
  rpcUrl: string;
  rpcHash: string;
  blockHeight: number;
}

/** Fetch deployed bytecode from chain (read-only `view_code`). */
export async function fetchCode(accountId: string, opts?: RpcOptions): Promise<FetchedCode> {
  const id = assertAccountId(accountId);
  const { result, rpcUrl } = await viewCode(id, opts);
  return {
    accountId: id,
    wasm: new Uint8Array(Buffer.from(result.code_base64, "base64")),
    rpcUrl,
    rpcHash: result.hash,
    blockHeight: result.block_height,
  };
}

async function fetchKeySummary(accountId: string, opts?: RpcOptions): Promise<AccessKeySummary | null> {
  try {
    const { result } = await viewAccessKeyList(accountId, opts);
    const full = result.keys.filter((k) => k.access_key.permission === "FullAccess").length;
    return { full_access: full, function_call: result.keys.length - full, locked: full === 0 };
  } catch {
    return null; // non-fatal: the card is still useful without key info
  }
}

/** Address → risk card. `*.xray-demo` ids resolve to the bundled demo contracts. */
export async function scan(accountId: string, opts?: RpcOptions): Promise<RiskCard> {
  const id = assertAccountId(accountId);
  if (isDemoAccount(id)) return scanWasm(await readDemoWasm(id), { accountId: id, source: "demo" });
  const code = await fetchCode(id, opts);
  const accessKeys = await fetchKeySummary(code.accountId, { ...opts, rpcUrls: [code.rpcUrl] });
  return scanWasm(code.wasm, {
    accountId: code.accountId,
    source: "rpc",
    rpcUrl: code.rpcUrl,
    blockHeight: code.blockHeight,
    rpcHash: code.rpcHash,
    accessKeys,
  });
}

export { RpcError };
