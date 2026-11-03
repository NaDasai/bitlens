/** Shared engine. HTTP server, CLI and MCP server are thin wrappers over these exports. */
export { scan, scanWasm, fetchCode, codeHash, type RiskCard, type RiskLevel, type Standard } from "./scan.js";
export { assertAccountId, isValidAccountId, InvalidAccountIdError } from "./accountId.js";
export { RpcError, DEFAULT_RPC_URLS, type RpcOptions } from "./rpc.js";
export { CAPABILITY_RULES, PRIVILEGED_PATTERNS, type DetectedCapability, type NotableMethod } from "./capabilities.js";
export { toErrorPayload, type ErrorPayload } from "./errors.js";
export { DEMO_CONTRACTS, DEMO_SUFFIX, isDemoAccount, readDemoWasm } from "./demo.js";
