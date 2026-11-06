/** Shared engine. HTTP server, CLI and MCP server are thin wrappers over these exports. */
export { scan, scanWasm, fetchCode, codeHash, type RiskCard, type RiskLevel, type Standard } from "./scan.js";
export { assertAccountId, isValidAccountId, InvalidAccountIdError } from "./accountId.js";
export { RpcError, DEFAULT_RPC_URLS, type RpcOptions } from "./rpc.js";
export { CAPABILITY_RULES, PRIVILEGED_PATTERNS, type DetectedCapability, type NotableMethod } from "./capabilities.js";
export { toErrorPayload, InputError, UpstreamError, type ErrorPayload } from "./errors.js";
export { DEMO_CONTRACTS, DEMO_SUFFIX, isDemoAccount, readDemoWasm } from "./demo.js";
export {
  suggestAttacks,
  listAttacks,
  runAttacks,
  customAttacks,
  verdictOf,
  warmupSpec,
  kitchenSinkArgs,
  SIM_ACCOUNTS,
  type AttackScenario,
  type AttackResult,
  type AttackReport,
  type AttackStatus,
  type Verdict,
} from "./attacks.js";
export { startWarmup, engineStatus, warmReady, runSpec, EngineNotReadyError, RUNNER_BIN } from "./engine.js";
export { scanWithCode, base58 } from "./scan.js";
export { validateScenario, fillPreset, scenarioMethods, PRESETS, ScenarioError, scenarioSchema, type Scenario } from "./scenario.js";
export { translateToScenario, type Translation } from "./textToTest.js";
export { standardSignatures, standardArgs, formatSignature, argTypeProblems, type StandardSignature } from "./standards.js";
export { llmStatus, llmProviders, chatJson, resetLlmCooldown, DEFAULT_NEAR_AI_MODEL, DEFAULT_OPEN_ROUTER_MODEL } from "./llm.js";
