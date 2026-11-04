/**
 * The Rust attack runner (runner/, over near-contract-sim), seen from Node.
 *
 * - `runSpec(spec)` shells out to the compiled `bitlens-runner` binary.
 * - `startWarmup()` builds the runner if needed (the first build compiles
 *   nearcore: 10-30 min) and does one throwaway sim run, in the background.
 *   It never blocks; `engineStatus()` / `warmReady()` report progress, and
 *   callers refuse attack runs with a clear "warming up" message until ready.
 */
import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";

export const RUNNER_DIR = fileURLToPath(new URL("../runner/", import.meta.url));
export const RUNNER_BIN = process.env.BITLENS_RUNNER_BIN ?? `${RUNNER_DIR}target/release/bitlens-runner`;

export type EngineState = "cold" | "building" | "warming" | "ready" | "failed";

const status: { state: EngineState; detail: string; since: number } = {
  state: existsSync(RUNNER_BIN) ? "warming" : "cold",
  detail: "",
  since: Date.now(),
};
let warmup: Promise<void> | null = null;

export class EngineNotReadyError extends Error {
  readonly code = "ENGINE_WARMING_UP";
}

export function engineStatus() {
  return { ...status, elapsed_s: Math.round((Date.now() - status.since) / 1000), runner_bin: RUNNER_BIN };
}

export function warmReady(): boolean {
  return status.state === "ready";
}

function setState(state: EngineState, detail = "") {
  status.state = state;
  status.detail = detail;
  status.since = Date.now();
}

function run(cmd: string, args: string[], opts: { cwd?: string; input?: string; timeoutMs: number }) {
  return new Promise<{ code: number; stdout: string; stderr: string }>((resolve, reject) => {
    const child = spawn(cmd, args, { cwd: opts.cwd, stdio: ["pipe", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      reject(new Error(`${cmd} timed out after ${opts.timeoutMs / 1000}s`));
    }, opts.timeoutMs);
    child.stdout.on("data", (d) => (stdout += d));
    child.stderr.on("data", (d) => (stderr = (stderr + d).slice(-20_000)));
    child.on("error", (e) => {
      clearTimeout(timer);
      reject(e);
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      resolve({ code: code ?? -1, stdout, stderr });
    });
    if (opts.input !== undefined) child.stdin.end(opts.input);
    else child.stdin.end();
  });
}

/** Run one spec through the runner binary. Throws EngineNotReadyError if the binary isn't built yet. */
export async function runSpec<T = any>(spec: unknown, opts: { timeoutMs?: number } = {}): Promise<T> {
  if (!existsSync(RUNNER_BIN)) {
    throw new EngineNotReadyError(
      `The attack engine is not built yet (${engineStatus().state}). The first build compiles nearcore and takes 10-30 minutes; retry shortly. Capability scans work meanwhile.`,
    );
  }
  const { code, stdout, stderr } = await run(RUNNER_BIN, ["-"], { input: JSON.stringify(spec), timeoutMs: opts.timeoutMs ?? 180_000 });
  const line = stdout.trim().split("\n").pop() ?? "";
  let parsed: any;
  try {
    parsed = JSON.parse(line);
  } catch {
    throw new Error(`Attack runner failed (exit ${code}): ${stderr.trim().split("\n").slice(-5).join(" | ") || "no output"}`);
  }
  if (parsed.error) throw new Error(`Attack runner: ${parsed.error}`);
  return parsed as T;
}

/**
 * Background warm-up: build the runner if missing, then one throwaway run on
 * the bundled clean demo contract. Idempotent; never awaited by servers.
 */
export function startWarmup(log: (msg: string) => void = () => {}, warmSpec?: () => Promise<unknown>): Promise<void> {
  if (warmup) return warmup;
  warmup = (async () => {
    try {
      if (!existsSync(RUNNER_BIN)) {
        setState("building", "cargo build --release in runner/ (first build compiles nearcore: 10-30 min, several GB)");
        log(`[engine] building attack runner: ${status.detail}`);
        const b = await run("cargo", ["build", "--release", "--locked"], { cwd: RUNNER_DIR, timeoutMs: 3 * 60 * 60_000 });
        if (b.code !== 0 || !existsSync(RUNNER_BIN)) throw new Error(`runner build failed: ${b.stderr.trim().split("\n").slice(-3).join(" | ")}`);
      }
      setState("warming", "first sim run (compiles the contract VM cache)");
      log("[engine] warming near-contract-sim with a throwaway run");
      if (warmSpec) await runSpec(await warmSpec());
      setState("ready");
      log("[engine] attack engine ready");
    } catch (e: any) {
      setState("failed", e?.message ?? String(e));
      log(`[engine] warm-up failed: ${status.detail}`);
      warmup = null; // allow a retry
    }
  })();
  return warmup;
}
