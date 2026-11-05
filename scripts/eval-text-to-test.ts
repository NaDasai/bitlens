/**
 * Text-to-test eval: run every sentence in evals/text-to-test.json through the
 * real LLM and the real sim, and compare the result with the expected one.
 * Makes prompt and model changes measurable. Uses the network and LLM credit,
 * so it is on demand only (not part of `npm test`).
 *
 *   npm run eval:t2t                              # OpenRouter (or whichever key is set)
 *   npm run eval:t2t -- --provider near           # NEAR AI Cloud only (needs NEAR_AI_API_KEY)
 *   npm run eval:t2t -- --provider openrouter --model qwen/qwen3.6-35b-a3b
 *   npm run eval:t2t -- --only vv-drain,ye-timeout --repeat 3
 *
 * A case passes when the scenario calls the expected method AND the sim gives
 * the expected result. Results are also written to evals/results/ (gitignored).
 * Exit code 1 if any case fails.
 */
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { runAttacks, scan, scenarioMethods, translateToScenario, type RiskCard } from "../core/index.js";

type Case = { id: string; contract: string; sentence: string; expect: string; method: string; preset: string };
type Row = {
  id: string;
  run: number;
  pass: boolean;
  expected: string;
  got: string;
  method_ok: boolean;
  attempts: number | null;
  translate_ms: number;
  provider: string | null;
  model: string | null;
  problem?: string;
  scenario?: unknown;
};

const args = process.argv.slice(2);
const opt = (name: string) => (args.includes(name) ? args[args.indexOf(name) + 1] : undefined);
const provider = opt("--provider")?.toLowerCase();
const model = opt("--model");
const only = opt("--only")?.split(",").filter(Boolean);
const repeat = Math.max(1, Math.min(10, Number(opt("--repeat") ?? 1)));

// Force one provider so the run measures exactly that provider and model.
if (provider === "near") {
  if (!process.env.NEAR_AI_API_KEY) fail("--provider near needs NEAR_AI_API_KEY in the environment.");
  delete process.env.OPEN_ROUTER_KEY;
  if (model) process.env.NEAR_AI_MODEL = model;
} else if (provider === "openrouter") {
  if (!process.env.OPEN_ROUTER_KEY) fail("--provider openrouter needs OPEN_ROUTER_KEY in the environment.");
  delete process.env.NEAR_AI_API_KEY;
  if (model) process.env.OPEN_ROUTER_MODEL = model;
} else if (provider) {
  fail(`--provider must be "near" or "openrouter", not "${provider}".`);
} else if (model) {
  fail("--model needs --provider, so it is clear which provider it applies to.");
}

function fail(msg: string): never {
  console.error(`✘ ${msg}`);
  process.exit(2);
}

const file = JSON.parse(await readFile(new URL("../evals/text-to-test.json", import.meta.url), "utf8")) as { cases: Case[] };
const cases = file.cases.filter((c) => !only || only.includes(c.id));
if (!cases.length) fail(`no case matches --only ${only?.join(",")}`);

const cards = new Map<string, RiskCard>();
const rows: Row[] = [];
const t0 = Date.now();

for (let run = 1; run <= repeat; run++) {
  for (const c of cases) {
    cards.set(c.contract, cards.get(c.contract) ?? (await scan(c.contract)));
    const row: Row = { id: c.id, run, pass: false, expected: c.expect, got: "-", method_ok: false, attempts: null, translate_ms: 0, provider: null, model: null };
    const start = Date.now();
    try {
      const t = await translateToScenario(c.sentence, cards.get(c.contract)!);
      row.translate_ms = Date.now() - start;
      Object.assign(row, { attempts: t.attempts, provider: t.provider, model: t.model, scenario: t.scenario });
      row.method_ok = scenarioMethods(t.scenario).includes(c.method);
      const { report } = await runAttacks(c.contract, undefined, { custom: [t.scenario] });
      const r = report.results[0];
      row.got = r?.status ?? "none";
      row.pass = row.method_ok && row.got === c.expect;
      if (!row.method_ok) row.problem = `scenario never calls ${c.method} (calls: ${scenarioMethods(t.scenario).join(", ") || "nothing"})`;
      else if (!row.pass) row.problem = r?.explanation?.slice(0, 200);
    } catch (e: any) {
      row.translate_ms ||= Date.now() - start;
      row.got = "error";
      row.problem = String(e?.message ?? e).slice(0, 200);
    }
    rows.push(row);
    const mark = row.pass ? "✔" : "✘";
    console.log(
      `${mark} ${c.id.padEnd(18)} expected ${c.expect.padEnd(7)} got ${row.got.padEnd(12)} ${row.attempts ?? "-"} attempt(s)  ${(row.translate_ms / 1000).toFixed(1)}s${row.problem ? `  ${row.problem}` : ""}`,
    );
  }
}

const passed = rows.filter((r) => r.pass).length;
const translated = rows.filter((r) => r.attempts !== null);
const firstTry = translated.filter((r) => r.attempts === 1).length;
const ms = translated.map((r) => r.translate_ms).sort((a, b) => a - b);
const pct = (n: number, d: number) => (d ? `${Math.round((100 * n) / d)}%` : "-");
const q = (p: number) => (ms.length ? (ms[Math.min(ms.length - 1, Math.floor(p * ms.length))] / 1000).toFixed(1) + "s" : "-");
const used = translated[0] ? `${translated[0].provider} (${translated[0].model})` : "no provider answered";
const summary = {
  when: new Date().toISOString(),
  provider: used,
  cases: cases.length,
  runs: repeat,
  passed,
  total: rows.length,
  pass_rate: pct(passed, rows.length),
  valid_scenario: pct(translated.length, rows.length),
  valid_first_try: pct(firstTry, rows.length),
  translate_median: q(0.5),
  translate_p90: q(0.9),
  wall_s: Math.round((Date.now() - t0) / 1000),
};

console.log(`\n${used}`);
console.log(
  `PASS ${passed}/${rows.length} (${summary.pass_rate}) · valid scenario ${summary.valid_scenario} · valid on first try ${summary.valid_first_try} · translation median ${summary.translate_median}, p90 ${summary.translate_p90} · ${summary.wall_s}s total`,
);

const dir = new URL("../evals/results/", import.meta.url);
await mkdir(dir, { recursive: true });
const out = new URL(`t2t-${summary.when.replace(/[:.]/g, "-")}.json`, dir);
await writeFile(out, JSON.stringify({ summary, rows }, null, 2));
console.log(`Saved: evals/results/${out.pathname.split("/").pop()}`);
process.exit(passed === rows.length ? 0 : 1);
