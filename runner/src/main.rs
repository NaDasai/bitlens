//! BitLens attack runner.
//!
//!   bitlens-runner <spec.json | ->        # prints a JSON report on stdout
//!   bitlens-runner --validate <file|->    # checks one scenario JSON, prints {"ok":..}
//!
//! Deploys the contract's real WASM in near-contract-sim (nearcore's own
//! runtime, in process), builds a base world (owner, victim, attacker, user),
//! then runs each scenario on its own clone of that world.
//!
//! A scenario is data, never code (see scenario.rs): canned presets and
//! scenarios translated from plain English by an LLM are the same JSON. Every
//! result comes from the sim's receipts and effects. Nothing here talks to any
//! network.

mod interp;
mod scenario;

use std::collections::BTreeMap;
use std::io::Read;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::time::Instant;

use serde::Deserialize;
use serde_json::{Value, json};

use interp::{ATTACKER, InitCandidate, OWNER, ScenarioResult, Status, USER, VICTIM, build_world, run_scenario};
use scenario::{Scenario, validate};

#[derive(Deserialize)]
struct Spec {
    wasm_path: String,
    contract_id: String,
    /// Tried in order, signed by owner.near (then by the contract itself), until one succeeds.
    #[serde(default)]
    init_candidates: Vec<InitSpec>,
    /// A payable method the victim uses to put funds in (so there is something to steal).
    #[serde(default)]
    deposit_method: Option<String>,
    /// Raw scenario objects: each is parsed and validated on its own, so one bad
    /// scenario is reported as an error result instead of failing the whole run.
    scenarios: Vec<Value>,
}

#[derive(Deserialize)]
struct InitSpec {
    method: String,
    #[serde(default)]
    args: Value,
}

fn parse_scenario(v: &Value) -> Result<Scenario, String> {
    let sc: Scenario = serde_json::from_value(v.clone()).map_err(|e| format!("invalid scenario JSON: {e}"))?;
    validate(&sc).map_err(|e| format!("invalid scenario: {e}"))?;
    Ok(sc)
}

fn error_result(id: &str, name: &str, explanation: String, trace: String) -> ScenarioResult {
    ScenarioResult {
        id: id.into(),
        name: name.into(),
        status: Status::Error,
        explanation,
        event_sequence: vec![],
        token_deltas: BTreeMap::new(),
        findings: vec![],
        trace,
        duration_ms: 0,
    }
}

fn read_input(arg: &str) -> String {
    if arg == "-" {
        let mut s = String::new();
        std::io::stdin().read_to_string(&mut s).expect("read stdin");
        s
    } else {
        std::fs::read_to_string(arg).unwrap_or_else(|e| fail(&format!("read {arg}: {e}")))
    }
}

fn main() {
    // Quiet nearcore's own logging and keep receipt trees free of ANSI colors.
    unsafe { std::env::set_var("NO_COLOR", "1") };
    let args: Vec<String> = std::env::args().skip(1).collect();

    if args.first().map(String::as_str) == Some("--validate") {
        let raw = read_input(args.get(1).map(String::as_str).unwrap_or("-"));
        let out = serde_json::from_str::<Value>(&raw).map_err(|e| format!("not JSON: {e}")).and_then(|v| parse_scenario(&v));
        match out {
            Ok(sc) => println!("{}", json!({ "ok": true, "id": sc.id, "steps": sc.steps.len(), "checks": sc.checks.len() })),
            Err(e) => println!("{}", json!({ "ok": false, "error": e })),
        }
        return;
    }

    let raw = read_input(args.first().map(String::as_str).unwrap_or("-"));
    let spec: Spec = serde_json::from_str(&raw).unwrap_or_else(|e| fail(&format!("bad spec: {e}")));
    let wasm = std::fs::read(&spec.wasm_path).unwrap_or_else(|e| fail(&format!("read {}: {e}", spec.wasm_path)));
    let inits: Vec<InitCandidate> = spec.init_candidates.iter().map(|c| InitCandidate { method: c.method.clone(), args: c.args.clone() }).collect();

    let t0 = Instant::now();
    let world = build_world(wasm, &spec.contract_id, &inits, spec.deposit_method.as_deref()).unwrap_or_else(|e| fail(&e));
    let setup_ms = t0.elapsed().as_millis();

    let results: Vec<ScenarioResult> = spec
        .scenarios
        .iter()
        .map(|v| {
            let id = v.get("id").and_then(Value::as_str).unwrap_or("?").chars().take(96).collect::<String>();
            let name = v.get("name").and_then(Value::as_str).unwrap_or("?").chars().take(160).collect::<String>();
            let sc = match parse_scenario(v) {
                Ok(sc) => sc,
                Err(e) => return error_result(&id, &name, e.clone(), e),
            };
            catch_unwind(AssertUnwindSafe(|| run_scenario(&world, &sc))).unwrap_or_else(|p| {
                let msg = p.downcast_ref::<String>().cloned().or_else(|| p.downcast_ref::<&str>().map(|s| s.to_string())).unwrap_or_default();
                error_result(&sc.id, &sc.name, format!("The simulator raised an error: {}", msg.lines().next().unwrap_or("")), msg)
            })
        })
        .collect();

    let report = json!({
        "engine": "near-contract-sim (nearcore 2.14.0 runtime, in-process)",
        "contract_id": world.contract,
        "accounts": { "owner": OWNER, "victim": VICTIM, "attacker": ATTACKER, "user": USER },
        "init": world.init,
        "victim_deposit": world.victim_deposit,
        "setup_ms": setup_ms,
        "scenarios": results,
    });
    println!("{}", serde_json::to_string(&report).unwrap());
}

fn fail(msg: &str) -> ! {
    println!("{}", json!({ "error": msg }));
    std::process::exit(1);
}
