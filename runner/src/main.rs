//! NEAR X-Ray attack runner.
//!
//!   xray-runner <spec.json | ->      # prints a JSON report on stdout
//!
//! Deploys the contract's real WASM in near-contract-sim (nearcore's own
//! runtime, in process), builds a base world (owner, victim, attacker), then
//! runs each scenario on its own clone of that world. Every result comes from
//! the sim's receipts and effects: nothing is mocked. Nothing here talks to
//! any network.

use std::collections::BTreeMap;
use std::io::Read;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::time::Instant;

use near_contract_sim::nearcore::near_primitives::action::DeleteAccountAction;
use near_contract_sim::{Action, Balance, Delta, Fault, Gas, Receipts, Sim, TxOutcome};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

const OWNER: &str = "owner.near";
const VICTIM: &str = "victim.near";
const ATTACKER: &str = "attacker.near";
const USER: &str = "user.near";
const YOCTO_PER_NEAR: u128 = 1_000_000_000_000_000_000_000_000;

fn near(n: u128) -> Balance {
    Balance::from_near(n)
}

// ---------------------------------------------------------------------------
// Spec (input) and report (output)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct Spec {
    wasm_path: String,
    contract_id: String,
    /// Tried in order, signed by owner.near (then by the contract itself), until one succeeds.
    #[serde(default)]
    init_candidates: Vec<CallSpec>,
    /// A payable method the victim uses to put funds in (so there is something to steal).
    #[serde(default)]
    deposit_method: Option<String>,
    scenarios: Vec<Scenario>,
}

#[derive(Deserialize, Serialize, Clone)]
struct CallSpec {
    method: String,
    #[serde(default)]
    args: Value,
}

#[derive(Deserialize)]
struct Scenario {
    id: String,
    name: String,
    #[serde(flatten)]
    kind: Kind,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Kind {
    /// 1. A non-owner calls a privileged-looking method.
    UnauthorizedCall { method: String, args: Value },
    /// 2. A non-owner tries to make the contract add a key (to its own account).
    UnauthorizedAddKey { method: String, args: Value },
    /// 3. Two withdraws in one block, before the first callback runs.
    DoubleWithdraw { deposit_method: String, withdraw_method: String, amount_arg: String },
    /// 4. The payout transfer fails: the balance must be restored.
    FailedTransferRefund { deposit_method: String, withdraw_method: String, amount_arg: String },
    /// 5. Caller-chosen gas starves the callback: nothing may be lost or duplicated.
    CallbackGas { deposit_method: String, withdraw_method: String, amount_arg: String },
    /// 6. A yielded call is never resumed: the timeout path must resolve cleanly.
    YieldTimeout { method: String, args: Value },
}

#[derive(Serialize, Clone, Copy, PartialEq)]
#[serde(rename_all = "snake_case")]
enum Status {
    Held,
    Broken,
    Inconclusive,
    /// The scenario's precondition does not exist in this contract (e.g. no callback to test).
    NotApplicable,
    Error,
}

#[derive(Serialize)]
struct Event {
    step: String,
    block: u64,
    from: String,
    to: String,
    action: String,
    deposit_near: String,
    ok: bool,
    detail: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    logs: Vec<String>,
}

#[derive(Serialize)]
struct TokenDelta {
    yocto: String,
    near: String,
}

#[derive(Serialize)]
struct ScenarioResult {
    id: String,
    name: String,
    status: Status,
    explanation: String,
    event_sequence: Vec<Event>,
    token_deltas: BTreeMap<String, TokenDelta>,
    findings: Vec<String>,
    trace: String,
    duration_ms: u128,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn fmt_near(yocto: u128) -> String {
    let whole = yocto / YOCTO_PER_NEAR;
    let frac = (yocto % YOCTO_PER_NEAR) / 10u128.pow(20); // 4 decimals
    format!("{whole}.{frac:04}")
}

fn fmt_delta(d: Delta) -> String {
    let s = if d < 0 { "-" } else if d > 0 { "+" } else { "" };
    format!("{s}{} NEAR", fmt_near(d.magnitude()))
}

/// Accumulates what a scenario did across its transactions.
struct Recorder {
    events: Vec<Event>,
    nets: BTreeMap<String, Delta>,
    traces: Vec<String>,
    watch: Vec<String>,
}

impl Recorder {
    fn new(contract: &str) -> Self {
        Recorder {
            events: vec![],
            nets: BTreeMap::new(),
            traces: vec![],
            watch: vec![contract.into(), ATTACKER.into(), VICTIM.into(), USER.into(), OWNER.into()],
        }
    }

    fn record(&mut self, step: &str, out: &TxOutcome) {
        self.record_inner(step, out, true);
    }

    /// Show the step in the sequence and trace, but keep it out of the net NEAR
    /// figures (test-harness moves such as an account deleting itself).
    fn record_setup(&mut self, step: &str, out: &TxOutcome) {
        self.record_inner(step, out, false);
    }

    fn record_inner(&mut self, step: &str, out: &TxOutcome, count: bool) {
        for r in &out.receipts {
            if r.refund.is_some() {
                continue; // gas / deposit refunds are not value movement worth showing
            }
            let action = if !r.method_names.is_empty() {
                format!("call {}", r.method_names.join(", "))
            } else {
                r.actions.join(", ")
            };
            let failure = r.failure().map(|f| f.to_string());
            let fault = r.fault.as_ref().map(|f| format!(" [forced fault: {f:?}]")).unwrap_or_default();
            self.events.push(Event {
                step: step.into(),
                block: r.block_height,
                from: r.predecessor_id.to_string(),
                to: r.receiver_id.to_string(),
                action,
                deposit_near: fmt_near(r.deposit.as_yoctonear()),
                ok: r.is_success(),
                detail: failure.map(|f| format!("FAILED: {f}")).unwrap_or_else(|| "ok".into()) + &fault,
                logs: r.logs.clone(),
            });
        }
        let e = out.effects();
        for who in self.watch.iter().filter(|_| count) {
            let d = e.near_net(who.as_str());
            let cur = self.nets.entry(who.clone()).or_insert(Delta::ZERO);
            *cur = cur.checked_add(d).unwrap_or(*cur);
        }
        self.traces.push(format!("── {step} ──\n{out}"));
    }

    fn net(&self, who: &str) -> Delta {
        self.nets.get(who).copied().unwrap_or(Delta::ZERO)
    }

    fn finish(self, id: &str, name: &str, status: Status, explanation: String, sim: &Sim, t0: Instant) -> ScenarioResult {
        let token_deltas = self
            .nets
            .iter()
            .filter(|(_, d)| **d != 0)
            .map(|(k, d)| {
                (k.clone(), TokenDelta { yocto: serde_json::to_value(d).map(|v| v.as_str().unwrap_or("").to_string()).unwrap_or_default(), near: fmt_delta(*d) })
            })
            .collect();
        ScenarioResult {
            id: id.into(),
            name: name.into(),
            status,
            explanation,
            event_sequence: self.events,
            token_deltas,
            findings: sim.findings().iter().map(|f| f.to_string().lines().next().unwrap_or("").to_string()).collect(),
            trace: self.traces.join("\n"),
            duration_ms: t0.elapsed().as_millis(),
        }
    }
}

fn panic_text(out: &TxOutcome) -> String {
    let raw = out.failure().map(|f| f.to_string()).unwrap_or_default();
    // One line, no SDK source paths, bounded length: this text ends up in reports.
    let mut t = raw.split_whitespace().collect::<Vec<_>>().join(" ");
    if let Some(i) = t.find(", /") { t.truncate(i); }
    if let Some(i) = t.find("', src/") { t.truncate(i); }
    if t.chars().count() > 220 { t = t.chars().take(220).collect::<String>() + "…"; }
    t
}

/// Rounding slack for NEAR comparisons (1 yocto guards, etc.): 0.000000000000000001 NEAR x 1e6.
const TOL: u128 = 1_000_000;

fn paid_to(out: &TxOutcome, who: &str) -> u128 {
    i128::try_from(out.effects().near_net(who)).unwrap_or(0).max(0) as u128
}

/// The call failed because we could not build valid input from bytecode alone,
/// not because of access control.
fn is_input_problem(msg: &str) -> bool {
    let m = msg.to_lowercase();
    ["deserialize", "missing field", "invalid type", "unknown variant", "invalid value", "invalid length", "expected value", "methodresolveerror", "method not found", "not initialized", "eof while parsing"]
        .iter()
        .any(|p| m.contains(p))
}

fn needs_one_yocto(msg: &str) -> bool {
    msg.contains("exactly 1 yoctoNEAR") || msg.contains("1 yocto")
}

/// Call; if the contract demands exactly 1 yoctoNEAR (NEP-141 style guards), retry with it.
fn call_flex(sim: &mut Sim, rec: &mut Recorder, step: &str, signer: &str, contract: &str, method: &str, args: &Value) -> TxOutcome {
    let out = sim.call(signer, contract, method).args_json(args).transact();
    if out.is_failure() && needs_one_yocto(&panic_text(&out)) {
        rec.record(&format!("{step} (no deposit)"), &out);
        let out = sim.call(signer, contract, method).args_json(args).deposit(Balance::from_yoctonear(1)).transact();
        rec.record(&format!("{step} (1 yocto)"), &out);
        return out;
    }
    rec.record(step, &out);
    out
}

// ---------------------------------------------------------------------------
// World
// ---------------------------------------------------------------------------

struct World {
    sim: Sim,
    contract: String,
    init: Value,
    victim_deposit: Value,
}

fn build_world(spec: &Spec) -> Result<World, String> {
    let wasm = std::fs::read(&spec.wasm_path).map_err(|e| format!("read {}: {e}", spec.wasm_path))?;
    let contract = spec.contract_id.clone();
    let mut sim = Sim::new();
    for a in [OWNER, VICTIM, ATTACKER, USER] {
        sim.create_account(a, near(100));
    }
    sim.create_account(contract.as_str(), near(50));
    catch_unwind(AssertUnwindSafe(|| sim.deploy(contract.as_str(), wasm))).map_err(|_| "deploy failed: the WASM did not load in nearcore's VM".to_string())?;

    let mut init = json!({ "ok": false, "tried": [] });
    'outer: for cand in &spec.init_candidates {
        for signer in [OWNER, contract.as_str()] {
            let out = sim.call(signer, contract.as_str(), &cand.method).args_json(&cand.args).transact();
            init["tried"].as_array_mut().unwrap().push(json!({ "method": cand.method, "signer": signer, "ok": out.is_success(), "error": panic_text(&out) }));
            if out.is_success() {
                init["ok"] = json!(true);
                init["method"] = json!(cand.method);
                init["signer"] = json!(signer);
                break 'outer;
            }
        }
    }

    let mut victim_deposit = json!(null);
    if let Some(dep) = &spec.deposit_method {
        let out = sim.call(VICTIM, contract.as_str(), dep).args_json(json!({})).deposit(near(20)).transact();
        victim_deposit = json!({ "method": dep, "amount_near": 20, "ok": out.is_success(), "error": panic_text(&out) });
    }
    Ok(World { sim, contract, init, victim_deposit })
}

// ---------------------------------------------------------------------------
// Scenarios
// ---------------------------------------------------------------------------

fn run_scenario(world: &World, sc: &Scenario) -> ScenarioResult {
    let t0 = Instant::now();
    let mut sim = world.sim.clone();
    let c = world.contract.as_str();
    let mut rec = Recorder::new(c);
    let (status, explanation) = match &sc.kind {
        Kind::UnauthorizedCall { method, args } => unauthorized_call(&mut sim, &mut rec, c, method, args, false),
        Kind::UnauthorizedAddKey { method, args } => unauthorized_call(&mut sim, &mut rec, c, method, args, true),
        Kind::DoubleWithdraw { deposit_method, withdraw_method, amount_arg } => {
            double_withdraw(&mut sim, &mut rec, c, deposit_method, withdraw_method, amount_arg)
        }
        Kind::FailedTransferRefund { deposit_method, withdraw_method, amount_arg } => {
            failed_transfer_refund(&mut sim, &mut rec, c, deposit_method, withdraw_method, amount_arg)
        }
        Kind::CallbackGas { deposit_method, withdraw_method, amount_arg } => {
            callback_gas(&mut sim, &mut rec, c, deposit_method, withdraw_method, amount_arg)
        }
        Kind::YieldTimeout { method, args } => yield_timeout(&mut sim, &mut rec, c, method, args),
    };
    rec.finish(&sc.id, &sc.name, status, explanation, &sim, t0)
}

/// 1 + 2. Privileged method from a non-owner.
fn unauthorized_call(sim: &mut Sim, rec: &mut Recorder, c: &str, method: &str, args: &Value, check_keys: bool) -> (Status, String) {
    let keys_before = sim.access_keys(c).len();
    let state_before = sim.view_state(c, b"");
    let code_before = sim.account(c).map(|a| a.code_hash);
    let out = call_flex(sim, rec, &format!("attacker.near calls {method}"), ATTACKER, c, method, args);
    if out.is_failure() {
        let msg = panic_text(&out);
        if is_input_problem(&msg) {
            return (
                Status::Inconclusive,
                format!("Could not build valid arguments for `{method}` from bytecode alone, so access control was not exercised. Contract said: {msg}"),
            );
        }
        return (Status::Held, format!("A non-owner call to `{method}` was rejected: {msg}"));
    }
    let gained = rec.net(ATTACKER);
    let keys_added = sim.access_keys(c).len().saturating_sub(keys_before);
    let state_changed = sim.view_state(c, b"") != state_before;
    let contract_lost = rec.net(c);
    if sim.account(c).map(|a| a.code_hash) != code_before {
        return (
            Status::Broken,
            format!("A non-owner call to `{method}` replaced {c}'s contract code. Anyone can redeploy it with their own logic and take everything it holds."),
        );
    }
    if check_keys && keys_added > 0 {
        return (
            Status::Broken,
            format!("A non-owner call to `{method}` added {keys_added} access key(s) to {c}. Whoever holds that key controls the account."),
        );
    }
    if gained > 0 {
        return (
            Status::Broken,
            format!(
                "A non-owner call to `{method}` succeeded and moved {} into attacker.near's account (the contract's balance changed by {}). Anyone can call it.",
                fmt_delta(gained),
                fmt_delta(contract_lost)
            ),
        );
    }
    if state_changed || keys_added > 0 {
        return (Status::Broken, format!("A non-owner call to `{method}` succeeded and changed the contract's state. It is not owner-gated."));
    }
    (
        Status::Held,
        format!("A non-owner call to `{method}` succeeded but had no effect (no state change, no funds moved): it behaves like a public no-op for this input."),
    )
}

fn amount_args(amount_arg: &str, yocto: u128) -> Value {
    json!({ amount_arg: yocto.to_string() })
}

fn deposit(sim: &mut Sim, rec: &mut Recorder, who: &str, c: &str, method: &str, amount: u128) -> Result<(), String> {
    // NEP-145: register storage up front so the deposit is credited in full
    // (some contracts otherwise take the storage fee out of the deposit).
    // Contracts without storage_deposit just fail this harmlessly; not recorded.
    let reg = sim.call(who, c, "storage_deposit").args_json(json!({ "account_id": who })).deposit(Balance::from_yoctonear(YOCTO_PER_NEAR / 10)).transact();
    if reg.is_success() {
        rec.record_setup(&format!("{who} registers storage (0.1 NEAR)"), &reg);
    }
    let out = sim.call(who, c, method).args_json(json!({})).deposit(Balance::from_yoctonear(amount)).transact();
    rec.record(&format!("{who} deposits {} NEAR", fmt_near(amount)), &out);
    if out.is_success() {
        return Ok(());
    }
    let e = panic_text(&out);
    let l = e.to_lowercase();
    if l.contains("not registered") || l.contains("storage") {
        // NEP-145 contracts want storage paid first.
        let reg = sim.call(who, c, "storage_deposit").args_json(json!({ "account_id": who })).deposit(Balance::from_yoctonear(YOCTO_PER_NEAR / 10)).transact();
        rec.record(&format!("{who} registers storage (0.1 NEAR)"), &reg);
        if reg.is_success() {
            let out = sim.call(who, c, method).args_json(json!({})).deposit(Balance::from_yoctonear(amount)).transact();
            rec.record(&format!("{who} deposits {} NEAR", fmt_near(amount)), &out);
            if out.is_success() {
                return Ok(());
            }
            return Err(panic_text(&out));
        }
    }
    Err(e)
}

/// Control run on a scratch copy: deposit `d`, then withdraw it all with default
/// gas and no faults. Value-flow scenarios are only judged when this works;
/// otherwise a failure is ours (could not drive the contract), not the contract's.
/// Returns the yoctoNEAR to attach to withdraw calls (0, or 1 for NEP-141-style guards).
fn baseline(sim: &Sim, who: &str, c: &str, dep: &str, wd: &str, arg: &str, d: u128) -> Result<u128, String> {
    let mut s = sim.clone();
    let mut scratch = Recorder::new(c);
    deposit(&mut s, &mut scratch, who, c, dep, d).map_err(|e| format!("deposit via `{dep}` failed: {e}"))?;
    let mut why = String::new();
    for y in [0u128, 1] {
        let mut t = s.clone();
        let out = t.call(who, c, wd).args_json(amount_args(arg, d)).deposit(Balance::from_yoctonear(y)).transact();
        let paid = paid_to(&out, who) + y;
        if out.is_success() && paid.abs_diff(d) <= TOL {
            return Ok(y);
        }
        why = if out.is_failure() { panic_text(&out) } else { format!("it succeeded but paid {} of {} NEAR", fmt_near(paid), fmt_near(d)) };
        if !needs_one_yocto(&why) {
            break;
        }
    }
    Err(format!("`{wd}` failed: {why}"))
}

fn no_baseline(dep: &str, wd: &str, e: &str) -> (Status, String) {
    (
        Status::Inconclusive,
        format!("Control run failed: a plain `{dep}` of 5 NEAR followed by a normal `{wd}` did not work in the sim ({e}). X-Ray could not drive this contract's deposit/withdraw flow from bytecode alone, so this scenario was not judged."),
    )
}

/// 3. Double-spend: two withdraws in the same block before the first callback resolves.
fn double_withdraw(sim: &mut Sim, rec: &mut Recorder, c: &str, dep: &str, wd: &str, arg: &str) -> (Status, String) {
    let d = 5 * YOCTO_PER_NEAR;
    let y = match baseline(sim, ATTACKER, c, dep, wd, arg, d) {
        Ok(y) => y,
        Err(e) => return no_baseline(dep, wd, &e),
    };
    if let Err(e) = deposit(sim, rec, ATTACKER, c, dep, d) {
        return (Status::Inconclusive, format!("Could not deposit via `{dep}`: {e}"));
    }
    let h1 = sim.call(ATTACKER, c, wd).args_json(amount_args(arg, d)).deposit(Balance::from_yoctonear(y)).submit();
    let h2 = sim.call(ATTACKER, c, wd).args_json(amount_args(arg, d)).deposit(Balance::from_yoctonear(y)).submit();
    sim.settle();
    let (o1, o2) = (sim.outcome(h1), sim.outcome(h2));
    rec.record(&format!("attacker.near withdraw #1 ({} NEAR)", fmt_near(d)), &o1);
    rec.record(&format!("attacker.near withdraw #2 ({} NEAR, same block)", fmt_near(d)), &o2);
    let received: i128 = [&o1, &o2].iter().map(|o| i128::try_from(o.effects().near_net(ATTACKER)).unwrap_or(0)).sum();
    let received = received.max(0) as u128 + 2 * y;
    if received > d + TOL {
        (
            Status::Broken,
            format!(
                "Double-spend: attacker.near deposited {} NEAR, sent two `{wd}` calls in the same block, and got {} NEAR back. The balance is checked but not debited before the payout, so both calls pass. The extra {} NEAR came out of other depositors' funds.",
                fmt_near(d),
                fmt_near(received),
                fmt_near(received - d)
            ),
        )
    } else if received == 0 && o1.is_failure() && o2.is_failure() {
        (Status::Inconclusive, format!("Neither withdraw succeeded (`{wd}`: {}), so the race was not exercised.", panic_text(&o1)))
    } else {
        (
            Status::Held,
            format!(
                "Two same-block `{wd}` calls paid out {} NEAR in total against a {} NEAR deposit. The second call was refused, so nothing was spent twice.",
                fmt_near(received),
                fmt_near(d)
            ),
        )
    }
}

/// 4. The payout transfer fails (the recipient account is gone when it lands):
///    the user's balance must be restored, not lost.
fn failed_transfer_refund(sim: &mut Sim, rec: &mut Recorder, c: &str, dep: &str, wd: &str, arg: &str) -> (Status, String) {
    let d = 5 * YOCTO_PER_NEAR;
    let y = match baseline(sim, USER, c, dep, wd, arg, d) {
        Ok(y) => y,
        Err(e) => return no_baseline(dep, wd, &e),
    };
    if let Err(e) = deposit(sim, rec, USER, c, dep, d) {
        return (Status::Inconclusive, format!("Could not deposit via `{dep}`: {e}"));
    }
    // Hold the payout so the account can be deleted before it lands: a real failure, not a forced one.
    let h = sim.call(USER, c, wd).args_json(amount_args(arg, d)).deposit(Balance::from_yoctonear(y)).inject(Receipts::action("Transfer"), Fault::Hold(4)).submit();
    let _ = sim.run_until(20, |s| s.outcome(h).receipt(wd).is_some());
    let del = sim.tx(USER, USER).action(Action::DeleteAccount(DeleteAccountAction { beneficiary_id: OWNER.parse().unwrap() })).transact();
    rec.record_setup("user.near deletes its account while the payout is in flight (test harness)", &del);
    sim.settle();
    let o = sim.outcome(h);
    rec.record(&format!("user.near withdraws {} NEAR (payout held, then fails)", fmt_near(d)), &o);
    let transfer_failed = o.receipts.iter().any(|r| r.actions.iter().any(|a| a.starts_with("Transfer")) && !r.is_success());
    if !transfer_failed {
        return (Status::Inconclusive, "Could not make the payout transfer fail (the withdraw may not pay out with a plain transfer).".into());
    }
    // A plain transfer with no callback cannot be refunded by the contract, and the only way
    // we can make it fail is the recipient deleting itself mid-flight: self-inflicted, not an attack.
    let transfer_block = o.receipts.iter().filter(|r| r.actions.iter().any(|a| a.starts_with("Transfer"))).map(|r| r.block_height).min().unwrap_or(0);
    let has_callback = o.receipts.iter().any(|r| {
        r.receiver_id.as_str() == c && r.predecessor_id.as_str() == c && !r.method_names.is_empty() && r.block_height >= transfer_block
    });
    if !has_callback {
        return (
            Status::NotApplicable,
            format!("`{wd}` pays out with a plain transfer and no callback, so there is no failure branch to test. The only way to make that transfer fail is the recipient deleting its own account mid-flight, which is self-inflicted, so it is not counted against the contract."),
        );
    }
    // The user comes back (same account id) and tries to withdraw again.
    sim.create_account(USER, near(5));
    let retry = sim.call(USER, c, wd).args_json(amount_args(arg, d)).deposit(Balance::from_yoctonear(y)).transact();
    rec.record("user.near re-creates its account and withdraws again", &retry);
    let got = paid_to(&retry, USER) + y;
    if got.abs_diff(d) <= TOL {
        (Status::Held, format!("The payout failed, the contract restored the {} NEAR balance, and the user withdrew it in full afterwards. Nothing was lost.", fmt_near(d)))
    } else {
        (
            Status::Broken,
            format!(
                "The payout failed but the balance was not restored: a later withdraw paid {} of {} NEAR. The failed-transfer branch loses user funds (the NEAR is stuck in the contract).",
                fmt_near(got),
                fmt_near(d)
            ),
        )
    }
}

/// 5. Caller-chosen gas: a withdraw with too little gas for its callback must
///    either fail cleanly or complete; funds paid + funds still withdrawable == deposit.
fn callback_gas(sim: &mut Sim, rec: &mut Recorder, c: &str, dep: &str, wd: &str, arg: &str) -> (Status, String) {
    let d = 5 * YOCTO_PER_NEAR;
    let y = match baseline(sim, USER, c, dep, wd, arg, d) {
        Ok(y) => y,
        Err(e) => return no_baseline(dep, wd, &e),
    };
    if let Err(e) = deposit(sim, rec, USER, c, dep, d) {
        return (Status::Inconclusive, format!("Could not deposit via `{dep}`: {e}"));
    }
    let points = [8u64, 12, 16, 20, 25, 30, 35, 40, 50, 75, 100, 150, 300];
    let mut summary = vec![];
    let mut broken: Option<(u64, u128, TxOutcome, TxOutcome)> = None;
    for tg in points {
        let mut s = sim.clone();
        let first = s.call(USER, c, wd).args_json(amount_args(arg, d)).deposit(Balance::from_yoctonear(y)).gas(Gas::from_teragas(tg)).transact();
        let probe = s.call(USER, c, wd).args_json(amount_args(arg, d)).deposit(Balance::from_yoctonear(y)).transact();
        // The probe's 1-yocto guard deposit is credited back to the user's total.
        let total = paid_to(&first, USER) + if first.is_success() { y } else { 0 } + paid_to(&probe, USER) + if probe.is_success() { y } else { 0 };
        let tag = if first.is_success() { "paid" } else { "refused" };
        summary.push(format!("{tg} Tgas: {tag}, total recoverable {} NEAR", fmt_near(total)));
        if total.abs_diff(d) > TOL && broken.is_none() {
            broken = Some((tg, total, first, probe));
        }
    }
    // Compress runs of identical outcomes: "8-25 Tgas: refused, 5.0000 NEAR recoverable".
    let mut runs: Vec<(u64, u64, String)> = vec![];
    for (tg, line) in points.iter().zip(&summary) {
        let what = line.split_once(": ").map(|(_, w)| w.to_string()).unwrap_or_default();
        match runs.last_mut() {
            Some((_, hi, w)) if *w == what => *hi = *tg,
            _ => runs.push((*tg, *tg, what)),
        }
    }
    let joined = runs
        .iter()
        .map(|(lo, hi, w)| if lo == hi { format!("{lo} Tgas: {w}") } else { format!("{lo}-{hi} Tgas: {w}") })
        .collect::<Vec<_>>()
        .join("; ");
    match broken {
        Some((tg, total, first, probe)) => {
            rec.record(&format!("user.near withdraws with {tg} Tgas"), &first);
            rec.record("user.near tries to withdraw the rest", &probe);
            let what = if total < d { "lost" } else { "duplicated" };
            (
                Status::Broken,
                format!(
                    "With {tg} Tgas attached to `{wd}`, the callback ran short of gas and left the books half-applied: the user can recover {} of {} NEAR ({} NEAR {what}). Sweep: {joined}",
                    fmt_near(total),
                    fmt_near(d),
                    fmt_near(total.abs_diff(d))
                ),
            )
        }
        None => {
            let mut s = sim.clone();
            let first = s.call(USER, c, wd).args_json(amount_args(arg, d)).deposit(Balance::from_yoctonear(y)).gas(Gas::from_teragas(points[0])).transact();
            rec.record(&format!("user.near withdraws with {} Tgas (lowest point)", points[0]), &first);
            let probe = s.call(USER, c, wd).args_json(amount_args(arg, d)).deposit(Balance::from_yoctonear(y)).transact();
            rec.record("user.near withdraws the rest with normal gas", &probe);
            (Status::Held, format!("At every caller gas from {} to {} Tgas the user could recover exactly {} NEAR. No half-applied state. Sweep: {joined}", points[0], points[points.len() - 1], fmt_near(d)))
        }
    }
}

/// 6. Stale yield: advance past the yield deadline; it must resolve cleanly.
fn yield_timeout(sim: &mut Sim, rec: &mut Recorder, c: &str, method: &str, args: &Value) -> (Status, String) {
    let h = sim.call(USER, c, method).args_json(args).deposit(Balance::from_yoctonear(0)).submit();
    let _ = sim.run_until(10, |s| !s.yields().is_empty() || s.is_idle());
    let ys = sim.yields();
    if ys.is_empty() {
        sim.settle();
        rec.record(&format!("user.near calls {method}"), &sim.outcome(h));
        return (Status::Inconclusive, format!("`{method}` did not yield with the arguments we could build, so the timeout path was not exercised."));
    }
    let deadline = ys[0].expires_at;
    sim.advance_to(deadline);
    sim.settle();
    let o = sim.outcome(h);
    rec.record(&format!("user.near calls {method}; nobody resumes; clock advanced past block {deadline}"), &o);
    let findings = sim.findings();
    if !o.is_complete() || !findings.is_empty() {
        (Status::Broken, format!("After the yield deadline the call did not resolve cleanly: {} pending receipt(s), {} finding(s).", o.pending.len(), findings.len()))
    } else {
        (Status::Held, "The yield timed out at its deadline and the timeout path resolved cleanly (no stuck receipts, no unhandled failures, NEAR conserved).".into())
    }
}

// ---------------------------------------------------------------------------

fn main() {
    // Quiet nearcore's own logging and keep receipt trees free of ANSI colors.
    unsafe { std::env::set_var("NO_COLOR", "1") };
    let arg = std::env::args().nth(1).unwrap_or_else(|| "-".into());
    let raw = if arg == "-" {
        let mut s = String::new();
        std::io::stdin().read_to_string(&mut s).expect("read stdin");
        s
    } else {
        std::fs::read_to_string(&arg).unwrap_or_else(|e| fail(&format!("read spec {arg}: {e}")))
    };
    let spec: Spec = serde_json::from_str(&raw).unwrap_or_else(|e| fail(&format!("bad spec: {e}")));

    let t0 = Instant::now();
    let world = match build_world(&spec) {
        Ok(w) => w,
        Err(e) => fail(&e),
    };
    let setup_ms = t0.elapsed().as_millis();
    let results: Vec<ScenarioResult> = spec
        .scenarios
        .iter()
        .map(|sc| {
            catch_unwind(AssertUnwindSafe(|| run_scenario(&world, sc))).unwrap_or_else(|p| {
                let msg = p.downcast_ref::<String>().cloned().or_else(|| p.downcast_ref::<&str>().map(|s| s.to_string())).unwrap_or_default();
                ScenarioResult {
                    id: sc.id.clone(),
                    name: sc.name.clone(),
                    status: Status::Error,
                    explanation: format!("The simulator raised an error: {}", msg.lines().next().unwrap_or("")),
                    event_sequence: vec![],
                    token_deltas: BTreeMap::new(),
                    findings: vec![],
                    trace: msg,
                    duration_ms: 0,
                }
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
