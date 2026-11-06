//! Executes a scenario (see scenario.rs) against near-contract-sim.
//!
//! Each step maps onto a fixed sim operation against the contract under test;
//! results come only from the sim's receipts and effects. Checks are evaluated
//! in order after the steps: the first one that fails decides the status
//! (`broken` unless the check says otherwise); if all hold, `held`.

use std::collections::{BTreeMap, BTreeSet};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::time::Instant;

use near_contract_sim::nearcore::near_primitives::action::DeleteAccountAction;
use near_contract_sim::{Action, Balance, CryptoHash, Fault, Gas, Receipts, Sim, Tx, TxOutcome};
use serde::Serialize;
use serde_json::{Map, Value, json};

use crate::scenario::{Acct, Check, Expect, Outcome, Role, Scenario, Step, What, parse_near, parse_signed_near, parse_yocto};

pub const OWNER: &str = "owner.near";
pub const VICTIM: &str = "victim.near";
pub const ATTACKER: &str = "attacker.near";
pub const USER: &str = "user.near";
pub const YOCTO_PER_NEAR: u128 = 1_000_000_000_000_000_000_000_000;
/// Rounding slack for NEAR comparisons (1-yocto guards and the like).
pub const TOL: u128 = 1_000_000;

pub fn role(r: Role) -> &'static str {
    match r {
        Role::Owner => OWNER,
        Role::Victim => VICTIM,
        Role::Attacker => ATTACKER,
        Role::User => USER,
    }
}

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------

#[derive(Serialize, Clone, Copy, PartialEq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Held,
    Broken,
    Inconclusive,
    /// The scenario's precondition does not exist in this contract (e.g. no callback to test).
    NotApplicable,
    Error,
}

impl From<Outcome> for Status {
    fn from(o: Outcome) -> Self {
        match o {
            Outcome::Broken => Status::Broken,
            Outcome::Inconclusive => Status::Inconclusive,
            Outcome::NotApplicable => Status::NotApplicable,
        }
    }
}

#[derive(Serialize, Clone)]
pub struct Event {
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
pub struct TokenDelta {
    yocto: String,
    near: String,
}

#[derive(Serialize)]
pub struct ScenarioResult {
    pub id: String,
    pub name: String,
    pub status: Status,
    pub explanation: String,
    pub event_sequence: Vec<Event>,
    pub token_deltas: BTreeMap<String, TokenDelta>,
    pub findings: Vec<String>,
    pub trace: String,
    pub duration_ms: u128,
}

// ---------------------------------------------------------------------------
// Formatting
// ---------------------------------------------------------------------------

pub fn fmt_near(yocto: u128) -> String {
    let whole = yocto / YOCTO_PER_NEAR;
    let frac = (yocto % YOCTO_PER_NEAR) / 10u128.pow(20); // 4 decimals
    format!("{whole}.{frac:04}")
}

fn fmt_signed(y: i128) -> String {
    let s = if y < 0 { "-" } else if y > 0 { "+" } else { "" };
    format!("{s}{} NEAR", fmt_near(y.unsigned_abs()))
}

pub fn panic_text(out: &TxOutcome) -> String {
    let raw = out.failure().map(|f| f.to_string()).unwrap_or_default();
    // One line, no SDK source paths, bounded length: this text ends up in reports.
    let mut t = raw.split_whitespace().collect::<Vec<_>>().join(" ");
    if let Some(i) = t.find(", /") {
        t.truncate(i);
    }
    if let Some(i) = t.find("', src/") {
        t.truncate(i);
    }
    if t.chars().count() > 220 {
        t = t.chars().take(220).collect::<String>() + "…";
    }
    t
}

fn net_of(out: &TxOutcome, who: &str) -> i128 {
    i128::try_from(out.effects().near_net(who)).unwrap_or(0)
}

fn paid_to(out: &TxOutcome, who: &str) -> u128 {
    net_of(out, who).max(0) as u128
}

/// The contract's rejection names the caller's lack of rights (not a bad value).
fn is_access_control(msg: &str) -> bool {
    let m = msg.to_lowercase();
    [
        "permission", "is private", "only the owner", "only owner", "not the owner", "not owner", "owner only", "only the approver",
        "unauthori", "not authori", "not allowed", "access denied", "requires one of these roles", "predecessor", "must be called by",
        "can only be called", "only admin", "not an admin", "only the admin", "forbidden",
    ]
    .iter()
    .any(|p| m.contains(p))
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

fn transfer_failed(out: &TxOutcome) -> bool {
    out.receipts.iter().any(|r| r.actions.iter().any(|a| a.starts_with("Transfer")) && !r.is_success())
}

/// The contract called itself back at or after its payout Transfer: a failure branch exists.
fn callback_after_transfer(out: &TxOutcome, c: &str) -> bool {
    let transfer_block = out.receipts.iter().filter(|r| r.actions.iter().any(|a| a.starts_with("Transfer"))).map(|r| r.block_height).min();
    let Some(tb) = transfer_block else { return false };
    out.receipts.iter().any(|r| r.receiver_id.as_str() == c && r.predecessor_id.as_str() == c && !r.method_names.is_empty() && r.block_height >= tb)
}

// ---------------------------------------------------------------------------
// Recorder: what happened, per step
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct StepRecord {
    id: String,
    label: String,
    nets: BTreeMap<String, i128>,
    signer: Option<String>,
    deposit: u128,
    ok: bool,
    harness: bool,
    attack: bool,
    error: String,
    transfer_failed: bool,
    has_callback: bool,
    complete: bool,
    /// How many times the call's arguments were fixed from the contract's own errors (argfix).
    arg_repairs: usize,
}

#[derive(Clone)]
struct Recorder {
    contract: String,
    events: Vec<Event>,
    steps: Vec<StepRecord>,
    traces: Vec<String>,
}

struct RecordOpts<'a> {
    id: &'a str,
    signer: Option<&'a str>,
    deposit: u128,
    harness: bool,
    attack: bool,
}

impl Recorder {
    fn new(contract: &str) -> Self {
        Recorder { contract: contract.into(), events: vec![], steps: vec![], traces: vec![] }
    }

    fn watch(&self) -> [&str; 5] {
        [self.contract.as_str(), ATTACKER, VICTIM, USER, OWNER]
    }

    fn record(&mut self, label: &str, out: &TxOutcome, o: RecordOpts) {
        for r in &out.receipts {
            if r.refund.is_some() {
                continue; // gas / deposit refunds are not value movement worth showing
            }
            let action = if !r.method_names.is_empty() { format!("call {}", r.method_names.join(", ")) } else { r.actions.join(", ") };
            let failure = r.failure().map(|f| f.to_string());
            let fault = r.fault.as_ref().map(|f| format!(" [forced fault: {f:?}]")).unwrap_or_default();
            self.events.push(Event {
                step: label.into(),
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
        let nets = self.watch().iter().map(|w| (w.to_string(), net_of(out, w))).collect();
        self.steps.push(StepRecord {
            id: o.id.into(),
            label: label.into(),
            nets,
            signer: o.signer.map(String::from),
            deposit: o.deposit,
            ok: out.is_success(),
            harness: o.harness,
            attack: o.attack,
            error: panic_text(out),
            transfer_failed: transfer_failed(out),
            has_callback: callback_after_transfer(out, &self.contract),
            complete: out.is_complete(),
            arg_repairs: 0,
        });
        self.traces.push(format!("── {label} ──\n{out}"));
    }

    /// Net NEAR of `who` over the given steps (or every non-harness step). A tiny
    /// guard deposit (1 yocto) the account attached to its own successful call is
    /// added back, so "got its 5 NEAR back" is exact.
    fn net(&self, who: &str, steps: Option<&[String]>) -> i128 {
        self.steps
            .iter()
            .filter(|s| match steps {
                Some(ids) => ids.contains(&s.id),
                None => !s.harness,
            })
            .map(|s| {
                let guard = if s.ok && s.signer.as_deref() == Some(who) && s.deposit > 0 && s.deposit <= TOL { s.deposit as i128 } else { 0 };
                s.nets.get(who).copied().unwrap_or(0) + guard
            })
            .sum()
    }

    fn step(&self, id: &str) -> Option<&StepRecord> {
        self.steps.iter().rev().find(|s| s.id == id)
    }

    fn absorb(&mut self, other: Recorder) {
        self.events.extend(other.events);
        self.steps.extend(other.steps);
        self.traces.extend(other.traces);
    }

    fn finish(self, id: &str, name: &str, status: Status, explanation: String, sim: &Sim, t0: Instant) -> ScenarioResult {
        let token_deltas = self
            .watch()
            .iter()
            .map(|w| (w.to_string(), self.net(w, None)))
            .filter(|(_, d)| *d != 0)
            .map(|(k, d)| (k, TokenDelta { yocto: d.to_string(), near: fmt_signed(d) }))
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

// ---------------------------------------------------------------------------
// Shared sim moves
// ---------------------------------------------------------------------------

fn amount_args(amount_arg: &str, yocto: u128) -> Value {
    json!({ amount_arg: yocto.to_string() })
}

/// Fund `who` via a payable method; NEP-145 storage is registered first so the
/// deposit is credited in full (contracts without storage_deposit just refuse it).
fn deposit(sim: &mut Sim, rec: &mut Recorder, id: &str, who: &str, c: &str, method: &str, amount: u128) -> Result<(), String> {
    let reg = sim.call(who, c, "storage_deposit").args_json(json!({ "account_id": who })).deposit(Balance::from_yoctonear(YOCTO_PER_NEAR / 10)).transact();
    if reg.is_success() {
        rec.record(&format!("{who} registers storage (0.1 NEAR)"), &reg, RecordOpts { id: "storage", signer: Some(who), deposit: YOCTO_PER_NEAR / 10, harness: true, attack: false });
    }
    let out = sim.call(who, c, method).args_json(json!({})).deposit(Balance::from_yoctonear(amount)).transact();
    rec.record(&format!("{who} deposits {} NEAR", fmt_near(amount)), &out, RecordOpts { id, signer: Some(who), deposit: amount, harness: false, attack: false });
    if out.is_success() { Ok(()) } else { Err(panic_text(&out)) }
}

/// Control run on a scratch copy: deposit `d`, then withdraw it all with default
/// gas and no faults. Returns the yoctoNEAR the withdraw needs attached (0, or 1
/// for NEP-141-style guards). If this fails, a failure later is ours, not the contract's.
fn control(sim: &Sim, who: &str, c: &str, dep: &str, wd: &str, arg: &str, d: u128) -> Result<u128, String> {
    let mut s = sim.clone();
    let mut scratch = Recorder::new(c);
    deposit(&mut s, &mut scratch, "control", who, c, dep, d).map_err(|e| format!("deposit via `{dep}` failed: {e}"))?;
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

// ---------------------------------------------------------------------------
// World
// ---------------------------------------------------------------------------

pub struct World {
    pub sim: Sim,
    pub contract: String,
    pub init: Value,
    pub victim_deposit: Value,
}

pub struct InitCandidate {
    pub method: String,
    pub args: Value,
}

/// How many times init may fix its arguments from the contract's JSON errors.
const MAX_ARG_REPAIRS: usize = 30;

pub fn build_world(wasm: Vec<u8>, contract: &str, init_candidates: &[InitCandidate], deposit_method: Option<&str>) -> Result<World, String> {
    let mut sim = Sim::new();
    for a in [OWNER, VICTIM, ATTACKER, USER] {
        sim.create_account(a, Balance::from_near(100));
    }
    sim.create_account(contract, Balance::from_near(50));
    catch_unwind(AssertUnwindSafe(|| sim.deploy(contract, wasm))).map_err(|_| "deploy failed: the WASM did not load in nearcore's VM".to_string())?;

    let mut init = json!({ "ok": false, "tried": [] });
    'outer: for cand in init_candidates {
        for signer in [OWNER, contract] {
            // Call, and while the contract says which JSON field is missing or mistyped, fix it and call
            // again (argfix): bytecode has no argument names, but the contract's own errors do.
            let mut args = cand.args.clone();
            let mut repairs = 0;
            let out = loop {
                let out = sim.call(signer, contract, &cand.method).args_json(&args).transact();
                if out.is_success() || repairs >= MAX_ARG_REPAIRS {
                    break out;
                }
                let raw = out.failure().map(|f| f.to_string()).unwrap_or_default();
                match crate::argfix::repair(&raw, &args, OWNER) {
                    Some(next) => {
                        args = next;
                        repairs += 1;
                    }
                    None => break out,
                }
            };
            init["tried"].as_array_mut().unwrap().push(json!({ "method": cand.method, "signer": signer, "ok": out.is_success(), "error": panic_text(&out), "arg_repairs": repairs }));
            if out.is_success() {
                init["ok"] = json!(true);
                init["method"] = json!(cand.method);
                init["signer"] = json!(signer);
                if repairs > 0 {
                    // Only the fields the contract asked for, not the whole generic set.
                    let asked: Map<String, Value> = args.as_object().map(|m| m.iter().filter(|(k, _)| cand.args.get(k.as_str()).is_none()).map(|(k, v)| (k.clone(), v.clone())).collect()).unwrap_or_default();
                    init["discovered_args"] = Value::Object(asked);
                    init["arg_repairs"] = json!(repairs);
                }
                break 'outer;
            }
        }
    }

    let mut victim_deposit = json!(null);
    if let Some(dep) = deposit_method {
        let out = sim.call(VICTIM, contract, dep).args_json(json!({})).deposit(Balance::from_near(20)).transact();
        victim_deposit = json!({ "method": dep, "amount_near": 20, "ok": out.is_success(), "error": panic_text(&out) });
    }
    Ok(World { sim, contract: contract.into(), init, victim_deposit })
}

impl World {
    /// No init method to call at all counts as initialised (stateless or lazily-initialised contract).
    fn initialised(&self) -> bool {
        self.init["ok"] == json!(true) || self.init["tried"].as_array().is_none_or(|t| t.is_empty())
    }
}

// ---------------------------------------------------------------------------
// Interpreter
// ---------------------------------------------------------------------------

struct Snapshot {
    code: Option<CryptoHash>,
    keys: usize,
    state: Vec<(Vec<u8>, Vec<u8>)>,
}

impl Snapshot {
    fn take(sim: &Sim, c: &str) -> Self {
        Snapshot { code: sim.account(c).map(|a| a.code_hash), keys: sim.access_keys(c).len(), state: sim.view_state(c, b"") }
    }
}

struct Pending {
    hash: CryptoHash,
    label: String,
    signer: String,
    deposit: u128,
    harness: bool,
    attack: bool,
}

struct Env<'a> {
    c: &'a str,
    initialised: bool,
    start: &'a Snapshot,
    guard: u128,
    vars: BTreeMap<String, String>,
    pending: BTreeMap<String, Pending>,
    yielded: BTreeSet<String>,
    auto: usize,
}

/// Why execution stopped early (setup did not work): status + explanation.
type Stop = (Status, String);

#[allow(clippy::too_many_arguments)]
fn build_call<'s>(sim: &'s mut Sim, who: &str, c: &str, method: &str, args: &Value, d: u128, gas: Option<u64>, hold: Option<u64>) -> Tx<'s> {
    let mut b = sim.call(who, c, method).args_json(args).deposit(Balance::from_yoctonear(d));
    if let Some(t) = gas {
        b = b.gas(Gas::from_teragas(t));
    }
    if let Some(h) = hold {
        b = b.inject(Receipts::action("Transfer"), Fault::Hold(h));
    }
    b
}

fn exec(sim: &mut Sim, rec: &mut Recorder, steps: &[Step], env: &mut Env) -> Result<(), Stop> {
    for st in steps {
        match st {
            Step::Call { id, signer, method, args, deposit_near, deposit_yocto, guard_deposit, gas_tgas, is_async, hold_transfer_blocks, attack, harness, expect } => {
                env.auto += 1;
                let id = id.clone().unwrap_or_else(|| format!("s{}", env.auto));
                let who = role(*signer);
                let mut dep = match (deposit_near, deposit_yocto) {
                    (Some(n), _) => parse_near(n).map_err(|e| (Status::Error, e))?,
                    (_, Some(y)) => parse_yocto(y).map_err(|e| (Status::Error, e))?,
                    _ => 0,
                };
                if *guard_deposit {
                    dep += env.guard;
                }
                let gas = match gas_tgas {
                    Some(Value::String(s)) if s == "$tgas" => env.vars.get("tgas").and_then(|t| t.parse().ok()),
                    Some(v) => v.as_u64(),
                    None => None,
                };
                let mut args = if args.is_null() { json!({}) } else { args.clone() };
                let mut label = format!("{who} calls {method}");
                if dep > 0 {
                    label += &format!(" ({} NEAR attached)", if dep <= TOL { format!("{dep} yocto") } else { fmt_near(dep) });
                }
                if let Some(t) = gas {
                    label += &format!(" with {t} Tgas");
                }
                let hold = *hold_transfer_blocks;
                if *is_async {
                    let hash = build_call(sim, who, env.c, method, &args, dep, gas, hold).submit();
                    if hold_transfer_blocks.is_some() {
                        label += " (payout held in flight)";
                    }
                    env.pending.insert(id, Pending { hash, label, signer: who.into(), deposit: dep, harness: *harness, attack: *attack });
                    continue;
                }
                let mut out = build_call(sim, who, env.c, method, &args, dep, gas, hold).transact();
                // NEP-141-style "exactly 1 yoctoNEAR" guards: retry once with it, when no deposit was chosen.
                if out.is_failure() && dep == 0 && !*guard_deposit && deposit_near.is_none() && deposit_yocto.is_none() && needs_one_yocto(&panic_text(&out)) {
                    rec.record(&format!("{label} (no deposit)"), &out, RecordOpts { id: "retry", signer: Some(who), deposit: 0, harness: true, attack: false });
                    dep = 1;
                    label += " (1 yocto)";
                    out = build_call(sim, who, env.c, method, &args, 1, gas, hold).transact();
                }
                // The contract said which JSON field is missing or mistyped: fix it and call again
                // (argfix). Failed attempts change no state, so only the final call is recorded.
                let mut repairs = 0;
                while out.is_failure() && repairs < MAX_ARG_REPAIRS {
                    let raw = out.failure().map(|f| f.to_string()).unwrap_or_default();
                    let Some(next) = crate::argfix::repair(&raw, &args, who) else { break };
                    args = next;
                    repairs += 1;
                    out = build_call(sim, who, env.c, method, &args, dep, gas, hold).transact();
                }
                if repairs > 0 {
                    label += &format!(" (arguments fixed from {repairs} contract error(s))");
                }
                rec.record(&label, &out, RecordOpts { id: &id, signer: Some(who), deposit: dep, harness: *harness, attack: *attack });
                if let Some(last) = rec.steps.last_mut() {
                    last.arg_repairs = repairs;
                }
                match expect {
                    Some(Expect::Success) if out.is_failure() => {
                        return Err((Status::Inconclusive, format!("Setup call `{method}` by {who} was expected to succeed but failed: {}", panic_text(&out))));
                    }
                    Some(Expect::Failure) if out.is_success() => {
                        return Err((Status::Inconclusive, format!("Setup call `{method}` by {who} was expected to fail but succeeded.")));
                    }
                    _ => {}
                }
            }
            Step::Deposit { id, signer, method, near } => {
                env.auto += 1;
                let id = id.clone().unwrap_or_else(|| format!("s{}", env.auto));
                let d = parse_near(near).map_err(|e| (Status::Error, e))?;
                deposit(sim, rec, &id, role(*signer), env.c, method, d)
                    .map_err(|e| (Status::Inconclusive, format!("Could not deposit {} NEAR via `{method}`: {e}", fmt_near(d))))?;
            }
            Step::Control { signer, deposit_method, withdraw_method, amount_arg, near } => {
                let d = parse_near(near).map_err(|e| (Status::Error, e))?;
                env.guard = control(sim, role(*signer), env.c, deposit_method, withdraw_method, amount_arg, d).map_err(|e| {
                    (
                        Status::Inconclusive,
                        format!("Control run failed: a plain `{deposit_method}` of {} NEAR followed by a normal `{withdraw_method}` did not work in the sim ({e}). BitLens could not drive this contract's deposit/withdraw flow from bytecode alone, so this scenario was not judged.", fmt_near(d)),
                    )
                })?;
                env.vars.insert("guard".into(), env.guard.to_string());
            }
            Step::Settle {} => flush(sim, rec, env),
            Step::WaitForReceipt { step, method } => {
                if let Some(p) = env.pending.get(step) {
                    let h = p.hash;
                    let _ = sim.run_until(20, |s| s.outcome(h).receipt(method).is_some());
                }
            }
            Step::WaitForYield { step } => {
                let _ = sim.run_until(10, |s| !s.yields().is_empty() || s.is_idle());
                if !sim.yields().is_empty() {
                    env.yielded.insert(step.clone());
                }
            }
            Step::AdvancePastYield {} => {
                if let Some(y) = sim.yields().first() {
                    let deadline = y.expires_at;
                    sim.advance_to(deadline);
                    env.vars.insert("deadline".into(), deadline.to_string());
                }
            }
            Step::AdvanceBlocks { blocks } => {
                let h = sim.height() + blocks;
                sim.advance_to(h);
            }
            Step::DeleteAccount { account, beneficiary } => {
                let (a, b) = (role(*account), role(*beneficiary));
                let out = sim.tx(a, a).action(Action::DeleteAccount(DeleteAccountAction { beneficiary_id: b.parse().unwrap() })).transact();
                rec.record(&format!("{a} deletes its account (test harness)"), &out, RecordOpts { id: "delete", signer: Some(a), deposit: 0, harness: true, attack: false });
            }
            Step::CreateAccount { account, near } => {
                let d = parse_near(near).map_err(|e| (Status::Error, e))?;
                sim.create_account(role(*account), Balance::from_yoctonear(d));
            }
            Step::Sweep { gas_tgas, steps, checks, label } => sweep(sim, rec, env, gas_tgas, steps, checks, label.as_deref())?,
        }
    }
    Ok(())
}

/// Settle and record every async call still in flight.
fn flush(sim: &mut Sim, rec: &mut Recorder, env: &mut Env) {
    if env.pending.is_empty() {
        return;
    }
    sim.settle();
    for (id, p) in std::mem::take(&mut env.pending) {
        let out = sim.outcome(p.hash);
        rec.record(&p.label, &out, RecordOpts { id: &id, signer: Some(&p.signer), deposit: p.deposit, harness: p.harness, attack: p.attack });
    }
}

fn sweep(sim: &mut Sim, rec: &mut Recorder, env: &mut Env, values: &[u64], steps: &[Step], checks: &[Check], label: Option<&str>) -> Result<(), Stop> {
    let mut lines: Vec<(u64, String)> = vec![];
    let mut first: Option<Recorder> = None;
    let mut violation: Option<(u64, Status, String, Recorder)> = None;
    for &tg in values {
        let mut s = sim.clone();
        let mut r = Recorder::new(env.c);
        let mut e = Env {
            c: env.c,
            initialised: env.initialised,
            start: env.start,
            guard: env.guard,
            vars: env.vars.clone(),
            pending: BTreeMap::new(),
            yielded: BTreeSet::new(),
            auto: env.auto,
        };
        e.vars.insert("tgas".into(), tg.to_string());
        exec(&mut s, &mut r, steps, &mut e)?;
        flush(&mut s, &mut r, &mut e);
        let verdict = evaluate(&s, &r, &e, checks);
        lines.push((tg, render(label.unwrap_or("{result}"), &r, &e).replace("{result}", if verdict.is_none() { "ok" } else { "violated" })));
        match verdict {
            Some((st, msg)) if violation.is_none() => violation = Some((tg, st, msg, r)),
            None if first.is_none() => first = Some(r),
            _ => {}
        }
    }
    // Compress runs of identical outcomes: "8-25 Tgas: refused; 30-300 Tgas: ok".
    let mut runs: Vec<(u64, u64, String)> = vec![];
    for (tg, what) in lines {
        match runs.last_mut() {
            Some((_, hi, w)) if *w == what => *hi = tg,
            _ => runs.push((tg, tg, what)),
        }
    }
    let summary = runs.iter().map(|(lo, hi, w)| if lo == hi { format!("{lo} Tgas: {w}") } else { format!("{lo}-{hi} Tgas: {w}") }).collect::<Vec<_>>().join("; ");
    env.vars.insert("sweep".into(), summary.clone());
    if let Some((tg, st, msg, r)) = violation {
        rec.absorb(r);
        return Err((st, format!("{} Sweep: {summary}", msg.replace("{tgas}", &tg.to_string()))));
    }
    if let Some(r) = first {
        rec.absorb(r);
    }
    Ok(())
}

fn acct<'a>(a: Acct, c: &'a str) -> &'a str {
    match a {
        Acct::Owner => OWNER,
        Acct::Victim => VICTIM,
        Acct::Attacker => ATTACKER,
        Acct::User => USER,
        Acct::Contract => c,
    }
}

/// Fill `{net.attacker}`, `{error.step}`, `{status.step}`, `{tgas}`, `{sweep}`, `{deadline}`…
fn render(t: &str, rec: &Recorder, env: &Env) -> String {
    let mut out = String::new();
    let mut rest = t;
    while let Some(i) = rest.find('{') {
        out.push_str(&rest[..i]);
        let tail = &rest[i + 1..];
        let Some(j) = tail.find('}') else {
            out.push_str(&rest[i..]);
            return out;
        };
        let key = &tail[..j];
        let val = if let Some(a) = key.strip_prefix("net.") {
            let who = match a {
                "contract" => Some(env.c),
                "owner" => Some(OWNER),
                "victim" => Some(VICTIM),
                "attacker" => Some(ATTACKER),
                "user" => Some(USER),
                _ => None,
            };
            who.map(|w| fmt_signed(rec.net(w, None)))
        } else if let Some(s) = key.strip_prefix("error.") {
            rec.step(s).map(|r| if r.error.is_empty() { "no error".into() } else { r.error.clone() })
        } else if let Some(s) = key.strip_prefix("status.") {
            rec.step(s).map(|r| if r.ok { "succeeded".into() } else { "failed".into() })
        } else {
            env.vars.get(key).cloned()
        };
        match val {
            Some(v) => out.push_str(&v),
            None => out.push_str(&rest[i..i + j + 2]),
        }
        rest = &tail[j + 1..];
    }
    out.push_str(rest);
    out
}

/// First failing check → (status, explanation). None = all held.
fn evaluate(sim: &Sim, rec: &Recorder, env: &Env, checks: &[Check]) -> Option<(Status, String)> {
    for ch in checks {
        let (pass, otherwise, message, default_msg): (bool, Option<Outcome>, &Option<String>, String) = match ch {
            Check::NetAtMost { account, near, steps, otherwise, message } => {
                let who = acct(*account, env.c);
                let (got, lim) = (rec.net(who, steps.as_deref()), parse_signed_near(near));
                (got <= lim + TOL as i128, *otherwise, message, format!("{who} ended {} (limit {}).", fmt_signed(got), fmt_signed(lim)))
            }
            Check::NetAtLeast { account, near, steps, otherwise, message } => {
                let who = acct(*account, env.c);
                let (got, lim) = (rec.net(who, steps.as_deref()), parse_signed_near(near));
                (got + TOL as i128 >= lim, *otherwise, message, format!("{who} ended {} (must be at least {}).", fmt_signed(got), fmt_signed(lim)))
            }
            Check::NetEquals { account, near, steps, otherwise, message } => {
                let who = acct(*account, env.c);
                let (got, want) = (rec.net(who, steps.as_deref()), parse_signed_near(near));
                (got.abs_diff(want) <= TOL, *otherwise, message, format!("{who} ended {} instead of {}.", fmt_signed(got), fmt_signed(want)))
            }
            Check::Unchanged { what, otherwise, message } => {
                let now = Snapshot::take(sim, env.c);
                let (pass, msg) = match what {
                    What::Code => (now.code == env.start.code, format!("{}'s contract code was replaced.", env.c)),
                    What::Keys => (now.keys == env.start.keys, format!("{} access key(s) were added to {}.", now.keys.saturating_sub(env.start.keys), env.c)),
                    What::State => (now.state == env.start.state, format!("{}'s storage changed.", env.c)),
                };
                (pass, *otherwise, message, msg)
            }
            Check::StepSucceeded { step, otherwise, message } => {
                let r = rec.step(step);
                (r.is_some_and(|r| r.ok), otherwise.or(Some(Outcome::Inconclusive)), message, format!("Step `{step}` did not succeed: {}", r.map(|r| r.error.as_str()).unwrap_or("it never ran")))
            }
            Check::StepFailed { step, otherwise, message } => {
                let r = rec.step(step);
                (r.is_some_and(|r| !r.ok), *otherwise, message, format!("Step `{step}` succeeded but should have been rejected."))
            }
            Check::AnySucceeded { steps, otherwise, message } => {
                let any = steps.iter().any(|s| rec.step(s).is_some_and(|r| r.ok));
                let err = steps.first().and_then(|s| rec.step(s)).map(|r| r.error.clone()).unwrap_or_default();
                (any, otherwise.or(Some(Outcome::Inconclusive)), message, format!("None of {} succeeded ({err}), so the scenario was not exercised.", steps.join(", ")))
            }
            Check::TransferFailed { step, otherwise, message } => {
                let r = rec.step(step);
                (r.is_some_and(|r| r.transfer_failed), otherwise.or(Some(Outcome::Inconclusive)), message, format!("Could not make the payout transfer of `{step}` fail."))
            }
            Check::CallbackAfterTransfer { step, otherwise, message } => {
                let r = rec.step(step);
                (r.is_some_and(|r| r.has_callback), otherwise.or(Some(Outcome::NotApplicable)), message, format!("`{step}` pays out with no callback afterwards, so there is no failure branch to test."))
            }
            Check::Completed { step, otherwise, message } => {
                let r = rec.step(step);
                let findings = sim.findings().len();
                (r.is_some_and(|r| r.complete) && findings == 0, *otherwise, message, format!("`{step}` did not resolve cleanly ({findings} sim finding(s), complete: {}).", r.is_some_and(|r| r.complete)))
            }
            Check::Yielded { step, otherwise, message } => {
                (env.yielded.contains(step), otherwise.or(Some(Outcome::Inconclusive)), message, format!("`{step}` did not create a yield with the arguments given, so the timeout path was not exercised."))
            }
        };
        if !pass {
            let status = otherwise.map(Status::from).unwrap_or(Status::Broken);
            let text = message.as_deref().map(|m| render(m, rec, env)).unwrap_or(default_msg);
            return Some((status, text));
        }
    }
    None
}

/// "attacker net ≤ 0, state unchanged" for default explanations.
fn check_names(checks: &[Check]) -> String {
    let who = |a: &Acct| format!("{a:?}").to_lowercase();
    let names: Vec<String> = checks
        .iter()
        .map(|c| match c {
            Check::NetAtMost { account, near, .. } => format!("{} net ≤ {} NEAR", who(account), near.as_str().map(String::from).unwrap_or(near.to_string())),
            Check::NetAtLeast { account, near, .. } => format!("{} net ≥ {} NEAR", who(account), near.as_str().map(String::from).unwrap_or(near.to_string())),
            Check::NetEquals { account, near, .. } => format!("{} net = {} NEAR", who(account), near.as_str().map(String::from).unwrap_or(near.to_string())),
            Check::Unchanged { what, .. } => format!("contract {} unchanged", format!("{what:?}").to_lowercase()),
            Check::StepSucceeded { step, .. } => format!("`{step}` succeeded"),
            Check::StepFailed { step, .. } => format!("`{step}` rejected"),
            Check::AnySucceeded { .. } => "setup ran".into(),
            Check::TransferFailed { .. } => "payout failure triggered".into(),
            Check::CallbackAfterTransfer { .. } => "failure branch present".into(),
            Check::Completed { step, .. } => format!("`{step}` resolved cleanly"),
            Check::Yielded { step, .. } => format!("`{step}` yielded"),
        })
        .collect();
    if names.is_empty() { "none were given".into() } else { names.join(", ") }
}

pub fn run_scenario(world: &World, sc: &Scenario) -> ScenarioResult {
    let t0 = Instant::now();
    let mut sim = world.sim.clone();
    let c = world.contract.as_str();
    let mut rec = Recorder::new(c);
    let start = Snapshot::take(&sim, c);
    let mut env = Env {
        c,
        initialised: world.initialised(),
        start: &start,
        guard: 0,
        vars: BTreeMap::new(),
        pending: BTreeMap::new(),
        yielded: BTreeSet::new(),
        auto: 0,
    };
    let ran = exec(&mut sim, &mut rec, &sc.steps, &mut env);
    flush(&mut sim, &mut rec, &mut env);
    let (status, explanation) = match ran {
        Err((st, msg)) => (st, msg),
        Ok(()) => match evaluate(&sim, &rec, &env, &sc.checks) {
            Some(v) => v,
            None => {
                // Every check held. A rejected attack call only proves access control if
                // the contract was set up and the rejection is not an argument problem.
                let rejected = rec.steps.iter().find(|s| s.attack && !s.ok).cloned();
                match rejected {
                    Some(r) if !env.initialised => (
                        Status::Inconclusive,
                        format!("The contract could not be initialised in the sim (no init method accepted the guessed arguments), so this rejection may only mean missing state, not an owner check. Contract said: {}", r.error),
                    ),
                    Some(r) if r.error.contains("MethodNotFound") => (
                        Status::Inconclusive,
                        format!("The contract has no such method ({}), so there was nothing to attack.", r.label),
                    ),
                    Some(r) if is_input_problem(&r.error) => (
                        Status::Inconclusive,
                        format!("Could not build valid arguments for this call from bytecode alone, so access control was not exercised. Contract said: {}", r.error),
                    ),
                    // Discovered arguments contain guessed values: a rejection only proves access
                    // control when the contract says so, not when it rejects one of our values.
                    Some(r) if r.arg_repairs > 0 && !is_access_control(&r.error) => (
                        Status::Inconclusive,
                        format!(
                            "BitLens found this call's arguments from the contract's own errors ({} fix(es)), but the contract then rejected one of the guessed values, not the caller, so access control was not exercised. Contract said: {}",
                            r.arg_repairs, r.error
                        ),
                    ),
                    Some(_) if sc.explain.rejected.is_some() => (Status::Held, render(sc.explain.rejected.as_deref().unwrap(), &rec, &env)),
                    Some(r) if sc.explain.held.is_none() => (Status::Held, format!("The attack was rejected ({}): {}. Checks held: {}.", r.label, r.error, check_names(&sc.checks))),
                    _ => (
                        Status::Held,
                        sc.explain.held.as_deref().map(|t| render(t, &rec, &env)).unwrap_or_else(|| format!("Every check held: {}.", check_names(&sc.checks))),
                    ),
                }
            }
        },
    };
    rec.finish(&sc.id, &sc.name, status, explanation, &sim, t0)
}
