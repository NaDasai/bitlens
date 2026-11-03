//! The scenario language: one JSON object per attack.
//!
//! Every scenario, whether a canned preset (scenarios/presets/*.json) or one
//! translated from plain English by an LLM, is this same data. The runner
//! never executes code from a scenario: it maps each step onto a fixed set of
//! near-contract-sim operations against the contract under test, then
//! evaluates the checks. Input is untrusted, so `validate` bounds everything.
//!
//! ```json
//! { "id": "custom_drain", "name": "Anyone can drain",
//!   "steps":  [ { "op": "call", "id": "hit", "as": "attacker", "method": "admin_drain",
//!                 "args": { "receiver_id": "attacker.near" }, "attack": true } ],
//!   "checks": [ { "check": "net_at_most", "account": "attacker", "near": "0" } ] }
//! ```

use serde::Deserialize;
use serde_json::Value;

/// Accounts a scenario may sign with: the sim's fixed test accounts, never arbitrary ids.
#[derive(Deserialize, Clone, Copy, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Owner,
    Victim,
    Attacker,
    User,
}

/// Accounts a check may look at: the roles plus the contract under test.
#[derive(Deserialize, Clone, Copy, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Acct {
    Owner,
    Victim,
    Attacker,
    User,
    Contract,
}

#[derive(Deserialize, Clone, Copy, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Broken,
    Inconclusive,
    NotApplicable,
}

#[derive(Deserialize, Clone, Copy, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Expect {
    Success,
    Failure,
}

#[derive(Deserialize, Clone, Copy, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum What {
    Code,
    Keys,
    State,
}

#[derive(Deserialize, Default, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct Explain {
    /// Shown when every check held.
    #[serde(default)]
    pub held: Option<String>,
    /// Shown instead when every check held because an `attack: true` call was rejected.
    #[serde(default)]
    pub rejected: Option<String>,
}

#[derive(Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct Scenario {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    pub steps: Vec<Step>,
    #[serde(default)]
    pub checks: Vec<Check>,
    #[serde(default)]
    pub explain: Explain,
}

#[derive(Deserialize, Clone, Debug)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Step {
    /// A function call on the contract under test.
    Call {
        #[serde(default)]
        id: Option<String>,
        #[serde(rename = "as")]
        signer: Role,
        method: String,
        #[serde(default)]
        args: Value,
        /// NEAR to attach (decimal string or number).
        #[serde(default)]
        deposit_near: Option<Value>,
        /// yoctoNEAR to attach (integer string or number).
        #[serde(default)]
        deposit_yocto: Option<Value>,
        /// Attach the 0-or-1 yocto that the last `control` step found the contract needs.
        #[serde(default)]
        guard_deposit: bool,
        /// Tgas to attach (number), or "$tgas" inside a sweep.
        #[serde(default)]
        gas_tgas: Option<Value>,
        /// Submit without waiting: several async calls land in the same block.
        #[serde(default, rename = "async")]
        is_async: bool,
        /// Hold the payout Transfer receipts this many blocks (to act while it is in flight).
        #[serde(default)]
        hold_transfer_blocks: Option<u64>,
        /// The call under test: if it is rejected and the contract was never initialised,
        /// or the rejection is an argument-decoding error, the result is inconclusive.
        #[serde(default)]
        attack: bool,
        /// Test-harness move: shown in the sequence, kept out of the NEAR totals.
        #[serde(default)]
        harness: bool,
        /// Setup expectation: if not met, the scenario stops as inconclusive.
        #[serde(default)]
        expect: Option<Expect>,
    },
    /// Fund `as` in the contract via a payable method (registers NEP-145 storage first).
    Deposit {
        #[serde(default)]
        id: Option<String>,
        #[serde(rename = "as")]
        signer: Role,
        method: String,
        near: Value,
    },
    /// Control run on a scratch copy: deposit then withdraw `near`. Inconclusive if that
    /// does not work; otherwise records the 0/1 yocto guard for `guard_deposit` calls.
    Control {
        #[serde(rename = "as")]
        signer: Role,
        deposit_method: String,
        withdraw_method: String,
        #[serde(default = "default_amount_arg")]
        amount_arg: String,
        near: Value,
    },
    /// Run blocks until nothing is in flight; async calls are recorded here.
    Settle {},
    /// Run until the async call `step` reaches its receipt for `method`.
    WaitForReceipt { step: String, method: String },
    /// Run until the async call `step` has created a yield (NEP-519).
    WaitForYield { step: String },
    /// Advance the chain to the first pending yield's timeout block.
    AdvancePastYield {},
    /// Advance the chain this many blocks.
    AdvanceBlocks { blocks: u64 },
    /// Harness: delete a test account (its balance goes to `beneficiary`).
    DeleteAccount { account: Role, beneficiary: Role },
    /// Harness: (re)create a test account with a balance.
    CreateAccount { account: Role, near: Value },
    /// Repeat `steps` on a fresh copy of the current state for each gas value
    /// (`gas_tgas: "$tgas"` in the steps), evaluating `checks` each time.
    Sweep {
        gas_tgas: Vec<u64>,
        steps: Vec<Step>,
        #[serde(default)]
        checks: Vec<Check>,
        /// Per-value summary, e.g. "{status.first}, recoverable {net.user}".
        #[serde(default)]
        label: Option<String>,
    },
}

fn default_amount_arg() -> String {
    "amount".into()
}

#[derive(Deserialize, Clone, Debug)]
#[serde(tag = "check", rename_all = "snake_case", deny_unknown_fields)]
pub enum Check {
    /// Net NEAR of `account` (over `steps`, or every non-harness step) must be <= `near`.
    NetAtMost {
        account: Acct,
        near: Value,
        #[serde(default)]
        steps: Option<Vec<String>>,
        #[serde(default, rename = "else")]
        otherwise: Option<Outcome>,
        #[serde(default)]
        message: Option<String>,
    },
    NetAtLeast {
        account: Acct,
        near: Value,
        #[serde(default)]
        steps: Option<Vec<String>>,
        #[serde(default, rename = "else")]
        otherwise: Option<Outcome>,
        #[serde(default)]
        message: Option<String>,
    },
    NetEquals {
        account: Acct,
        near: Value,
        #[serde(default)]
        steps: Option<Vec<String>>,
        #[serde(default, rename = "else")]
        otherwise: Option<Outcome>,
        #[serde(default)]
        message: Option<String>,
    },
    /// The contract's code / access keys / storage must equal what it was before the steps.
    Unchanged {
        what: What,
        #[serde(default, rename = "else")]
        otherwise: Option<Outcome>,
        #[serde(default)]
        message: Option<String>,
    },
    StepSucceeded {
        step: String,
        #[serde(default, rename = "else")]
        otherwise: Option<Outcome>,
        #[serde(default)]
        message: Option<String>,
    },
    StepFailed {
        step: String,
        #[serde(default, rename = "else")]
        otherwise: Option<Outcome>,
        #[serde(default)]
        message: Option<String>,
    },
    AnySucceeded {
        steps: Vec<String>,
        #[serde(default, rename = "else")]
        otherwise: Option<Outcome>,
        #[serde(default)]
        message: Option<String>,
    },
    /// A Transfer receipt of the call failed.
    TransferFailed {
        step: String,
        #[serde(default, rename = "else")]
        otherwise: Option<Outcome>,
        #[serde(default)]
        message: Option<String>,
    },
    /// The contract called itself back after the call's Transfer (a failure branch exists).
    CallbackAfterTransfer {
        step: String,
        #[serde(default, rename = "else")]
        otherwise: Option<Outcome>,
        #[serde(default)]
        message: Option<String>,
    },
    /// The call's receipt tree finished and the sim raised no findings.
    Completed {
        step: String,
        #[serde(default, rename = "else")]
        otherwise: Option<Outcome>,
        #[serde(default)]
        message: Option<String>,
    },
    /// The call created a yield (see wait_for_yield).
    Yielded {
        step: String,
        #[serde(default, rename = "else")]
        otherwise: Option<Outcome>,
        #[serde(default)]
        message: Option<String>,
    },
}

// ---------------------------------------------------------------------------
// Validation: scenarios may come from an LLM, so bound everything.
// ---------------------------------------------------------------------------

pub const MAX_STEPS: usize = 40;
pub const MAX_CHECKS: usize = 20;
pub const MAX_NEAR: u128 = 1000;
pub const MAX_ARGS_BYTES: usize = 16 * 1024;

fn ident_ok(s: &str, max: usize) -> bool {
    !s.is_empty() && s.len() <= max && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b':')
}

fn method_ok(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// Parse a NEAR amount (number or decimal string, up to 24 decimals) into yocto.
pub fn parse_near(v: &Value) -> Result<u128, String> {
    let s = match v {
        Value::Number(n) => n.to_string(),
        Value::String(s) => s.trim().to_string(),
        _ => return Err(format!("amount must be a number or decimal string, got {v}")),
    };
    let (neg, s) = s.strip_prefix('-').map(|r| (true, r.to_string())).unwrap_or((false, s));
    if neg {
        return Err(format!("amount must not be negative: -{s}"));
    }
    let (int, frac) = s.split_once('.').unwrap_or((&s, ""));
    if int.is_empty() && frac.is_empty() || !int.bytes().all(|b| b.is_ascii_digit()) || !frac.bytes().all(|b| b.is_ascii_digit()) || frac.len() > 24 {
        return Err(format!("bad NEAR amount {s:?}"));
    }
    let int: u128 = if int.is_empty() { 0 } else { int.parse().map_err(|_| format!("bad NEAR amount {s:?}"))? };
    if int > MAX_NEAR {
        return Err(format!("NEAR amount {s} is above the {MAX_NEAR} NEAR limit"));
    }
    let frac_y: u128 = if frac.is_empty() { 0 } else { format!("{frac:0<24}").parse().unwrap() };
    Ok(int * 1_000_000_000_000_000_000_000_000 + frac_y)
}

pub fn parse_yocto(v: &Value) -> Result<u128, String> {
    let y: u128 = match v {
        Value::Number(n) => n.as_u64().map(u128::from).ok_or_else(|| format!("bad yocto amount {n}"))?,
        Value::String(s) => s.trim().parse().map_err(|_| format!("bad yocto amount {s:?}"))?,
        _ => return Err(format!("yocto amount must be an integer, got {v}")),
    };
    if y > MAX_NEAR * 1_000_000_000_000_000_000_000_000 {
        return Err("yocto amount above the limit".into());
    }
    Ok(y)
}

pub fn validate(sc: &Scenario) -> Result<(), String> {
    if !ident_ok(&sc.id, 96) {
        return Err(format!("scenario id {:?}: use 1-96 of a-z A-Z 0-9 _ - :", sc.id));
    }
    if sc.name.is_empty() || sc.name.len() > 160 {
        return Err("scenario name must be 1-160 characters".into());
    }
    if sc.description.as_ref().is_some_and(|d| d.len() > 1000) {
        return Err("scenario description longer than 1000 characters".into());
    }
    if sc.steps.is_empty() {
        return Err("a scenario needs at least one step".into());
    }
    let mut ids: Vec<String> = vec![];
    let mut count = 0usize;
    validate_steps(&sc.steps, false, &mut ids, &mut count)?;
    if count > MAX_STEPS {
        return Err(format!("too many steps ({count} > {MAX_STEPS})"));
    }
    if sc.checks.len() > MAX_CHECKS {
        return Err(format!("too many checks ({} > {MAX_CHECKS})", sc.checks.len()));
    }
    validate_checks(&sc.checks, &ids)?;
    for t in [&sc.explain.held, &sc.explain.rejected].into_iter().flatten() {
        if t.len() > 600 {
            return Err("explain text longer than 600 characters".into());
        }
    }
    Ok(())
}

fn validate_steps(steps: &[Step], in_sweep: bool, ids: &mut Vec<String>, count: &mut usize) -> Result<(), String> {
    let add_id = |id: &Option<String>, ids: &mut Vec<String>| -> Result<(), String> {
        if let Some(id) = id {
            if !ident_ok(id, 32) {
                return Err(format!("step id {id:?}: use 1-32 of a-z A-Z 0-9 _ -"));
            }
            if ids.contains(id) {
                return Err(format!("duplicate step id {id:?}"));
            }
            ids.push(id.clone());
        }
        Ok(())
    };
    for st in steps {
        *count += 1;
        match st {
            Step::Call { id, method, args, deposit_near, deposit_yocto, gas_tgas, is_async, hold_transfer_blocks, expect, .. } => {
                add_id(id, ids)?;
                if !method_ok(method) {
                    return Err(format!("method name {method:?} is not a valid NEAR method name"));
                }
                if !(args.is_null() || args.is_object()) {
                    return Err(format!("args of `{method}` must be a JSON object"));
                }
                if serde_json::to_vec(args).map(|v| v.len()).unwrap_or(usize::MAX) > MAX_ARGS_BYTES {
                    return Err(format!("args of `{method}` larger than {MAX_ARGS_BYTES} bytes"));
                }
                if let Some(v) = deposit_near {
                    parse_near(v)?;
                }
                if let Some(v) = deposit_yocto {
                    parse_yocto(v)?;
                }
                if deposit_near.is_some() && deposit_yocto.is_some() {
                    return Err(format!("`{method}`: give deposit_near or deposit_yocto, not both"));
                }
                match gas_tgas {
                    None => {}
                    Some(Value::String(s)) if s == "$tgas" => {
                        if !in_sweep {
                            return Err("gas_tgas \"$tgas\" is only allowed inside a sweep".into());
                        }
                    }
                    Some(v) => match v.as_u64() {
                        Some(t) if (1..=300).contains(&t) => {}
                        _ => return Err(format!("gas_tgas must be 1-300, got {v}")),
                    },
                }
                if hold_transfer_blocks.is_some_and(|b| b == 0 || b > 50) {
                    return Err("hold_transfer_blocks must be 1-50".into());
                }
                if hold_transfer_blocks.is_some() && !is_async {
                    return Err("hold_transfer_blocks needs \"async\": true (act while the payout is held)".into());
                }
                if *is_async && expect.is_some() {
                    return Err("expect is only for synchronous calls".into());
                }
            }
            Step::Deposit { id, method, near, .. } => {
                add_id(id, ids)?;
                if !method_ok(method) {
                    return Err(format!("method name {method:?} is not valid"));
                }
                parse_near(near)?;
            }
            Step::Control { deposit_method, withdraw_method, amount_arg, near, .. } => {
                for m in [deposit_method, withdraw_method, amount_arg] {
                    if !method_ok(m) {
                        return Err(format!("name {m:?} is not valid"));
                    }
                }
                parse_near(near)?;
            }
            Step::Settle {} | Step::AdvancePastYield {} => {}
            Step::WaitForReceipt { step, method } => {
                if !ids.contains(step) || !method_ok(method) {
                    return Err(format!("wait_for_receipt refers to unknown step {step:?} or bad method"));
                }
            }
            Step::WaitForYield { step } => {
                if !ids.contains(step) {
                    return Err(format!("wait_for_yield refers to unknown step {step:?}"));
                }
            }
            Step::AdvanceBlocks { blocks } => {
                if *blocks == 0 || *blocks > 5000 {
                    return Err("advance_blocks must be 1-5000".into());
                }
            }
            Step::DeleteAccount { account, beneficiary } => {
                if account == beneficiary {
                    return Err("delete_account: beneficiary must differ from the account".into());
                }
            }
            Step::CreateAccount { near, .. } => {
                parse_near(near)?;
            }
            Step::Sweep { gas_tgas, steps, checks, label } => {
                if in_sweep {
                    return Err("sweeps cannot be nested".into());
                }
                if gas_tgas.is_empty() || gas_tgas.len() > 20 || gas_tgas.iter().any(|t| *t == 0 || *t > 300) {
                    return Err("sweep gas_tgas: 1-20 values, each 1-300".into());
                }
                if label.as_ref().is_some_and(|l| l.len() > 200) {
                    return Err("sweep label longer than 200 characters".into());
                }
                let mut inner = ids.clone();
                validate_steps(steps, true, &mut inner, count)?;
                validate_checks(checks, &inner)?;
                // Ids inside a sweep are per-iteration; outer checks may not refer to them.
            }
        }
    }
    Ok(())
}

fn validate_checks(checks: &[Check], ids: &[String]) -> Result<(), String> {
    let known = |s: &String| -> Result<(), String> {
        if ids.contains(s) { Ok(()) } else { Err(format!("check refers to unknown step id {s:?}")) }
    };
    for c in checks {
        let message = match c {
            Check::NetAtMost { near, steps, message, .. } | Check::NetAtLeast { near, steps, message, .. } | Check::NetEquals { near, steps, message, .. } => {
                // Negative bounds are allowed for net checks ("lost at most 1 NEAR" = at_least -1).
                let v = match near {
                    Value::String(s) => Value::String(s.trim_start_matches('-').to_string()),
                    Value::Number(n) => Value::String(n.to_string().trim_start_matches('-').to_string()),
                    other => other.clone(),
                };
                parse_near(&v)?;
                for s in steps.iter().flatten() {
                    known(s)?;
                }
                message
            }
            Check::Unchanged { message, .. } => message,
            Check::StepSucceeded { step, message, .. }
            | Check::StepFailed { step, message, .. }
            | Check::TransferFailed { step, message, .. }
            | Check::CallbackAfterTransfer { step, message, .. }
            | Check::Completed { step, message, .. }
            | Check::Yielded { step, message, .. } => {
                known(step)?;
                message
            }
            Check::AnySucceeded { steps, message, .. } => {
                for s in steps {
                    known(s)?;
                }
                message
            }
        };
        if message.as_ref().is_some_and(|m| m.len() > 600) {
            return Err("check message longer than 600 characters".into());
        }
    }
    Ok(())
}

/// Signed NEAR bound for net checks (may be negative).
pub fn parse_signed_near(v: &Value) -> i128 {
    let s = match v {
        Value::String(s) => s.trim().to_string(),
        Value::Number(n) => n.to_string(),
        _ => "0".into(),
    };
    let (neg, rest) = s.strip_prefix('-').map(|r| (true, r)).unwrap_or((false, s.as_str()));
    let y = parse_near(&Value::String(rest.to_string())).unwrap_or(0) as i128;
    if neg { -y } else { y }
}
