//! YIELD ESCROW: a vault whose payouts wait for an approver, using NEP-519
//! yield/resume. Same deposit / withdraw / get_balance interface as the other
//! demo vaults; plain `withdraw` is the correct one from clean_vault.
//!
//! - `request_payout(amount)` debits the caller and yields until the approver
//!   calls `approve_payout(request_id, approved)`. The yield callback
//!   `on_payout_decision` pays out on approval and re-credits on rejection.
//! - **Planted bug:** if nobody answers before the yield times out (~200
//!   blocks), the callback receives an error and only logs "expired". It never
//!   re-credits, so the requested NEAR is stuck in the contract with no owner.
//!   (Build with `--features fixed` for the correct version.)
//!
//! A capability scan shows only an ordinary payout contract. The bug is in the
//! timeout path, so it only shows up when that path is actually run.

use near_sdk::json_types::U128;
use near_sdk::store::LookupMap;
use near_sdk::{
    env, log, near, require, AccountId, Gas, GasWeight, NearToken, PanicOnDefault, Promise, PromiseError, PromiseOrValue,
    YieldId,
};

const GAS_FOR_ON_WITHDRAW: Gas = Gas::from_tgas(10);
const GAS_FOR_DECISION: Gas = Gas::from_tgas(30);
const MIN_WITHDRAW_GAS: Gas = Gas::from_tgas(30);

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Escrow {
    owner_id: AccountId,
    approver_id: AccountId,
    balances: LookupMap<AccountId, u128>,
    pending: LookupMap<u64, YieldId>,
    next_request: u64,
    total: u128,
}

#[near]
impl Escrow {
    #[init]
    pub fn new(owner_id: AccountId, approver_id: Option<AccountId>) -> Self {
        let approver_id = approver_id.unwrap_or_else(|| owner_id.clone());
        Self { owner_id, approver_id, balances: LookupMap::new(b"b"), pending: LookupMap::new(b"p"), next_request: 0, total: 0 }
    }

    #[payable]
    pub fn deposit(&mut self) {
        let amount = env::attached_deposit().as_yoctonear();
        require!(amount > 0, "attach NEAR to deposit");
        let caller = env::predecessor_account_id();
        let bal = self.bal(&caller);
        self.balances.insert(caller, bal + amount);
        self.total += amount;
    }

    /// Immediate withdraw (correct: debit first, re-credit on failure).
    pub fn withdraw(&mut self, amount: U128) -> Promise {
        require!(env::prepaid_gas() >= MIN_WITHDRAW_GAS, "attach at least 30 Tgas");
        let caller = env::predecessor_account_id();
        self.debit(&caller, amount.0);
        self.pay(caller, amount.0)
    }

    /// Payout that needs the approver's sign-off. Debits now, decides later.
    pub fn request_payout(&mut self, amount: U128) -> Promise {
        let caller = env::predecessor_account_id();
        self.debit(&caller, amount.0);
        let request_id = self.next_request;
        self.next_request += 1;
        let args = near_sdk::serde_json::json!({ "request_id": request_id, "account_id": caller, "amount": amount });
        let (promise, yield_id) = Promise::new_yield("on_payout_decision", args.to_string().into_bytes(), GAS_FOR_DECISION, GasWeight(0));
        self.pending.insert(request_id, yield_id);
        log!("payout request {} for {} yocto waiting for {}", request_id, amount.0, self.approver_id);
        promise
    }

    /// Approver answers a pending request.
    pub fn approve_payout(&mut self, request_id: u64, approved: bool) {
        require!(env::predecessor_account_id() == self.approver_id, "only the approver can call this");
        let yield_id = self.pending.remove(&request_id).unwrap_or_else(|| env::panic_str("no such pending request"));
        if yield_id.resume(near_sdk::serde_json::to_vec(&approved).unwrap()).is_err() {
            env::panic_str("request already expired");
        }
    }

    #[private]
    pub fn on_payout_decision(
        &mut self,
        request_id: u64,
        account_id: AccountId,
        amount: U128,
        #[callback_result] decision: Result<bool, PromiseError>,
    ) -> PromiseOrValue<U128> {
        self.pending.remove(&request_id);
        match decision {
            Ok(true) => PromiseOrValue::Promise(self.pay(account_id, amount.0)),
            Ok(false) => {
                self.credit(&account_id, amount.0);
                PromiseOrValue::Value(U128(0))
            }
            Err(_) => {
                log!("payout request {} expired", request_id);
                if cfg!(feature = "fixed") {
                    self.credit(&account_id, amount.0);
                }
                // BUG (default build): the debited amount is never re-credited.
                PromiseOrValue::Value(U128(0))
            }
        }
    }

    #[private]
    pub fn on_withdraw(&mut self, account_id: AccountId, amount: U128, #[callback_result] result: Result<(), PromiseError>) -> U128 {
        if result.is_ok() {
            return amount;
        }
        self.credit(&account_id, amount.0);
        U128(0)
    }

    pub fn set_approver(&mut self, approver_id: AccountId) {
        require!(env::predecessor_account_id() == self.owner_id, "only the owner can call this");
        self.approver_id = approver_id;
    }

    pub fn get_balance(&self, account_id: AccountId) -> U128 {
        U128(self.bal(&account_id))
    }

    pub fn get_approver(&self) -> AccountId {
        self.approver_id.clone()
    }

    pub fn total_deposits(&self) -> U128 {
        U128(self.total)
    }
}

impl Escrow {
    fn bal(&self, id: &AccountId) -> u128 {
        self.balances.get(id).copied().unwrap_or(0)
    }

    fn debit(&mut self, id: &AccountId, amount: u128) {
        let bal = self.bal(id);
        require!(amount > 0 && amount <= bal, "insufficient balance");
        self.balances.insert(id.clone(), bal - amount);
        self.total -= amount;
    }

    fn credit(&mut self, id: &AccountId, amount: u128) {
        let bal = self.bal(id);
        self.balances.insert(id.clone(), bal + amount);
        self.total += amount;
    }

    fn pay(&self, to: AccountId, amount: u128) -> Promise {
        Promise::new(to.clone()).transfer(NearToken::from_yoctonear(amount)).then(
            Self::ext(env::current_account_id())
                .with_static_gas(GAS_FOR_ON_WITHDRAW)
                .with_unused_gas_weight(0)
                .on_withdraw(to, U128(amount)),
        )
    }
}
