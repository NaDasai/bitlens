//! CLEAN vault: a correct native-NEAR vault. Every BitLens attack should be HELD.
//!
//! - `deposit()` (payable) credits the caller.
//! - `withdraw(amount)` **debits first**, then transfers, then `on_withdraw`
//!   re-credits if the transfer failed. Two withdraws in flight can never
//!   spend the same balance twice.
//! - `on_withdraw` gets a fixed 10 Tgas (weight 0) and `withdraw` refuses to
//!   start with less than 30 Tgas prepaid, so the callback can never be
//!   starved by a caller choosing a low gas budget.
//! - Admin methods (`set_owner`, `set_paused`) check the owner.

use near_sdk::json_types::U128;
use near_sdk::store::LookupMap;
use near_sdk::{env, near, require, AccountId, Gas, NearToken, PanicOnDefault, Promise, PromiseError};

const GAS_FOR_ON_WITHDRAW: Gas = Gas::from_tgas(10);
const MIN_WITHDRAW_GAS: Gas = Gas::from_tgas(30);

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Vault {
    owner_id: AccountId,
    balances: LookupMap<AccountId, u128>,
    total: u128,
    paused: bool,
}

#[near]
impl Vault {
    #[init]
    pub fn new(owner_id: AccountId) -> Self {
        Self { owner_id, balances: LookupMap::new(b"b"), total: 0, paused: false }
    }

    #[payable]
    pub fn deposit(&mut self) {
        require!(!self.paused, "paused");
        let amount = env::attached_deposit().as_yoctonear();
        require!(amount > 0, "attach NEAR to deposit");
        let caller = env::predecessor_account_id();
        let bal = self.bal(&caller);
        self.balances.insert(caller, bal + amount);
        self.total += amount;
    }

    pub fn withdraw(&mut self, amount: U128) -> Promise {
        require!(!self.paused, "paused");
        require!(env::prepaid_gas() >= MIN_WITHDRAW_GAS, "attach at least 30 Tgas");
        let amount = amount.0;
        let caller = env::predecessor_account_id();
        let bal = self.bal(&caller);
        require!(amount > 0 && amount <= bal, "insufficient balance");
        // Effects before interactions: debit now, re-credit in the callback on failure.
        self.balances.insert(caller.clone(), bal - amount);
        self.total -= amount;
        Promise::new(caller.clone()).transfer(NearToken::from_yoctonear(amount)).then(
            Self::ext(env::current_account_id())
                .with_static_gas(GAS_FOR_ON_WITHDRAW)
                .with_unused_gas_weight(0)
                .on_withdraw(caller, U128(amount)),
        )
    }

    #[private]
    pub fn on_withdraw(
        &mut self,
        account_id: AccountId,
        amount: U128,
        #[callback_result] result: Result<(), PromiseError>,
    ) -> U128 {
        if result.is_ok() {
            return amount;
        }
        let bal = self.bal(&account_id);
        self.balances.insert(account_id, bal + amount.0);
        self.total += amount.0;
        U128(0)
    }

    pub fn set_owner(&mut self, owner_id: AccountId) {
        self.assert_owner();
        self.owner_id = owner_id;
    }

    pub fn set_paused(&mut self, paused: bool) {
        self.assert_owner();
        self.paused = paused;
    }

    pub fn get_balance(&self, account_id: AccountId) -> U128 {
        U128(self.bal(&account_id))
    }

    pub fn get_owner(&self) -> AccountId {
        self.owner_id.clone()
    }

    pub fn total_deposits(&self) -> U128 {
        U128(self.total)
    }
}

impl Vault {
    fn bal(&self, id: &AccountId) -> u128 {
        self.balances.get(id).copied().unwrap_or(0)
    }

    fn assert_owner(&self) {
        require!(env::predecessor_account_id() == self.owner_id, "only the owner can call this");
    }
}
