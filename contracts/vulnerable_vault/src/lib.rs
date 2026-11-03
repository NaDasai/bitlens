//! VULNERABLE vault: looks like the clean vault, with two planted bugs.
//!
//! BUG 1 (`admin_drain`): an "emergency drain" meant for the owner, but the
//! owner check was forgotten. Anyone can send the vault's entire NEAR balance
//! (everyone's deposits) to any account.
//!
//! BUG 2 (`withdraw`): checks the balance, transfers, and only **debits in the
//! callback**. Two withdraws sent before the first callback runs both pass the
//! check, both get paid, and the debit saturates at zero: the attacker takes
//! out twice what they put in, at the other depositors' expense.

use near_sdk::json_types::U128;
use near_sdk::store::LookupMap;
use near_sdk::{env, near, require, AccountId, Gas, NearToken, PanicOnDefault, Promise, PromiseError};

const GAS_FOR_ON_WITHDRAW: Gas = Gas::from_tgas(10);
const MIN_WITHDRAW_GAS: Gas = Gas::from_tgas(30);
const ONE_NEAR: u128 = 1_000_000_000_000_000_000_000_000;

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
        // BUG 2: no debit here. It happens in on_withdraw, after the money has left.
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
        if result.is_err() {
            return U128(0);
        }
        let bal = self.bal(&account_id);
        self.balances.insert(account_id, bal.saturating_sub(amount.0));
        self.total = self.total.saturating_sub(amount.0);
        amount
    }

    pub fn set_owner(&mut self, owner_id: AccountId) {
        self.assert_owner();
        self.owner_id = owner_id;
    }

    pub fn set_paused(&mut self, paused: bool) {
        self.assert_owner();
        self.paused = paused;
    }

    /// "Emergency" drain of the whole vault to `receiver_id`.
    pub fn admin_drain(&mut self, receiver_id: AccountId) -> Promise {
        // BUG 1: missing self.assert_owner();
        let reserved = env::storage_byte_cost().as_yoctonear() * env::storage_usage() as u128;
        let amount = env::account_balance().as_yoctonear().saturating_sub(reserved + ONE_NEAR);
        self.total = 0;
        Promise::new(receiver_id).transfer(NearToken::from_yoctonear(amount))
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
