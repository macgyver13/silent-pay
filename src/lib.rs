pub mod demo;
pub mod finalize;
pub mod payroll;
pub mod recipients;
pub mod wallet;

pub use finalize::{finalize_payroll, FinalizePayrollResult};
pub use payroll::{
    build_initial_payroll_psbt, derive_treasury_script_pubkey, BuildInitialPayrollConfig,
    BuildInitialPayrollResult, TreasuryPrevout, CHANGE_CHAIN, RECEIVE_CHAIN,
};
pub use recipients::{
    load_recipients, save_recipients, PayrollRecipient, RecipientConfig, RecipientEntry,
};
pub use wallet::{load_wallet, parse_wallet, save_wallet, TreasurySigner, TreasuryWalletConfig};
