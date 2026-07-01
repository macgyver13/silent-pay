pub mod musig2_psbt;
pub mod musig2_spdk;
pub mod operations;
pub mod real_payroll;
pub mod recipients;
pub mod wallet;
pub mod workflow;

pub use operations::{
    build_payroll, finalize_payroll, scan_recipients, BuildPayrollConfig, BuildPayrollResult,
    FinalizePayrollResult, PayrollOutput, RecipientScanResult, ScanRecipientsResult,
};
pub use real_payroll::{
    build_initial_payroll_psbt, BuildInitialPayrollConfig, BuildInitialPayrollResult,
    TreasuryPrevout,
};
pub use recipients::{
    load_recipients, save_recipients, PayrollRecipient, RecipientConfig, RecipientEntry,
};
pub use wallet::{load_wallet, save_wallet, TreasurySigner, TreasuryWalletConfig};
