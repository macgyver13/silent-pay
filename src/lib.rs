pub mod musig2_psbt;
pub mod musig2_spdk;
pub mod operations;
pub mod recipients;
pub mod workflow;

pub use operations::{
    build_payroll, finalize_payroll, scan_recipients, BuildPayrollConfig, BuildPayrollResult,
    FinalizePayrollResult, PayrollOutput, RecipientScanResult, ScanRecipientsResult,
};
pub use recipients::{load_recipients, PayrollRecipient, RecipientConfig};
