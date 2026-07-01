//! Demo / fixture code: deterministic key material and the demo build/scan flows.
//!
//! Everything here relies on hardcoded fixtures (a fixed mnemonic, static cosigner
//! xpubs, deterministic nonces). Real-wallet code must not depend on this module.

pub mod operations;
pub mod workflow;

pub use operations::{
    build_payroll, scan_recipients, BuildPayrollConfig, BuildPayrollResult, DetectedOutput,
    PayrollOutput, RecipientScanResult, ScanRecipientsResult,
};
