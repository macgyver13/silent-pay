//! Demo / fixture code: deterministic key material and the demo build/scan flows.
//!
//! Everything here relies on hardcoded fixtures (a fixed mnemonic, static cosigner
//! xpubs, deterministic nonces). Real-wallet code must not depend on this module.

pub mod operations;
pub mod recipients;
pub mod workflow;

pub use operations::{
    build_payroll, scan_recipients, verify_receipt, BuildPayrollConfig, BuildPayrollResult,
    DetectedOutput, PayrollOutput, ReceiptDetection, RecipientScanResult, ScanRecipientsResult,
    VerifyReceiptResult,
};
pub use recipients::{
    generate_demo_recipients, load_demo_recipients, save_demo_recipients, DemoRecipientEntry,
    RECIPIENT_SEEDS,
};
