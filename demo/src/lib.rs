//! Demo / fixture code: deterministic key material and the demo build/scan flows.
//!
//! `operations`, `recipients`, and `workflow` rely entirely on hardcoded fixtures
//! (a fixed mnemonic, static cosigner xpubs, deterministic nonces); real-wallet
//! code must not depend on them. `live` is the deliberate exception: it talks to
//! a real Bitcoin Core node and is not deterministic, but it never synthesizes
//! signer contributions -- see its module docs.

pub mod live;
pub mod live_cli;
pub mod operations;
pub mod recipients;
pub mod workflow;

pub use live::{
    broadcast_and_confirm, fund_regtest_treasury, scan_funded_prevout, verify_onchain_receipt,
};
pub use operations::{
    build_payroll, scan_recipients, verify_receipt, BuildPayrollConfig, BuildPayrollResult,
    DetectedOutput, PayrollOutput, ReceiptDetection, RecipientScanResult, ScanRecipientsResult,
    VerifyReceiptResult,
};
pub use recipients::{
    generate_demo_recipients, load_demo_recipients, save_demo_recipients, DemoRecipientEntry,
    RECIPIENT_SEEDS,
};
