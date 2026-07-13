//! Demo-only recipient config that carries a watch-only scan key + silent
//! payment address (no seed, no spend key). Generated deterministically from
//! `RECIPIENT_SEEDS` for running simulated demos. Production recipient parsing
//! in `silent_pay::recipients` is intentionally left untouched.

use anyhow::{bail, Context, Result};
use bitcoin::Amount;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use silentpayments::{Network as SpNetwork, SilentPaymentAddress, SpVersion};
use std::fs;
use std::path::Path;

use silent_pay::recipients::recipient_keys;

/// Demo recipient seeds paired with their payment amount (sats). Each seed
/// deterministically derives a scan/spend key pair via `recipient_keys`.
pub const RECIPIENT_SEEDS: [([u8; 32], u64); 5] = [
    ([0xb1; 32], 18_000),
    ([0xb2; 32], 16_000),
    ([0xb3; 32], 150_000),
    ([0xb4; 32], 10_000),
    ([0xb5; 32], 20_000),
];

/// Network used for generated demo silent payment addresses.
const DEMO_NETWORK: SpNetwork = SpNetwork::Testnet;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DemoRecipientConfig {
    pub recipients: Vec<DemoRecipientEntry>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DemoRecipientEntry {
    pub label: Option<String>,
    pub amount_sat: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seed_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scan_key_hex: Option<String>,
}

/// A resolved recipient ready to be scanned: everything scanning needs, with no
/// spend authority.
#[derive(Debug, Clone)]
pub struct DemoScanTarget {
    pub label: Option<String>,
    pub amount: Amount,
    pub scan_sk: SecretKey,
    pub address: SilentPaymentAddress,
}

/// Build watch-only demo recipients from `RECIPIENT_SEEDS`: each carries a
/// testnet silent payment address and its scan private key, but no seed.
pub fn generate_demo_recipients() -> Vec<DemoRecipientEntry> {
    let secp = Secp256k1::new();
    RECIPIENT_SEEDS
        .iter()
        .enumerate()
        .map(|(idx, (seed, amount_sat))| {
            let (scan_sk, spend_sk) = recipient_keys(seed);
            let scan_pk = PublicKey::from_secret_key(&secp, &scan_sk);
            let spend_pk = PublicKey::from_secret_key(&secp, &spend_sk);
            let address =
                SilentPaymentAddress::new(scan_pk, spend_pk, DEMO_NETWORK, SpVersion::ZERO);
            DemoRecipientEntry {
                label: Some(format!("recipient-{}", idx + 1)),
                amount_sat: *amount_sat,
                seed_hex: None,
                address: Some(address.to_string()),
                scan_key_hex: Some(hex::encode(scan_sk.secret_bytes())),
            }
        })
        .collect()
}

pub fn save_demo_recipients(
    path: impl AsRef<Path>,
    recipients: &[DemoRecipientEntry],
) -> Result<()> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
    }
    let config = DemoRecipientConfig {
        recipients: recipients.to_vec(),
    };
    // Round-trip to validate the file we are about to write is loadable.
    load_from_str(&toml::to_string(&config)?)?;
    fs::write(path, toml::to_string_pretty(&config)?)
        .with_context(|| format!("failed to write demo recipients {}", path.display()))
}

pub fn load_demo_recipients(path: impl AsRef<Path>) -> Result<Vec<DemoScanTarget>> {
    let path = path.as_ref();
    let contents = fs::read_to_string(path)
        .with_context(|| format!("failed to read demo recipients {}", path.display()))?;
    load_from_str(&contents)
}

fn load_from_str(contents: &str) -> Result<Vec<DemoScanTarget>> {
    let config: DemoRecipientConfig =
        toml::from_str(contents).context("failed to parse demo recipients TOML")?;
    if config.recipients.is_empty() {
        bail!("demo recipients config must contain at least one recipient");
    }
    config
        .recipients
        .into_iter()
        .enumerate()
        .map(|(idx, entry)| resolve_target(idx, entry))
        .collect()
}

fn resolve_target(idx: usize, entry: DemoRecipientEntry) -> Result<DemoScanTarget> {
    if entry.amount_sat == 0 {
        bail!("recipient[{idx}] amount_sat must be greater than zero");
    }
    let amount = Amount::from_sat(entry.amount_sat);

    let (scan_sk, address) = match (entry.scan_key_hex, entry.seed_hex) {
        (Some(scan_key_hex), _) => {
            let scan_sk = parse_scan_key(&scan_key_hex)
                .with_context(|| format!("recipient[{idx}] has invalid scan_key_hex"))?;
            let address_str = entry
                .address
                .ok_or_else(|| anyhow::anyhow!("recipient[{idx}] scan_key_hex requires address"))?;
            let address = SilentPaymentAddress::try_from(address_str.as_str())
                .map_err(|e| anyhow::anyhow!("recipient[{idx}] invalid address: {e}"))?;
            (scan_sk, address)
        }
        (None, Some(seed_hex)) => {
            let seed = parse_seed(&seed_hex)
                .with_context(|| format!("recipient[{idx}] has invalid seed_hex"))?;
            let secp = Secp256k1::new();
            let (scan_sk, spend_sk) = recipient_keys(&seed);
            let address = match entry.address {
                Some(address_str) => SilentPaymentAddress::try_from(address_str.as_str())
                    .map_err(|e| anyhow::anyhow!("recipient[{idx}] invalid address: {e}"))?,
                None => SilentPaymentAddress::new(
                    PublicKey::from_secret_key(&secp, &scan_sk),
                    PublicKey::from_secret_key(&secp, &spend_sk),
                    DEMO_NETWORK,
                    SpVersion::ZERO,
                ),
            };
            (scan_sk, address)
        }
        (None, None) => {
            bail!("recipient[{idx}] needs scan_key_hex+address or seed_hex")
        }
    };

    Ok(DemoScanTarget {
        label: entry.label,
        amount,
        scan_sk,
        address,
    })
}

fn parse_scan_key(scan_key_hex: &str) -> Result<SecretKey> {
    let bytes = hex::decode(scan_key_hex.trim())?;
    SecretKey::from_slice(&bytes).context("scan_key_hex is not a valid secret key")
}

fn parse_seed(seed_hex: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(seed_hex.trim())?;
    <[u8; 32]>::try_from(bytes.as_slice())
        .map_err(|_| anyhow::anyhow!("seed_hex must decode to exactly 32 bytes"))
}
