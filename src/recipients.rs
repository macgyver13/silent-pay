use anyhow::{bail, Context, Result};
use bitcoin::Amount;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use silentpayments::{Network as SpNetwork, SilentPaymentAddress, SpVersion};
use std::fs;
use std::path::Path;

#[derive(Debug, Deserialize, Serialize)]
pub struct RecipientConfig {
    pub recipients: Vec<RecipientEntry>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RecipientEntry {
    pub label: Option<String>,
    pub amount_sat: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seed_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PayrollRecipient {
    pub label: Option<String>,
    pub amount: Amount,
    pub address: SilentPaymentAddress,
    pub seed: Option<[u8; 32]>,
}

pub fn load_recipients(path: impl AsRef<Path>) -> Result<Vec<PayrollRecipient>> {
    let path = path.as_ref();
    let contents = fs::read_to_string(path)
        .with_context(|| format!("failed to read recipients config {}", path.display()))?;
    parse_recipients(&contents)
}

pub fn save_recipients(path: impl AsRef<Path>, recipients: &[RecipientEntry]) -> Result<()> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
    }
    let config = RecipientConfig {
        recipients: recipients.to_vec(),
    };
    parse_recipients(&toml::to_string(&config)?)?;
    fs::write(path, toml::to_string_pretty(&config)?)
        .with_context(|| format!("failed to write recipients config {}", path.display()))
}

pub fn parse_recipients(contents: &str) -> Result<Vec<PayrollRecipient>> {
    let config: RecipientConfig =
        toml::from_str(contents).context("failed to parse recipients TOML")?;
    if config.recipients.is_empty() {
        bail!("recipients config must contain at least one recipient");
    }

    config
        .recipients
        .into_iter()
        .enumerate()
        .map(|(idx, entry)| entry.into_payroll_recipient(idx))
        .collect()
}

pub fn recipient_keys(seed: &[u8; 32]) -> (SecretKey, SecretKey) {
    (derive_key(seed, b"scan"), derive_key(seed, b"spend"))
}

fn derive_key(seed: &[u8; 32], tag: &[u8]) -> SecretKey {
    let mut hasher = Sha256::new();
    hasher.update(tag);
    hasher.update(seed);
    let digest = hasher.finalize();
    SecretKey::from_slice(&digest).expect("sha256 output is a valid secret key")
}

impl RecipientEntry {
    fn into_payroll_recipient(self, idx: usize) -> Result<PayrollRecipient> {
        if self.amount_sat == 0 {
            bail!("recipient[{idx}] amount_sat must be greater than zero");
        }

        match (self.seed_hex, self.address) {
            (Some(seed_hex), None) => {
                let seed = parse_seed(&seed_hex)
                    .with_context(|| format!("recipient[{idx}] has invalid seed_hex"))?;
                let secp = Secp256k1::new();
                let (scan_sk, spend_sk) = recipient_keys(&seed);
                let scan_pk = PublicKey::from_secret_key(&secp, &scan_sk);
                let spend_pk = PublicKey::from_secret_key(&secp, &spend_sk);
                let address = SilentPaymentAddress::new(
                    scan_pk,
                    spend_pk,
                    SpNetwork::Mainnet,
                    SpVersion::ZERO,
                );
                Ok(PayrollRecipient {
                    label: self.label,
                    amount: Amount::from_sat(self.amount_sat),
                    address,
                    seed: Some(seed),
                })
            }
            (None, Some(address)) => Ok(PayrollRecipient {
                label: self.label,
                amount: Amount::from_sat(self.amount_sat),
                address: SilentPaymentAddress::try_from(address.as_str())
                    .with_context(|| format!("recipient[{idx}] has invalid address"))?,
                seed: None,
            }),
            (Some(_), Some(_)) => {
                bail!("recipient[{idx}] must use either seed_hex or address, not both")
            }
            (None, None) => bail!("recipient[{idx}] must define seed_hex or address"),
        }
    }
}

fn parse_seed(seed_hex: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(seed_hex)?;
    <[u8; 32]>::try_from(bytes.as_slice())
        .map_err(|_| anyhow::anyhow!("seed_hex must decode to exactly 32 bytes"))
}

pub fn address_amounts(recipients: &[PayrollRecipient]) -> Vec<(SilentPaymentAddress, Amount)> {
    recipients
        .iter()
        .map(|recipient| (recipient.address, recipient.amount))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_seed_backed_recipients() {
        let parsed = parse_recipients(
            r#"
            [[recipients]]
            label = "alice"
            amount_sat = 1000
            seed_hex = "b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1"
            "#,
        )
        .expect("valid config");

        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].amount.to_sat(), 1000);
        assert!(parsed[0].seed.is_some());
    }

    #[test]
    fn rejects_bad_seed_length() {
        assert!(parse_recipients(
            r#"
            [[recipients]]
            amount_sat = 1000
            seed_hex = "abcd"
            "#,
        )
        .is_err());
    }

    #[test]
    fn rejects_zero_amount() {
        assert!(parse_recipients(
            r#"
            [[recipients]]
            amount_sat = 0
            seed_hex = "b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1"
            "#,
        )
        .is_err());
    }
}
