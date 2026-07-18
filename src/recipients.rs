use anyhow::{bail, Context, Result};
use bitcoin::Amount;
use serde::{Deserialize, Serialize};
use silentpayments::SilentPaymentAddress;
use std::fs;
use std::path::Path;

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecipientConfig {
    pub recipients: Vec<RecipientEntry>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecipientEntry {
    pub label: Option<String>,
    pub amount_sat: u64,
    pub address: String,
}

#[derive(Debug, Clone)]
pub struct PayrollRecipient {
    pub label: Option<String>,
    pub amount: Amount,
    pub address: SilentPaymentAddress,
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

impl RecipientEntry {
    fn into_payroll_recipient(self, idx: usize) -> Result<PayrollRecipient> {
        if self.amount_sat == 0 {
            bail!("recipient[{idx}] amount_sat must be greater than zero");
        }

        Ok(PayrollRecipient {
            label: self.label,
            amount: Amount::from_sat(self.amount_sat),
            address: SilentPaymentAddress::try_from(self.address.as_str())
                .with_context(|| format!("recipient[{idx}] has invalid address"))?,
        })
    }
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
    use secp256k1::{PublicKey, Secp256k1, SecretKey};
    use silentpayments::{Network as SpNetwork, SpVersion};

    fn test_address() -> String {
        let secp = Secp256k1::new();
        let scan_sk = SecretKey::from_slice(&[3u8; 32]).expect("scan key");
        let spend_sk = SecretKey::from_slice(&[4u8; 32]).expect("spend key");
        SilentPaymentAddress::new(
            PublicKey::from_secret_key(&secp, &scan_sk),
            PublicKey::from_secret_key(&secp, &spend_sk),
            SpNetwork::Testnet,
            SpVersion::ZERO,
        )
        .to_string()
    }

    #[test]
    fn parses_address_backed_recipients() {
        let address = test_address();
        let parsed = parse_recipients(&format!(
            r#"
            [[recipients]]
            label = "alice"
            amount_sat = 1000
            address = "{address}"
            "#
        ))
        .expect("valid config");

        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].amount.to_sat(), 1000);
        assert_eq!(parsed[0].address.to_string(), address);
    }

    #[test]
    fn rejects_zero_amount() {
        let address = test_address();
        assert!(parse_recipients(&format!(
            r#"
            [[recipients]]
            amount_sat = 0
            address = "{address}"
            "#
        ),)
        .is_err());
    }

    #[test]
    fn rejects_missing_address() {
        let err = parse_recipients(
            r#"
            [[recipients]]
            amount_sat = 1000
            "#,
        )
        .expect_err("address should be required");

        assert!(err.to_string().contains("failed to parse recipients TOML"));
    }
}
