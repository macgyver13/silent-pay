use anyhow::{bail, Context, Result};
use bitcoin::bip32::{DerivationPath, Fingerprint, Xpub};
use bitcoin::NetworkKind;
use serde::{Deserialize, Serialize};
use silentpayments::Network as SpNetwork;
use std::fs;
use std::path::Path;
use std::str::FromStr;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TreasuryWalletConfig {
    #[serde(default = "default_network")]
    pub network: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub descriptor: Option<String>,
    #[serde(default)]
    pub derivation_index: u32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub signers: Vec<TreasurySigner>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TreasurySigner {
    pub xfp: String,
    pub derivation_path: String,
    pub xpub: String,
}

pub fn load_wallet(path: impl AsRef<Path>) -> Result<TreasuryWalletConfig> {
    let path = path.as_ref();
    let contents = fs::read_to_string(path)
        .with_context(|| format!("failed to read wallet config {}", path.display()))?;
    parse_wallet(&contents)
}

pub fn save_wallet(path: impl AsRef<Path>, wallet: &TreasuryWalletConfig) -> Result<()> {
    let normalized = wallet.normalized()?;
    fs::write(path.as_ref(), toml::to_string_pretty(&normalized)?)
        .with_context(|| format!("failed to write wallet config {}", path.as_ref().display()))
}

pub fn parse_wallet(contents: &str) -> Result<TreasuryWalletConfig> {
    let wallet: TreasuryWalletConfig =
        toml::from_str(contents).context("failed to parse wallet TOML")?;
    wallet.normalized()
}

impl TreasuryWalletConfig {
    pub fn normalized(&self) -> Result<Self> {
        let network = parse_network(&self.network)?;
        let mut signers = self.signers.clone();
        if signers.is_empty() {
            let descriptor = self
                .descriptor
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("wallet must define signers or descriptor"))?;
            signers = parse_descriptor_signers(descriptor)?;
        }
        if signers.len() < 2 {
            bail!("N-of-N MuSig2 wallet requires at least two signers");
        }
        for (idx, signer) in signers.iter().enumerate() {
            signer
                .validate(network)
                .with_context(|| format!("signer[{idx}] is invalid"))?;
        }
        let descriptor = Some(descriptor_from_signers(&signers));
        Ok(Self {
            network: network_name(network).to_string(),
            descriptor,
            derivation_index: self.derivation_index,
            signers,
        })
    }

    pub fn network_value(&self) -> Result<SpNetwork> {
        parse_network(&self.network)
    }

    pub fn descriptor_string(&self) -> Result<String> {
        Ok(self
            .normalized()?
            .descriptor
            .expect("normalized descriptor"))
    }
}

impl TreasurySigner {
    pub fn fingerprint(&self) -> Result<Fingerprint> {
        parse_fingerprint(&self.xfp)
    }

    pub fn derivation_path_value(&self) -> Result<DerivationPath> {
        DerivationPath::from_str(&self.derivation_path)
            .with_context(|| format!("invalid derivation path {}", self.derivation_path))
    }

    pub fn xpub_value(&self) -> Result<Xpub> {
        Xpub::from_str(&self.xpub).with_context(|| "invalid xpub")
    }

    fn validate(&self, network: SpNetwork) -> Result<()> {
        self.fingerprint()?;
        self.derivation_path_value()?;
        let xpub = self.xpub_value()?;
        if network == SpNetwork::Mainnet && xpub.network != NetworkKind::Main {
            bail!("mainnet wallet requires mainnet xpubs");
        }
        if network != SpNetwork::Mainnet && xpub.network != NetworkKind::Test {
            bail!("test/regtest wallet requires testnet xpubs");
        }
        Ok(())
    }
}

pub fn parse_network(value: &str) -> Result<SpNetwork> {
    SpNetwork::try_from(value).map_err(|e| anyhow::anyhow!("invalid network {value}: {e}"))
}

pub fn descriptor_from_signers(signers: &[TreasurySigner]) -> String {
    let parts: Vec<String> = signers
        .iter()
        .map(|signer| {
            let path = signer.derivation_path.trim_start_matches("m/");
            format!("[{}/{}]{}", signer.xfp, path, signer.xpub)
        })
        .collect();
    format!("tr(musig({})/0/*)", parts.join(","))
}

fn parse_descriptor_signers(descriptor: &str) -> Result<Vec<TreasurySigner>> {
    let descriptor = descriptor.trim();
    let body = descriptor
        .strip_prefix("tr(musig(")
        .and_then(|s| s.strip_suffix(")/0/*)"))
        .ok_or_else(|| {
            anyhow::anyhow!("descriptor must look like tr(musig([xfp/path]xpub,...)/0/*)")
        })?;
    body.split(',')
        .enumerate()
        .map(|(idx, part)| parse_descriptor_signer(idx, part.trim()))
        .collect()
}

fn parse_descriptor_signer(idx: usize, part: &str) -> Result<TreasurySigner> {
    let origin_end = part
        .find(']')
        .ok_or_else(|| anyhow::anyhow!("descriptor signer[{idx}] missing ]"))?;
    let origin = part
        .strip_prefix('[')
        .ok_or_else(|| anyhow::anyhow!("descriptor signer[{idx}] missing ["))?
        .get(..origin_end - 1)
        .ok_or_else(|| anyhow::anyhow!("descriptor signer[{idx}] has invalid origin"))?;
    let xpub = part
        .get(origin_end + 1..)
        .ok_or_else(|| anyhow::anyhow!("descriptor signer[{idx}] missing xpub"))?;
    let (xfp, path) = origin
        .split_once('/')
        .ok_or_else(|| anyhow::anyhow!("descriptor signer[{idx}] origin must include xfp/path"))?;
    Ok(TreasurySigner {
        xfp: xfp.to_string(),
        derivation_path: format!("m/{path}"),
        xpub: xpub.to_string(),
    })
}

fn parse_fingerprint(value: &str) -> Result<Fingerprint> {
    let bytes = hex::decode(value).with_context(|| "fingerprint must be hex")?;
    let arr: [u8; 4] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("fingerprint must be exactly 4 bytes"))?;
    Ok(Fingerprint::from(arr))
}

fn default_network() -> String {
    "testnet".to_string()
}

fn network_name(network: SpNetwork) -> &'static str {
    match network {
        SpNetwork::Mainnet => "bitcoin",
        SpNetwork::Testnet => "testnet",
        SpNetwork::Regtest => "regtest",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const XPUB1: &str = "tpubDF2rnouQaaYrY6CUWTapYkeFEs3h3qrzL4M52ZGoPeU9dkarJMtrw6VF1zJRGuGuAFxYS3kXtavfAwQPTQkU5dyNYpbgxcpftrR8H3U85Ez";
    const XPUB2: &str = "tpubDFcrvj5n7gyazzxdg9k6uvzQsoQWow1xbksr7EvKPRBgUbwCdqu2qxyTJjYFNJ7MQLfdXSJV4n8xPZGtrvwQtEbktinC4EP3k8JN2hcBtz4";

    #[test]
    fn parses_signer_rows() {
        let wallet = parse_wallet(&format!(
            r#"
            network = "testnet"

            [[signers]]
            xfp = "0f056943"
            derivation_path = "m/48h/1h/0h/3h"
            xpub = "{XPUB1}"

            [[signers]]
            xfp = "6ba6cfd0"
            derivation_path = "m/48h/1h/0h/3h"
            xpub = "{XPUB2}"
            "#
        ))
        .expect("wallet");

        assert_eq!(wallet.signers.len(), 2);
        assert_eq!(wallet.derivation_index, 0);
        assert!(wallet.descriptor.unwrap().starts_with("tr(musig("));
    }

    #[test]
    fn parses_descriptor() {
        let descriptor =
            format!("tr(musig([0f056943/48h/1h/0h/3h]{XPUB1},[6ba6cfd0/48h/1h/0h/3h]{XPUB2})/0/*)");
        let wallet = parse_wallet(&format!(
            "network = \"testnet\"\ndescriptor = \"{descriptor}\"\n"
        ))
        .expect("wallet");
        assert_eq!(wallet.signers.len(), 2);
    }

    #[test]
    fn rejects_single_signer() {
        assert!(parse_wallet(&format!(
            r#"
            network = "testnet"
            [[signers]]
            xfp = "0f056943"
            derivation_path = "m/48h/1h/0h/3h"
            xpub = "{XPUB1}"
            "#
        ))
        .is_err());
    }

    #[test]
    fn rejects_bad_fingerprint() {
        assert!(parse_wallet(&format!(
            r#"
            network = "testnet"
            [[signers]]
            xfp = "bad"
            derivation_path = "m/48h/1h/0h/3h"
            xpub = "{XPUB1}"
            [[signers]]
            xfp = "6ba6cfd0"
            derivation_path = "m/48h/1h/0h/3h"
            xpub = "{XPUB2}"
            "#
        ))
        .is_err());
    }
}
