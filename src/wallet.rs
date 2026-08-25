use anyhow::{bail, Context, Result};
use bitcoin::bip32::{DerivationPath, Fingerprint, Xpub};
use bitcoin::NetworkKind;
use serde::{Deserialize, Serialize};
use silentpayments::Network as SpNetwork;
use std::fs;
use std::path::Path;
use std::str::FromStr;

/// How the wallet's MuSig2 aggregate key is derived. Encoded entirely in the shape
/// of the registered descriptor -- see [`descriptor_from_signers`] and
/// [`parse_descriptor_signers`] -- so it is never independently settable: the
/// descriptor is the only source of truth, and this is always recomputed from it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WalletKeyArch {
    /// `tr(musig([xfp/path]xpub,...)/<0;1>/*)`. Aggregates the signers' account-level
    /// keys, then derives the aggregate (BIP-328 synthetic derivation). Matches the
    /// COLDCARD/Jade firmware and the signet interop demonstration.
    #[default]
    AggregateThenDerive,
    /// `tr(musig([xfp/path]xpub/<0;1>/*,...))`. Derives each signer's key first
    /// (BIP-390 ranged participants), then aggregates directly -- no synthetic
    /// derivation layer. Proof of concept only; no firmware supports it yet.
    DeriveThenAggregate,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TreasuryWalletConfig {
    #[serde(default = "default_network")]
    pub network: String,
    pub descriptor: String,
    #[serde(default)]
    pub last_derivation_index: u32,
    #[serde(default = "default_change_derivation_index")]
    pub change_derivation_index: u32,
    /// Derived from `descriptor` by [`TreasuryWalletConfig::normalized`]; never an
    /// input. Empty on a config that has not been normalized yet.
    #[serde(skip)]
    pub signers: Vec<TreasurySigner>,
    /// Derived from `descriptor`; see [`WalletKeyArch`]. Defaults to
    /// `AggregateThenDerive` on a config that has not been normalized yet, since
    /// that is what an empty descriptor would otherwise parse to.
    #[serde(skip)]
    pub key_arch: WalletKeyArch,
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
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
    }
    let normalized = wallet.normalized()?;
    fs::write(path, toml::to_string_pretty(&normalized)?)
        .with_context(|| format!("failed to write wallet config {}", path.display()))
}

pub fn parse_wallet(contents: &str) -> Result<TreasuryWalletConfig> {
    let raw: RawTreasuryWalletConfig =
        toml::from_str(contents).context("failed to parse wallet TOML")?;
    let wallet = TreasuryWalletConfig {
        network: raw.network,
        descriptor: raw.descriptor,
        last_derivation_index: raw.last_derivation_index,
        // Change lives on its own BIP-32 internal chain (/1/*), so its index is
        // independent of the receive (/0/*) index and starts at 0.
        change_derivation_index: raw
            .change_derivation_index
            .unwrap_or_else(default_change_derivation_index),
        signers: Vec::new(),
        key_arch: WalletKeyArch::default(),
    };
    wallet.normalized()
}

#[derive(Debug, Deserialize)]
struct RawTreasuryWalletConfig {
    #[serde(default = "default_network")]
    network: String,
    /// The wallet's only source of truth for its signer set and key architecture
    /// -- see [`WalletKeyArch`]. There is deliberately no `[[signers]]` input path:
    /// a raw signer list has no way to express which descriptor form it implies,
    /// so requiring the descriptor keeps that choice unambiguous.
    descriptor: String,
    #[serde(default)]
    last_derivation_index: u32,
    #[serde(default)]
    change_derivation_index: Option<u32>,
}

impl TreasuryWalletConfig {
    pub fn normalized(&self) -> Result<Self> {
        let network = parse_network(&self.network)?;
        let (signers, key_arch) = parse_descriptor_signers(&self.descriptor)?;
        if signers.len() < 2 {
            bail!("N-of-N MuSig2 wallet requires at least two signers");
        }
        for (idx, signer) in signers.iter().enumerate() {
            signer
                .validate(network)
                .with_context(|| format!("signer[{idx}] is invalid"))?;
        }
        let descriptor = descriptor_from_signers(&signers, key_arch);
        Ok(Self {
            network: network_name(network).to_string(),
            descriptor,
            last_derivation_index: self.last_derivation_index,
            change_derivation_index: self.change_derivation_index,
            signers,
            key_arch,
        })
    }

    pub fn network_value(&self) -> Result<SpNetwork> {
        parse_network(&self.network)
    }

    pub fn descriptor_string(&self) -> Result<String> {
        Ok(self.normalized()?.descriptor)
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

/// BIP-389 multipath suffix on the receive/change branches: branch 0 is receive,
/// branch 1 is change, so the change branch is committed to by the registered
/// descriptor rather than assumed.
const MULTIPATH_SUFFIX: &str = "/<0;1>/*";

pub fn descriptor_from_signers(signers: &[TreasurySigner], arch: WalletKeyArch) -> String {
    let parts: Vec<String> = signers
        .iter()
        .map(|signer| {
            let path = signer.derivation_path.trim_start_matches("m/");
            let key = format!("[{}/{}]{}", signer.xfp, path, signer.xpub);
            match arch {
                WalletKeyArch::AggregateThenDerive => key,
                // BIP-390: the multipath/wildcard step lives on each participant
                // instead of on the musig() aggregate.
                WalletKeyArch::DeriveThenAggregate => format!("{key}{MULTIPATH_SUFFIX}"),
            }
        })
        .collect();
    match arch {
        WalletKeyArch::AggregateThenDerive => {
            format!("tr(musig({}){MULTIPATH_SUFFIX})", parts.join(","))
        }
        WalletKeyArch::DeriveThenAggregate => format!("tr(musig({}))", parts.join(",")),
    }
}

fn parse_descriptor_signers(descriptor: &str) -> Result<(Vec<TreasurySigner>, WalletKeyArch)> {
    let descriptor = descriptor.trim();
    let malformed = || {
        anyhow::anyhow!(
            "descriptor must look like tr(musig([xfp/path]xpub,...)/<0;1>/*)              or tr(musig([xfp/path]xpub/<0;1>/*,...))"
        )
    };
    let inner = descriptor.strip_prefix("tr(musig(").ok_or_else(malformed)?;

    // Two shapes distinguished by where the BIP-389 multipath step lives: on the
    // musig() aggregate (AggregateThenDerive) or on each participant
    // (DeriveThenAggregate) -- never both, never neither.
    if let Some(body) = inner.strip_suffix(&format!("){MULTIPATH_SUFFIX})")) {
        let signers = body
            .split(',')
            .enumerate()
            .map(|(idx, part)| parse_descriptor_signer(idx, part.trim(), false))
            .collect::<Result<Vec<_>>>()?;
        Ok((signers, WalletKeyArch::AggregateThenDerive))
    } else if let Some(body) = inner.strip_suffix("))") {
        let signers = body
            .split(',')
            .enumerate()
            .map(|(idx, part)| parse_descriptor_signer(idx, part.trim(), true))
            .collect::<Result<Vec<_>>>()?;
        Ok((signers, WalletKeyArch::DeriveThenAggregate))
    } else {
        Err(malformed())
    }
}

fn parse_descriptor_signer(
    idx: usize,
    part: &str,
    expect_multipath_suffix: bool,
) -> Result<TreasurySigner> {
    let part = if expect_multipath_suffix {
        part.strip_suffix(MULTIPATH_SUFFIX).ok_or_else(|| {
            anyhow::anyhow!("descriptor signer[{idx}] missing {MULTIPATH_SUFFIX} suffix")
        })?
    } else {
        part
    };
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

fn default_change_derivation_index() -> u32 {
    0
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

    fn test_signers() -> Vec<TreasurySigner> {
        vec![
            TreasurySigner {
                xfp: "0f056943".to_string(),
                derivation_path: "m/48h/1h/0h/3h".to_string(),
                xpub: XPUB1.to_string(),
            },
            TreasurySigner {
                xfp: "6ba6cfd0".to_string(),
                derivation_path: "m/48h/1h/0h/3h".to_string(),
                xpub: XPUB2.to_string(),
            },
        ]
    }

    #[test]
    fn parses_aggregate_then_derive_descriptor() {
        let descriptor = format!(
            "tr(musig([0f056943/48h/1h/0h/3h]{XPUB1},[6ba6cfd0/48h/1h/0h/3h]{XPUB2})/<0;1>/*)"
        );
        let wallet = parse_wallet(&format!(
            "network = \"testnet\"\ndescriptor = \"{descriptor}\"\n"
        ))
        .expect("wallet");
        assert_eq!(wallet.signers.len(), 2);
        assert_eq!(wallet.key_arch, WalletKeyArch::AggregateThenDerive);
    }

    #[test]
    fn parses_derive_then_aggregate_descriptor() {
        let descriptor = format!(
            "tr(musig([0f056943/48h/1h/0h/3h]{XPUB1}/<0;1>/*,[6ba6cfd0/48h/1h/0h/3h]{XPUB2}/<0;1>/*))"
        );
        let wallet = parse_wallet(&format!(
            "network = \"testnet\"\ndescriptor = \"{descriptor}\"\n"
        ))
        .expect("wallet");
        assert_eq!(wallet.signers.len(), 2);
        assert_eq!(wallet.signers[0].xfp, "0f056943");
        assert_eq!(wallet.signers[0].derivation_path, "m/48h/1h/0h/3h");
        assert_eq!(wallet.signers[1].xpub, XPUB2);
        assert_eq!(wallet.key_arch, WalletKeyArch::DeriveThenAggregate);
    }

    #[test]
    fn parses_derivation_indices() {
        let descriptor = format!(
            "tr(musig([0f056943/48h/1h/0h/3h]{XPUB1},[6ba6cfd0/48h/1h/0h/3h]{XPUB2})/<0;1>/*)"
        );
        let wallet = parse_wallet(&format!(
            "network = \"testnet\"\nlast_derivation_index = 3\nchange_derivation_index = 4\ndescriptor = \"{descriptor}\"\n"
        ))
        .expect("wallet");

        assert_eq!(wallet.last_derivation_index, 3);
        assert_eq!(wallet.change_derivation_index, 4);
    }

    #[test]
    fn rejects_receive_only_descriptor() {
        let descriptor =
            format!("tr(musig([0f056943/48h/1h/0h/3h]{XPUB1},[6ba6cfd0/48h/1h/0h/3h]{XPUB2})/0/*)");
        parse_wallet(&format!(
            "network = \"testnet\"\ndescriptor = \"{descriptor}\"\n"
        ))
        .expect_err("receive-only descriptor must be rejected");
    }

    #[test]
    fn rejects_descriptor_missing_multipath_suffix_on_one_participant() {
        // First participant carries the BIP-390 multipath suffix, second does not --
        // an inconsistent DeriveThenAggregate descriptor that must be rejected
        // rather than silently misparsed.
        let descriptor = format!(
            "tr(musig([0f056943/48h/1h/0h/3h]{XPUB1}/<0;1>/*,[6ba6cfd0/48h/1h/0h/3h]{XPUB2}))"
        );
        parse_wallet(&format!(
            "network = \"testnet\"\ndescriptor = \"{descriptor}\"\n"
        ))
        .expect_err("inconsistent per-participant multipath must be rejected");
    }

    #[test]
    fn descriptor_round_trips_aggregate_then_derive() {
        let signers = test_signers();
        let descriptor = descriptor_from_signers(&signers, WalletKeyArch::AggregateThenDerive);
        assert!(descriptor.ends_with("/<0;1>/*)"));
        let (parsed, arch) = parse_descriptor_signers(&descriptor).expect("signers");
        assert_eq!(arch, WalletKeyArch::AggregateThenDerive);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].xfp, "0f056943");
        assert_eq!(parsed[0].derivation_path, "m/48h/1h/0h/3h");
        assert_eq!(parsed[1].xpub, XPUB2);
    }

    #[test]
    fn descriptor_round_trips_derive_then_aggregate() {
        let signers = test_signers();
        let descriptor = descriptor_from_signers(&signers, WalletKeyArch::DeriveThenAggregate);
        assert!(!descriptor.ends_with("/<0;1>/*)"));
        assert!(descriptor.contains("/<0;1>/*,"));
        let (parsed, arch) = parse_descriptor_signers(&descriptor).expect("signers");
        assert_eq!(arch, WalletKeyArch::DeriveThenAggregate);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].xfp, "0f056943");
        assert_eq!(parsed[0].derivation_path, "m/48h/1h/0h/3h");
        assert_eq!(parsed[1].xpub, XPUB2);
    }

    #[test]
    fn rejects_single_signer() {
        let descriptor = format!("tr(musig([0f056943/48h/1h/0h/3h]{XPUB1})/<0;1>/*)");
        assert!(parse_wallet(&format!(
            "network = \"testnet\"\ndescriptor = \"{descriptor}\"\n"
        ))
        .is_err());
    }

    #[test]
    fn rejects_bad_fingerprint() {
        let descriptor = format!(
            "tr(musig([bad/48h/1h/0h/3h]{XPUB1},[6ba6cfd0/48h/1h/0h/3h]{XPUB2})/<0;1>/*)"
        );
        assert!(parse_wallet(&format!(
            "network = \"testnet\"\ndescriptor = \"{descriptor}\"\n"
        ))
        .is_err());
    }
}
