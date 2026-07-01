use anyhow::{bail, Context, Result};
use bip375_helpers::transaction::build_psbt;
use bitcoin::bip32::{ChildNumber, DerivationPath, Fingerprint};
use bitcoin::key::{TweakedPublicKey, XOnlyPublicKey};
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, TxOut, Txid};
use hmac::{Hmac, Mac};
use psbt::Psbt;
use psbt_v2::v2::{Input, Output};
use secp256k1::{PublicKey, Secp256k1};
use sha2::Sha512;
use silentpayments::Network as SpNetwork;
use std::fs;
use std::path::{Path, PathBuf};

use crate::musig2_psbt;
use crate::musig2_spdk::keyagg;
use crate::recipients::{address_amounts, load_recipients, PayrollRecipient};
use crate::wallet::{TreasuryWalletConfig, TreasuryWalletConfig as WalletConfig};

#[derive(Debug, Clone)]
pub struct TreasuryPrevout {
    pub txid: Txid,
    pub vout: u32,
    pub amount: Amount,
}

#[derive(Debug, Clone)]
pub struct BuildInitialPayrollConfig {
    pub wallet: TreasuryWalletConfig,
    pub recipients_path: PathBuf,
    pub prevout: TreasuryPrevout,
    pub psbt_path: PathBuf,
    pub fee: Amount,
}

#[derive(Debug, Clone)]
pub struct BuildInitialPayrollResult {
    pub psbt_path: PathBuf,
    pub recipient_count: usize,
    pub total_output_sat: u64,
    pub change_sat: u64,
    pub descriptor: String,
}

impl BuildInitialPayrollConfig {
    pub fn new(
        wallet: TreasuryWalletConfig,
        recipients_path: impl Into<PathBuf>,
        prevout: TreasuryPrevout,
        psbt_path: impl Into<PathBuf>,
    ) -> Self {
        Self {
            wallet,
            recipients_path: recipients_path.into(),
            prevout,
            psbt_path: psbt_path.into(),
            fee: Amount::from_sat(1_000),
        }
    }
}

pub fn build_initial_payroll_psbt(
    config: BuildInitialPayrollConfig,
) -> Result<BuildInitialPayrollResult> {
    let wallet = config.wallet.normalized()?;
    let descriptor = wallet.descriptor_string()?;
    let recipients = load_recipients(&config.recipients_path)?;
    validate_recipient_networks(wallet.network_value()?, &recipients)?;

    let total_output = recipients
        .iter()
        .try_fold(Amount::ZERO, |acc, recipient| {
            acc.checked_add(recipient.amount)
        })
        .ok_or_else(|| anyhow::anyhow!("recipient output amount overflow"))?;
    let spend_amount = total_output
        .checked_add(config.fee)
        .ok_or_else(|| anyhow::anyhow!("recipient amount plus fee overflow"))?;
    if config.prevout.amount <= spend_amount {
        bail!("prevout amount must be greater than total recipients plus fee");
    }
    let change = config
        .prevout
        .amount
        .checked_sub(spend_amount)
        .ok_or_else(|| anyhow::anyhow!("change amount underflow"))?;

    let secp = Secp256k1::new();
    let input_keys = derive_wallet_public_keys(&secp, &wallet, wallet.input_derivation_index)?;
    let change_keys = derive_wallet_public_keys(&secp, &wallet, wallet.change_derivation_index)?;
    let recipient_pairs = address_amounts(&recipients);
    let psbt = construct_initial_psbt(
        &input_keys,
        &change_keys,
        &config.prevout,
        &recipient_pairs,
        change,
    )?;

    if let Some(parent) = config.psbt_path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
    }
    fs::write(&config.psbt_path, psbt.serialize())
        .with_context(|| format!("failed to write PSBT {}", config.psbt_path.display()))?;

    Ok(BuildInitialPayrollResult {
        psbt_path: config.psbt_path,
        recipient_count: recipients.len(),
        total_output_sat: total_output.to_sat(),
        change_sat: change.to_sat(),
        descriptor,
    })
}

struct WalletPublicKeys {
    participant_pks: Vec<PublicKey>,
    untweaked_agg_pk: PublicKey,
    plain_child_xonly: bitcoin::key::XOnlyPublicKey,
    p2tr_script: ScriptBuf,
    derivation_index: u32,
    /// Per-participant TAP_BIP32_DERIVATION key origins: the cosigner's derived
    /// x-only key with its master fingerprint and full path from that master.
    participant_origins: Vec<(XOnlyPublicKey, Fingerprint, DerivationPath)>,
}

fn derive_wallet_public_keys(
    secp: &Secp256k1<secp256k1::All>,
    wallet: &WalletConfig,
    derivation_index: u32,
) -> Result<WalletPublicKeys> {
    let mut participant_pks = Vec::with_capacity(wallet.signers.len());
    let mut participant_origins = Vec::with_capacity(wallet.signers.len());
    let child_path = signer_child_path(derivation_index);
    for signer in &wallet.signers {
        let xpub = signer.xpub_value()?;
        let child = xpub
            .derive_pub(secp, &child_path)
            .with_context(|| format!("failed to derive signer xpub {}", signer.xfp))?;
        participant_pks.push(child.public_key);

        let (xonly, _) = child.public_key.x_only_public_key();
        let full_path = signer.derivation_path_value()?.extend(&child_path);
        participant_origins.push((xonly, signer.fingerprint()?, full_path));
    }

    let base_ctx = keyagg::build_key_agg_ctx(&participant_pks)?;
    let untweaked_agg_pk = keyagg::from_musig2_pubkey(&base_ctx.aggregated_pubkey())?;
    let path_indices = vec![0, derivation_index];
    let plain_child_pk = apply_bip328_plain_tweaks(secp, untweaked_agg_pk, &path_indices)?;
    let (plain_child_xonly, _) = plain_child_pk.x_only_public_key();
    let (tweaked_ctx, _) =
        keyagg::build_tweaked_key_agg_ctx(secp, &participant_pks, &path_indices)?;
    let taproot_pk = keyagg::from_musig2_pubkey(&tweaked_ctx.aggregated_pubkey())?;
    let (taproot_xonly, _) = taproot_pk.x_only_public_key();
    let p2tr_script =
        ScriptBuf::new_p2tr_tweaked(TweakedPublicKey::dangerous_assume_tweaked(taproot_xonly));

    Ok(WalletPublicKeys {
        participant_pks,
        untweaked_agg_pk,
        plain_child_xonly,
        p2tr_script,
        derivation_index,
        participant_origins,
    })
}

fn construct_initial_psbt(
    input_keys: &WalletPublicKeys,
    change_keys: &WalletPublicKeys,
    prevout: &TreasuryPrevout,
    recipients: &[(silentpayments::SilentPaymentAddress, Amount)],
    change: Amount,
) -> Result<Psbt> {
    let mut input = Input::new(&OutPoint::new(prevout.txid, prevout.vout));
    input.sequence = Some(Sequence::MAX);
    input.witness_utxo = Some(TxOut {
        value: prevout.amount,
        script_pubkey: input_keys.p2tr_script.clone(),
    });

    let mut outputs: Vec<Output> = recipients
        .iter()
        .map(|(address, amount)| {
            let mut output = Output::new(TxOut {
                value: *amount,
                script_pubkey: ScriptBuf::new(),
            });
            output.sp_v0_info = Some(sp_v0_info_bytes(address));
            output
        })
        .collect();
    outputs.push(Output::new(TxOut {
        value: change,
        script_pubkey: change_keys.p2tr_script.clone(),
    }));

    let mut psbt = build_psbt(vec![input], outputs).map_err(|e| anyhow::anyhow!(e))?;
    psbt.inputs[0].tap_internal_key = Some(input_keys.plain_child_xonly);
    musig2_psbt::set_input_musig2_participant_pubkeys(
        &mut psbt.inputs[0],
        &input_keys.untweaked_agg_pk,
        &input_keys.participant_pks,
    );
    // The aggregate MuSig2 key's [0, index] child-derivation path lives in a
    // TAP_BIP32_DERIVATION entry (BIP-373), not in the BIP-376 SP-spend field
    // (which is only for spending inputs that are themselves silent-payment
    // outputs). The finalizer reads it back to re-derive the aggregate for ECDH.
    musig2_psbt::set_input_musig2_agg_derivation(
        &mut psbt.inputs[0],
        &input_keys.untweaked_agg_pk,
        input_keys.derivation_index,
    );
    // BIP-373: per-participant TAP_BIP32_DERIVATION so each cosigner's signing
    // device can recognize its key on the MuSig2 taproot input.
    for (xonly, fingerprint, path) in &input_keys.participant_origins {
        psbt.inputs[0]
            .tap_key_origins
            .insert(*xonly, (Vec::new(), (*fingerprint, path.clone())));
    }

    for output in &mut psbt.outputs {
        if output.sp_v0_info.is_none() {
            musig2_psbt::set_output_musig2_participant_pubkeys(
                output,
                &change_keys.untweaked_agg_pk,
                &change_keys.participant_pks,
            );
            for (xonly, fingerprint, path) in &change_keys.participant_origins {
                output
                    .tap_key_origins
                    .insert(*xonly, (Vec::new(), (*fingerprint, path.clone())));
            }
        }
    }

    Ok(psbt)
}

fn validate_recipient_networks(
    wallet_network: SpNetwork,
    recipients: &[PayrollRecipient],
) -> Result<()> {
    for (idx, recipient) in recipients.iter().enumerate() {
        if recipient.address.get_network() != wallet_network {
            bail!(
                "recipient[{idx}] network {:?} does not match wallet network {:?}",
                recipient.address.get_network(),
                wallet_network
            );
        }
    }
    Ok(())
}

fn sp_v0_info_bytes(address: &silentpayments::SilentPaymentAddress) -> [u8; 66] {
    let mut bytes = [0u8; 66];
    bytes[..33].copy_from_slice(&address.get_scan_key().serialize());
    bytes[33..].copy_from_slice(&address.get_spend_key().serialize());
    bytes
}

fn signer_child_path(index: u32) -> DerivationPath {
    [0, index].iter().map(|&n| ChildNumber::from(n)).collect()
}

fn apply_bip328_plain_tweaks(
    secp: &Secp256k1<secp256k1::All>,
    mut current_pk: PublicKey,
    path: &[u32],
) -> Result<PublicKey> {
    type HmacSha512 = Hmac<Sha512>;

    let mut chaincode =
        hex::decode("868087ca02a6f974c4598924c36b57762d32cb45717167e300622c7167e38965")
            .context("invalid synthetic chaincode")?;
    for index in path {
        let mut data = Vec::with_capacity(37);
        data.extend_from_slice(&current_pk.serialize());
        data.extend_from_slice(&index.to_be_bytes());

        let mut mac = HmacSha512::new_from_slice(&chaincode).context("HMAC init failed")?;
        mac.update(&data);
        let result = mac.finalize().into_bytes();
        let scalar = secp256k1::Scalar::from_be_bytes(result[..32].try_into()?)
            .map_err(|e| anyhow::anyhow!("invalid derivation scalar: {e}"))?;
        current_pk = current_pk.add_exp_tweak(secp, &scalar)?;
        chaincode = result[32..64].to_vec();
    }
    Ok(current_pk)
}

#[allow(dead_code)]
pub fn inspect_initial_payroll_psbt(path: impl AsRef<Path>) -> Result<Psbt> {
    let bytes = fs::read(path.as_ref())
        .with_context(|| format!("failed to read PSBT {}", path.as_ref().display()))?;
    Psbt::deserialize(&bytes).context("failed to parse PSBT")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recipients::RecipientEntry;
    use crate::wallet::TreasurySigner;
    use secp256k1::SecretKey;
    use silentpayments::{SilentPaymentAddress, SpVersion};
    use std::collections::HashSet;
    use std::str::FromStr;

    const XPUB1: &str = "tpubDF2rnouQaaYrY6CUWTapYkeFEs3h3qrzL4M52ZGoPeU9dkarJMtrw6VF1zJRGuGuAFxYS3kXtavfAwQPTQkU5dyNYpbgxcpftrR8H3U85Ez";
    const XPUB2: &str = "tpubDFcrvj5n7gyazzxdg9k6uvzQsoQWow1xbksr7EvKPRBgUbwCdqu2qxyTJjYFNJ7MQLfdXSJV4n8xPZGtrvwQtEbktinC4EP3k8JN2hcBtz4";

    #[test]
    fn builds_initial_psbt_without_private_contributions() {
        let dir =
            std::env::temp_dir().join(format!("silent-pay-real-payroll-{}", std::process::id()));
        fs::create_dir_all(&dir).expect("temp dir");
        let recipients_path = dir.join("recipients.toml");
        let psbt_path = dir.join("payroll.psbt");

        let secp = Secp256k1::new();
        let scan_sk = SecretKey::from_slice(&[3u8; 32]).expect("scan key");
        let spend_sk = SecretKey::from_slice(&[4u8; 32]).expect("spend key");
        let address = SilentPaymentAddress::new(
            PublicKey::from_secret_key(&secp, &scan_sk),
            PublicKey::from_secret_key(&secp, &spend_sk),
            SpNetwork::Testnet,
            SpVersion::ZERO,
        );
        crate::recipients::save_recipients(
            &recipients_path,
            &[RecipientEntry {
                label: Some("alice".to_string()),
                amount_sat: 2_000,
                seed_hex: None,
                address: Some(address.to_string()),
            }],
        )
        .expect("save recipients");

        let wallet = TreasuryWalletConfig {
            network: "testnet".to_string(),
            descriptor: None,
            input_derivation_index: 0,
            change_derivation_index: 1,
            signers: vec![
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
            ],
        };
        let prevout = TreasuryPrevout {
            txid: Txid::from_str(
                "1111111111111111111111111111111111111111111111111111111111111111",
            )
            .expect("txid"),
            vout: 7,
            amount: Amount::from_sat(10_000),
        };

        let result = build_initial_payroll_psbt(BuildInitialPayrollConfig::new(
            wallet,
            &recipients_path,
            prevout.clone(),
            &psbt_path,
        ))
        .expect("build psbt");
        let psbt = inspect_initial_payroll_psbt(&result.psbt_path).expect("inspect");

        assert_eq!(
            psbt.inputs[0].previous_txid.to_string(),
            prevout.txid.to_string()
        );
        assert_eq!(psbt.inputs[0].spent_output_index, prevout.vout);
        assert_eq!(
            psbt.inputs[0].witness_utxo.as_ref().expect("utxo").value,
            prevout.amount
        );
        let input_script = &psbt.inputs[0]
            .witness_utxo
            .as_ref()
            .expect("utxo")
            .script_pubkey;
        let change_script = &psbt
            .outputs
            .iter()
            .find(|output| output.sp_v0_info.is_none())
            .expect("change output")
            .script_pubkey;
        assert_ne!(input_script, change_script);
        assert_eq!(
            psbt.outputs
                .iter()
                .filter(|output| output.sp_v0_info.is_some())
                .count(),
            1
        );
        assert!(psbt.inputs[0].musig2_pub_nonces.is_empty());
        assert!(psbt.inputs[0].musig2_partial_sigs.is_empty());
        assert!(psbt.inputs[0].unknowns.is_empty());

        // Input carries one TAP_BIP32_DERIVATION per MuSig2 participant (full path
        // account + /0/index) plus one for the aggregate key ([0, index]). No
        // BIP-376 SP-spend derivation is present (this input is not an SP output).
        let input_origins = &psbt.inputs[0].tap_key_origins;
        assert_eq!(input_origins.len(), 3);
        let signer_fps = HashSet::from([
            Fingerprint::from_str("0f056943").expect("fp"),
            Fingerprint::from_str("6ba6cfd0").expect("fp"),
        ]);
        let input_fps: HashSet<Fingerprint> =
            input_origins.values().map(|(_, (fp, _))| *fp).collect();
        assert!(signer_fps.is_subset(&input_fps));
        for (_, (fp, path)) in input_origins.values() {
            if signer_fps.contains(fp) {
                assert_eq!(
                    *path,
                    DerivationPath::from_str("m/48h/1h/0h/3h/0/0").expect("path")
                );
            }
        }
        // The aggregate entry carries the bare [0, input_index] MuSig2 child path.
        assert!(input_origins.values().any(|(_, (_, path))| *path
            == DerivationPath::from_str("m/0/0").expect("path")));
        assert!(psbt.inputs[0].sp_spend_bip32_derivations.is_empty());

        // Change output carries the same per-participant derivations at the
        // change index (/0/1).
        let change_origins = &psbt
            .outputs
            .iter()
            .find(|output| output.sp_v0_info.is_none())
            .expect("change output")
            .tap_key_origins;
        assert_eq!(change_origins.len(), 2);
        for (_, (_, path)) in change_origins.values() {
            assert_eq!(
                *path,
                DerivationPath::from_str("m/48h/1h/0h/3h/0/1").expect("path")
            );
        }
    }
}
