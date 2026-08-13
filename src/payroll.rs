use anyhow::{bail, Context, Result};
use bitcoin::bip32::{DerivationPath, Fingerprint};
use bitcoin::key::{TweakedPublicKey, XOnlyPublicKey};
use bitcoin::{Amount, OutPoint, ScriptBuf, TxOut, Txid};
use hmac::{Hmac, Mac};
use psbt::{core::utils::to_sp_v0_info, Psbt};
use psbt_v2::Output;
use secp256k1::{PublicKey, Secp256k1};
use sha2::Sha512;
use silentpayments::Network as SpNetwork;
use std::fs;
use std::path::{Path, PathBuf};

use crate::recipients::{address_amounts, load_recipients, PayrollRecipient};
use crate::wallet::TreasuryWalletConfig;
use psbt::musig2::{build_psbt, keyagg};

/// BIP-32 external (receive) chain: synthetic `/0/*` leaf on the aggregate key.
pub const RECEIVE_CHAIN: u32 = 0;
/// BIP-32 internal (change) chain: synthetic `/1/*` leaf on the aggregate key.
pub const CHANGE_CHAIN: u32 = 1;

#[derive(Debug, Clone)]
pub struct TreasuryPrevout {
    pub txid: Txid,
    pub vout: u32,
    pub amount: Amount,
    /// BIP-32 chain of the prevout being spent: [`RECEIVE_CHAIN`] or [`CHANGE_CHAIN`].
    pub chain: u32,
    pub derivation_index: u32,
}

#[derive(Debug, Clone)]
pub struct BuildInitialPayrollConfig {
    pub wallet: TreasuryWalletConfig,
    pub recipients_path: PathBuf,
    pub prevout: TreasuryPrevout,
    pub psbt_path: PathBuf,
    pub fee: Amount,
    pub dust_limit: Amount,
}

#[derive(Debug, Clone)]
pub struct BuildInitialPayrollResult {
    pub psbt_path: PathBuf,
    pub recipient_count: usize,
    pub total_output_sat: u64,
    pub change_sat: Option<u64>,
    pub effective_fee_sat: u64,
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
            dust_limit: Amount::from_sat(546),
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
    for (idx, recipient) in recipients.iter().enumerate() {
        if recipient.amount < config.dust_limit {
            bail!(
                "recipient[{idx}] amount {} sat is below dust limit {} sat",
                recipient.amount.to_sat(),
                config.dust_limit.to_sat()
            );
        }
    }

    let total_output = recipients
        .iter()
        .try_fold(Amount::ZERO, |acc, recipient| {
            acc.checked_add(recipient.amount)
        })
        .ok_or_else(|| anyhow::anyhow!("recipient output amount overflow"))?;
    let spend_amount = total_output
        .checked_add(config.fee)
        .ok_or_else(|| anyhow::anyhow!("recipient amount plus fee overflow"))?;
    if config.prevout.amount < spend_amount {
        bail!("prevout amount must cover total recipients plus fee");
    }
    let change = config
        .prevout
        .amount
        .checked_sub(spend_amount)
        .ok_or_else(|| anyhow::anyhow!("change amount underflow"))?;
    let change = if change == Amount::ZERO {
        None
    } else if config.dust_limit == Amount::ZERO || change >= config.dust_limit {
        Some(change)
    } else {
        None
    };
    let effective_fee = config
        .prevout
        .amount
        .checked_sub(total_output)
        .and_then(|remaining| match change {
            Some(change) => remaining.checked_sub(change),
            None => Some(remaining),
        })
        .ok_or_else(|| anyhow::anyhow!("effective fee amount underflow"))?;

    let secp = Secp256k1::new();
    let input_keys = derive_wallet_public_keys(
        &secp,
        &wallet,
        config.prevout.chain,
        config.prevout.derivation_index,
    )?;
    let change_keys =
        derive_wallet_public_keys(&secp, &wallet, CHANGE_CHAIN, wallet.change_derivation_index)?;
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
        change_sat: change.map(|amount| amount.to_sat()),
        effective_fee_sat: effective_fee.to_sat(),
        descriptor,
    })
}

pub fn derive_treasury_script_pubkey(
    wallet: &TreasuryWalletConfig,
    chain: u32,
    derivation_index: u32,
) -> Result<ScriptBuf> {
    let wallet = wallet.normalized()?;
    let secp = Secp256k1::new();
    Ok(derive_wallet_public_keys(&secp, &wallet, chain, derivation_index)?.p2tr_script)
}

struct WalletPublicKeys {
    participant_pks: Vec<PublicKey>,
    untweaked_agg_pk: PublicKey,
    plain_child_xonly: bitcoin::key::XOnlyPublicKey,
    p2tr_script: ScriptBuf,
    chain: u32,
    derivation_index: u32,
    /// Per-participant TAP_BIP32_DERIVATION key origins: the cosigner's derived
    /// x-only key with its master fingerprint and full path from that master.
    participant_origins: Vec<(XOnlyPublicKey, Fingerprint, DerivationPath)>,
}

fn derive_wallet_public_keys(
    secp: &Secp256k1<secp256k1::All>,
    wallet: &TreasuryWalletConfig,
    chain: u32,
    derivation_index: u32,
) -> Result<WalletPublicKeys> {
    let mut participant_pks = Vec::with_capacity(wallet.signers.len());
    let mut participant_origins = Vec::with_capacity(wallet.signers.len());
    for signer in &wallet.signers {
        // MuSig2 aggregates the cosigners' account-level keys (the xpub itself);
        // the per-index child is derived synthetically from the aggregate (BIP-328),
        // not by deriving each cosigner. This matches the Coldcard firmware's
        // `musig(...)/change/index` model.
        let xpub = signer.xpub_value()?;
        participant_pks.push(xpub.public_key);

        let (xonly, _) = xpub.public_key.x_only_public_key();
        let full_path = signer.derivation_path_value()?;
        participant_origins.push((xonly, signer.fingerprint()?, full_path));
    }

    participant_pks.sort_by_key(|key| key.serialize());
    let base_ctx = keyagg::build_key_agg_ctx(&participant_pks)?;
    let untweaked_agg_pk = keyagg::from_musig2_pubkey(&base_ctx.aggregated_pubkey())?;
    let path_indices = vec![chain, derivation_index];
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
        chain,
        derivation_index,
        participant_origins,
    })
}

fn construct_initial_psbt(
    input_keys: &WalletPublicKeys,
    change_keys: &WalletPublicKeys,
    prevout: &TreasuryPrevout,
    recipients: &[(silentpayments::SilentPaymentAddress, Amount)],
    change: Option<Amount>,
) -> Result<Psbt> {
    let mut outputs: Vec<Output> = recipients
        .iter()
        .map(|(address, amount)| {
            let mut output = Output::new(TxOut {
                value: *amount,
                script_pubkey: ScriptBuf::new(),
            });
            output.sp_v0_info = Some(to_sp_v0_info(address));
            output
        })
        .collect();
    if let Some(change) = change {
        outputs.push(Output::new(TxOut {
            value: change,
            script_pubkey: change_keys.p2tr_script.clone(),
        }));
    }

    let mut psbt = build_psbt(vec![OutPoint::new(prevout.txid, prevout.vout)], outputs)?;
    psbt.inputs[0].witness_utxo = Some(TxOut {
        value: prevout.amount,
        script_pubkey: input_keys.p2tr_script.clone(),
    });
    psbt.inputs[0].tap_internal_key = Some(input_keys.plain_child_xonly);
    psbt.inputs[0]
        .set_musig2_participant_pubkeys(&input_keys.untweaked_agg_pk, &input_keys.participant_pks);
    // The aggregate MuSig2 key's [chain, index] child-derivation path lives in a
    // TAP_BIP32_DERIVATION entry (BIP-373), not in the BIP-376 SP-spend field
    // (which is only for spending inputs that are themselves silent-payment
    // outputs). The finalizer reads it back to re-derive the aggregate for ECDH.
    psbt.inputs[0].set_musig2_agg_derivation(
        &input_keys.untweaked_agg_pk,
        input_keys.plain_child_xonly,
        input_keys.chain,
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
            output.set_musig2_participant_pubkeys(
                &change_keys.untweaked_agg_pk,
                &change_keys.participant_pks,
            );
            output.tap_internal_key = Some(change_keys.plain_child_xonly);
            // Mirrors the input side: the aggregate's [chain, index] path lets a signer
            // verify the change output rather than trust it. It recomputes the aggregate
            // from the participant list, checks the synthetic fingerprint, and re-derives
            // at this path to reproduce PSBT_OUT_TAP_INTERNAL_KEY.
            output.set_musig2_agg_derivation(
                &change_keys.untweaked_agg_pk,
                change_keys.plain_child_xonly,
                change_keys.chain,
                change_keys.derivation_index,
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
    use crate::wallet::{descriptor_from_signers, TreasurySigner};
    use secp256k1::SecretKey;
    use silentpayments::{SilentPaymentAddress, SpVersion};
    use std::collections::HashSet;
    use std::str::FromStr;

    const XPUB1: &str = "tpubDF2rnouQaaYrY6CUWTapYkeFEs3h3qrzL4M52ZGoPeU9dkarJMtrw6VF1zJRGuGuAFxYS3kXtavfAwQPTQkU5dyNYpbgxcpftrR8H3U85Ez";
    const XPUB2: &str = "tpubDFcrvj5n7gyazzxdg9k6uvzQsoQWow1xbksr7EvKPRBgUbwCdqu2qxyTJjYFNJ7MQLfdXSJV4n8xPZGtrvwQtEbktinC4EP3k8JN2hcBtz4";

    fn test_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "silent-pay-real-payroll-{}-{name}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).expect("temp dir");
        dir
    }

    fn test_wallet() -> TreasuryWalletConfig {
        TreasuryWalletConfig {
            network: "testnet".to_string(),
            descriptor: None,
            last_derivation_index: 0,
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
        }
    }

    fn test_prevout(amount_sat: u64) -> TreasuryPrevout {
        TreasuryPrevout {
            txid: Txid::from_str(
                "1111111111111111111111111111111111111111111111111111111111111111",
            )
            .expect("txid"),
            vout: 7,
            amount: Amount::from_sat(amount_sat),
            chain: RECEIVE_CHAIN,
            derivation_index: 0,
        }
    }

    fn save_test_recipients(path: &Path, amount_sat: u64) {
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
            path,
            &[RecipientEntry {
                label: Some("alice".to_string()),
                amount_sat,
                address: address.to_string(),
            }],
        )
        .expect("save recipients");
    }

    fn build_test_psbt(
        name: &str,
        recipient_sat: u64,
        prevout_sat: u64,
        fee_sat: u64,
        dust_limit_sat: u64,
    ) -> Result<BuildInitialPayrollResult> {
        let dir = test_dir(name);
        let recipients_path = dir.join("recipients.toml");
        let psbt_path = dir.join("payroll.psbt");
        save_test_recipients(&recipients_path, recipient_sat);

        let mut config = BuildInitialPayrollConfig::new(
            test_wallet(),
            &recipients_path,
            test_prevout(prevout_sat),
            &psbt_path,
        );
        config.fee = Amount::from_sat(fee_sat);
        config.dust_limit = Amount::from_sat(dust_limit_sat);
        build_initial_payroll_psbt(config)
    }

    fn change_output_count(psbt: &Psbt) -> usize {
        psbt.outputs
            .iter()
            .filter(|output| output.sp_v0_info.is_none())
            .count()
    }

    #[test]
    fn builds_initial_psbt_without_private_contributions() {
        let dir = test_dir("builds_initial_psbt_without_private_contributions");
        let recipients_path = dir.join("recipients.toml");
        let psbt_path = dir.join("payroll.psbt");

        save_test_recipients(&recipients_path, 2_000);
        let wallet = test_wallet();
        let prevout = test_prevout(10_000);

        let result = build_initial_payroll_psbt(BuildInitialPayrollConfig::new(
            wallet.clone(),
            &recipients_path,
            prevout.clone(),
            &psbt_path,
        ))
        .expect("build psbt");
        let psbt = inspect_initial_payroll_psbt(&result.psbt_path).expect("inspect");
        assert_eq!(result.change_sat, Some(7_000));
        assert_eq!(result.effective_fee_sat, 1_000);

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

        // Input carries one TAP_BIP32_DERIVATION per MuSig2 participant at the
        // account-level path (the aggregated key), plus one for the synthetic
        // aggregate child ([0, index]). No BIP-376 SP-spend derivation is present
        // (this input is not an SP output).
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
                    DerivationPath::from_str("m/48h/1h/0h/3h").expect("path")
                );
            }
        }
        // The aggregate entry carries the bare [0, input_index] MuSig2 child path
        // and is keyed by the taproot internal key (the derived aggregate), with
        // the synthetic root fingerprint hash160(untweaked_agg_pk)[..4].
        let secp = Secp256k1::new();
        let input_keys = derive_wallet_public_keys(
            &secp,
            &wallet.normalized().expect("wallet"),
            RECEIVE_CHAIN,
            0,
        )
        .expect("keys");
        let internal_key = psbt.inputs[0].tap_internal_key.expect("internal key");
        assert_eq!(internal_key, input_keys.plain_child_xonly);
        let (_, (agg_fp, agg_path)) = input_origins.get(&internal_key).expect("aggregate origin");
        assert_eq!(*agg_path, DerivationPath::from_str("m/0/0").expect("path"));
        assert_eq!(
            *agg_fp,
            psbt_v2::musig2_agg_fingerprint(&input_keys.untweaked_agg_pk)
        );
        assert!(psbt.inputs[0].sp_spend_bip32_derivations.is_empty());

        // Change output mirrors the input: per-participant derivations at the
        // account-level path, plus the synthetic aggregate child at
        // [CHANGE_CHAIN, change_index] keyed by the output's internal key.
        let change_output = psbt
            .outputs
            .iter()
            .find(|output| output.sp_v0_info.is_none())
            .expect("change output");
        let change_keys = derive_wallet_public_keys(
            &secp,
            &wallet.normalized().expect("wallet"),
            CHANGE_CHAIN,
            1,
        )
        .expect("keys");
        let change_internal_key = change_output.tap_internal_key.expect("internal key");
        assert_eq!(change_internal_key, change_keys.plain_child_xonly);

        let change_origins = &change_output.tap_key_origins;
        assert_eq!(change_origins.len(), 3);
        for (xonly, (_, (fp, path))) in change_origins.iter() {
            if *xonly == change_internal_key {
                continue;
            }
            assert!(signer_fps.contains(fp));
            assert_eq!(
                *path,
                DerivationPath::from_str("m/48h/1h/0h/3h").expect("path")
            );
        }

        let (leaf_hashes, (change_fp, change_path)) = change_origins
            .get(&change_internal_key)
            .expect("aggregate origin");
        assert!(leaf_hashes.is_empty());
        assert_eq!(
            *change_path,
            DerivationPath::from_str("m/1/1").expect("path")
        );
        assert_eq!(
            *change_fp,
            psbt_v2::v2::musig2_agg_fingerprint(&change_keys.untweaked_agg_pk)
        );
    }

    /// Replays the checks a hardware signer performs on the change output:
    /// recompute the bare aggregate from the participant list, verify the synthetic
    /// fingerprint belongs to it, re-derive at the supplied path to reproduce
    /// PSBT_OUT_TAP_INTERNAL_KEY, and taproot-tweak that to reproduce the script.
    #[test]
    fn change_output_is_verifiable() {
        let result = build_test_psbt("change_output_is_verifiable", 2_000, 10_000, 1_000, 546)
            .expect("build psbt");
        let psbt = inspect_initial_payroll_psbt(&result.psbt_path).expect("inspect");
        let secp = Secp256k1::new();
        let change_output = psbt
            .outputs
            .iter()
            .find(|output| output.sp_v0_info.is_none())
            .expect("change output");

        // 1. The participant list recomputes the bare aggregate.
        let participant_lists = change_output
            .parse_musig2_participant_pubkeys()
            .expect("participant pubkeys");
        assert_eq!(participant_lists.len(), 1);
        let (claimed_agg_pk, mut participants) = participant_lists[0].clone();
        participants.sort_by_key(|key| key.serialize());
        let ctx = keyagg::build_key_agg_ctx(&participants).expect("key agg");
        let recomputed_agg_pk = keyagg::from_musig2_pubkey(&ctx.aggregated_pubkey()).expect("agg");
        assert_eq!(recomputed_agg_pk, claimed_agg_pk);

        // 2. The fingerprint belongs to that aggregate's synthetic root, and the
        //    origin entry is keyed by the internal key with no leaf hashes.
        let internal_key = change_output.tap_internal_key.expect("internal key");
        let (leaf_hashes, (fingerprint, path)) = change_output
            .tap_key_origins
            .get(&internal_key)
            .expect("aggregate origin");
        assert!(leaf_hashes.is_empty());
        assert_eq!(
            *fingerprint,
            psbt_v2::v2::musig2_agg_fingerprint(&recomputed_agg_pk)
        );

        // 3. Deriving the aggregate at the supplied path reproduces the internal key.
        let path_indices: Vec<u32> = path.into_iter().map(|c| u32::from(*c)).collect();
        let derived =
            apply_bip328_plain_tweaks(&secp, recomputed_agg_pk, &path_indices).expect("derive");
        assert_eq!(derived.x_only_public_key().0, internal_key);

        // 4. The path selects the change branch of the registered descriptor.
        assert_eq!(path_indices[0], CHANGE_CHAIN);
        assert!(descriptor_from_signers(&test_wallet().signers).ends_with("/<0;1>/*)"));

        // 5. Deriving the descriptor at that branch/index reproduces PSBT_OUT_SCRIPT.
        let (tweaked_ctx, _) =
            keyagg::build_tweaked_key_agg_ctx(&secp, &participants, &path_indices)
                .expect("tweaked agg");
        let taproot_pk =
            keyagg::from_musig2_pubkey(&tweaked_ctx.aggregated_pubkey()).expect("taproot");
        let expected_script = ScriptBuf::new_p2tr_tweaked(
            TweakedPublicKey::dangerous_assume_tweaked(taproot_pk.x_only_public_key().0),
        );
        assert_eq!(change_output.script_pubkey, expected_script);
    }

    #[test]
    fn rejects_recipient_below_dust_limit() {
        let err = build_test_psbt(
            "rejects_recipient_below_dust_limit",
            545,
            10_000,
            1_000,
            546,
        )
        .unwrap_err();

        assert_eq!(
            err.to_string(),
            "recipient[0] amount 545 sat is below dust limit 546 sat"
        );
    }

    #[test]
    fn accepts_recipient_equal_to_dust_limit() {
        let result = build_test_psbt(
            "accepts_recipient_equal_to_dust_limit",
            546,
            10_000,
            1_000,
            546,
        )
        .expect("build psbt");

        assert_eq!(result.total_output_sat, 546);
    }

    #[test]
    fn omits_change_below_dust_limit_and_adds_it_to_fee() {
        let result = build_test_psbt(
            "omits_change_below_dust_limit_and_adds_it_to_fee",
            2_000,
            3_545,
            1_000,
            546,
        )
        .expect("build psbt");
        let psbt = inspect_initial_payroll_psbt(&result.psbt_path).expect("inspect");

        assert_eq!(result.change_sat, None);
        assert_eq!(result.effective_fee_sat, 1_545);
        assert_eq!(change_output_count(&psbt), 0);
    }

    #[test]
    fn omits_zero_change_without_increasing_fee() {
        let result = build_test_psbt(
            "omits_zero_change_without_increasing_fee",
            2_000,
            3_000,
            1_000,
            546,
        )
        .expect("build psbt");
        let psbt = inspect_initial_payroll_psbt(&result.psbt_path).expect("inspect");

        assert_eq!(result.change_sat, None);
        assert_eq!(result.effective_fee_sat, 1_000);
        assert_eq!(change_output_count(&psbt), 0);
    }

    #[test]
    fn creates_change_equal_to_dust_limit() {
        let result = build_test_psbt(
            "creates_change_equal_to_dust_limit",
            2_000,
            3_546,
            1_000,
            546,
        )
        .expect("build psbt");
        let psbt = inspect_initial_payroll_psbt(&result.psbt_path).expect("inspect");

        assert_eq!(result.change_sat, Some(546));
        assert_eq!(result.effective_fee_sat, 1_000);
        assert_eq!(change_output_count(&psbt), 1);
    }

    #[test]
    fn creates_change_above_dust_limit() {
        let result = build_test_psbt("creates_change_above_dust_limit", 2_000, 10_000, 1_000, 546)
            .expect("build psbt");
        let psbt = inspect_initial_payroll_psbt(&result.psbt_path).expect("inspect");

        assert_eq!(result.change_sat, Some(7_000));
        assert_eq!(result.effective_fee_sat, 1_000);
        assert_eq!(change_output_count(&psbt), 1);
    }
}
