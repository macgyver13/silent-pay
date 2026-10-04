use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use bitcoin::bip32::{ChildNumber, DerivationPath};
use bitcoin::{Amount, Transaction};
use frost_secp256k1_tr as frost;
use psbt::Psbt;
use rand::{CryptoRng, RngCore};
use secp256k1::{PublicKey, Secp256k1};
use silentpayments::{Network as SpNetwork, SilentPaymentAddress, SpVersion};

use crate::derivation::{derive_public, DerivedPublic};
use crate::frost_psbt::FrostInputExt;
use crate::frost_spdk::{self, Round1Secret};
use crate::wallet::{PublicWalletFile, ShareFile};
use crate::workflow;

pub struct PendingRoundOne {
    initial: Psbt,
    secret: Round1Secret,
    key: frost::keys::KeyPackage,
    public: DerivedPublic,
    recipients: Vec<SilentPaymentAddress>,
}

pub struct Companion {
    share: ShareFile,
    wallet_directory: PathBuf,
    pending: Option<PendingRoundOne>,
}

impl Companion {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let share = ShareFile::load(path)?;
        share.packages()?;
        Ok(Self {
            share,
            wallet_directory: path
                .parent()
                .context("companion share has no parent folder")?
                .to_owned(),
            pending: None,
        })
    }

    pub fn participant(&self) -> u16 {
        self.share.participant
    }

    pub fn has_active_nonce(&self) -> bool {
        self.pending.is_some()
    }

    pub fn wallet_directory(&self) -> &Path {
        &self.wallet_directory
    }

    pub fn round_one_file(&self) -> PathBuf {
        self.wallet_directory
            .join(format!("frost-round-one.{}.psbt", self.participant()))
    }

    pub fn round_two_file(&self) -> PathBuf {
        self.wallet_directory
            .join(format!("frost-round-two.{}.psbt", self.participant()))
    }

    pub fn round_one<R: RngCore + CryptoRng>(
        &mut self,
        initial: &Psbt,
        rng: &mut R,
    ) -> Result<Psbt> {
        if self.pending.is_some() {
            bail!("this companion already holds a nonce for an active session");
        }
        let (root_key, root_public) = self.share.packages()?;
        let path = discover_child_path(initial, &root_public, &self.share.root_fingerprint)?;
        let public = derive_public(&root_public, &path)?;
        validate_wallet_binding(
            initial,
            &root_public,
            &public.derived,
            &self.share.root_fingerprint,
            &path,
        )?;
        let recipients = recipients(initial)?;
        let mut contribution = initial.clone();
        let secret = workflow::contribute(
            &Secp256k1::new(),
            &mut contribution,
            &root_key,
            &public,
            rng,
        )?;
        self.pending = Some(PendingRoundOne {
            initial: initial.clone(),
            secret,
            key: root_key,
            public,
            recipients,
        });
        Ok(contribution)
    }

    pub fn round_two(&mut self, signing: &Psbt) -> Result<Psbt> {
        let pending = self.pending.take().context(
            "no in-memory round-one nonce; restart requires a fresh coordinator session",
        )?;
        let result = (|| {
            validate_session_intent(&pending.initial, signing)?;
            let (_, signers) = signing.inputs[0]
                .frost_signer_set()?
                .context("missing FROST signer set")?;
            if !signers.contains(&frost_spdk::psbt_identifier(*pending.key.identifier())?) {
                bail!("this companion was not selected by the signing PSBT");
            }
            let mut contribution = signing.clone();
            let sighash = workflow::compute_sighash(&contribution)?;
            let package = workflow::signing_package(&contribution, &sighash, &pending.public)?;
            workflow::partial_sign(
                &Secp256k1::new(),
                &mut contribution,
                &package,
                pending.secret,
                &pending.key,
                &pending.public,
                &pending.recipients,
            )?;
            Ok(contribution)
        })();
        // The nonce is consumed on every signing attempt. This deliberately
        // prevents retry after approval or validation failure.
        result
    }
}

pub fn create_initial(
    wallet: &PublicWalletFile,
    receive_index: u32,
    amount: Amount,
) -> Result<Psbt> {
    let root = wallet.package()?;
    let path = [0, receive_index];
    let derived = derive_public(&root, &path)?.derived;
    let change_public = derive_public(&root, &[1, receive_index])?.derived;
    let setup = workflow::setup_public(derived)?;
    let change_setup = workflow::setup_public(change_public)?;
    let mut psbt = workflow::construct_psbt(&setup, &root, &[(setup.sp_address, amount)])?;
    let receive_source = (
        wallet.fingerprint()?,
        DerivationPath::from(vec![
            ChildNumber::from_normal_idx(path[0])?,
            ChildNumber::from_normal_idx(path[1])?,
        ]),
    );
    psbt.inputs[0]
        .tap_key_origins
        .insert(setup.internal_key, (vec![], receive_source));
    let change_source = (
        wallet.fingerprint()?,
        DerivationPath::from(vec![
            ChildNumber::from_normal_idx(1)?,
            ChildNumber::from_normal_idx(receive_index)?,
        ]),
    );
    for output in &mut psbt.outputs {
        if output.sp_v0_info.is_none() {
            output.script_pubkey = change_setup.p2tr_script.clone();
            output
                .tap_key_origins
                .insert(change_setup.internal_key, (vec![], change_source.clone()));
            output.tap_internal_key = Some(change_setup.internal_key);
        }
    }
    Ok(psbt)
}

pub fn collect_round_one(
    wallet: &PublicWalletFile,
    initial: &Psbt,
    contributions: &[Psbt],
) -> Result<Psbt> {
    if contributions.len() != 2 {
        bail!("exactly two independent round-one PSBTs are required");
    }
    let mut combined = initial.clone();
    for contribution in contributions {
        validate_transaction_shape(initial, contribution)?;
        combined = combined.combine_with(contribution.clone())?;
    }
    if combined.inputs[0].frost_commitments()?.len() != 2 {
        bail!("round one must contain exactly two distinct commitments");
    }
    let public = authenticated_public(wallet, &combined)?;
    workflow::derive_sp_outputs(&Secp256k1::new(), &mut combined, &public)?;
    Ok(combined)
}

pub fn collect_round_two(signing: &Psbt, contributions: &[Psbt]) -> Result<Psbt> {
    if contributions.len() != 2 {
        bail!("exactly two independent round-two PSBTs are required");
    }
    let mut combined = signing.clone();
    for contribution in contributions {
        validate_transaction_shape(signing, contribution)?;
        combined = combined.combine_with(contribution.clone())?;
    }
    if combined.inputs[0].frost_signature_shares()?.len() != 2 {
        bail!("round two must contain exactly two distinct signature shares");
    }
    Ok(combined)
}

pub fn finalize(wallet: &PublicWalletFile, psbt: &mut Psbt) -> Result<Transaction> {
    let public = authenticated_public(wallet, psbt)?;
    let sighash = workflow::compute_sighash(psbt)?;
    let package = workflow::signing_package(psbt, &sighash, &public)?;
    workflow::aggregate_and_extract(psbt, &package, &public)
}

fn authenticated_public(wallet: &PublicWalletFile, psbt: &Psbt) -> Result<DerivedPublic> {
    let root = wallet.package()?;
    let path = discover_child_path(psbt, &root, &wallet.root_fingerprint)?;
    frost_spdk::validate_threshold_info(&psbt.inputs[0], &root)
        .context("PSBT FROST threshold info does not match the authenticated coordinator wallet")?;
    derive_public(&root, &path)
}

fn discover_child_path(
    psbt: &Psbt,
    root_public: &frost::keys::PublicKeyPackage,
    expected_fingerprint: &str,
) -> Result<[u32; 2]> {
    let input = psbt.inputs.first().context("missing FROST input")?;
    let witness = input
        .witness_utxo
        .as_ref()
        .context("missing witness_utxo")?;
    let mut matches = Vec::new();

    for (internal_key, (_, (fingerprint, derivation))) in &input.tap_key_origins {
        if hex::encode(fingerprint.to_bytes()) != expected_fingerprint {
            continue;
        }
        let [first, second] = derivation.as_ref() else {
            continue;
        };
        let path = match (first, second) {
            (ChildNumber::Normal { index: branch }, ChildNumber::Normal { index })
                if *branch <= 1 =>
            {
                [*branch, *index]
            }
            _ => continue,
        };
        let derived = derive_public(root_public, &path)?.derived;
        let setup = workflow::setup_public(derived)?;
        if setup.internal_key == *internal_key && setup.p2tr_script == witness.script_pubkey {
            matches.push(path);
        }
    }

    match matches.as_slice() {
        [path] => Ok(*path),
        [] => bail!("no Taproot key origin matches the authenticated FROST wallet"),
        _ => bail!("multiple Taproot key origins match the authenticated FROST wallet"),
    }
}

fn recipients(psbt: &Psbt) -> Result<Vec<SilentPaymentAddress>> {
    psbt.outputs
        .iter()
        .filter_map(|output| output.sp_v0_info)
        .map(|info| {
            Ok(SilentPaymentAddress::new(
                info.scan_key().context("parse SP scan key")?.0,
                info.spend_key().context("parse SP spending key")?.0,
                SpNetwork::Mainnet,
                SpVersion::ZERO,
            ))
        })
        .collect()
}

fn validate_wallet_binding(
    psbt: &Psbt,
    root_public: &frost::keys::PublicKeyPackage,
    receive_public: &frost::keys::PublicKeyPackage,
    expected_fingerprint: &str,
    path: &[u32; 2],
) -> Result<()> {
    let setup = workflow::setup_public(receive_public.clone())?;
    let (_, source) = psbt.inputs[0]
        .tap_key_origins
        .get_key_value(&setup.internal_key)
        .context("missing standard Taproot key origin for derived FROST key")?;
    let expected_path = DerivationPath::from(vec![
        ChildNumber::from_normal_idx(path[0])?,
        ChildNumber::from_normal_idx(path[1])?,
    ]);
    if hex::encode(source.1 .0.to_bytes()) != expected_fingerprint || source.1 .1 != expected_path {
        bail!("Taproot key origin does not match the authenticated FROST wallet");
    }
    let witness = psbt.inputs[0]
        .witness_utxo
        .as_ref()
        .context("missing witness_utxo")?;
    if witness.script_pubkey != setup.p2tr_script {
        bail!("witness_utxo does not pay the derived FROST key");
    }
    let change_public = derive_public(root_public, &[1, path[1]])?.derived;
    let change_setup = workflow::setup_public(change_public)?;
    let change = psbt
        .outputs
        .iter()
        .filter(|output| output.sp_v0_info.is_none())
        .collect::<Vec<_>>();
    if change.len() != 1 || change[0].script_pubkey != change_setup.p2tr_script {
        bail!("PSBT change does not pay the authenticated derived FROST key");
    }
    let (_, change_source) = change[0]
        .tap_key_origins
        .get_key_value(&change_setup.internal_key)
        .context("change is missing its standard Taproot key origin")?;
    let expected_change_path = DerivationPath::from(vec![
        ChildNumber::from_normal_idx(1)?,
        ChildNumber::from_normal_idx(path[1])?,
    ]);
    if change_source.1 .1 != expected_change_path {
        bail!("change Taproot key origin has the wrong derivation path");
    }
    Ok(())
}

fn validate_transaction_shape(expected: &Psbt, actual: &Psbt) -> Result<()> {
    if expected.global.tx_version != actual.global.tx_version
        || expected.global.input_count != actual.global.input_count
        || expected.global.output_count != actual.global.output_count
        || expected.inputs.len() != actual.inputs.len()
        || expected.outputs.len() != actual.outputs.len()
    {
        bail!("contribution changed the PSBT transaction shape");
    }
    for (a, b) in expected.inputs.iter().zip(&actual.inputs) {
        if a.previous_txid != b.previous_txid
            || a.spent_output_index != b.spent_output_index
            || a.sequence != b.sequence
            || a.witness_utxo != b.witness_utxo
            || a.tap_internal_key != b.tap_internal_key
            || a.tap_key_origins != b.tap_key_origins
        {
            bail!("contribution modified an input");
        }
    }
    for (a, b) in expected.outputs.iter().zip(&actual.outputs) {
        if a.amount != b.amount
            || a.script_pubkey != b.script_pubkey
            || a.sp_v0_info != b.sp_v0_info
        {
            bail!("contribution modified an output");
        }
    }
    Ok(())
}

fn validate_session_intent(initial: &Psbt, signing: &Psbt) -> Result<()> {
    if initial.global.tx_version != signing.global.tx_version
        || initial.global.fallback_lock_time != signing.global.fallback_lock_time
        || initial.global.input_count != signing.global.input_count
        || initial.global.output_count != signing.global.output_count
        || initial.inputs.len() != signing.inputs.len()
        || initial.outputs.len() != signing.outputs.len()
    {
        bail!("signing PSBT does not match the pending round-one intent");
    }
    for (a, b) in initial.inputs.iter().zip(&signing.inputs) {
        if a.previous_txid != b.previous_txid
            || a.spent_output_index != b.spent_output_index
            || a.sequence != b.sequence
            || a.witness_utxo != b.witness_utxo
            || a.tap_internal_key != b.tap_internal_key
            || a.tap_key_origins != b.tap_key_origins
        {
            bail!("signing PSBT modified a pending round-one input");
        }
    }
    for (a, b) in initial.outputs.iter().zip(&signing.outputs) {
        let script_matches = if a.sp_v0_info.is_some() {
            true
        } else {
            a.script_pubkey == b.script_pubkey
        };
        if a.amount != b.amount || a.sp_v0_info != b.sp_v0_info || !script_matches {
            bail!("signing PSBT modified a pending round-one output");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet;
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn full_file_equivalent_flow_for_every_subset() {
        let directory = std::env::temp_dir().join(format!("frost-flow-{}", rand::random::<u64>()));
        let (wallet_path, shares) = wallet::provision(&directory).unwrap();
        let wallet = PublicWalletFile::load(wallet_path).unwrap();
        for subset in [[0, 1], [0, 2], [1, 2]] {
            let initial = create_initial(&wallet, 7, Amount::from_sat(90_000)).unwrap();
            let mut companions = [
                Companion::load(&shares[subset[0]]).unwrap(),
                Companion::load(&shares[subset[1]]).unwrap(),
            ];
            let mut rng = StdRng::seed_from_u64(40 + subset[0] as u64 * 3 + subset[1] as u64);
            let round_one = companions
                .iter_mut()
                .map(|companion| companion.round_one(&initial, &mut rng).unwrap())
                .collect::<Vec<_>>();
            let signing = collect_round_one(&wallet, &initial, &round_one).unwrap();
            let message = workflow::compute_sighash(&signing).unwrap();
            let round_two = companions
                .iter_mut()
                .map(|companion| companion.round_two(&signing).unwrap())
                .collect::<Vec<_>>();
            assert!(companions
                .iter()
                .all(|companion| !companion.has_active_nonce()));
            let mut signed = collect_round_two(&signing, &round_two).unwrap();
            let transaction = finalize(&wallet, &mut signed).unwrap();
            let signature = secp256k1::schnorr::Signature::from_slice(
                transaction.input[0].witness.iter().next().unwrap(),
            )
            .unwrap();
            let public = derive_public(&wallet.package().unwrap(), &[0, 7]).unwrap();
            let setup = workflow::setup_public(public.derived).unwrap();
            Secp256k1::verification_only()
                .verify_schnorr(
                    &signature,
                    &secp256k1::Message::from_digest(message),
                    &setup.output_key,
                )
                .unwrap();

            // Recipient side: scan with b_scan against the spent output key.
            // Coordinator and companions share the ECDH code, so only this
            // independent check catches a combination that is wrong for both.
            let secp = Secp256k1::new();
            let scan_secret = secp256k1::SecretKey::from_slice(&[0x11; 32]).unwrap();
            let spend_key = secp256k1::PublicKey::from_secret_key(
                &secp,
                &secp256k1::SecretKey::from_slice(&[0x22; 32]).unwrap(),
            );
            let input_key = secp256k1::PublicKey::from_x_only_public_key(
                setup.output_key,
                secp256k1::Parity::Even,
            );
            let input_hash =
                frost_spdk::input_hash(&signed.inputs[0].outpoint_bytes(), &input_key).unwrap();
            let shared = input_key
                .mul_tweak(&secp, &secp256k1::Scalar::from(scan_secret))
                .unwrap()
                .mul_tweak(
                    &secp,
                    &secp256k1::Scalar::from_be_bytes(input_hash).unwrap(),
                )
                .unwrap();
            let expected =
                frost_spdk::derive_silent_payment_output(&secp, &spend_key, &shared, 0).unwrap();
            let sp_index = signed
                .outputs
                .iter()
                .position(|output| output.sp_v0_info.is_some())
                .unwrap();
            assert_eq!(
                transaction.output[sp_index].script_pubkey,
                bitcoin::ScriptBuf::new_p2tr_tweaked(
                    bitcoin::key::TweakedPublicKey::dangerous_assume_tweaked(
                        expected.x_only_public_key().0
                    )
                ),
                "recipient cannot find the payment for subset {subset:?}"
            );
        }
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn nonce_is_consumed_after_every_round_two_attempt() {
        let directory = std::env::temp_dir().join(format!("frost-nonce-{}", rand::random::<u64>()));
        let (wallet_path, shares) = wallet::provision(&directory).unwrap();
        let wallet = PublicWalletFile::load(wallet_path).unwrap();
        let first = create_initial(&wallet, 1, Amount::from_sat(50_000)).unwrap();
        let second = create_initial(&wallet, 1, Amount::from_sat(50_000)).unwrap();
        let mut companion = Companion::load(&shares[0]).unwrap();
        let mut rng = StdRng::seed_from_u64(9);
        companion.round_one(&first, &mut rng).unwrap();
        assert!(companion.round_one(&first, &mut rng).is_err());
        assert!(companion.round_two(&second).is_err());
        assert!(!companion.has_active_nonce());
        companion.round_one(&first, &mut rng).unwrap();
        assert!(companion.has_active_nonce());
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn initial_psbt_has_no_frost_global_fields() {
        let directory =
            std::env::temp_dir().join(format!("frost-no-globals-{}", rand::random::<u64>()));
        let (wallet_path, _) = wallet::provision(&directory).unwrap();
        let wallet = PublicWalletFile::load(wallet_path).unwrap();
        let psbt = create_initial(&wallet, 7, Amount::from_sat(50_000)).unwrap();

        assert!(psbt
            .global
            .unknowns
            .keys()
            .all(|key| !matches!(key.type_value, 0x50..=0x52)));
        assert_eq!(
            discover_child_path(&psbt, &wallet.package().unwrap(), &wallet.root_fingerprint)
                .unwrap(),
            [0, 7]
        );
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn companion_file_names_include_the_round_and_share_identifier() {
        let directory =
            std::env::temp_dir().join(format!("frost-file-names-{}", rand::random::<u64>()));
        let (_, shares) = wallet::provision(&directory).unwrap();
        let companion = Companion::load(&shares[1]).unwrap();
        assert_eq!(
            companion.round_one_file(),
            directory.join("frost-round-one.2.psbt")
        );
        assert_eq!(
            companion.round_two_file(),
            directory.join("frost-round-two.2.psbt")
        );
        std::fs::remove_dir_all(directory).unwrap();
    }
}
