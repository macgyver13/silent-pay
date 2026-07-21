use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use bitcoin::bip32::{ChildNumber, DerivationPath};
use bitcoin::{Amount, Transaction};
use frost_secp256k1_tr as frost;
use psbt::Psbt;
use rand::{rngs::OsRng, CryptoRng, RngCore};
use secp256k1::{PublicKey, Secp256k1};
use silentpayments::{Network as SpNetwork, SilentPaymentAddress, SpVersion};

use crate::derivation::{derive_key, derive_public};
use crate::frost_psbt::FrostInputExt;
use crate::frost_spdk::Round1Secret;
use crate::session;
use crate::wallet::{PublicWalletFile, ShareFile};
use crate::workflow;

pub struct PendingRoundOne {
    session_id: [u8; 32],
    secret: Round1Secret,
    key: frost::keys::KeyPackage,
    public: frost::keys::PublicKeyPackage,
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
        let session_id = session::validate(initial)?;
        let path = session::child_path(initial)?;
        let (root_key, root_public) = self.share.packages()?;
        let (key, public, _) = derive_key(&root_key, &root_public, &path)?;
        validate_wallet_binding(
            initial,
            &root_public,
            &public,
            &self.share.root_fingerprint,
            &path,
        )?;
        let recipients = recipients(initial)?;
        let mut contribution = initial.clone();
        let secret =
            workflow::contribute(&Secp256k1::new(), &mut contribution, &key, &public, rng)?;
        self.pending = Some(PendingRoundOne {
            session_id,
            secret,
            key,
            public,
            recipients,
        });
        Ok(contribution)
    }

    pub fn round_two(&mut self, signing: &Psbt) -> Result<Psbt> {
        let session_id = session::validate(signing)?;
        let pending = self.pending.take().context(
            "no in-memory round-one nonce; restart requires a fresh coordinator session",
        )?;
        if session_id != pending.session_id {
            self.pending = Some(pending);
            bail!("signing PSBT belongs to a different FROST session");
        }
        let result = (|| {
            let commitments = signing.inputs[0].frost_commitments()?;
            let identifier = pending.key.identifier().serialize();
            if !commitments.contains_key(&identifier) {
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
    let (derived, _) = derive_public(&root, &path)?;
    let (change_public, _) = derive_public(&root, &[1, receive_index])?;
    let setup = workflow::setup_public(derived)?;
    let change_setup = workflow::setup_public(change_public)?;
    let mut psbt = workflow::construct_psbt(&setup, &[(setup.sp_address, amount)])?;
    session::initialize(&mut psbt, &mut OsRng);
    session::set_child_path(&mut psbt, path[0], path[1]);
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
            // The provisional participant tag describes the input signing
            // roster. Change instead uses its standard Taproot key origin.
            output.unknowns.retain(|key, _| key.type_value != 0x20);
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
    let session_id = session::validate(initial)?;
    let mut combined = initial.clone();
    for contribution in contributions {
        if session::validate(contribution)? != session_id {
            bail!("round-one contribution belongs to a different session");
        }
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
    let session_id = session::validate(signing)?;
    let mut combined = signing.clone();
    for contribution in contributions {
        if session::validate(contribution)? != session_id {
            bail!("round-two contribution belongs to a different session");
        }
        validate_transaction_shape(signing, contribution)?;
        combined = combined.combine_with(contribution.clone())?;
    }
    if combined.inputs[0].frost_signature_shares()?.len() != 2 {
        bail!("round two must contain exactly two distinct signature shares");
    }
    Ok(combined)
}

pub fn finalize(wallet: &PublicWalletFile, psbt: &mut Psbt) -> Result<Transaction> {
    session::validate(psbt)?;
    let public = authenticated_public(wallet, psbt)?;
    let sighash = workflow::compute_sighash(psbt)?;
    let package = workflow::signing_package(psbt, &sighash, &public)?;
    workflow::aggregate_and_extract(psbt, &package, &public)
}

fn authenticated_public(
    wallet: &PublicWalletFile,
    psbt: &Psbt,
) -> Result<frost::keys::PublicKeyPackage> {
    let path = session::child_path(psbt)?;
    let (expected, _) = derive_public(&wallet.package()?, &path)?;
    let encoded = public_from_psbt(psbt)?;
    if encoded != expected {
        bail!("PSBT FROST roster does not match the authenticated coordinator wallet");
    }
    Ok(expected)
}

fn public_from_psbt(psbt: &Psbt) -> Result<frost::keys::PublicKeyPackage> {
    let config = psbt.inputs[0]
        .frost_configuration()?
        .context("missing FROST configuration")?;
    let verifying_key = frost::VerifyingKey::deserialize(&config.group_verifying_key)?;
    let shares = psbt.inputs[0]
        .frost_verifying_shares()?
        .into_iter()
        .map(|(id, share)| {
            Ok((
                frost::Identifier::deserialize(&id)?,
                frost::keys::VerifyingShare::deserialize(&share)?,
            ))
        })
        .collect::<Result<_>>()?;
    Ok(frost::keys::PublicKeyPackage::new(
        shares,
        verifying_key,
        Some(config.min_signers),
    ))
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
    let (change_public, _) = derive_public(root_public, &[1, path[1]])?;
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
            let public = public_from_psbt(&signed).unwrap();
            let setup = workflow::setup_public(public.clone()).unwrap();
            Secp256k1::verification_only()
                .verify_schnorr(
                    &signature,
                    &secp256k1::Message::from_digest(message),
                    &setup.output_key,
                )
                .unwrap();
        }
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn nonce_cannot_be_reused_or_crossed_between_sessions() {
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
        assert!(companion.has_active_nonce());
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
